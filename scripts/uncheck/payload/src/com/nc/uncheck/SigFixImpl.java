package com.nc.uncheck;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * SigFixImpl —— 真正干活的类。**不被打进 App 的 dex**，而是单独编成
 * `payload.dex` 放进 assets，运行时由 {@link SigFix}（引导器）
 * 用 `DexFile(String)` 让 **BootClassLoader** 加载。
 *
 * 为什么要独立 dex：见 SigFix 的注释。核心是「由谁加载决定了能不能
 * 访问隐藏 API」——BootClassLoader 域被视为系统代码，不受 hidden API 拦截。
 *
 * ==== 它做的事 ====
 * 把 `ActivityThread` 里持有 `IPackageManager` 的字段换成动态代理，
 * 于是 App 问系统要签名时，拿到的是**原版证书**。
 * App 自己的校验代码一个字都不动，所以它怎么写校验、怎么混淆都不影响。
 *
 * ==== 兼容性约束（每一条都对应一类"换手机就打不开"）====
 * 1. 永不抛异常出本类：每个步骤独立 try/catch，失败只记日志。
 * 2. 字段按**类型**查找，不按名字（`sPackageManager` / `mPackageManager` 改过名）。
 * 3. 在 `IPackageManager` **接口层**代理，不在 Parcel 字节层，
 *    避免 AIDL 编解码随版本变化而失效。
 * 4. `SigningDetails` 里所有 `Signature[]` 字段都换（signatures +
 *    pastSigningCertificates 是两个不同字段，只换前者时
 *    `getSigningCertificateHistory()` 会读到旧值）。
 * 5. 只改目标包自己的 `PackageInfo`，别的包（如 emoji 字体 Provider）保持原样。
 * 6. 幂等：已是被 Proxy 包过的对象就跳过，不叠加。
 */
public final class SigFixImpl {

    private static final String TAG = "SigFixImpl";

    /** payload.dex 的绝对路径，由引导器在调用 install 前通过 setPayloadPath 传入。 */
    private static String sPayloadPath;

    /** 供引导器设置 payload.dex 路径（handlerLoader 需要它）。 */
    public static void setPayloadPath(String path) {
        sPayloadPath = path;
    }

    private static Signature[] sFake;
    private static String sTargetPkg;
    private static boolean sFakeReady;
    /** 只打一次"已生效"日志，避免每次 PackageInfo 都刷屏。 */
    private static boolean sLoggedOnce;

    private SigFixImpl() {
    }

    /**
     * @param ctx     目标 App 的 Context
     * @param certB64 原版证书 DER 的 Base64
     */
    public static void install(Context ctx, String certB64) {
        Log.i(TAG, "install() 进入（BootClassLoader 域）");

        if (!sFakeReady) {
            try {
                byte[] der = Base64.decode(certB64, Base64.DEFAULT);
                sFake = new Signature[]{new Signature(der)};
                sFakeReady = true;
                Log.i(TAG, "伪造证书就绪，DER " + der.length + " 字节");
            } catch (Throwable t) {
                Log.e(TAG, "构造 Signature 失败", t);
                return;
            }
        }

        if (sTargetPkg == null) {
            try {
                sTargetPkg = ctx.getPackageName();
            } catch (Throwable t) {
                Log.e(TAG, "取包名失败", t);
                return;
            }
            Log.i(TAG, "目标包名: " + sTargetPkg);
        }

        // 关键验证点：现在能否访问隐藏 API（能则说明 BootClassLoader 绕法生效）
        try {
            Class<?> clsAt = Class.forName("android.app.ActivityThread");
            Method m = clsAt.getDeclaredMethod("currentActivityThread", new Class[0]);
            m.setAccessible(true);
            Object at = m.invoke(null);
            Log.i(TAG, "隐藏 API 可访问 ✓ currentActivityThread=" + (at != null));
        } catch (Throwable t) {
            Log.e(TAG, "隐藏 API 仍不可访问 ✗ BootClassLoader 绕法在本机无效", t);
            return;
        }

        // ① 最稳的一层：替换 PackageInfo.CREATOR。
        //    所有 PackageInfo 都要经 Parcel 反序列化，必然走这里。
        //    依赖的字段是 public static，不在 hidden 名单里，跨版本最稳。
        hookPackageInfoCreator();
        // ② 兜底：代理 IPackageManager 接口（覆盖不经 Parcel 的路径）
        hookActivityThread();
        hookExistingPackageManager(ctx);

    }

    // ───────────────────────── 主 hook ─────────────────────────

    /**
     * 替换 PackageInfo.CREATOR —— 本模块最稳的一层。
     *
     * ==== 为什么它比 IPackageManager 代理更稳 ====
     * · 拦截点在 **Parcel 反序列化**：任何从 binder 拿回来的 PackageInfo
     *   都要经过 CREATOR.createFromParcel，一条都漏不掉；
     * · 依赖的东西极少：`PackageInfo.CREATOR` 是 **public static final** 字段，
     *   属于 SDK 公开面，不在 hidden API 名单里 —— 不需要 BootClassLoader
     *   绕法、不需要 setHiddenApiExemptions、不需要猜任何内部字段名；
     * · 十年没变过（对比我们代理那两层依赖的 ActivityThread 字段，
     *   历史上改过名，且 static/实例之分踩过坑）。
     *
     * 做法参考 MT / ApkSignatureKiller 的实证实现，但代码是我们自己写的：
     * 用一个自定义 Creator 包住原 Creator，在 createFromParcel 返回前
     * 把 signatures[0] 与 signingInfo 的证书数组元素原地换掉。
     *
     * ⚠️ 只换**数组元素**而不是换对象：
     *   AOSP 的 getApkContentsSigners() 直接 `return mSigningDetails.signatures`
     *   （返回字段本身，不拷贝），所以改元素等于改内部状态。
     *   换对象则要碰 hidden 构造器 —— 实测 Android 17 上
     *   `SigningDetails(Signature[], int)` 会 NoSuchMethodException。
     */
    private static void hookPackageInfoCreator() {
        try {
            Field f = PackageInfo.class.getDeclaredField("CREATOR");
            f.setAccessible(true);
            Object orig = f.get(null);
            if (!(orig instanceof android.os.Parcelable.Creator)) {
                Log.w(TAG, "CREATOR 不是 Parcelable.Creator，跳过");
                return;
            }
            if (Proxy.isProxyClass(orig.getClass())) {
                Log.i(TAG, "CREATOR 已被代理过（幂等），跳过");
                return;
            }
            android.os.Parcelable.Creator wrapper = newPackageInfoCreator(orig);
            if (wrapper == null) {
                return;
            }
            // ⚠️ 必须用 Unsafe 而不是 Field.set：
            //   PackageInfo.CREATOR 是 public **static final**，Android 17 上
            //   反射 set 会抛 IllegalAccessException
            //   （Cannot set public static final field）。
            //   MT / ApkSignatureKiller 就是栽在这 —— 它没兜底，直接把异常
            //   抛成 RuntimeException，导致 ExceptionInInitializerError、
            //   App 在 makeApplicationInner 阶段就崩（实测简盒 v2.1.2）。
            //
            //   Unsafe.putObject 直接写内存，绕过 final 与访问检查。
            //   如果 Unsafe 也不可用，则放弃这一层（还有 IPackageManager 代理兜底）。
            boolean ok = false;
            try {
                Object unsafe = getUnsafe();
                if (unsafe != null) {
                    java.lang.reflect.Method mPut = unsafe.getClass().getMethod(
                            "putObject", Object.class, long.class, Object.class);
                    java.lang.reflect.Method mOff = unsafe.getClass().getMethod(
                            "staticFieldOffset", java.lang.reflect.Field.class);
                    java.lang.reflect.Method mBase = unsafe.getClass().getMethod(
                            "staticFieldBase", java.lang.reflect.Field.class);
                    long off = (Long) mOff.invoke(unsafe, f);
                    Object base = mBase.invoke(unsafe, f);
                    mPut.invoke(unsafe, base, off, wrapper);
                    ok = true;
                }
            } catch (Throwable t) {
                Log.w(TAG, "Unsafe 写 CREATOR 失败，退回 Field.set", t);
            }
            if (!ok) {
                f.set(null, wrapper);   // 可能抛 IllegalAccessException，由外层 catch
            }

            Object after = f.get(null);
            Log.i(TAG, "✓ PackageInfo.CREATOR 替换"
                    + (after == wrapper ? "成功（回读一致）" : "失败（回读不一致）"));
        } catch (Throwable t) {
            Log.e(TAG, "替换 PackageInfo.CREATOR 失败", t);
        }
    }

    /** 拿 sun.misc.Unsafe（反射 theUnsafe 字段）。失败返回 null。 */
    private static Object getUnsafe() {
        try {
            Class<?> clsUnsafe = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field f = clsUnsafe.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            return f.get(null);
        } catch (Throwable t) {
            Log.w(TAG, "拿 Unsafe 失败", t);
            return null;
        }
    }

    /**
     * 用 handlerLoader 加载 PackageInfoCreator 并实例化。
     *
     * ⚠️ 为什么不能直接 `new PackageInfoCreator(...)`：
     *   本类跑在 BootClassLoader 域，而 PackageInfoCreator 这个内部类
     *   在 payload.dex 里、boot 看不到 → NoClassDefFoundError
     *   （实测日志：Class not found using the boot class loader）。
     *   必须通过 handlerLoader（parent=boot，自身含 payload.dex）加载。
     */
    private static android.os.Parcelable.Creator newPackageInfoCreator(Object orig) {
        try {
            ClassLoader cl = handlerLoader(null);
            if (cl == null) {
                Log.e(TAG, "handlerLoader 为 null，无法创建 Creator");
                return null;
            }
            Class<?> cls = Class.forName(
                    "com.nc.uncheck.SigFixImpl$PackageInfoCreator", true, cl);
            java.lang.reflect.Constructor<?> ctor = cls.getDeclaredConstructor(
                    android.os.Parcelable.Creator.class, String.class, Signature[].class);
            ctor.setAccessible(true);
            return (android.os.Parcelable.Creator) ctor.newInstance(
                    (android.os.Parcelable.Creator) orig, sTargetPkg, sFake);
        } catch (Throwable t) {
            Log.e(TAG, "创建 PackageInfoCreator 失败", t);
            return null;
        }
    }

    /**
     * 包住原 Creator：反序列化出 PackageInfo 后，改掉它的签名。
     *
     * 注意这里的 Signature[] 是**实例字段**（不是静态），因为本类会被
     * handlerLoader 重新加载成另一个 Class 副本 —— 静态字段在副本之间不共享
     * （这个坑本模块踩过：日志里 sFake=false sTargetPkg=null）。
     */
    public static final class PackageInfoCreator
            implements android.os.Parcelable.Creator<Object> {

        private final android.os.Parcelable.Creator mOrig;
        private final String mPkg;
        private final Signature[] mFake;

        PackageInfoCreator(android.os.Parcelable.Creator orig, String pkg, Signature[] fake) {
            mOrig = orig;
            mPkg = pkg;
            mFake = fake;
        }

        @Override
        public Object createFromParcel(android.os.Parcel source) {
            Object o = mOrig.createFromParcel(source);
            try {
                if (o instanceof PackageInfo) {
                    patchOne((PackageInfo) o, mFake, mPkg);
                }
            } catch (Throwable t) {
                Log.e(TAG, "[Creator] patch 失败", t);
            }
            return o;
        }

        @Override
        public Object[] newArray(int size) {
            return mOrig.newArray(size);
        }
    }

    private static void hookActivityThread() {
        try {
            Class<?> clsAt = Class.forName("android.app.ActivityThread");
            Class<?> clsIpm = Class.forName("android.content.pm.IPackageManager");

            // ⚠️ ActivityThread 里那个字段是 **STATIC VOLATILE**（dexdump 实测：
            //    name='sPackageManager' type='Landroid/content/pm/IPackageManager;'
            //    access=0x0048 (STATIC VOLATILE)）。
            //    原来按「实例字段」用 field.get(activityThread) 去改，
            //    对 static 字段取到的是 null / 改的是错误位置 —— 这是
            //    「hook 报告成功但 App 完全没走代理」的真正原因。
            //    正确做法：static 字段一律 field.get(null) / field.set(null, ...)。
            Field field = findFieldByType(clsAt, clsIpm);
            if (field == null) {
                Log.w(TAG, "ActivityThread 里找不到 IPackageManager 类型字段");
                return;
            }
            field.setAccessible(true);

            boolean isStatic = java.lang.reflect.Modifier.isStatic(field.getModifiers());
            Object holder = isStatic ? null : currentActivityThread(clsAt);
            if (!isStatic && holder == null) {
                Log.w(TAG, "ActivityThread 实例为 null，跳过");
                return;
            }

            Object real = field.get(holder);
            if (real == null) {
                Log.w(TAG, "字段当前为 null（static=" + isStatic + "），跳过");
                return;
            }

            Object proxy = wrapIpm(clsIpm, real);
            if (proxy == null) {
                return;
            }
            field.set(holder, proxy);
            Object after = field.get(holder);
            Log.i(TAG, "✓ ActivityThread." + field.getName()
                    + "（" + (isStatic ? "STATIC" : "实例") + "）替换"
                    + (after == proxy ? "成功（回读一致）"
                        : "后回读不一致！实际仍是 "
                          + (after == null ? "null" : after.getClass().getName())));
        } catch (Throwable t) {
            Log.e(TAG, "hook ActivityThread 失败", t);
        }
    }

    private static Object currentActivityThread(Class<?> clsAt) {
        try {
            Method m = clsAt.getDeclaredMethod("currentActivityThread", new Class[0]);
            m.setAccessible(true);
            return m.invoke(null);
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 补一刀：改已创建出来的 ApplicationPackageManager 实例里的引用。
     *
     * 为什么必须补：`ApplicationPackageManager` 在构造时就把 `IPackageManager`
     * 存进了自己的字段。install() 执行时框架很可能已经创建过 PM 实例，
     * 那些实例仍指向旧对象 —— 只改 ActivityThread 覆盖不到它们。
     */
    private static void hookExistingPackageManager(Context ctx) {
        try {
            Object pm = ctx.getPackageManager();
            if (pm == null) {
                return;
            }
            Class<?> clsIpm = Class.forName("android.content.pm.IPackageManager");
            Field field = findFieldByType(pm.getClass(), clsIpm);
            if (field == null) {
                Log.w(TAG, pm.getClass().getName() + " 里找不到 IPackageManager 类型字段");
                return;
            }
            field.setAccessible(true);
            boolean isStatic = java.lang.reflect.Modifier.isStatic(field.getModifiers());
            Object holder = isStatic ? null : pm;
            Object real = field.get(holder);
            if (real == null) {
                Log.w(TAG, pm.getClass().getName() + "." + field.getName()
                        + " 为 null（static=" + isStatic + "），跳过");
                return;
            }
            Object proxy = wrapIpm(clsIpm, real);
            if (proxy == null) {
                return;
            }
            field.set(holder, proxy);
            // 改完立刻回读：`ApplicationPackageManager.mPM` 是 PRIVATE FINAL，
            // 反射 set 在部分 ART 上会静默失败（不抛异常但值没变）。
            // 不回读就等于「报告成功、实际没改」—— 本模块栽过这个跟头。
            Object after = field.get(holder);
            boolean ok = (after == proxy);
            Log.i(TAG, "✓ " + pm.getClass().getSimpleName() + "." + field.getName()
                    + "（" + (isStatic ? "STATIC" : "实例") + "）替换"
                    + (ok ? "成功（回读一致）" : "后回读不一致！实际仍是 "
                        + (after == null ? "null" : after.getClass().getName())));
        } catch (Throwable t) {
            Log.e(TAG, "hook 已存在的 PackageManager 失败", t);
        }
    }

    private static Object wrapIpm(Class<?> iface, Object real) {
        try {
            if (Proxy.isProxyClass(real.getClass())) {
                Log.i(TAG, "已是代理，跳过（幂等）");
                return null;
            }
            ClassLoader cl = handlerLoader(iface);
            if (cl == null) {
                Log.e(TAG, "handlerLoader 为 null");
                return null;
            }
            // 用 cl 重新加载 handler 类，确保它对该 loader 可见
            Class<?> clsHandler = Class.forName(
                    "com.nc.uncheck.SigFixImpl$IpmHandler", true, cl);
            java.lang.reflect.Constructor<?> ctor = clsHandler.getDeclaredConstructor(
                    Object.class, Signature[].class, String.class);
            ctor.setAccessible(true);
            Object handler = ctor.newInstance(real, sFake, sTargetPkg);

            // Proxy 用 iface 的 loader 解析接口、用传入的 loader 解析 handler。
            // 传 cl（parent=boot）两边都能看到。
            return Proxy.newProxyInstance(cl, new Class[]{iface},
                    (InvocationHandler) handler);
        } catch (Throwable t) {
            Log.e(TAG, "wrapIpm 失败", t);
            return null;
        }
    }

    private static ClassLoader sHandlerLoader;

    /**
     * 给 Proxy 用的 ClassLoader。
     *
     * ==== 为什么这么绕 ====
     * 实测（Android 17）：
     *   · IPackageManager / IPackageManager$Stub$Proxy 的 ClassLoader 都是
     *     BootClassLoader（null）
     *   · Proxy.newProxyInstance 会用【接口的 ClassLoader】去解析 handler 类
     *   · 我们的 handler（SigFixImpl$IpmHandler）在 payload.dex 里，boot 看不到
     *   → NoClassDefFoundError: Class not found using the boot class loader
     *
     * ==== 解法 ====
     * 造一个 PathClassLoader(path=payload.dex, parent=BootClassLoader)：
     *   parent 是 boot → 能解析系统接口
     *   自身路径含 payload.dex → 能解析 handler
     * 但 Proxy 仍会用 iface.getClassLoader()。
     * 所以这里直接**把 handler 类也用这个 loader 重新加载一份**，
     * 保证 IpmHandler 的 Class 对象来自 sHandlerLoader。
     */
    private static synchronized ClassLoader handlerLoader(Class<?> iface) throws Throwable {
        if (sHandlerLoader != null) {
            return sHandlerLoader;
        }
        String dexPath = sPayloadPath;
        if (dexPath == null) {
            Log.e(TAG, "sPayloadPath 未设置");
            return null;
        }
        Class<?> clsPCL = Class.forName("dalvik.system.PathClassLoader");
        java.lang.reflect.Constructor<?> ctor =
                clsPCL.getDeclaredConstructor(String.class, ClassLoader.class);
        sHandlerLoader = (ClassLoader) ctor.newInstance(dexPath, null);
        Log.i(TAG, "handlerLoader 已创建: " + dexPath
                + " (parent=" + (sHandlerLoader.getParent() == null ? "BOOT" : "other") + ")");
        return sHandlerLoader;
    }

    private static final class IpmHandler implements InvocationHandler {
        private final Object mReal;
        /** 伪造签名。**必须是实例字段**：
         *  handler 类被 handlerLoader 重新加载后，是另一个 Class 副本，
         *  它看到的 SigFixImpl 静态字段全是 null（实测：sFake=false
         *  sTargetPkg=null）。所以数据必须经构造器传进来。 */
        private final Signature[] mFake;
        private final String mTargetPkg;

        IpmHandler(Object real, Signature[] fake, String targetPkg) {
            mReal = real;
            mFake = fake;
            mTargetPkg = targetPkg;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object ret;
            try {
                ret = method.invoke(mReal, args);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                throw (cause != null) ? cause : e;
            }
            try {
                patchPackageInfos(ret, mFake, mTargetPkg);
            } catch (Throwable t) {
                Log.e(TAG, "[patchResult] 抛异常", t);
            }
            return ret;
        }
    }

    // ───────────────────────── 返回值改写 ─────────────────────────

    /**
     * 入口：拿到一个 binder 返回值，若是 PackageInfo（或数组）就改。
     *
     * ⚠️ 所有数据经参数传入，**不读任何静态字段**。
     *   原因：PackageInfoCreator / IpmHandler 这两个内部类会被
     *   handlerLoader 重新加载成另一个 Class 副本，静态字段在副本间不共享
     *   （实测日志：sFake=false sTargetPkg=null，导致改写全被 null 检查挡掉）。
     */
    private static void patchPackageInfos(Object ret, Signature[] fake, String targetPkg) {
        if (ret == null || fake == null || targetPkg == null) {
            return;
        }
        if (ret instanceof PackageInfo) {
            patchOne((PackageInfo) ret, fake, targetPkg);
        } else if (ret instanceof PackageInfo[]) {
            PackageInfo[] arr = (PackageInfo[]) ret;
            for (int i = 0; i < arr.length; i++) {
                patchOne(arr[i], fake, targetPkg);
            }
        }
    }

    /** 改一个 PackageInfo：signatures + signingInfo 两条路都改。 */
    private static void patchOne(PackageInfo pi, Signature[] fake, String targetPkg) {
        if (pi == null) {
            return;
        }
        String pn = pi.packageName;
        if (pn == null || !pn.equals(targetPkg)) {
            return;
        }
        try {
            pi.signatures = fake;
        } catch (Throwable ignored) {
        }
        try {
            patchSigningInfoOf(pi, fake);
        } catch (Throwable ignored) {
        }
    }

    /**
     * 让 pi.signingInfo 返回假签名。
     *
     * ==== 做法来源 ====
     * MT / ApkSignatureKiller 的实证实现：不构造对象、不碰 hidden 字段，而是
     *     Signature[] arr = signingInfo.getApkContentsSigners();
     *     arr[0] = 假签名;
     *
     * ==== 为什么必须这么写（另外两条路都试过、都失败）====
     *  ① 改 mSigningDetails 字段：hidden 字段，Android 17 上
     *     getDeclaredFields() 只返回 CREATOR 和几个 VERSION_* 常量，看不到它。
     *  ② 构造新 SigningInfo：SigningDetails(Signature[], int) 构造器虽然
     *     存在于 dexdump，但 getDeclaredConstructor 报 NoSuchMethodException。
     *
     * ==== 为什么改数组元素就够了 ====
     * AOSP 的 getApkContentsSigners() 直接 return mSigningDetails.signatures
     * —— 返回字段本身、不做拷贝。所以改元素等于改内部状态。
     *
     * history 那份也要改：hasMultipleSigners() 为 false 且存在历史证书时，
     * getSigningCertificateHistory() 返回另一个数组（pastSigningCertificates），
     * 只改 contents 会让走 history 分支的 App 读到旧值。
     */
    private static void patchSigningInfoOf(PackageInfo pi, Signature[] fake) {
        if (Build.VERSION.SDK_INT < 28) {
            return;
        }
        Object info;
        try {
            info = pi.signingInfo;
        } catch (Throwable t) {
            return;
        }
        if (info == null) {
            // GET_SIGNATURES 查询下本来就是 null，App 读的是 pi.signatures。
            return;
        }

        boolean any = false;

        try {
            Method m = info.getClass().getMethod("getApkContentsSigners");
            Signature[] arr = (Signature[]) m.invoke(info);
            if (arr != null && arr.length > 0) {
                arr[0] = fake[0];
                any = true;
                if (!sLoggedOnce) {
                    sLoggedOnce = true;
                    Log.i(TAG, "签名伪造已生效，证书指纹="
                            + sha256Of(((Signature[]) m.invoke(info))[0]));
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "改 contents 失败", t);
        }

        try {
            Method m = info.getClass().getMethod("getSigningCertificateHistory");
            Signature[] arr = (Signature[]) m.invoke(info);
            if (arr != null && arr.length > 0) {
                arr[0] = fake[0];
                any = true;
            }
        } catch (Throwable t) {
            // 部分版本/查询方式下没有该方法或不可用，忽略
        }

        if (!any) {
            Log.w(TAG, "contents 与 history 都没改成，signingInfo 未被伪造");
        }
    }

    /** 算 Signature 的 SHA-256 前 8 字节 hex，用于和 App 的期望值对照。 */
    private static String sha256Of(Signature sig) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(sig.toByteArray());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(8, d.length); i++) {
                sb.append(String.format("%02x", d[i]));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "err";
        }
    }

    /** 按字段**类型**查找，不按名字。见类注释第 2 条。 */
    private static Field findFieldByType(Class<?> owner, Class<?> type) {
        Class<?> c = owner;
        while (c != null && c != Object.class) {
            Field[] fields;
            try {
                fields = c.getDeclaredFields();
            } catch (Throwable t) {
                c = c.getSuperclass();
                continue;
            }
            for (int i = 0; i < fields.length; i++) {
                if (fields[i].getType() == type) {
                    return fields[i];
                }
            }
            c = c.getSuperclass();
        }
        return null;
    }
}
