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
 * SigFix —— 通用去签名校验载荷（唯一源码真相）
 *
 * smali 由 build.sh 自动生成，永不手改（同 string-enc/stub-src/StrDec.java 的先例）。
 *
 * ==== 核心思路 ====
 * 不改目标 App 的任何校验代码。App 无论怎么写校验，最终必须从某个「信息源」取签名：
 *   A. PackageManager.getPackageInfo(...).signatures / .signingInfo   ← 本类代理这一层
 *   B. PackageManager.checkSignatures(...)                            ← 顺带覆盖（同一接口）
 *   C. 自读 APK 文件（sourceDir / ZipFile / stat）                     ← 本版不覆盖，见 README
 *   D. 硬编码常量 / 上报服务器                                          ← 本版不覆盖，见 README
 * 本类把 A/B 的返回值换成「原版证书」，于是 App 自己算出来的哈希就是原版哈希，
 * 与它自己的期望值自然相等 —— 不需要知道它把期望值写在哪、怎么混淆的。
 *
 * ==== 兼容性设计（这是重点，逐条对应「换手机就打不开」的风险）====
 * 1. 永不抛异常出本类：每个步骤独立 try/catch，任何一步失败都静默降级，
 *    App 照常启动（最坏情况=校验没过，弹个警告，不会闪退）。
 * 2. 字段一律「按类型找，不按名字找」（findFieldByType）：
 *    ActivityThread 里那个 IPackageManager 字段在历史版本上叫过 sPackageManager /
 *    mPackageManager，硬编码名字的实现在换 ROM 时必废。按类型匹配与名字无关。
 * 3. 在 IPackageManager「接口层」做代理，不在 Parcel/Binder「字节层」：
 *    拿到的是已经反序列化好的 PackageInfo 普通对象，直接改字段即可。
 *    不需要知道 transaction code、不需要重写 writeToParcel、不随 Android
 *    版本改 Parcel 布局而失效。
 * 4. SigningInfo 内部结构按类型扫描，不认 SigningDetails 里的字段名：
 *    把所有 Signature[] 类型的字段都换掉（signatures + pastSigningCertificates
 *    两个都要换，否则 getSigningCertificateHistory() 会走到另一个字段）。
 * 5. 只改目标包自己的 PackageInfo（按 packageName 过滤）：
 *    否则 App 查别的包（典型：androidx emoji2 校验字体 Provider 的签名）会拿到
 *    错的值而崩 —— 这是「本机好、别人机崩」的经典成因。
 * 6. 幂等 + 不叠加别人已有的代理：Proxy.isProxyClass 检查，已 hook 就跳过。
 * 7. 不用 lambda / 新语法：d8 min-api 21 下编，避免脱糖差异。
 *
 * ==== 已知不覆盖（诚实口径，见 README「覆盖边界」）====
 * - App 绕过 PackageManager、直接从 /dev/binder 拿 "package" 服务：需 hook ServiceManager
 * - App 自读 APK 文件（sourceDir + ZipFile / 解析 Signing Block / stat 文件大小）
 * - App 把测量结果上报服务器裁决
 * - Play Integrity / SafetyNet
 */
public final class SigFix {

    private static final String TAG = "SigFix";

    /**
     * 原证书 DER 的 Base64。由 scripts/uncheck/inject.py 在注入时替换成真实值。
     * 占位符必须保持「以 __ 开头」的形态：install() 见占位符未被替换就整体放弃，
     * 避免拿垃圾串构造 Signature 后行为不可预期。
     */
    private static final String CERT_B64 = "__NC_SIGFIX_CERT_B64__";

    /** 伪造后的签名数组（原版证书），全局共用一份。 */
    private static Signature[] sFake;

    /** 目标包名。只改这个包的 PackageInfo，别的包一律放过。 */
    private static String sTargetPkg;

    private static volatile boolean sFakeReady;

    private SigFix() {
    }

    /**
     * 唯一对外入口。可重复调用（双保险注入点会各调一次），内部幂等。
     *
     * @param ctx 目标 App 的 Context，用于取包名。为 null 则整体放弃
     *            （拿不到包名就无法安全过滤，宁可不生效也不要改到别的包）。
     */
    public static void install(Context ctx) {
        if (ctx == null) {
            return;
        }

        if (!sFakeReady) {
            if (CERT_B64 == null || CERT_B64.startsWith("__")) {
                return;
            }
            try {
                sFake = new Signature[]{new Signature(Base64.decode(CERT_B64, Base64.DEFAULT))};
                sFakeReady = true;
            } catch (Throwable t) {
                return;
            }
        }

        if (sTargetPkg == null) {
            try {
                sTargetPkg = ctx.getPackageName();
            } catch (Throwable t) {
                return;
            }
            if (sTargetPkg == null) {
                return;
            }
        }

        // 顺序有讲究：先解 hidden API 限制，否则后面反射 ActivityThread 会被拦。
        // 但即使豁免失败也继续试 —— 低版本 Android 本来就不需要豁免。
        try {
            exemptHiddenApi();
        } catch (Throwable ignored) {
        }

        hookActivityThread();

        hookExistingPackageManager(ctx);
    }

    // ───────────────────────── hidden API 豁免 ─────────────────────────

    /**
     * 解除 hidden API 黑/灰名单限制（Android 9+）。
     *
     * 走的是业界通行的纯 Java 路径：用 Class.forName / getDeclaredMethod 拿到
     * VMRuntime 的 Method 对象再 invoke。这里访问的是 SDK 公开方法（Class.forName
     * 等）本身不受限制，拿到 Method 对象后的调用才绕开「调用点所属类是否在名单里」
     * 的判定。
     *
     * ⚠️ 风险（如实记录）：setHiddenApiExemptions 属 unsupported（灰名单），
     * 个别 OEM ROM 或未来 Android 版本可能收紧为黑名单。失败时本方法抛异常，
     * 由 install() 吞掉，此时后续反射 ActivityThread 会失败 → hook 不生效，
     * 但 App 仍能正常启动（不闪退）。这也是为什么「不得把异常抛出去」是硬约束。
     */
    private static void exemptHiddenApi() throws Throwable {
        Method mForName = Class.class.getDeclaredMethod("forName", new Class[]{String.class});
        Method mGetDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod",
                new Class[]{String.class, Class[].class});
        if (mForName == null || mGetDeclaredMethod == null) {
            return;
        }

        Class<?> clsVmRuntime = (Class<?>) mForName.invoke(null, new Object[]{"dalvik.system.VMRuntime"});
        if (clsVmRuntime == null) {
            return;
        }

        Method mGetRuntime = (Method) mGetDeclaredMethod.invoke(clsVmRuntime,
                new Object[]{"getRuntime", new Class[0]});
        if (mGetRuntime == null) {
            return;
        }
        Object vmRuntime = mGetRuntime.invoke(null);
        if (vmRuntime == null) {
            return;
        }

        Method mSetExemptions = (Method) mGetDeclaredMethod.invoke(clsVmRuntime,
                new Object[]{"setHiddenApiExemptions", new Class[]{String[].class}});
        if (mSetExemptions == null) {
            return;
        }
        // "L" 是前缀豁免：所有以 L 开头的签名（即全部类）都放行。
        mSetExemptions.invoke(vmRuntime, new Object[]{new String[]{"L"}});
    }

    // ───────────────────────── 主 hook：ActivityThread ─────────────────────────

    /**
     * 把 ActivityThread 里持有 IPackageManager 的那个字段换成我们的代理。
     *
     * 为什么选这个字段而不是别处：它是进程内所有 ContextImpl 构造
     * ApplicationPackageManager 时的共同来源，改一处即全局生效。
     */
    private static void hookActivityThread() {
        try {
            Class<?> clsAt = Class.forName("android.app.ActivityThread");
            Class<?> clsIpm = Class.forName("android.content.pm.IPackageManager");
            if (clsAt == null || clsIpm == null) {
                return;
            }

            Method mCurrent = clsAt.getDeclaredMethod("currentActivityThread", new Class[0]);
            mCurrent.setAccessible(true);
            Object activityThread = mCurrent.invoke(null);
            if (activityThread == null) {
                return;
            }

            Field field = findFieldByType(clsAt, clsIpm);
            if (field == null) {
                return;
            }
            field.setAccessible(true);
            Object real = field.get(activityThread);
            if (real == null) {
                return;
            }

            Object proxy = wrapIpm(clsIpm, real);
            if (proxy == null) {
                return;
            }
            field.set(activityThread, proxy);
        } catch (Throwable ignored) {
        }
    }

    /**
     * 补一刀：改已存在的 ApplicationPackageManager 实例里的 IPackageManager 引用。
     *
     * 为什么必须补：ApplicationPackageManager 在构造时就把 IPackageManager 存进了
     * 自己的字段。install() 执行时，框架为了加载资源很可能已经创建过 PM 实例，
     * 那些实例仍指向旧的真实对象 —— 只改 ActivityThread 覆盖不到它们。
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
                return;
            }
            field.setAccessible(true);
            Object real = field.get(pm);
            if (real == null) {
                return;
            }
            Object proxy = wrapIpm(clsIpm, real);
            if (proxy == null) {
                return;
            }
            field.set(pm, proxy);
        } catch (Throwable ignored) {
        }
    }

    // ───────────────────────── 代理构造 ─────────────────────────

    private static Object wrapIpm(Class<?> iface, Object real) {
        try {
            // 已经有人（另一个 hook 框架 / 我们自己的上一次调用）代理过，不叠加：
            // 叠加会让异常处理链变长，且我们无法确认对方语义。
            if (Proxy.isProxyClass(real.getClass())) {
                return null;
            }
            ClassLoader cl = iface.getClassLoader();
            return Proxy.newProxyInstance(cl, new Class[]{iface}, new IpmHandler(real));
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * IPackageManager 的代理处理器。
     *
     * 关键点：走到这里时 AIDL 的 Parcel 编解码已经在真实对象内部做完了，
     * 我们拿到的是普通 Java 对象。所以只需要「转发 + 改结果」。
     */
    private static final class IpmHandler implements InvocationHandler {

        private final Object mReal;

        IpmHandler(Object real) {
            mReal = real;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object ret;
            try {
                ret = method.invoke(mReal, args);
            } catch (InvocationTargetException e) {
                // 保持原样向外抛，不能把 InvocationTargetException 透给系统框架：
                // 框架只 catch 它自己认识的服务端异常类型。
                Throwable cause = e.getCause();
                throw (cause != null) ? cause : e;
            }
            try {
                patchResult(ret);
            } catch (Throwable ignored) {
                // 改结果失败也要把原始结果还给调用方，绝不因我们的问题让 App 崩
            }
            return ret;
        }
    }

    // ───────────────────────── 返回值改写 ─────────────────────────

    private static void patchResult(Object ret) {
        if (ret == null) {
            return;
        }
        if (ret instanceof PackageInfo) {
            patchPackageInfo((PackageInfo) ret);
        } else if (ret instanceof PackageInfo[]) {
            PackageInfo[] arr = (PackageInfo[]) ret;
            for (int i = 0; i < arr.length; i++) {
                patchPackageInfo(arr[i]);
            }
        }
        // 注：getInstalledPackages 等接口可能返回 ParceledListSlice，
        // 展开它需要调 getList()，而 getList() 会触发一次 Binder 读取、有副作用。
        // 本版不展开（目标 App 极少用这个接口查自己签名）。见 README 覆盖边界。
    }

    private static void patchPackageInfo(PackageInfo pi) {
        if (pi == null || sFake == null) {
            return;
        }
        // 只动目标包自身。别的包（emoji 字体 Provider、同签名校验等）保持原样。
        if (pi.packageName == null || !pi.packageName.equals(sTargetPkg)) {
            return;
        }
        try {
            pi.signatures = sFake;
        } catch (Throwable ignored) {
        }
        try {
            patchSigningInfo(pi);
        } catch (Throwable ignored) {
        }
    }

    /**
     * Android 9+ 走 SigningInfo。App 可能读 getApkContentsSigners() 或
     * getSigningCertificateHistory()，两者分别对应 SigningDetails 里两个不同的
     * Signature[] 字段 —— 所以按类型扫，把所有 Signature[] 字段一起换掉。
     */
    private static void patchSigningInfo(PackageInfo pi) {
        if (Build.VERSION.SDK_INT < 28) {
            return;
        }
        Object signingInfo;
        try {
            signingInfo = pi.signingInfo;
        } catch (Throwable t) {
            return;
        }
        if (signingInfo == null) {
            return;
        }

        Class<?> clsSigningDetails;
        try {
            clsSigningDetails = Class.forName("android.content.pm.SigningDetails");
        } catch (Throwable t) {
            return;
        }

        Field fieldDetails = findFieldByType(signingInfo.getClass(), clsSigningDetails);
        if (fieldDetails == null) {
            return;
        }
        Object details;
        try {
            fieldDetails.setAccessible(true);
            details = fieldDetails.get(signingInfo);
        } catch (Throwable t) {
            return;
        }
        if (details == null) {
            return;
        }

        replaceAllSignatureArrays(details, clsSigningDetails);
    }

    /**
     * 把 owner 类（含父类）里所有 Signature[] 字段都替换成 sFake。
     *
     * 为什么是「所有」而不是「叫 signatures 那个」：
     *   SigningDetails.signatures             → getApkContentsSigners()
     *   SigningDetails.pastSigningCertificates → getSigningCertificateHistory()
     * 只换前者时，hasMultipleSigners() 为 false（我们只放 1 个签名）会让
     * getSigningCertificateHistory() 走到后者，读到的是原版之外的旧值 ——
     * 表现为「某些 App 的哈希比对用 history 就过不去」。
     */
    private static void replaceAllSignatureArrays(Object owner, Class<?> start) {
        Class<?> c = start;
        while (c != null && c != Object.class) {
            Field[] fields;
            try {
                fields = c.getDeclaredFields();
            } catch (Throwable t) {
                c = c.getSuperclass();
                continue;
            }
            for (int i = 0; i < fields.length; i++) {
                Field f = fields[i];
                if (f.getType() != Signature[].class) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    f.set(owner, sFake);
                } catch (Throwable ignored) {
                }
            }
            c = c.getSuperclass();
        }
    }

    // ───────────────────────── 工具：按类型找字段 ─────────────────────────

    /**
     * 【兼容性核心】按字段「类型」查找，不按名字。
     *
     * 历史教训（对照 SRPatch / ApkSignatureKillerEx）：它们都硬编码
     * sPackageManager / mPackageManager / mCreators，Android 改一次名就整体失效，
     * 而且失效方式是「不报错，只是没生效」，极难排查。
     */
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
