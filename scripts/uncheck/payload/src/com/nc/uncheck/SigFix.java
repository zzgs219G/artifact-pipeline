package com.nc.uncheck;

import android.content.Context;
import android.util.Log;

/**
 * SigFix —— 通用去签名校验载荷的**引导器**（bootstrap）。
 *
 * ⚠️ 这个类必须待在 App 自己的 ClassLoader 里（也就是和别的类一起被打进
 * classes.dex 或我们新增的 classesN.dex）。它的唯一职责是：
 *
 *   1. 把「真正干活的类」反序列化成一个**独立的 dex 文件**写到私有目录；
 *   2. 用 `dalvik.system.DexFile` 的废弃构造方法 `DexFile(String)`
 *      加载那个 dex —— 这条路径会让 ART 用 **BootClassLoader** 加载它；
 *   3. 反射调用真正干活的类。
 *
 * ==== 为什么要这么绕 ====
 *
 * 目标是反射访问隐藏 API（`ActivityThread` / `IPackageManager` 等）。
 * Android 9+ 对「应用代码」反射隐藏 API 做了拦截，判定依据是
 * **加载该 Class 的 ClassLoader / DexFile 的 domain**。
 * 而由 BootClassLoader 加载的 dex 被视为系统代码，不受拦截。
 *
 * 直接调 `VMRuntime.setHiddenApiExemptions("L")` 这条路在 Android 15+
 * （实机测的是 Android 17 / SDK 37）上被标成 `blocked`，
 * 报 `NoSuchMethodException`，纯反射拿不到。
 *
 * 业界已验证的纯 Java 绕法有两条：
 *   a) 把类的 `Class.classLoader` 置为 null —— **Android Q 起失效**
 *      （Q 之后判定的是"DexFile 的 ClassLoader"，不是"类的"）
 *   b) `new DexFile(path)`（不传 ClassLoader）让 BootClassLoader 加载
 *      —— Android P~U 已验证有效，本类采用这条
 *
 * ==== 已知风险（如实记录） ====
 * · `DexFile(String)` 已被标记 @Deprecated，官方随时可能删除。
 *   Android 17 上经 dexdump 实测仍存在（`<init>(Ljava/lang/String;)V`）。
 *   若未来版本删掉，本类会在引导阶段失败 —— 但**不会闪退**：
 *   所有路径都 try/catch，失败只记日志，App 照常启动（校验照旧）。
 * · 写 dex 到 codeCacheDir 需要文件系统可写，正常情况下 App 私有目录必然可写。
 * · 本类只负责引导，不写任何业务逻辑，便于单独审查。
 */
public final class SigFix {

    private static final String TAG = "SigFix";

    /** 真正干活的类：位于我们另行投放的 dex 里，由 BootClassLoader 加载。 */
    private static final String PAYLOAD_CLASS = "com.nc.uncheck.SigFixImpl";

    /** 投放的 dex 文件名（放在 codeCacheDir 下）。 */
    private static final String PAYLOAD_DEX = "sigfix-payload.dex";

    /** 资产名：注入时由 scripts/uncheck/inject.py 放进 assets/。 */
    private static final String PAYLOAD_ASSET = "nc_sigfix/payload.dex";

    /**
     * 原版证书 DER 的 Base64 —— **运行时从 assets/nc_sigfix/sigfix.json 读**，
     * 不再烘焙进 dex。
     *
     * 为什么改（2026-11-21）：烘焙进 dex 需要重建字符串池（证书长度不固定，
     * 不能原位替换），对"只消费编译好 dex"的场景不友好，且每换一个目标
     * App 就要重编一次 dex。挪到 JSON 后 dex 变成静态资产。
     */
    private static final String CONFIG_ASSET = "nc_sigfix/sigfix.json";

    /** 兼容旧路径：仍接受由 SigFixApp 传入的证书（它已经从 JSON 读好了）。 */
    private static String CERT_B64 = null;

    private static volatile boolean sDone;

    /** hook 分层（2026-11-27）：1=核心 2=+at/readlink 3=全量（缺省）。
     *  为什么可降档：18 个 hook 全挂会波及与校验无关的代码 —— 实测
     *  JMComic(Capacitor WebView) 在两层模式下图片/网络加载失败，
     *  仅 Java 层正常。详见 nativeHookApkPath 调用点的注释。 */
    private static int sHookLevel = 3;

    private SigFix() {
    }

    /**
     * 唯一对外入口。可重复调用（多注入点会各调一次），内部幂等。
     *
     * @param ctx 目标 App 的 Context（Activity / Application 本身即是）
     */
    public static void install(Context ctx) {
        Log.i(TAG, "install() 进入，ctx=" + (ctx == null ? "null" : ctx.getClass().getName()));
        if (ctx == null) {
            return;
        }
        if (sDone) {
            Log.i(TAG, "已安装过，跳过");
            return;
        }

        if (CERT_B64 == null || CERT_B64.isEmpty()) {
            CERT_B64 = readCertFromConfig(ctx);
        }
        if (CERT_B64 == null || CERT_B64.isEmpty()) {
            Log.e(TAG, "没有可用证书（sigfix.json 缺失或无 cert 字段），放弃");
            return;
        }

        // ⚠️ 关键：Application.attachBaseContext 阶段 Context 还没就绪。
        //
        // 实测（简盒 v2.1.2 / Android 17）：
        //   在 Application.attachBaseContext 里调 ctx.getCodeCacheDir() →
        //   NullPointerException: ContextWrapper.getCodeCacheDir() on a null object
        //   原因：Application.attach() 先调 attachBaseContext，此时 mBase 刚设置，
        //   依赖 mBase 的那些 API（getCodeCacheDir / getFilesDir / getAssets 等）
        //   尚不可用。
        //
        // 所以：拿不到目录时**不标记完成**，等下一个注入点（onCreate）再来。
        // 注入器会往多个生命周期方法各插一份调用，天然形成重试链。
        try {
            ctx.getCodeCacheDir();
        } catch (Throwable t) {
            Log.i(TAG, "Context 尚未就绪（" + t.getClass().getSimpleName()
                    + "），等待下一个注入点重试");
            return;   // 注意：没有设置 sDone，下一处调用会重新尝试
        }

        sDone = true;
        try {
            boot(ctx);
        } catch (Throwable t) {
            // 引导失败：只记日志。校验没绕过是"没生效"，不能让 App 崩。
            Log.e(TAG, "引导失败（去校验未生效，App 可正常使用）", t);
        }
    }

    private static void boot(Context ctx) throws Throwable {
        // 0) native 层：APK 路径重定向（让 so 读到 origin.apk 的签名块）
        //
        // ⚠️ 必须在**这里**（app 域）做，不能在 SigFixImpl（boot 域）里做：
        //    System.loadLibrary 按"调用类的 ClassLoader"查找 nativeLibraryDir，
        //    BootClassLoader 域找不到导航库目录，会静默失败。
        //
        // 这一层解决的是 Java 层 hook 覆盖不到的两条路径：
        //   ① App 自己 ZipFile(base.apk) 读 META-INF/*.RSA
        //   ② native so 直接解析 APK Signing Block（__open_2 + fstat + mmap 读签名块）
        // 不同目标 so 的导入符号不同（有的不含 openat，有的 fopen 走 PLT），
        // 所以 native 侧用 shadowhook 的 inline hook，覆盖路径类函数全集：
        // open/open64/__open_2/openat/openat64/fopen/fopen64/access/faccessat/stat/lstat/readlink/opendir。
        installNativeRedirect(ctx);

        // 1) 投放 payload dex 到私有目录（已存在且大小一致则跳过）
        java.io.File dexOut = new java.io.File(ctx.getCodeCacheDir(), PAYLOAD_DEX);
        boolean needWrite = true;
        try {
            long expect = assetSize(ctx, PAYLOAD_ASSET);
            if (dexOut.isFile() && dexOut.length() == expect && expect > 0) {
                needWrite = false;
                Log.i(TAG, "payload dex 已存在且大小一致，跳过投放");
            }
        } catch (Throwable ignored) {
        }
        if (needWrite) {
            // 先删旧文件：上一次运行可能已把它设成只读（400），
            // 直接 FileOutputStream 覆盖会 EACCES（实测踩过）。
            if (dexOut.exists() && !dexOut.delete()) {
                Log.w(TAG, "旧 payload dex 删不掉: " + dexOut.getAbsolutePath());
            }
            extractAsset(ctx, PAYLOAD_ASSET, dexOut);
            Log.i(TAG, "payload dex 已投放: " + dexOut.getAbsolutePath()
                    + " (" + dexOut.length() + " B)");
        }

        // 2) 用 DexFile(String) 让 BootClassLoader 加载 → 里面的类天然享有系统权限
        //
        // ⚠️ 必须用「不传 ClassLoader」的那个重载。传了 ClassLoader 就退回
        //    普通应用域，隐藏 API 照样被拦，等于白绕。
        Object dexFile = null;
        Class<?> impl;
        try {
            Class<?> clsDexFile = Class.forName("dalvik.system.DexFile");
            java.lang.reflect.Constructor<?> ctor =
                    clsDexFile.getDeclaredConstructor(String.class);
            ctor.setAccessible(true);
            dexFile = ctor.newInstance(dexOut.getAbsolutePath());
            Log.i(TAG, "DexFile(String) 构造成功");

            java.lang.reflect.Method loadClass =
                    clsDexFile.getDeclaredMethod("loadClass", String.class, ClassLoader.class);
            loadClass.setAccessible(true);
            impl = (Class<?>) loadClass.invoke(dexFile, PAYLOAD_CLASS, null);
            if (impl == null) {
                throw new IllegalStateException("loadClass 返回 null: " + PAYLOAD_CLASS);
            }
            Log.i(TAG, "payload 类已加载（BootClassLoader 域）: " + impl.getName());
        } catch (Throwable t) {
            Log.e(TAG, "DexFile 引导失败", t);
            throw t;
        }

        // 3) 先告诉实现类 payload.dex 在哪 —— 它建 Proxy 时需要知道
        //    （Proxy 的 ClassLoader 必须同时看到系统接口与本 dex 里的 handler 类）
        try {
            java.lang.reflect.Method setPath =
                    impl.getDeclaredMethod("setPayloadPath", String.class);
            setPath.setAccessible(true);
            setPath.invoke(null, dexOut.getAbsolutePath());
        } catch (Throwable t) {
            Log.w(TAG, "setPayloadPath 失败（Proxy 可能因此建不出来）", t);
        }

        // 4) 反射调用真正的 install
        java.lang.reflect.Method install =
                impl.getDeclaredMethod("install", Context.class, String.class);
        install.setAccessible(true);
        install.invoke(null, ctx, CERT_B64);
        Log.i(TAG, "payload install() 调用完成");
    }

    /** 从 assets/nc_sigfix/sigfix.json 读 cert 字段。失败返回空串。 */
    private static String readCertFromConfig(Context ctx) {
        java.io.InputStream in = null;
        try {
            in = ctx.getAssets().open(CONFIG_ASSET);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            org.json.JSONObject o =
                    new org.json.JSONObject(new String(bos.toByteArray(), "UTF-8"));
            String c = o.optString("cert", "");
            /* hook 分层（2026-11-27）：同一次读取顺带取 hookLevel，
             * 缺省 3=全量（与历史行为一致）。越界值由 native 侧钳位。 */
            sHookLevel = o.optInt("hookLevel", 3);
            Log.i(TAG, "从 sigfix.json 读到证书: " + (c.isEmpty() ? "空" : c.length() + " 字符")
                    + "，hookLevel=" + sHookLevel);
            return c;
        } catch (Throwable t) {
            Log.e(TAG, "读 sigfix.json 失败", t);
            return "";
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    // ─────────────────── native 层 APK 路径重定向 ───────────────────

    /** native 库名（打进 lib/{abi}/libusign.so） */
    private static final String NATIVE_LIB = "usign";

    /** origin.apk 在 assets 里的位置（注入器投放，= 原签名 APK 全量副本） */
    private static final String ORIGIN_ASSET = "nc_sigfix/origin.apk";

    /** origin.apk 在私有目录的落点文件名 */
    private static final String ORIGIN_FILE = "sigfix-origin.apk";

    /** 只装一次的标记（native hook 是进程级的，重复装会互相覆盖） */
    private static volatile boolean sNativeDone;

    /**
     * native 层：把 base.apk 的所有文件读操作重定向到 origin.apk。
     *
     * ==== 为什么需要这一层 ====
     * Java 层三层 hook（CREATOR / PMS 代理 / signingInfo）只能拦
     * "通过 PackageManager 问签名"的路径。目标 App 若绕开 PMS：
     *   · Java:  new ZipFile(getPackageResourcePath()) → 读 META-INF/*.RSA
     *   · native: __open_2 + fstat + mmap 解析 APK Signing Block（v2/v3）
     * 就完全不受影响。不同目标 so 的导入表各不相同（有的用 __open_2、
     * 有的用 fopen、有的用 open），所以覆盖的函数集按「路径类 libc 函数」
     * 全集来挂，不针对某个具体 so 裁剪。
     *
     * ==== 失败只降级 ====
     * 任何一步失败都只记日志：App 照常启动，只是这条路径没绕过。
     * 绝不能让 native 层的问题把 App 搞崩。
     */
    private static void installNativeRedirect(Context ctx) {
        if (sNativeDone) {
            Log.i(TAG, "native hook 已安装，跳过");
            return;
        }
        java.io.File rep = null;
        try {
            // ① 定位当前 APK 路径（优先 PackageManager，失败退回 /proc/self/maps）
            String apkPath = resolveApkPath(ctx);
            if (apkPath == null) {
                Log.w(TAG, "拿不到自身 APK 路径，跳过 native 重定向");
                return;
            }

            // ② 释放 origin.apk 到私有目录（已存在且大小一致则复用）
            rep = new java.io.File(ctx.getCodeCacheDir(), ORIGIN_FILE);
            long expect = assetSize(ctx, ORIGIN_ASSET);
            if (rep.isFile() && rep.length() == expect && expect > 0) {
                Log.i(TAG, "origin.apk 已存在，复用: " + rep.length() + " B");
            } else {
                if (rep.exists() && !rep.delete()) {
                    Log.w(TAG, "旧 origin.apk 删不掉，尝试覆盖");
                }
                extractAssetPlain(ctx, ORIGIN_ASSET, rep);
                Log.i(TAG, "origin.apk 已释放: " + rep.length() + " B");
            }

            // ③ 加载 native 库并装 hook
            //
            // 用绝对路径 System.load 而不是 loadLibrary：
            //   · loadLibrary 依赖 java.library.path / ClassLoader 的 nativeLibraryDir，
            //     在部分 ROM + 多 ClassLoader 场景下会找不到；
            //   · 绝对路径最直接，且能明确知道加载的是我们打进包里的那一份。
            String libDir = ctx.getApplicationInfo().nativeLibraryDir;
            java.io.File so = new java.io.File(libDir, "lib" + NATIVE_LIB + ".so");
            if (!so.isFile()) {
                Log.w(TAG, "找不到 native 库: " + so.getAbsolutePath()
                        + "（该 ABI 未投放？），跳过 native 重定向");
                return;
            }
            System.load(so.getAbsolutePath());
            Log.i(TAG, "native 库已加载: " + so.getAbsolutePath());

            /* hook 分层（2026-11-27）：level 从 sigfix.json 的 hookLevel 读，
             * 缺省 3（全量）。1=核心 2=+at/readlink 3=全量。
             * 为什么要能降档：18 个 hook 全挂会波及与校验无关的代码 ——
             * 实测 JMComic(Capacitor) 两层模式下图片/网络加载失败。 */
            boolean ok = nativeHookApkPath(apkPath, rep.getAbsolutePath(), sHookLevel);
            if (ok) {
                sNativeDone = true;
                Log.i(TAG, "native 重定向已生效: " + apkPath + " -> " + rep.getAbsolutePath());
            } else {
                Log.e(TAG, "native 重定向返回失败（去校验仅剩 Java 层生效）");
            }
        } catch (Throwable t) {
            Log.e(TAG, "native 重定向安装失败（仅 Java 层生效）", t);
        }
    }

    /** 取自身 APK 路径。优先 PMS，退回 /proc/self/maps 扫描。 */
    private static String resolveApkPath(Context ctx) {
        // 优先：ApplicationInfo.sourceDir（最可靠，且是真实安装路径）
        try {
            String p = ctx.getApplicationInfo().sourceDir;
            if (p != null && p.endsWith(".apk") && new java.io.File(p).isFile()) {
                return p;
            }
        } catch (Throwable ignored) {
        }
        // 退回：/proc/self/maps 里找 base.apk
        java.io.BufferedReader r = null;
        try {
            final String pkg = ctx.getPackageName();
            r = new java.io.BufferedReader(new java.io.FileReader("/proc/self/maps"));
            String line;
            while ((line = r.readLine()) != null) {
                String[] arr = line.split("\\s+");
                if (arr.length == 0) {
                    continue;
                }
                String path = arr[arr.length - 1];
                if (path.startsWith("/data/app/") && path.endsWith("/base.apk")
                        && path.contains(pkg)) {
                    return path;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Throwable ignored) {
                }
            }
        }
        return null;
    }

    /**
     * 投放普通资产（不 setReadOnly）。
     *
     * 与 extractAsset 的区别：那个是给 dex 用的（必须设只读，否则系统拒绝加载），
     * 这是给 origin.apk 用的 —— 它只是个被读取的数据文件，不需要只读，
     * 也不需要走 dex 的那套校验。
     */
    private static void extractAssetPlain(Context ctx, String name, java.io.File out)
            throws Throwable {
        java.io.InputStream in = ctx.getAssets().open(name);
        try {
            java.io.FileOutputStream os = new java.io.FileOutputStream(out);
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
                os.flush();
            } finally {
                os.close();
            }
        } finally {
            in.close();
        }
    }

    /** native 实现：安装 IO 重定向 hook。成功返回 true。 */
    private static native boolean nativeHookApkPath(String apkPath, String repPath, int level);

    private static long assetSize(Context ctx, String name) throws Throwable {        android.content.res.AssetFileDescriptor fd = ctx.getAssets().openFd(name);
        try {
            return fd.getLength();
        } finally {
            fd.close();
        }
    }

    private static void extractAsset(Context ctx, String name, java.io.File out) throws Throwable {
        java.io.InputStream in = ctx.getAssets().open(name);
        try {
            java.io.FileOutputStream os = new java.io.FileOutputStream(out);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
                os.flush();
            } finally {
                os.close();
            }
        } finally {
            in.close();
        }

        // ⚠️ 必须改成只读，否则加载会被系统拒绝。
        //
        // 实测（Android 17 / HyperOS）：
        //   SecurityException: Writable dex file '.../sigfix-payload.dex' is not allowed.
        //   at dalvik.system.DexFile.openDexFileNative
        //
        // Android 14+ 禁止加载"可写"的 dex 文件，用来堵"把代码写到磁盘再加载"
        // 这类注入手法。setReadOnly() 之后就能正常加载了 —— 文件依然在我们
        // 自己的私有目录里，只是去掉写权限位。
        out.setReadOnly();
        if (out.canWrite()) {
            Log.w(TAG, "setReadOnly() 未生效，尝试 chmod");
            try {
                java.lang.Runtime.getRuntime().exec(
                        new String[]{"chmod", "400", out.getAbsolutePath()}).waitFor();
            } catch (Throwable ignored) {
            }
        }
        Log.i(TAG, "payload dex 已设为只读: canWrite=" + out.canWrite());
    }
}
