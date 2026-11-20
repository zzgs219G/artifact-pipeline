package com.nc.uncheck;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * SigFixApp —— 通过 AndroidManifest 的 android:name 挂到 Application 位的引导器。
 *
 * ==== 为什么需要它 ====
 * 把 hook 装在 Activity.onCreate 里，时序太晚：目标 App 若在
 * Application.onCreate / attachBaseContext / ContentProvider.onCreate
 * 里就校验签名，就会漏掉。
 *
 * Application 是系统在进程启动后**最早**实例化的应用类，从这里挂载
 * 可以覆盖上述所有时机。这也是 MT / ApkSignatureKiller 选这条路的根本原因。
 *
 * ==== 与 MT 的关键区别：不改父类，做代理 ===
 *
 * MT 的做法是把目标 App 原有 Application 的**父类**改掉
 * （`xiApplication extends Application` → `extends KillerApplication`），
 * Manifest 不动。缺点是：如果原类继承的是 TinkerApplication /
 * MultiDexApplication 这类有特殊逻辑的父类，换掉父类等于把那些逻辑删了，
 * App 会起不来。
 *
 * 本类的做法：
 *   1. Manifest 的 android:name 指向本类（AXML 改写，一次性）
 *   2. 本类继承最普通的 Application，只做"拦截器"
 *   3. 反射创建**原来的** Application 实例，把 Context 交给它，
 *      并把它替换成系统眼中的 mInitialApplication
 *   4. 之后所有生命周期回调都转发给原实例
 *
 * 于是原类的继承关系、全部初始化逻辑、甚至 getClass().getName()
 * 都保持原样 —— 比换父类更完整。
 *
 * ==== 硬约束 ====
 * 本类的每一个步骤都必须在 try/catch 内、失败只降级不抛。
 * 一旦这里抛异常，系统在 makeApplicationInner 阶段就会
 * ExceptionInInitializerError / 直接崩（MT 的包在简盒 v2.1.2 上就是这样崩的）。
 */
public class SigFixApp extends Application {

    private static final String TAG = "SigFixApp";

    /**
     * 可变配置全部来自 assets/nc_sigfix/sigfix.json，**dex 里一个都不存**。
     *
     * 为什么这样设计（2026-11-21 重构）：
     *   原先证书 Base64 与原 Application 类名是"烘焙进 dex 的字符串常量"，
     *   靠构建期替换 smali 里的哨兵实现。那个做法有两个硬伤：
     *     ① 证书长度随 keystore 变（888~1152 字符），dex 字符串池要重建，
     *        不能原位替换 —— 对"只拿得到编译好 dex"的消费者（ApkForge）不友好；
     *     ② 每换一个目标 App 都要重新编一次 dex，dex 不再是静态资产。
     *   改成读 JSON 后：dex 完全静态、可缓存、可下载；
     *   所有可变数据集中在一份小文件里，改它不用碰 dex。
     */
    private static final String CONFIG_ASSET = "nc_sigfix/sigfix.json";

    /** 从 sigfix.json 读到的原 Application 类名（可能为空）。 */
    private static String sOriginalApp = "";

    /** 从 sigfix.json 读到的原证书 Base64。 */
    static String sCertB64 = "";

    /** 原 Application 实例。 */
    private Application mOriginal;

    /** 原 Application 自己的 base Context（用于之后转发）。 */
    private Context mBase;

    @Override
    protected void attachBaseContext(Context base) {
        // ⚠️ 必须先调 super：我们的基类是 Application，它的 attach 逻辑
        //    负责把 mBase 设好，否则后面 ActionBar/Resources 相关全部 null。
        super.attachBaseContext(base);
        mBase = base;

        // ① 装 hook —— 必须在原 Application 初始化**之前**。
        //    目标 App 的校验很可能就在它自己的 attachBaseContext 里。
        try {
            SigFix.install(base);
            Log.i(TAG, "hook 安装完成（早于原 Application 初始化）");
        } catch (Throwable t) {
            Log.e(TAG, "hook 安装失败（不影响 App 启动）", t);
        }

        // ② 读配置（证书 + 原 Application 类名）
        loadConfig(base);

        // ③ 创建原 Application 并接管
        try {
            createOriginalApplication(base);
        } catch (Throwable t) {
            Log.e(TAG, "创建原 Application 失败（App 可能行为异常）", t);
        }
    }

    /**
     * 读 assets/nc_sigfix/sigfix.json：
     *   { "cert": "<原证书 DER 的 Base64>", "originalApp": "com.x.Y" }
     *
     * 读不到不算致命：cert 缺失会导致签名伪造不生效（但有日志），
     * originalApp 缺失则本类不接管任何原 Application。
     */
    private static void loadConfig(Context ctx) {
        java.io.InputStream in = null;
        try {
            in = ctx.getAssets().open(CONFIG_ASSET);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            String json = new String(bos.toByteArray(), "UTF-8");
            org.json.JSONObject o = new org.json.JSONObject(json);
            sCertB64 = o.optString("cert", "");
            sOriginalApp = o.optString("originalApp", "");
            Log.i(TAG, "配置已读取：cert " + (sCertB64.isEmpty() ? "缺失" : sCertB64.length() + " 字符")
                    + "，originalApp=" + (sOriginalApp.isEmpty() ? "(无)" : sOriginalApp));
        } catch (Throwable t) {
            Log.e(TAG, "读取 " + CONFIG_ASSET + " 失败", t);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (mOriginal == null) {
            Log.w(TAG, "没有原 Application，只跑我们的初始化");
            return;
        }
        try {
            // 转发给原 Application.onCreate。
            // 用反射调用而不是直接调：类型是 Application，但实现是原类，
            // 直接 mOriginal.onCreate() 走虚分派即可 —— 这里显式说明意图。
            mOriginal.onCreate();
            Log.i(TAG, "已转发 onCreate 给 " + sOriginalApp);
        } catch (Throwable t) {
            Log.e(TAG, "转发 onCreate 失败", t);
        }
    }

    /**
     * 反射创建原 Application 并替换 mInitialApplication。
     *
     * 关键点：原 Application 也需要拿到正确的 base Context，
     * 否则它内部的 getResources()/getPackageName() 等全是 null。
     */
    private void createOriginalApplication(Context base) throws Throwable {
        if (sOriginalApp == null || sOriginalApp.isEmpty()
                || sOriginalApp.equals(SigFixApp.class.getName())) {
            Log.i(TAG, "无原 Application 需要接管（原包没有 android:name）");
            return;
        }

        Class<?> cls = Class.forName(sOriginalApp, false, base.getClassLoader());
        if (!Application.class.isAssignableFrom(cls)) {
            Log.w(TAG, sOriginalApp + " 不是 Application 子类，跳过");
            return;
        }

        // ⚠️ 必须用【无参构造 + Application.attach(Context)】，不能用
        //    Instrumentation.newApplication。
        //
        //    实测（简盒 v2.1.2）：newApplication 会先把 base context 设好，
        //    之后我们再调原类的 attachBaseContext，它内部的
        //    super.attachBaseContext() 就抛
        //      IllegalStateException: Base context already set
        //    → 原类在 attachBaseContext 里的初始化（dex 加载、SP 读取等）全部没跑。
        //
        //    改成 Application.attach(Context) 后：它只设置 mBase/mLoadedApk 等
        //    必要字段，不标记"已 attach"，原类再调 super.attachBaseContext 就正常。
        Application app = (Application) cls.getDeclaredConstructor().newInstance();
        attachContext(app, base);
        mOriginal = app;

        // ⚠️ 先把原实例的 mBase 清零，再让它跑 attachBaseContext。
        //
        // 实测（简盒 v2.1.2 / Android 17）：Application.attach(Context) 内部会
        // 调 attachBaseContext 并标记"已设置"，之后原类自己的
        // attachBaseContext 里再调 super.attachBaseContext() 就抛
        //   IllegalStateException: Base context already set
        // （ContextWrapper.attachBaseContext 有 mBase != null 的断言）。
        //
        // 清零 mBase 后，原类的 super 调用就能正常执行，
        // 它在 attachBaseContext 里的初始化逻辑（dex 加载 / SP 读取等）才不会丢。
        clearBaseContext(app);

        // 让原 Application 跑它自己的 attachBaseContext（尊重其 override）
        try {
            invokeAttachBaseContext(app, base);
            Log.i(TAG, "已调用原 Application.attachBaseContext");
        } catch (Throwable t) {
            Log.w(TAG, "调用原 Application.attachBaseContext 失败（其内部初始化可能缺失）", t);
        }

        // 替换 ActivityThread.mInitialApplication —— 让系统认为原实例才是真的
        replaceInitialApplication(app);
        Log.i(TAG, "已接管原 Application: " + sOriginalApp);
    }

    private Application newApplicationViaInstrumentation(Class<?> cls, Context base)
            throws Throwable {
        Class<?> clsAt = Class.forName("android.app.ActivityThread");
        Method current = clsAt.getDeclaredMethod("currentActivityThread", new Class[0]);
        current.setAccessible(true);
        Object at = current.invoke(null);
        if (at == null) {
            return null;
        }
        Field fInstr = null;
        Class<?> c = clsAt;
        while (c != null && c != Object.class) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == Instrumentation.class) {
                    fInstr = f;
                    break;
                }
            }
            if (fInstr != null) break;
            c = c.getSuperclass();
        }
        if (fInstr == null) {
            return null;
        }
        fInstr.setAccessible(true);
        Instrumentation instr = (Instrumentation) fInstr.get(at);
        if (instr == null) {
            return null;
        }
        // Instrumentation.newApplication(Class, Context) 是隐藏 API，可直接调
        Method m = Instrumentation.class.getDeclaredMethod(
                "newApplication", Class.class, Context.class);
        m.setAccessible(true);
        return (Application) m.invoke(instr, cls, base);
    }

    /**
     * 把 Application 实例的 mBase 置为 null，让后续 attachBaseContext 能正常执行。
     *
     * ContextWrapper.attachBaseContext 的实现是：
     *     if (mBase != null) throw new IllegalStateException("Base context already set");
     *     mBase = context;
     * 所以必须先清零。
     */
    private void clearBaseContext(Application app) {
        try {
            Field f = findFieldOfType(Context.class, app.getClass());
            if (f == null) {
                Log.w(TAG, "找不到 mBase 字段，跳过清零");
                return;
            }
            f.setAccessible(true);
            f.set(app, null);
            Log.i(TAG, "mBase 已清零（" + f.getName() + "）");
        } catch (Throwable t) {
            Log.w(TAG, "清零 mBase 失败", t);
        }
    }

    /** 退回路径：用反射调 Application.attach(Context)，给新实例装 Context。 */
    private void attachContext(Application app, Context base) {
        try {
            Method m = Application.class.getDeclaredMethod("attach", Context.class);
            m.setAccessible(true);
            m.invoke(app, base);
            return;
        } catch (Throwable ignored) {
        }
        try {
            Field f = findFieldOfType(Context.class, app.getClass());
            if (f != null) {
                f.setAccessible(true);
                f.set(app, base);
            }
        } catch (Throwable t) {
            Log.w(TAG, "给原 Application 设置 Context 失败", t);
        }
    }

    /** 调原 Application.attachBaseContext(base)，尊重它的 override。 */
    private void invokeAttachBaseContext(Application app, Context base) {
        try {
            Method m = findMethod(app.getClass(), "attachBaseContext", Context.class);
            if (m == null) {
                return;
            }
            m.setAccessible(true);
            m.invoke(app, base);
        } catch (Throwable t) {
            Log.w(TAG, "原 Application.attachBaseContext 调用失败", t);
        }
    }

    /**
     * 把系统眼里的 mInitialApplication 换成原实例。
     *
     * 为什么必须换：系统之后很多地方会调
     * ActivityThread.mInitialApplication，如果不换，那些回调会落到
     * 我们这个"壳"上，原 Application 就拿不到 onCreate/onLowMemory 等。
     */
    private void replaceInitialApplication(Application original) {
        try {
            Class<?> clsAt = Class.forName("android.app.ActivityThread");
            Method current = clsAt.getDeclaredMethod("currentActivityThread", new Class[0]);
            current.setAccessible(true);
            Object at = current.invoke(null);
            if (at == null) {
                return;
            }
            Field f = findFieldOfType(Application.class, clsAt);
            if (f == null) {
                Log.w(TAG, "ActivityThread 里找不到 Application 类型字段");
                return;
            }
            f.setAccessible(true);
            f.set(at, original);
            Object after = f.get(at);
            Log.i(TAG, "mInitialApplication 替换"
                    + (after == original ? "成功（回读一致）" : "失败（回读不一致）"));
        } catch (Throwable t) {
            Log.e(TAG, "替换 mInitialApplication 失败", t);
        }
    }

    private static Field findFieldOfType(Class<?> type, Class<?> owner) {
        Class<?> c = owner;
        while (c != null && c != Object.class) {
            try {
                for (Field f : c.getDeclaredFields()) {
                    if (f.getType() == type) {
                        return f;
                    }
                }
            } catch (Throwable ignored) {
            }
            c = c.getSuperclass();
        }
        return null;
    }

    private static Method findMethod(Class<?> owner, String name, Class<?>... params) {
        Class<?> c = owner;
        while (c != null && c != Object.class) {
            try {
                Method m = c.getDeclaredMethod(name, params);
                if (m != null) {
                    return m;
                }
            } catch (Throwable ignored) {
            }
            c = c.getSuperclass();
        }
        return null;
    }
}
