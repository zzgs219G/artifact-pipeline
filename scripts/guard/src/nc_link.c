/*
 * nc_link.c — Java 层判决式签名联动(2026-XX 用户需求,新文件,不改动 sig_check.c)
 *
 * 协议(与 Java 侧 inject-javacheck.py 生成的 Guard/NcLink 对应):
 *   1. Java 用 PackageManager 实测当前安装包签名 → fp = SHA256(certDER)
 *   2. Java 再算 t1 = SHA256(fp) 并经 JNI 送入本模块
 *   3. 本模块还原存储形态: out[i] = t1[i] ^ SIG_SALT[i%16] ^ (i*0x9E & 0xFF)
 *      恒定时间比对 out == SIG_HASH_STORED → 返回判定
 *
 * 设计红线(与用户对齐的"联动不削弱"原则):
 *   - 标准答案(SIG_HASH_STORED)全程不出 so,Java 层只拿"过/不过"一个结论;
 *   - 本模块【只判不杀】:杀由 Java 侧执行(快死/可见),与 sig_check.c 的
 *     延时暗杀相互独立 —— 攻击者 patch 本函数返回恒真,只能废掉 Java 这条
 *     快线,sig_check 的独立校验(直读 APK 文件)不受影响;
 *   - so 缺失时 Java 侧拿不到结论 → fail-closed(loadLibrary 从"可删开关"
 *     变"承重墙"),这是本模块存在的第一意义;
 *   - 与 sig_check.c 的派生公式逐字节同源(生成侧 make-sig-hash.sh 唯一真相),
 *     两侧一致性由对拍测试钉死(tests/test-javacheck.sh 内 host 编译场景)。
 *
 * 调试模式:SIG_HASH_STORED 全零 → 返回真(与 sig_check.c 的 slot 判定同语义)。
 * 零日志设计:本文件不含任何字符串常量(strings 扫 so 零语义泄露)。
 */

/* 心跳接口(实现在本文件下方;env_check.c 的 watchdog 调用检查端)
 * nc_heartbeat_arm_constructor 供 so constructor(env_check.c / sig_check.c)调用——
 * 2026-10-16 修复:武装点从「首次喂」移到「so 加载」,
 * 删喂食调用从「永久沉默」变成「倒计时死刑」。 */
void nc_heartbeat_touch(void);
int nc_heartbeat_expired(void);
void nc_heartbeat_arm_constructor(void);

#include <jni.h>
#include <stddef.h>
#include <time.h>
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移 */
#include "sig_hash.h"

/* ── 判决核心进加密段 ────────────────────────────────────────────────
 *
 * 修的是实测报告 §8.1 最致命缺陷：加密了壳（ncVerify 转发器），把核留在
 * 明文 —— 判定算法 nc_verify_t1 与两张表 SIG_SALT/SIG_HASH_STORED 全在
 * .rodata，`od` 一条命令就能读出并反推出 32 字节通过凭据（报告 5 分钟做到）。
 *
 * 现在【判定函数 + 两张表】一并标进加密段，解锁后才可执行/可读。
 *
 * ⚠️ 三条纪律（违反任一即死锁或崩溃）：
 *   ① ncVerify / heartbeat 这两个 JNI 入口【绝不能】进 .ncx —— 它们是
 *      unlock 的调用方，锁进去 = 开锁器被锁进箱子 = 死锁。
 *      本文件只标判决核心，不标 JNI 入口。
 *   ② 宿主测试（NCLINK_HOST_TEST）下必须【不标段】：宿主 clang 没有解锁
 *      设施，标了段就读到密文 → 测试假红。用宏条件化。
 *   ③ 表必须 retain：LOCAL_LDFLAGS 含 -Wl,--gc-sections，无引用会被
 *      连段回收（报错十一同款）。
 *
 * 开关只有一个：NC_GUARD_SECTIONED。为什么不用 __ANDROID__ 自动判断——
 *   那样宿主端任何一次"想验证段布局"的编译都会踩坑（标了段却没人解锁
 *   → 读到密文 → 假红）。显式开关让"我要标段"成为必须说出口的事。
 *
 * 性能：零开销（段标记只是链接期属性）。解锁只在 constructor 跑一次。
 */
#if defined(NC_GUARD_SECTIONED) && !defined(NCLINK_HOST_TEST)
#  define NC_VERIFY_SECTION __attribute__((section(NC_SEC_CODE), retain, used))
#else
#  define NC_VERIFY_SECTION            /* 宿主测试/普通宿主构建：不标段 */
#endif

/* 表进加密段的宏：与函数同理，但额外要求 used+retain（防 gc-sections）。
 *
 * ⚠️ 2026-10-19 实测踩坑（必须记住）：表【不能】与函数放同一个段。
 *    clang 报 `'nc_verify_t1' causes a section type conflict with 'SIG_SALT'`
 *    —— 因为 .ncx 是 AXR（可执行）段，而 SIG_SALT 是 const 数据，
 *    LLVM 拒绝让同一段既装代码又装只读数据。
 *    解法：数据单独进 .ncxr（AWR，不可执行），由锁箱器一并加密。
 *    这也更合理——代码段解出来是 RX，数据段解出来是 R，权限各自最小。 */
#if defined(NC_GUARD_SECTIONED) && !defined(NCLINK_HOST_TEST)
#  define NC_VERIFY_TABLE_SECTION \
        __attribute__((section(NC_SEC_CONST), retain, used))
#else
#  define NC_VERIFY_TABLE_SECTION
#endif

/* ── Java 心跳状态(记录侧) ───────────────────────────────────────
 * nc_link.c 是心跳记录的正确归属:它是 Java↔Native 的桥接层,
 * 且在 guard/envcheck 两种勾选组合下都会参与编译(protect.sh:354/363
 * 把它随 sigcheck 拷入;envcheck 单勾时 nc_link 不在工程里,此时没有
 * Java 壳喂心跳,watchdog 侧 armed==0 自然跳过检查,组合自洽)。
 * volatile + noinline 防 -O2 常量折叠(同 LSGS 的实测教训)。
 * 纯静态,不导出符号。 */
volatile long long nc_heartbeat_last_ms = 0;   /* 最近一次心跳时间 */
volatile long long nc_heartbeat_armed_ms = 0;  /* 武装时刻(constructor 置) */

__attribute__((noinline))
void nc_heartbeat_arm_constructor(void)
{
    long long now = (long long)time(NULL) * 1000LL;
    long long expected = 0;
    /* CAS 武装:constructor 可能多个(sig_check/env_check 都调),只取第一个 */
    if (nc_heartbeat_armed_ms == 0) {
        __atomic_compare_exchange_n(&nc_heartbeat_armed_ms, &expected, now,
                                    0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
}

__attribute__((noinline))
void nc_heartbeat_touch(void)
{
    long long now = (long long)time(NULL) * 1000LL;
    if (nc_heartbeat_armed_ms == 0) {
        nc_heartbeat_armed_ms = now;    /* 首次喂 = 武装(CAS 语义可省:
                                           重复武装只是时间窗略移,无害) */
    }
    nc_heartbeat_last_ms = now;
}

/* watchdog 检查端（env_check.c 调用）：
 * 返回 0 = 正常（未武装/宽限期内/保活窗口内），非 0 = 超时（该杀）。
 * 武装点在 so constructor —— so 加载即倒计时，N 秒内 Java 必须开始喂，
 * 否则视为 Java 壳被删 → 杀。（旧版 armed 由首喂置位 → 删喂食调用 =
 * 永久沉默，真机实证为盲区。）
 *
 * ── 参数选型 ────────────────────────────────────────────────────────
 * 现行值（不再分调试/发布两套，一套走天下）：
 *   FIRST_GRACE 90s —— 防误杀低端机冷启动。这是唯一必须大的：
 *       它只在"启动后第一次喂食前"生效，与检测能力无关。
 *   KEEPALIVE    8s —— 对 Guard.java 的 5s 喂食周期留 1.6 倍余量
 *       （一次 GC 停顿/线程调度延迟不致死）。
 *   -DNC_HB_DEBUG_FAST 仍保留（5s/5s），但【不再必要】。
 *
 * 为什么保活窗不需要为攻击者收紧：心跳超时是状态检测（"喂食停了没"），
 *   不是一次性定时炸弹。攻击者 patch 喂食后，早 5s 发现与晚 25s 发现，
 *   他没有可利用的时间窗（发现即杀，杀前干不了任何事）。延迟的真实成本
 *   全落在开发者调试体验上。
 *
 * 实际死期（配 env_check.c 的 5s 轮询）：删喂食后 ≈ KEEPALIVE(8s) 内
 *   某刻 expired() 置位，下一轮轮询(≤5s)读到 → 最坏 ~13s，典型 ~8-10s。
 *
 * 历史教训：2026-10-16 为调试改成 5s/5s，注释写"发布前必须改回"，但
 *   靠人记的"必须"一直没改回 —— 5s 宽限会误杀冷启动超 5 秒的设备。
 *   后又一度改成"发布 25s/调试 5s"两套，但本项目的调试方式就是拿
 *   CI 发布包做逆向实验，不存在两种产物，宏开关对真实工作流无效。
 *   → 这类"参数忘了改回"靠注释提醒拦不住，只能靠结构：默认即发布值。 */
#ifdef NC_HB_DEBUG_FAST
#  define NC_HB_FIRST_GRACE_MS   5000LL
#  define NC_HB_KEEPALIVE_MS     5000LL
#else
#  define NC_HB_FIRST_GRACE_MS  90000LL
#  define NC_HB_KEEPALIVE_MS     8000LL
#endif

__attribute__((noinline))
int nc_heartbeat_expired(void)
{
    long long armed = nc_heartbeat_armed_ms;
    long long last, now;
    if (armed == 0)
        return 0;                        /* so 尚未加载完(constructor 未跑),防御性兜底 */
    last = nc_heartbeat_last_ms;
    now = (long long)time(NULL) * 1000LL;
    if (last == 0)
        return (now - armed) > NC_HB_FIRST_GRACE_MS;
    return (now - last) > NC_HB_KEEPALIVE_MS;
}


/*
 * 判决核心(宿主可测:NCLINK_HOST_TEST 时编译为纯逻辑函数)。
 * 非静态:由 -fvisibility=hidden 收敛符号面,JNI 入口是唯一导出面。
 * 返回 1 = 判定通过(或调试模式跳过),0 = 判定不过(Java 侧执行杀)。
 *
 * ⚠️ NC_VERIFY_SECTION（2026-10-19）：生产构建下本函数进 .ncx 密文段。
 *    它【不是】unlock 的调用方，是纯被调方，所以可以安全上锁。
 *    调用方 ncVerify（JNI 入口）刻意不标——那会造成解锁死锁。
 */
NC_VERIFY_SECTION
int nc_verify_t1(const unsigned char *t1, int len)
{
    unsigned char expected[SIG_HASH_LEN];
    int i, mismatch = 0, slot_configured = 0;

    if (t1 == NULL || len != SIG_HASH_LEN)
        return 0;                       /* 异形入参 = 不过(fail-closed) */

    for (i = 0; i < SIG_HASH_LEN; i++) {
        if (SIG_HASH_STORED[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured)
        return 1;                       /* 调试模式:槽位全零跳过(同 sig_check.c) */

    for (i = 0; i < SIG_HASH_LEN; i++) {
        expected[i] = (unsigned char)(t1[i] ^ SIG_SALT[i % SIG_SALT_LEN]
                                      ^ (unsigned char)((i * 0x9E) & 0xFF));
    }
    for (i = 0; i < SIG_HASH_LEN; i++)
        mismatch |= expected[i] ^ SIG_HASH_STORED[i];   /* 恒定时间 */
    return mismatch == 0;
}

/* ── 可信实测输入（2026-11-25）────────────────────────────────────────
 *
 * 背景：Java 侧 Guard.c() 用 PackageManager 取证书 —— 那正是去校验模块在
 * IPackageManager 代理层撒谎的地方。于是「加固 + 去校验」组合包里 Java 永远
 * 测到原开发者的诱饵证书，与 SIG_HASH_STORED（逆向者自己的证书）不符 →
 * ncVerify 返回 false → Guard.kill() → 主人自己签的包也闪退。
 *
 * 修法：sig_check.c 的可信路线（内联 svc / 裸 syscall / 复用系统 fd）读的是
 * 真实 base.apk，inline hook 够不到。它把实测指纹的 t1 发布在这里，ncVerify
 * 优先用它判定；Java 入参降级为"风控对照数据"，不再是判决依据。
 *
 * 三角比对得到的四种结论（native 侧裁决，Java 只执行 kill）：
 *   可信=基准, Java=可信   → 正常包                          → 放行
 *   可信=基准, Java≠可信   → PM 被代理篡改，但主人在场        → 放行(记风控)
 *   可信≠基准              → 真被陌生证书重签（Java 报什么都不算数）→ 拒
 *   可信未测到             → 退化到只看 Java 入参（旧语义，不变） → 按 Java 判
 *
 * ⚠️ 为什么"可信≠基准"时不采信 Java 的申辩：若采信，攻击者只需让
 *    PackageManager 报基准值就能通关 —— 那正是我们要修的洞。
 * ⚠️ 回退分支的真实触发场景【只有一种】：可信路线全失败（seccomp 拦掉
 *    openat 系调用 / 平台不支持 /proc/self/fd）。不是"sig_check.c 未编入"
 *    —— protect.sh:717-719 把两者无条件成对拷入同一个 NDK 工程，必然
 *    同时在场（缺席时本文件也不存在）。
 *    弱符号声明仍保留：它让宿主测试能用强定义注入假的可信值
 *    （test-nclink-judge.c 正是这么做的），也保证单独编本文件时不链接失败。
 */
extern int nc_trusted_t1_get(unsigned char out[SIG_HASH_LEN])
    __attribute__((weak));      /* 由 sig_check.c 强定义；单独编本文件时为 NULL */

/* ── 裁决结果码（2026-11-25 风控上报）─────────────────────────────────
 *
 * 为什么要上报：Java 侧用 PackageManager 测证书，而那是去校验撒谎的地方。
 * 改用可信实测值裁决后，主人自己的包不再闪退，但**"PM 报的和实测不一致"
 * 这个事实被丢掉了** —— 排障时只能从 C 层六路表反推"Java 大概被污染了"，
 * 看不到确切值。
 *
 * 本组常量把三角比对的结果编码成返回码，供：
 *   · 宿主测试断言分支走向（不必解析日志）
 *   · 将来若新增 int 版 JNI 入口（如 lastJudge()），Java 侧据此打日志
 *
 * ⚠️ 为什么不在本文件打日志：nc_link.c 有硬纪律 ——【零字符串常量】
 *    （strings 扫 so 零语义泄露，见文件头注）。要打日志就得写文案，写文案
 *    就破纪律。文案留给 Java 侧（它本来就有字符串）。
 * ⚠️ 当前 ncVerify 仍返回 jboolean，所以只外露 DENY / OK 两个值；
 *    OK_PM_TAINTED / OK_NO_TRUSTED 在内部分辨，宿主可断言。 */
#define NC_JUDGE_DENY          0   /* 否决（Java 侧执行 kill） */
#define NC_JUDGE_OK            1   /* 通过，且 PM 与可信实测一致（正常包） */
#define NC_JUDGE_OK_PM_TAINTED 2   /* 通过，但 PM 与可信实测不一致（去校验环境） */
#define NC_JUDGE_OK_NO_TRUSTED 3   /* 通过，走旧语义（可信路线不可用） */

/* 最近一次裁决结果（供 lastJudge() 上报）。
 * ⚠️ 初值 -1 = 尚未裁决过，与四个合法码都不冲突 —— Java 侧据此区分
 *    "还没跑"和"跑了被拒"。 */
volatile int nc_last_judge = -1;

/* 三角比对裁决。纯逻辑，宿主可测（test-nclink-judge.c 链接本文件直接调）。
 *
 * 返回值见上方 NC_JUDGE_* 常量。
 *
 * ⚠️ 纯被调方，可以进 .ncx（同 nc_verify_t1）；调用它的 ncVerify 是
 *    JNI 入口，绝不能标段 —— 那是 unlock 调用方，标了即死锁。 */
NC_VERIFY_SECTION
int nc_link_judge(const unsigned char *java_t1, int java_len)
{
    unsigned char trusted[SIG_HASH_LEN];
    int have_trusted = 0;
    int verdict;

    /* 弱符号：sig_check.c 未编入本 so 时该指针为 NULL → 走下面的回退分支。 */
    if (nc_trusted_t1_get != NULL)
        have_trusted = nc_trusted_t1_get(trusted);

    if (have_trusted) {
        int java_ok = 0;

        /* 可信实测值说了算。
         * ⚠️ 判定【不】参考 Java 入参：若"可信值不符时再看 Java 报的值"，
         *    攻击者只需让 PackageManager 报基准值就能通关 —— 那正是本次
         *    要修的洞（去校验模块就在那层撒谎）。 */
        if (!nc_verify_t1(trusted, SIG_HASH_LEN))
            verdict = NC_JUDGE_DENY;
        else {
            /* 裁决已定（放行）。下面这一段【只用于区分上报码】，不参与判定：
             *   java_ok=1 → PM 与实测一致（正常包）
             *   java_ok=0 → PM 与实测不一致，或 Java 没传（去校验 / 测量失败）
             * 这个区分是纯观测：无论哪个分支都返回"放行"。 */
            if (java_t1 != NULL && java_len == SIG_HASH_LEN)
                java_ok = nc_verify_t1(java_t1, SIG_HASH_LEN);
            verdict = java_ok ? NC_JUDGE_OK : NC_JUDGE_OK_PM_TAINTED;
        }
    } else {
        /* 可信路线不可用（seccomp 拦掉 openat 系 / 平台不支持 /proc/self/fd）
         * → 保持改动前的语义：Java 传什么就按什么判（fail-closed）。 */
        if (java_t1 == NULL || java_len != SIG_HASH_LEN)
            verdict = NC_JUDGE_DENY;
        else
            verdict = nc_verify_t1(java_t1, java_len) ? NC_JUDGE_OK_NO_TRUSTED
                                                      : NC_JUDGE_DENY;
    }

    /* 记下最近一次结果，供 lastJudge() 上报。
     * ⚠️ 纯记录，不参与本次判定 —— 写在最后一行，无论走哪个分支都覆盖。 */
    __atomic_store_n(&nc_last_judge, verdict, __ATOMIC_RELEASE);
    return verdict;
}

#ifndef NCLINK_HOST_TEST
/* ── JNI 入口实现（2026-11-04 改为动态注册）──────────────────────────
 *
 * 曾经是短名绑定：JNIEXPORT jboolean JNICALL
 *                 Java_com_nc_link_NcLink_ncVerify(...)
 * 符号名会进 .dynsym —— 等于给逆向者一张地图（`nm -D` 即知三个入口）。
 * JNIEXPORT 自带 visibility("default")，对 -fvisibility=hidden 免疫，
 * 靠 version script 也收敛不掉（lib-ndk.sh:155 记过三种写法均失败）。
 *
 * 现在：这三个函数【不再带 JNIEXPORT】（→ 受 -fvisibility=hidden 支配
 * → hidden），改由 nc_link_jni.c 的 nc_link_register_natives() 在
 * JNI_OnLoad 里 RegisterNatives。函数名也删掉了 Java_ 前缀，改叫
 * nc_link_jni_*,使"按名字猜入口"这条路径也断掉。
 *
 * 为什么可以动态注册（2026-10-19 曾失败）：那次是在 constructor 里
 * FindClass，动态链接器执行 constructor 时 classloader 上下文未建立。
 * 本次走 JNI_OnLoad（ART 回调，会切到发起 load 的 loader），位置不同。
 * 详见 nc_link_jni.c 头部注释与 nc_link_jni.h 的契约说明。 */

/* ncVerify([B)Z 的实现体 */
jboolean nc_link_jni_ncVerify(JNIEnv *env, jclass clazz, jbyteArray measured)
{
    jsize len;
    jbyte *buf;
    jboolean ok = JNI_FALSE;

    (void)clazz;
    if (measured == NULL)
        return JNI_FALSE;
    len = (*env)->GetArrayLength(env, measured);
    if (len != SIG_HASH_LEN)
        return JNI_FALSE;
    buf = (*env)->GetByteArrayElements(env, measured, NULL);
    if (buf == NULL)
        return JNI_FALSE;
    ok = (nc_link_judge((const unsigned char *)buf, (int)len) != NC_JUDGE_DENY)
         ? JNI_TRUE : JNI_FALSE;
    (*env)->ReleaseByteArrayElements(env, measured, buf, JNI_ABORT);
    return ok;
}

/* lastJudge()I 的实现体 —— 风控上报（2026-11-25）
 *
 * 返回最近一次 nc_link_judge 的结果码，纯只读：
 *   -1 尚未裁决  0 否决  1 正常包  2 PM 被污染但主人在场  3 旧语义通过
 *
 * ⚠️ 不重新裁决、不影响任何判定、不碰心跳 —— Java 侧随时可调多次。
 * ⚠️ 不影响 ncVerify：即使本方法注册失败，判定链照原样工作。 */
jint nc_link_jni_lastJudge(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return (jint)__atomic_load_n(&nc_last_judge, __ATOMIC_ACQUIRE);
}

/* Java→Native 心跳(2026-10 借鉴 XopProtector 双向绑定设计):
 * Guard 注入壳每 5 秒喂一次;env_watchdog 检查 armed 后超时未喂 = Java 层
 * 被删/被绕过 → 走 delayed_kill。记录侧只做原子时间戳(纳秒级,零开销)。
 * ⚠️ 身份校验防冒充:攻击者 patch 掉 Java 校验后自己喂 ping 即可绕过整个
 * 心跳机制 —— 所以 clazz 必须是 NcLink 本类(IsSameObject 锁死),
 * 这是 Xop shell_heartbeat_ok 的同款纪律。
 * ⚠️ 动态注册下这层校验更必要:RegisterNatives 表在运行期可被重复注册,
 * 身份校验是"谁在调"这一侧的纵深。 */
void nc_link_jni_heartbeat(JNIEnv *env, jclass clazz)
{
    jclass self;
    /* 仅允许 NcLink 本类调用。self 为 NULL 时视为异常环境,
     * 不记录本次心跳(watchdog 超时路径自会兜底,fail-closed)。 */
    self = (*env)->FindClass(env, "com/nc/link/NcLink");
    if (self != NULL) {
        if ((*env)->IsSameObject(env, clazz, self)) {
            nc_heartbeat_touch();
        }
        (*env)->DeleteLocalRef(env, self);
    }
}
#endif /* NCLINK_HOST_TEST */
