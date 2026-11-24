.class public final Lcom/test/placeholder/Guard;
.super Ljava/lang/Object;




# static fields
.field private static volatile heartbeatStarted:Z


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static c(Landroid/content/Context;)V
    .locals 5

    :try_start_0
    invoke-static {}, Lcom/nc/link/NcLink;->ensureLoaded()V

    invoke-static {}, Lcom/test/placeholder/Guard;->ncguardSelftest()V

    invoke-static {}, Lcom/nc/link/NcLink;->heartbeat()V

    invoke-static {}, Lcom/test/placeholder/Guard;->startHeartbeat()V

    const-string v0, "SHA-256"

    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v0

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object p0

    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v3, 0x1c

    const/4 v4, 0x0

    if-lt v2, v3, :cond_0

    const/high16 v2, 0x8000000

    invoke-virtual {v1, p0, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object p0

    iget-object p0, p0, Landroid/content/pm/PackageInfo;->signingInfo:Landroid/content/pm/SigningInfo;

    invoke-virtual {p0}, Landroid/content/pm/SigningInfo;->getApkContentsSigners()[Landroid/content/pm/Signature;

    move-result-object p0

    aget-object p0, p0, v4

    invoke-virtual {p0}, Landroid/content/pm/Signature;->toByteArray()[B

    move-result-object p0

    goto :goto_0

    :cond_0
    const/16 v2, 0x40

    invoke-virtual {v1, p0, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object p0

    iget-object p0, p0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    aget-object p0, p0, v4

    invoke-virtual {p0}, Landroid/content/pm/Signature;->toByteArray()[B

    move-result-object p0

    :goto_0
    invoke-virtual {v0, p0}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object p0

    invoke-static {p0}, Lcom/nc/link/NcLink;->ncVerify([B)Z

    move-result p0

    if-nez p0, :cond_1

    invoke-static {}, Lcom/test/placeholder/Guard;->kill()V

    :cond_1
    invoke-static {}, Lcom/test/placeholder/Guard;->reportJudge()V
    :try_end_0
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catch_0
    invoke-static {}, Lcom/test/placeholder/Guard;->kill()V

    :catchall_0
    return-void
.end method

.method private static kill()V
    .locals 1

    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v0

    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V

    return-void
.end method

.method private static ncguardSelftest()V
    .locals 4

    const-string v0, "selftest rc="

    :try_start_0
    invoke-static {}, Lcom/nc/link/NcLink;->selftest()I

    move-result v1

    const/16 v2, 0x3b

    if-eq v1, v2, :cond_0

    const-string v2, "ncguard"

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    :cond_0
    return-void
.end method

.method private static reportJudge()V
    .locals 3

    :try_start_0
    invoke-static {}, Lcom/nc/link/NcLink;->lastJudge()I

    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v1, 0x2

    const-string v2, "nc"

    if-ne v0, v1, :cond_0

    :try_start_1
    const-string v0, "\u98ce\u63a7: PackageManager \u4e0e\u5b9e\u6d4b\u8bc1\u4e66\u4e0d\u4e00\u81f4\uff08\u53bb\u6821\u9a8c\u73af\u5883\uff09\uff0c\u5b9e\u9645\u4ee5 APK \u5b9e\u6d4b\u4e3a\u51c6\uff0c\u5df2\u653e\u884c"

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_0
    const/4 v1, 0x3

    if-ne v0, v1, :cond_1

    const-string v0, "\u98ce\u63a7: \u53ef\u4fe1\u8def\u7ebf\u4e0d\u53ef\u7528\uff0c\u672c\u6b21\u6309 PackageManager \u503c\u88c1\u51b3"

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_1
    const/4 v1, 0x1

    if-ne v0, v1, :cond_2

    const-string v0, "\u98ce\u63a7: PackageManager \u4e0e\u5b9e\u6d4b\u4e00\u81f4\uff08\u6b63\u5e38\u73af\u5883\uff09"

    invoke-static {v2, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_2
    if-nez v0, :cond_3

    const-string v0, "\u98ce\u63a7: \u88c1\u51b3\u4e3a\u62d2\u7edd"

    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :catchall_0
    :cond_3
    return-void
.end method

.method private static startHeartbeat()V
    .locals 2

    sget-boolean v0, Lcom/test/placeholder/Guard;->heartbeatStarted:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    sput-boolean v0, Lcom/test/placeholder/Guard;->heartbeatStarted:Z

    new-instance v1, Lcom/test/placeholder/Guard$Hb;

    invoke-direct {v1}, Lcom/test/placeholder/Guard$Hb;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/Thread;->setDaemon(Z)V

    invoke-virtual {v1}, Ljava/lang/Thread;->start()V

    return-void
.end method
