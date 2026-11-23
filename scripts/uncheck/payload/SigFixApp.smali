.class public Lcom/nc/uncheck/SigFixApp;
.super Landroid/app/Application;

# static fields
.field private static final CONFIG_ASSET:Ljava/lang/String; = "nc_sigfix/sigfix.json"

.field private static final TAG:Ljava/lang/String; = "SigFixApp"

.field static sCertB64:Ljava/lang/String; = ""

.field static sMinProxy:Z = false

.field private static sOriginalApp:Ljava/lang/String; = ""

# instance fields
.field private mBase:Landroid/content/Context;

.field private mOriginal:Landroid/app/Application;

# direct methods
.method static constructor <clinit>()V
    .locals 0

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Application;-><init>()V

    return-void
.end method

.method private attachContext(Landroid/app/Application;Landroid/content/Context;)V
    .locals 6

    const/4 v0, 0x1

    :try_start_0
    const-class v1, Landroid/app/Application;

    const-string v2, "attach"

    new-array v3, v0, [Ljava/lang/Class;

    const-class v4, Landroid/content/Context;

    const/4 v5, 0x0

    aput-object v4, v3, v5

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/reflect/Method;->setAccessible(Z)V

    new-array v2, v0, [Ljava/lang/Object;

    aput-object p2, v2, v5

    invoke-virtual {v1, p1, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    :try_start_1
    const-class v1, Landroid/content/Context;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-static {v1, v2}, Lcom/nc/uncheck/SigFixApp;->findFieldOfType(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Field;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v1, v0}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    invoke-virtual {v1, p1, p2}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception p1

    const-string p2, "SigFixApp"

    const-string v0, "\u7ed9\u539f Application \u8bbe\u7f6e Context \u5931\u8d25"

    invoke-static {p2, v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_0
    :goto_0
    return-void
.end method

.method private clearBaseContext(Landroid/app/Application;)V
    .locals 4

    const-string v0, "SigFixApp"

    const-string v1, "mBase \u5df2\u6e05\u96f6\uff08"

    :try_start_0
    const-class v2, Landroid/content/Context;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-static {v2, v3}, Lcom/nc/uncheck/SigFixApp;->findFieldOfType(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Field;

    move-result-object v2

    if-nez v2, :cond_0

    const-string p1, "\u627e\u4e0d\u5230 mBase \u5b57\u6bb5\uff0c\u8df3\u8fc7\u6e05\u96f6"

    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_0
    const/4 v3, 0x1

    invoke-virtual {v2, v3}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    const/4 v3, 0x0

    invoke-virtual {v2, p1, v3}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v1, "\uff09"

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    const-string v1, "\u6e05\u96f6 mBase \u5931\u8d25"

    invoke-static {v0, v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-void
.end method

.method private createOriginalApplication(Landroid/content/Context;)V
    .locals 4
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Throwable;
        }
    .end annotation

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    const-string v1, "SigFixApp"

    if-eqz v0, :cond_5

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_5

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    const-class v2, Lcom/nc/uncheck/SigFixApp;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto/16 :goto_2

    :cond_0
    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    invoke-virtual {p1}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v2

    const/4 v3, 0x0

    invoke-static {v0, v3, v2}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    move-result-object v0

    const-class v2, Landroid/app/Application;

    invoke-virtual {v2, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v2

    if-nez v2, :cond_1

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, " \u4e0d\u662f Application \u5b50\u7c7b\uff0c\u8df3\u8fc7"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_1
    new-array v2, v3, [Ljava/lang/Class;

    invoke-virtual {v0, v2}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v0

    new-array v2, v3, [Ljava/lang/Object;

    invoke-virtual {v0, v2}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/Application;

    invoke-direct {p0, v0, p1}, Lcom/nc/uncheck/SigFixApp;->attachContext(Landroid/app/Application;Landroid/content/Context;)V

    iput-object v0, p0, Lcom/nc/uncheck/SigFixApp;->mOriginal:Landroid/app/Application;

    sget-boolean v2, Lcom/nc/uncheck/SigFixApp;->sMinProxy:Z

    if-nez v2, :cond_2

    invoke-direct {p0, v0}, Lcom/nc/uncheck/SigFixApp;->clearBaseContext(Landroid/app/Application;)V

    :cond_2
    :try_start_0
    invoke-direct {p0, v0, p1}, Lcom/nc/uncheck/SigFixApp;->invokeAttachBaseContext(Landroid/app/Application;Landroid/content/Context;)V

    const-string p1, "\u5df2\u8c03\u7528\u539f Application.attachBaseContext"

    invoke-static {v1, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    const-string v2, "\u8c03\u7528\u539f Application.attachBaseContext \u5931\u8d25\uff08\u5176\u5185\u90e8\u521d\u59cb\u5316\u53ef\u80fd\u7f3a\u5931\uff09"

    invoke-static {v1, v2, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_0
    sget-boolean p1, Lcom/nc/uncheck/SigFixApp;->sMinProxy:Z

    if-nez p1, :cond_3

    invoke-direct {p0, v0}, Lcom/nc/uncheck/SigFixApp;->replaceInitialApplication(Landroid/app/Application;)V

    :cond_3
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "\u5df2\u63a5\u7ba1\u539f Application: "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    sget-boolean v0, Lcom/nc/uncheck/SigFixApp;->sMinProxy:Z

    if-eqz v0, :cond_4

    const-string v0, "\uff08\u6700\u5c0f\u4ee3\u7406\uff1a\u4e0d\u6e05 mBase / \u4e0d\u66ff\u6362 mInitialApplication\uff09"

    goto :goto_1

    :cond_4
    const-string v0, "\uff08\u5b8c\u6574\u4ee3\u7406\uff09"

    :goto_1
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_5
    :goto_2
    const-string p1, "\u65e0\u539f Application \u9700\u8981\u63a5\u7ba1\uff08\u539f\u5305\u6ca1\u6709 android:name\uff09"

    invoke-static {v1, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method private static findFieldOfType(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Field;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/Class<",
            "*>;)",
            "Ljava/lang/reflect/Field;"
        }
    .end annotation

    :goto_0
    if-eqz p1, :cond_2

    const-class v0, Ljava/lang/Object;

    if-eq p1, v0, :cond_2

    :try_start_0
    invoke-virtual {p1}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v0

    array-length v1, v0

    const/4 v2, 0x0

    :goto_1
    if-ge v2, v1, :cond_1

    aget-object v3, v0, v2

    invoke-virtual {v3}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-ne v4, p0, :cond_0

    return-object v3

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :catchall_0
    :cond_1
    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p1

    goto :goto_0

    :cond_2
    const/4 p0, 0x0

    return-object p0
.end method

.method private static varargs findMethod(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/String;",
            "[",
            "Ljava/lang/Class<",
            "*>;)",
            "Ljava/lang/reflect/Method;"
        }
    .end annotation

    :goto_0
    if-eqz p0, :cond_1

    const-class v0, Ljava/lang/Object;

    if-eq p0, v0, :cond_1

    :try_start_0
    invoke-virtual {p0, p1, p2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v0, :cond_0

    return-object v0

    :catchall_0
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p0

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method private invokeAttachBaseContext(Landroid/app/Application;Landroid/content/Context;)V
    .locals 6

    :try_start_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-string v1, "attachBaseContext"

    const/4 v2, 0x1

    new-array v3, v2, [Ljava/lang/Class;

    const-class v4, Landroid/content/Context;

    const/4 v5, 0x0

    aput-object v4, v3, v5

    invoke-static {v0, v1, v3}, Lcom/nc/uncheck/SigFixApp;->findMethod(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {v0, v2}, Ljava/lang/reflect/Method;->setAccessible(Z)V

    new-array v1, v2, [Ljava/lang/Object;

    aput-object p2, v1, v5

    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    const-string p2, "SigFixApp"

    const-string v0, "\u539f Application.attachBaseContext \u8c03\u7528\u5931\u8d25"

    invoke-static {p2, v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-void
.end method

.method private static loadConfig(Landroid/content/Context;)V
    .locals 6

    const-string v0, ""

    const-string v1, "SigFixApp"

    const/4 v2, 0x0

    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object p0

    const-string v3, "nc_sigfix/sigfix.json"

    invoke-virtual {p0, v3}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v2

    new-instance p0, Ljava/io/ByteArrayOutputStream;

    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    const/16 v3, 0x1000

    new-array v3, v3, [B

    :goto_0
    invoke-virtual {v2, v3}, Ljava/io/InputStream;->read([B)I

    move-result v4

    const/4 v5, 0x0

    if-lez v4, :cond_0

    invoke-virtual {p0, v3, v5, v4}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    goto :goto_0

    :cond_0
    new-instance v3, Ljava/lang/String;

    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object p0

    const-string v4, "UTF-8"

    invoke-direct {v3, p0, v4}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0, v3}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    const-string v3, "cert"

    invoke-virtual {p0, v3, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    sput-object v3, Lcom/nc/uncheck/SigFixApp;->sCertB64:Ljava/lang/String;

    const-string v3, "originalApp"

    invoke-virtual {p0, v3, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    const-string v0, "minProxy"

    invoke-virtual {p0, v0, v5}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result p0

    sput-boolean p0, Lcom/nc/uncheck/SigFixApp;->sMinProxy:Z

    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v0, "\u914d\u7f6e\u5df2\u8bfb\u53d6\uff1acert "

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sCertB64:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    const-string v0, "\u7f3a\u5931"

    goto :goto_1

    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v3, Lcom/nc/uncheck/SigFixApp;->sCertB64:Ljava/lang/String;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v3, " \u5b57\u7b26"

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_1
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    const-string v0, "\uff0coriginalApp="

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    const-string v0, "(\u65e0)"

    goto :goto_2

    :cond_2
    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    :goto_2
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    const-string v0, "\uff0cminProxy="

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    sget-boolean v0, Lcom/nc/uncheck/SigFixApp;->sMinProxy:Z

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {v1, p0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v2, :cond_3

    :try_start_1
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    return-void

    :catchall_0
    move-exception p0

    :try_start_2
    const-string v0, "\u8bfb\u53d6 nc_sigfix/sigfix.json \u5931\u8d25"

    invoke-static {v1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    if-eqz v2, :cond_3

    :try_start_3
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :catchall_1
    :cond_3
    return-void

    :catchall_2
    move-exception p0

    if-eqz v2, :cond_4

    :try_start_4
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    :catchall_3
    :cond_4
    throw p0
.end method

.method private newApplicationViaInstrumentation(Ljava/lang/Class;Landroid/content/Context;)Landroid/app/Application;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;",
            "Landroid/content/Context;",
            ")",
            "Landroid/app/Application;"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Throwable;
        }
    .end annotation

    const-string v0, "android.app.ActivityThread"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Class;

    const-string v3, "currentActivityThread"

    invoke-virtual {v0, v3, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v2

    const/4 v3, 0x1

    invoke-virtual {v2, v3}, Ljava/lang/reflect/Method;->setAccessible(Z)V

    new-array v4, v1, [Ljava/lang/Object;

    const/4 v5, 0x0

    invoke-virtual {v2, v5, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_0

    return-object v5

    :cond_0
    move-object v4, v5

    :goto_0
    if-eqz v0, :cond_4

    const-class v6, Ljava/lang/Object;

    if-eq v0, v6, :cond_4

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v6

    array-length v7, v6

    const/4 v8, 0x0

    :goto_1
    if-ge v8, v7, :cond_2

    aget-object v9, v6, v8

    invoke-virtual {v9}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    move-result-object v10

    const-class v11, Landroid/app/Instrumentation;

    if-ne v10, v11, :cond_1

    move-object v4, v9

    goto :goto_2

    :cond_1
    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_2
    :goto_2
    if-eqz v4, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object v0

    goto :goto_0

    :cond_4
    :goto_3
    if-nez v4, :cond_5

    return-object v5

    :cond_5
    invoke-virtual {v4, v3}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    invoke-virtual {v4, v2}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/Instrumentation;

    if-nez v0, :cond_6

    return-object v5

    :cond_6
    const-class v2, Landroid/app/Instrumentation;

    const/4 v4, 0x2

    new-array v5, v4, [Ljava/lang/Class;

    const-class v6, Ljava/lang/Class;

    aput-object v6, v5, v1

    const-class v6, Landroid/content/Context;

    aput-object v6, v5, v3

    const-string v6, "newApplication"

    invoke-virtual {v2, v6, v5}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v2

    invoke-virtual {v2, v3}, Ljava/lang/reflect/Method;->setAccessible(Z)V

    new-array v4, v4, [Ljava/lang/Object;

    aput-object p1, v4, v1

    aput-object p2, v4, v3

    invoke-virtual {v2, v0, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/app/Application;

    return-object p1
.end method

.method private replaceInitialApplication(Landroid/app/Application;)V
    .locals 7

    const-string v0, "SigFixApp"

    const-string v1, "mInitialApplication \u66ff\u6362"

    :try_start_0
    const-string v2, "android.app.ActivityThread"

    invoke-static {v2}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v2

    const-string v3, "currentActivityThread"

    const/4 v4, 0x0

    new-array v5, v4, [Ljava/lang/Class;

    invoke-virtual {v2, v3, v5}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v3

    const/4 v5, 0x1

    invoke-virtual {v3, v5}, Ljava/lang/reflect/Method;->setAccessible(Z)V

    new-array v4, v4, [Ljava/lang/Object;

    const/4 v6, 0x0

    invoke-virtual {v3, v6, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_0

    return-void

    :cond_0
    const-class v4, Landroid/app/Application;

    invoke-static {v4, v2}, Lcom/nc/uncheck/SigFixApp;->findFieldOfType(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Field;

    move-result-object v2

    if-nez v2, :cond_1

    const-string p1, "ActivityThread \u91cc\u627e\u4e0d\u5230 Application \u7c7b\u578b\u5b57\u6bb5"

    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_1
    invoke-virtual {v2, v5}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    invoke-virtual {v2, v3, p1}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2, v3}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, p1, :cond_2

    const-string p1, "\u6210\u529f\uff08\u56de\u8bfb\u4e00\u81f4\uff09"

    goto :goto_0

    :cond_2
    const-string p1, "\u5931\u8d25\uff08\u56de\u8bfb\u4e0d\u4e00\u81f4\uff09"

    :goto_0
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    const-string v1, "\u66ff\u6362 mInitialApplication \u5931\u8d25"

    invoke-static {v0, v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-void
.end method

# virtual methods
.method protected attachBaseContext(Landroid/content/Context;)V
    .locals 3

    const-string v0, "SigFixApp"

    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V

    iput-object p1, p0, Lcom/nc/uncheck/SigFixApp;->mBase:Landroid/content/Context;

    :try_start_0
    invoke-static {p1}, Lcom/nc/uncheck/SigFix;->install(Landroid/content/Context;)V

    const-string v1, "hook \u5b89\u88c5\u5b8c\u6210\uff08\u65e9\u4e8e\u539f Application \u521d\u59cb\u5316\uff09"

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    const-string v2, "hook \u5b89\u88c5\u5931\u8d25\uff08\u4e0d\u5f71\u54cd App \u542f\u52a8\uff09"

    invoke-static {v0, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_0
    invoke-static {p1}, Lcom/nc/uncheck/SigFixApp;->loadConfig(Landroid/content/Context;)V

    :try_start_1
    invoke-direct {p0, p1}, Lcom/nc/uncheck/SigFixApp;->createOriginalApplication(Landroid/content/Context;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_1

    :catchall_1
    move-exception p1

    const-string v1, "\u521b\u5efa\u539f Application \u5931\u8d25\uff08App \u53ef\u80fd\u884c\u4e3a\u5f02\u5e38\uff09"

    invoke-static {v0, v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_1
    return-void
.end method

.method public onCreate()V
    .locals 3

    const-string v0, "\u5df2\u8f6c\u53d1 onCreate \u7ed9 "

    invoke-super {p0}, Landroid/app/Application;->onCreate()V

    iget-object v1, p0, Lcom/nc/uncheck/SigFixApp;->mOriginal:Landroid/app/Application;

    const-string v2, "SigFixApp"

    if-nez v1, :cond_0

    const-string v0, "\u6ca1\u6709\u539f Application\uff0c\u53ea\u8dd1\u6211\u4eec\u7684\u521d\u59cb\u5316"

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_0
    :try_start_0
    invoke-virtual {v1}, Landroid/app/Application;->onCreate()V

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v0, Lcom/nc/uncheck/SigFixApp;->sOriginalApp:Ljava/lang/String;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception v0

    const-string v1, "\u8f6c\u53d1 onCreate \u5931\u8d25"

    invoke-static {v2, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-void
.end method
