.class public final Lcom/test/placeholder/Guard$Hb;
.super Ljava/lang/Thread;





# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 2

    :catchall_0
    :goto_0
    :try_start_0
    invoke-static {}, Lcom/nc/link/NcLink;->heartbeat()V

    const-wide/16 v0, 0x1388

    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0
.end method
