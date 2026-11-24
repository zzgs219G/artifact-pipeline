.class public final Lcom/nc/link/NcLink;
.super Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static ensureLoaded()V
    .locals 1

    const-string v0, "nc"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method

.method public static native heartbeat()V
.end method

.method public static native lastJudge()I
.end method

.method public static native ncVerify([B)Z
.end method

.method public static native selftest()I
.end method
