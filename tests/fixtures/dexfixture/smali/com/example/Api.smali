.class public Lcom/example/Api;
.super Ljava/lang/Object;
.source "Api.java"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "dexfixture"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
# Endpoint string + permission-gated platform API in ONE method: the two
# citations the link graph needs for method->endpoint and endpoint->permission.
.method public static fetch()Ljava/lang/String;
    .locals 2

    const-string v0, "https://api.example.test/v1/feed"

    invoke-virtual {p0, v0}, Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;

    return-object v0
.end method
