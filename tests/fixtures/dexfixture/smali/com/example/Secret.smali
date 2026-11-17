.class public Lcom/example/Secret;
.super Ljava/lang/Object;
.source "Secret.java"

.annotation runtime Lcom/example/Marked;
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String; = "secret"


# instance fields
.field public count:I


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public static load()V
    .locals 0

    .annotation runtime Lcom/example/Marked;
    .end annotation

    return-void
.end method
