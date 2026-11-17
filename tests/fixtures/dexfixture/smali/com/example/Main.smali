.class public Lcom/example/Main;
.super Ljava/lang/Object;
.source "Main.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
# Launcher entry point: one internal call edge Main.onCreate -> Api.fetch, so the
# endpoint in Api.fetch is reachable from an exported component by a real edge.
.method public onCreate()V
    .locals 0

    invoke-static {}, Lcom/example/Api;->fetch()Ljava/lang/String;

    return-void
.end method

# JNI target: libdexfixture.so exports Java_com_example_Main_compute.
.method public static native compute()V
.end method

.method public static load()V
    .locals 0

    return-void
.end method

# Class.forName with a literal argument (one-hop resolvable)
.method public static reflectLiteral()Ljava/lang/Class;
    .locals 1

    const-string v0, "com.example.Secret"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

# Class.forName with a parameter argument (not resolvable)
.method public static reflectDynamic(Ljava/lang/String;)Ljava/lang/Class;
    .locals 1

    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

# getDeclaredMethod + Method.invoke, dynamic receiver
.method public static invokeReflect(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-string v1, "load"

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Class;

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, p0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

# literal Class.forName followed by getMethod + invoke
.method public static invokeLiteral()Ljava/lang/Object;
    .locals 4

    const-string v0, "com.example.Secret"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const-string v1, "load"

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Class;

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
