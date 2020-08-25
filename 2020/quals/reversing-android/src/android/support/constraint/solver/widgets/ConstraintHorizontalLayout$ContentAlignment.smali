.class public final enum Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;
.super Ljava/lang/Enum;
.source "ConstraintHorizontalLayout.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "ContentAlignment"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum BEGIN:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum END:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum LEFT:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum RIGHT:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum TOP:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

.field public static final enum VERTICAL_MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;


# direct methods
.method static constructor <clinit>()V
    .registers 10

    .line 27
    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "BEGIN"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->BEGIN:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "MIDDLE"

    const/4 v3, 0x1

    invoke-direct {v0, v1, v3}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "END"

    const/4 v4, 0x2

    invoke-direct {v0, v1, v4}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->END:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "TOP"

    const/4 v5, 0x3

    invoke-direct {v0, v1, v5}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->TOP:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "VERTICAL_MIDDLE"

    const/4 v6, 0x4

    invoke-direct {v0, v1, v6}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->VERTICAL_MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "BOTTOM"

    const/4 v7, 0x5

    invoke-direct {v0, v1, v7}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "LEFT"

    const/4 v8, 0x6

    invoke-direct {v0, v1, v8}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    const-string v1, "RIGHT"

    const/4 v9, 0x7

    invoke-direct {v0, v1, v9}, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    .line 26
    const/16 v0, 0x8

    new-array v0, v0, [Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->BEGIN:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v2

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v3

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->END:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v4

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->TOP:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v5

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->VERTICAL_MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v6

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v7

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v8

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    aput-object v1, v0, v9

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->$VALUES:[Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .registers 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 26
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;
    .registers 2
    .param p0, "name"    # Ljava/lang/String;

    .line 26
    const-class v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    return-object v0
.end method

.method public static values()[Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;
    .registers 1

    .line 26
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->$VALUES:[Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    invoke-virtual {v0}, [Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    return-object v0
.end method
