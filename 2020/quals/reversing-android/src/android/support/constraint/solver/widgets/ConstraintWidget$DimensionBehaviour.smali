.class public final enum Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
.super Ljava/lang/Enum;
.source "ConstraintWidget.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/constraint/solver/widgets/ConstraintWidget;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "DimensionBehaviour"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

.field public static final enum FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

.field public static final enum MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

.field public static final enum MATCH_PARENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

.field public static final enum WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;


# direct methods
.method static constructor <clinit>()V
    .registers 6

    .line 143
    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const-string v1, "FIXED"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const-string v1, "WRAP_CONTENT"

    const/4 v3, 0x1

    invoke-direct {v0, v1, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const-string v1, "MATCH_CONSTRAINT"

    const/4 v4, 0x2

    invoke-direct {v0, v1, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const-string v1, "MATCH_PARENT"

    const/4 v5, 0x3

    invoke-direct {v0, v1, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_PARENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 142
    const/4 v0, 0x4

    new-array v0, v0, [Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v1, v0, v2

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v1, v0, v3

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v1, v0, v4

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_PARENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v1, v0, v5

    sput-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->$VALUES:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .registers 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 142
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .registers 2
    .param p0, "name"    # Ljava/lang/String;

    .line 142
    const-class v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    return-object v0
.end method

.method public static values()[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .registers 1

    .line 142
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->$VALUES:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {v0}, [Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    return-object v0
.end method
