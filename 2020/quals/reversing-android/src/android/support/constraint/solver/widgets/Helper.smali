.class public Landroid/support/constraint/solver/widgets/Helper;
.super Landroid/support/constraint/solver/widgets/ConstraintWidget;
.source "Helper.java"


# instance fields
.field protected mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mWidgetsCount:I


# direct methods
.method public constructor <init>()V
    .registers 2

    .line 8
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    .line 9
    const/4 v0, 0x4

    new-array v0, v0, [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 10
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    return-void
.end method


# virtual methods
.method public add(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 4
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 18
    iget v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    add-int/lit8 v0, v0, 0x1

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    array-length v1, v1

    if-le v0, v1, :cond_18

    .line 19
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    array-length v1, v1

    mul-int/lit8 v1, v1, 0x2

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 21
    :cond_18
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v1, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    aput-object p1, v0, v1

    .line 22
    iget v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    .line 23
    return-void
.end method

.method public removeAllIds()V
    .registers 2

    .line 29
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    .line 30
    return-void
.end method
