.class public Landroid/support/constraint/Group;
.super Landroid/support/constraint/ConstraintHelper;
.source "Group.java"


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .registers 2
    .param p1, "context"    # Landroid/content/Context;

    .line 39
    invoke-direct {p0, p1}, Landroid/support/constraint/ConstraintHelper;-><init>(Landroid/content/Context;)V

    .line 40
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .registers 3
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;

    .line 43
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/ConstraintHelper;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 44
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .registers 4
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;
    .param p3, "defStyleAttr"    # I

    .line 47
    invoke-direct {p0, p1, p2, p3}, Landroid/support/constraint/ConstraintHelper;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 48
    return-void
.end method


# virtual methods
.method protected init(Landroid/util/AttributeSet;)V
    .registers 3
    .param p1, "attrs"    # Landroid/util/AttributeSet;

    .line 55
    invoke-super {p0, p1}, Landroid/support/constraint/ConstraintHelper;->init(Landroid/util/AttributeSet;)V

    .line 56
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/Group;->mUseViewMeasure:Z

    .line 57
    return-void
.end method

.method public updatePostLayout(Landroid/support/constraint/ConstraintLayout;)V
    .registers 5
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 88
    invoke-virtual {p0}, Landroid/support/constraint/Group;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 89
    .local v0, "params":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    iget-object v1, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setWidth(I)V

    .line 90
    iget-object v1, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHeight(I)V

    .line 91
    return-void
.end method

.method public updatePreLayout(Landroid/support/constraint/ConstraintLayout;)V
    .registers 9
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 65
    invoke-virtual {p0}, Landroid/support/constraint/Group;->getVisibility()I

    move-result v0

    .line 66
    .local v0, "visibility":I
    const/4 v1, 0x0

    .line 67
    .local v1, "elevation":F
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v3, 0x15

    if-lt v2, v3, :cond_f

    .line 68
    invoke-virtual {p0}, Landroid/support/constraint/Group;->getElevation()F

    move-result v1

    .line 70
    :cond_f
    const/4 v2, 0x0

    .line 70
    .local v2, "i":I
    :goto_10
    iget v4, p0, Landroid/support/constraint/Group;->mCount:I

    if-ge v2, v4, :cond_30

    .line 71
    iget-object v4, p0, Landroid/support/constraint/Group;->mIds:[I

    aget v4, v4, v2

    .line 72
    .local v4, "id":I
    invoke-virtual {p1, v4}, Landroid/support/constraint/ConstraintLayout;->getViewById(I)Landroid/view/View;

    move-result-object v5

    .line 73
    .local v5, "view":Landroid/view/View;
    if-eqz v5, :cond_2d

    .line 74
    invoke-virtual {v5, v0}, Landroid/view/View;->setVisibility(I)V

    .line 75
    const/4 v6, 0x0

    cmpl-float v6, v1, v6

    if-lez v6, :cond_2d

    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v6, v3, :cond_2d

    .line 76
    invoke-virtual {v5, v1}, Landroid/view/View;->setElevation(F)V

    .line 70
    .end local v4    # "id":I
    .end local v5    # "view":Landroid/view/View;
    :cond_2d
    add-int/lit8 v2, v2, 0x1

    goto :goto_10

    .line 80
    .end local v2    # "i":I
    :cond_30
    return-void
.end method
