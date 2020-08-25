.class public Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;
.super Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
.source "ConstraintHorizontalLayout.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;
    }
.end annotation


# instance fields
.field private mAlignment:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;


# direct methods
.method public constructor <init>()V
    .registers 2

    .line 35
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;-><init>()V

    .line 30
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mAlignment:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    .line 35
    return-void
.end method

.method public constructor <init>(II)V
    .registers 4
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 54
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;-><init>(II)V

    .line 30
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mAlignment:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    .line 55
    return-void
.end method

.method public constructor <init>(IIII)V
    .registers 6
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I

    .line 45
    invoke-direct {p0, p1, p2, p3, p4}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;-><init>(IIII)V

    .line 30
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->MIDDLE:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mAlignment:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    .line 46
    return-void
.end method


# virtual methods
.method public addToSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 13
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 63
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    if-eqz v0, :cond_6b

    .line 64
    move-object v0, p0

    .line 65
    .local v0, "previous":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v1, 0x0

    .line 65
    .local v1, "i":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 65
    .local v2, "mChildrenSize":I
    :goto_10
    if-ge v1, v2, :cond_54

    .line 66
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    move-object v9, v3

    check-cast v9, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 67
    .local v9, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-eq v0, p0, :cond_2c

    .line 68
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v3, v0, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    .line 69
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v3, v9, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    goto :goto_42

    .line 71
    :cond_2c
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 72
    .local v3, "strength":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mAlignment:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->END:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    if-ne v4, v5, :cond_36

    .line 73
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->WEAK:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 75
    .end local v3    # "strength":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    .local v10, "strength":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    :cond_36
    move-object v10, v3

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v7, 0x0

    move-object v3, v9

    move-object v5, v0

    move-object v8, v10

    invoke-virtual/range {v3 .. v8}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 78
    .end local v10    # "strength":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    :goto_42
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v3, p0, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    .line 79
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v3, p0, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    .line 80
    move-object v0, v9

    .line 65
    .end local v9    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v1, v1, 0x1

    goto :goto_10

    .line 82
    .end local v1    # "i":I
    .end local v2    # "mChildrenSize":I
    :cond_54
    if-eq v0, p0, :cond_6b

    .line 83
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 84
    .local v1, "strength":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout;->mAlignment:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;->BEGIN:Landroid/support/constraint/solver/widgets/ConstraintHorizontalLayout$ContentAlignment;

    if-ne v2, v3, :cond_60

    .line 85
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->WEAK:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 87
    :cond_60
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v7, 0x0

    move-object v3, v0

    move-object v5, p0

    move-object v8, v1

    invoke-virtual/range {v3 .. v8}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 91
    .end local v0    # "previous":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v1    # "strength":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    :cond_6b
    invoke-super {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 92
    return-void
.end method
