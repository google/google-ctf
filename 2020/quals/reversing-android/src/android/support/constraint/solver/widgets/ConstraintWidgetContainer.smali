.class public Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
.super Landroid/support/constraint/solver/widgets/WidgetContainer;
.source "ConstraintWidgetContainer.java"


# static fields
.field private static final DEBUG:Z = false

.field static final DEBUG_GRAPH:Z = false

.field private static final DEBUG_LAYOUT:Z = false

.field private static final MAX_ITERATIONS:I = 0x8

.field private static final USE_SNAPSHOT:Z = true


# instance fields
.field mDebugSolverPassCount:I

.field public mGroupsWrapOptimized:Z

.field private mHeightMeasuredTooSmall:Z

.field mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

.field mHorizontalChainsSize:I

.field public mHorizontalWrapOptimized:Z

.field private mIsRtl:Z

.field private mOptimizationLevel:I

.field mPaddingBottom:I

.field mPaddingLeft:I

.field mPaddingRight:I

.field mPaddingTop:I

.field public mSkipSolver:Z

.field private mSnapshot:Landroid/support/constraint/solver/widgets/Snapshot;

.field protected mSystem:Landroid/support/constraint/solver/LinearSystem;

.field mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

.field mVerticalChainsSize:I

.field public mVerticalWrapOptimized:Z

.field public mWidgetGroups:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;",
            ">;"
        }
    .end annotation
.end field

.field private mWidthMeasuredTooSmall:Z

.field public mWrapFixedHeight:I

.field public mWrapFixedWidth:I


# direct methods
.method public constructor <init>()V
    .registers 4

    .line 82
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;-><init>()V

    .line 41
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mIsRtl:Z

    .line 47
    new-instance v1, Landroid/support/constraint/solver/LinearSystem;

    invoke-direct {v1}, Landroid/support/constraint/solver/LinearSystem;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    .line 56
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    .line 57
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    .line 59
    const/4 v1, 0x4

    new-array v2, v1, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 60
    new-array v1, v1, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 62
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    .line 63
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mGroupsWrapOptimized:Z

    .line 64
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalWrapOptimized:Z

    .line 65
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalWrapOptimized:Z

    .line 66
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWrapFixedWidth:I

    .line 67
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWrapFixedHeight:I

    .line 69
    const/4 v1, 0x7

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    .line 70
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSkipSolver:Z

    .line 72
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidthMeasuredTooSmall:Z

    .line 73
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHeightMeasuredTooSmall:Z

    .line 166
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mDebugSolverPassCount:I

    .line 83
    return-void
.end method

.method public constructor <init>(II)V
    .registers 6
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 104
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/solver/widgets/WidgetContainer;-><init>(II)V

    .line 41
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mIsRtl:Z

    .line 47
    new-instance v1, Landroid/support/constraint/solver/LinearSystem;

    invoke-direct {v1}, Landroid/support/constraint/solver/LinearSystem;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    .line 56
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    .line 57
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    .line 59
    const/4 v1, 0x4

    new-array v2, v1, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 60
    new-array v1, v1, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 62
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    .line 63
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mGroupsWrapOptimized:Z

    .line 64
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalWrapOptimized:Z

    .line 65
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalWrapOptimized:Z

    .line 66
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWrapFixedWidth:I

    .line 67
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWrapFixedHeight:I

    .line 69
    const/4 v1, 0x7

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    .line 70
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSkipSolver:Z

    .line 72
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidthMeasuredTooSmall:Z

    .line 73
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHeightMeasuredTooSmall:Z

    .line 166
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mDebugSolverPassCount:I

    .line 105
    return-void
.end method

.method public constructor <init>(IIII)V
    .registers 8
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I

    .line 94
    invoke-direct {p0, p1, p2, p3, p4}, Landroid/support/constraint/solver/widgets/WidgetContainer;-><init>(IIII)V

    .line 41
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mIsRtl:Z

    .line 47
    new-instance v1, Landroid/support/constraint/solver/LinearSystem;

    invoke-direct {v1}, Landroid/support/constraint/solver/LinearSystem;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    .line 56
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    .line 57
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    .line 59
    const/4 v1, 0x4

    new-array v2, v1, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 60
    new-array v1, v1, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 62
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    .line 63
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mGroupsWrapOptimized:Z

    .line 64
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalWrapOptimized:Z

    .line 65
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalWrapOptimized:Z

    .line 66
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWrapFixedWidth:I

    .line 67
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWrapFixedHeight:I

    .line 69
    const/4 v1, 0x7

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    .line 70
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSkipSolver:Z

    .line 72
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidthMeasuredTooSmall:Z

    .line 73
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHeightMeasuredTooSmall:Z

    .line 166
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mDebugSolverPassCount:I

    .line 95
    return-void
.end method

.method private addHorizontalChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 7
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 744
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    add-int/lit8 v0, v0, 0x1

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    array-length v1, v1

    if-lt v0, v1, :cond_18

    .line 745
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    array-length v1, v1

    mul-int/lit8 v1, v1, 0x2

    .line 746
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 748
    :cond_18
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    new-instance v2, Landroid/support/constraint/solver/widgets/ChainHead;

    const/4 v3, 0x0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->isRtl()Z

    move-result v4

    invoke-direct {v2, p1, v3, v4}, Landroid/support/constraint/solver/widgets/ChainHead;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;IZ)V

    aput-object v2, v0, v1

    .line 749
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    .line 750
    return-void
.end method

.method private addVerticalChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 7
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 759
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    array-length v2, v2

    if-lt v0, v2, :cond_18

    .line 760
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    array-length v2, v2

    mul-int/lit8 v2, v2, 0x2

    .line 761
    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/widgets/ChainHead;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    .line 763
    :cond_18
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsArray:[Landroid/support/constraint/solver/widgets/ChainHead;

    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    new-instance v3, Landroid/support/constraint/solver/widgets/ChainHead;

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->isRtl()Z

    move-result v4

    invoke-direct {v3, p1, v1, v4}, Landroid/support/constraint/solver/widgets/ChainHead;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;IZ)V

    aput-object v3, v0, v2

    .line 764
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    add-int/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    .line 765
    return-void
.end method

.method private resetChains()V
    .registers 2

    .line 718
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    .line 719
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    .line 720
    return-void
.end method


# virtual methods
.method addChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)V
    .registers 5
    .param p1, "constraintWidget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "type"    # I

    .line 729
    move-object v0, p1

    .line 730
    .local v0, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-nez p2, :cond_7

    .line 731
    invoke-direct {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addHorizontalChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    goto :goto_d

    .line 732
    :cond_7
    const/4 v1, 0x1

    if-ne p2, v1, :cond_d

    .line 733
    invoke-direct {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addVerticalChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 735
    :cond_d
    :goto_d
    return-void
.end method

.method public addChildrenToSolver(Landroid/support/constraint/solver/LinearSystem;)Z
    .registers 9
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 180
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 181
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 183
    .local v0, "count":I
    const/4 v1, 0x0

    move v2, v1

    .line 183
    .local v2, "i":I
    :goto_b
    const/4 v3, 0x1

    if-ge v2, v0, :cond_4f

    .line 184
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 185
    .local v4, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    instance-of v5, v4, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v5, :cond_46

    .line 186
    iget-object v5, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v5, v5, v1

    .line 187
    .local v5, "horizontalBehaviour":Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    iget-object v6, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v3, v6, v3

    .line 188
    .local v3, "verticalBehaviour":Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v6, :cond_2b

    .line 189
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {v4, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 191
    :cond_2b
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v3, v6, :cond_34

    .line 192
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {v4, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 194
    :cond_34
    invoke-virtual {v4, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 195
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v6, :cond_3e

    .line 196
    invoke-virtual {v4, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 198
    :cond_3e
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v3, v6, :cond_45

    .line 199
    invoke-virtual {v4, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 201
    .end local v3    # "verticalBehaviour":Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .end local v5    # "horizontalBehaviour":Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    :cond_45
    goto :goto_4c

    .line 202
    :cond_46
    invoke-static {p0, p1, v4}, Landroid/support/constraint/solver/widgets/Optimizer;->checkMatchParent(Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 203
    invoke-virtual {v4, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 183
    .end local v4    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_4c
    add-int/lit8 v2, v2, 0x1

    goto :goto_b

    .line 207
    .end local v2    # "i":I
    :cond_4f
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHorizontalChainsSize:I

    if-lez v2, :cond_56

    .line 208
    invoke-static {p0, p1, v1}, Landroid/support/constraint/solver/widgets/Chain;->applyChainConstraints(Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;Landroid/support/constraint/solver/LinearSystem;I)V

    .line 210
    :cond_56
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mVerticalChainsSize:I

    if-lez v1, :cond_5d

    .line 211
    invoke-static {p0, p1, v3}, Landroid/support/constraint/solver/widgets/Chain;->applyChainConstraints(Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;Landroid/support/constraint/solver/LinearSystem;I)V

    .line 213
    :cond_5d
    return v3
.end method

.method public analyze(I)V
    .registers 5
    .param p1, "optimizationLevel"    # I

    .line 280
    invoke-super {p0, p1}, Landroid/support/constraint/solver/widgets/WidgetContainer;->analyze(I)V

    .line 281
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 282
    .local v0, "count":I
    const/4 v1, 0x0

    .line 282
    .local v1, "i":I
    :goto_a
    if-ge v1, v0, :cond_1a

    .line 283
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v2, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->analyze(I)V

    .line 282
    add-int/lit8 v1, v1, 0x1

    goto :goto_a

    .line 285
    .end local v1    # "i":I
    :cond_1a
    return-void
.end method

.method public fillMetrics(Landroid/support/constraint/solver/Metrics;)V
    .registers 3
    .param p1, "metrics"    # Landroid/support/constraint/solver/Metrics;

    .line 44
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/LinearSystem;->fillMetrics(Landroid/support/constraint/solver/Metrics;)V

    .line 45
    return-void
.end method

.method public getHorizontalGuidelines()Ljava/util/ArrayList;
    .registers 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/Guideline;",
            ">;"
        }
    .end annotation

    .line 693
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 694
    .local v0, "guidelines":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/Guideline;>;"
    const/4 v1, 0x0

    .line 694
    .local v1, "i":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 694
    .local v2, "mChildrenSize":I
    :goto_c
    if-ge v1, v2, :cond_29

    .line 695
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 696
    .local v3, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    instance-of v4, v3, Landroid/support/constraint/solver/widgets/Guideline;

    if-eqz v4, :cond_26

    .line 697
    move-object v4, v3

    check-cast v4, Landroid/support/constraint/solver/widgets/Guideline;

    .line 698
    .local v4, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/Guideline;->getOrientation()I

    move-result v5

    if-nez v5, :cond_26

    .line 699
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 694
    .end local v3    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v4    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    :cond_26
    add-int/lit8 v1, v1, 0x1

    goto :goto_c

    .line 703
    .end local v1    # "i":I
    .end local v2    # "mChildrenSize":I
    :cond_29
    return-object v0
.end method

.method public getOptimizationLevel()I
    .registers 2

    .line 122
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    return v0
.end method

.method public getSystem()Landroid/support/constraint/solver/LinearSystem;
    .registers 2

    .line 707
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    return-object v0
.end method

.method public getType()Ljava/lang/String;
    .registers 2

    .line 141
    const-string v0, "ConstraintLayout"

    return-object v0
.end method

.method public getVerticalGuidelines()Ljava/util/ArrayList;
    .registers 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/Guideline;",
            ">;"
        }
    .end annotation

    .line 674
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 675
    .local v0, "guidelines":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/Guideline;>;"
    const/4 v1, 0x0

    .line 675
    .local v1, "i":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 675
    .local v2, "mChildrenSize":I
    :goto_c
    if-ge v1, v2, :cond_2a

    .line 676
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 677
    .local v3, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    instance-of v4, v3, Landroid/support/constraint/solver/widgets/Guideline;

    if-eqz v4, :cond_27

    .line 678
    move-object v4, v3

    check-cast v4, Landroid/support/constraint/solver/widgets/Guideline;

    .line 679
    .local v4, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/Guideline;->getOrientation()I

    move-result v5

    const/4 v6, 0x1

    if-ne v5, v6, :cond_27

    .line 680
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 675
    .end local v3    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v4    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    :cond_27
    add-int/lit8 v1, v1, 0x1

    goto :goto_c

    .line 684
    .end local v1    # "i":I
    .end local v2    # "mChildrenSize":I
    :cond_2a
    return-object v0
.end method

.method public getWidgetGroups()Ljava/util/List;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;",
            ">;"
        }
    .end annotation

    .line 777
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    return-object v0
.end method

.method public handlesInternalConstraints()Z
    .registers 2

    .line 661
    const/4 v0, 0x0

    return v0
.end method

.method public isHeightMeasuredTooSmall()Z
    .registers 2

    .line 164
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHeightMeasuredTooSmall:Z

    return v0
.end method

.method public isRtl()Z
    .registers 2

    .line 267
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mIsRtl:Z

    return v0
.end method

.method public isWidthMeasuredTooSmall()Z
    .registers 2

    .line 159
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidthMeasuredTooSmall:Z

    return v0
.end method

.method public layout()V
    .registers 29

    .line 298
    move-object/from16 v1, p0

    iget v2, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mX:I

    .line 299
    .local v2, "prex":I
    iget v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mY:I

    .line 300
    .local v3, "prey":I
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v4

    const/4 v5, 0x0

    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    move-result v4

    .line 301
    .local v4, "prew":I
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v6

    invoke-static {v5, v6}, Ljava/lang/Math;->max(II)I

    move-result v6

    .line 302
    .local v6, "preh":I
    iput-boolean v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidthMeasuredTooSmall:Z

    .line 303
    iput-boolean v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHeightMeasuredTooSmall:Z

    .line 305
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v7, :cond_46

    .line 306
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSnapshot:Landroid/support/constraint/solver/widgets/Snapshot;

    if-nez v7, :cond_2a

    .line 307
    new-instance v7, Landroid/support/constraint/solver/widgets/Snapshot;

    invoke-direct {v7, v1}, Landroid/support/constraint/solver/widgets/Snapshot;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    iput-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSnapshot:Landroid/support/constraint/solver/widgets/Snapshot;

    .line 309
    :cond_2a
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSnapshot:Landroid/support/constraint/solver/widgets/Snapshot;

    invoke-virtual {v7, v1}, Landroid/support/constraint/solver/widgets/Snapshot;->updateFrom(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 314
    iget v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingLeft:I

    invoke-virtual {v1, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setX(I)V

    .line 315
    iget v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingTop:I

    invoke-virtual {v1, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setY(I)V

    .line 316
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetAnchors()V

    .line 317
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v7}, Landroid/support/constraint/solver/LinearSystem;->getCache()Landroid/support/constraint/solver/Cache;

    move-result-object v7

    invoke-virtual {v1, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetSolverVariables(Landroid/support/constraint/solver/Cache;)V

    goto :goto_4a

    .line 319
    :cond_46
    iput v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mX:I

    .line 320
    iput v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mY:I

    .line 323
    :goto_4a
    iget v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    const/16 v8, 0x20

    const/16 v9, 0x8

    const/4 v10, 0x1

    if-eqz v7, :cond_6a

    .line 324
    invoke-virtual {v1, v9}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimizeFor(I)Z

    move-result v7

    if-nez v7, :cond_5c

    .line 325
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimizeReset()V

    .line 327
    :cond_5c
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimizeFor(I)Z

    move-result v7

    if-nez v7, :cond_65

    .line 328
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimize()V

    .line 330
    :cond_65
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    iput-boolean v10, v7, Landroid/support/constraint/solver/LinearSystem;->graphOptimizer:Z

    goto :goto_6e

    .line 332
    :cond_6a
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    iput-boolean v5, v7, Landroid/support/constraint/solver/LinearSystem;->graphOptimizer:Z

    .line 335
    :goto_6e
    const/4 v7, 0x0

    .line 336
    .local v7, "wrap_override":Z
    iget-object v11, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v11, v11, v10

    .line 337
    .local v11, "originalVerticalDimensionBehaviour":Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    iget-object v12, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v12, v12, v5

    .line 345
    .local v12, "originalHorizontalDimensionBehaviour":Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    invoke-direct/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetChains()V

    .line 347
    iget-object v13, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v13}, Ljava/util/List;->size()I

    move-result v13

    if-nez v13, :cond_93

    .line 348
    iget-object v13, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v13}, Ljava/util/List;->clear()V

    .line 349
    iget-object v13, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    new-instance v14, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    iget-object v15, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-direct {v14, v15}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;-><init>(Ljava/util/List;)V

    invoke-interface {v13, v5, v14}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 352
    :cond_93
    const/4 v13, 0x0

    .line 353
    .local v13, "countSolve":I
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v14}, Ljava/util/List;->size()I

    move-result v14

    .line 354
    .local v14, "groupSize":I
    iget-object v15, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 355
    .local v15, "allChildren":Ljava/util/List;, "Ljava/util/List<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v9

    sget-object v10, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v9, v10, :cond_af

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v9

    sget-object v10, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v9, v10, :cond_ad

    goto :goto_af

    :cond_ad
    move v9, v5

    goto :goto_b0

    :cond_af
    :goto_af
    const/4 v9, 0x1

    .line 357
    .local v9, "hasWrapContent":Z
    :goto_b0
    move v10, v7

    move v7, v5

    .line 357
    .local v7, "groupIndex":I
    .local v10, "wrap_override":Z
    :goto_b2
    if-ge v7, v14, :cond_333

    iget-boolean v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSkipSolver:Z

    if-nez v5, :cond_333

    .line 358
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    iget-boolean v5, v5, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mSkipSolver:Z

    if-eqz v5, :cond_cb

    .line 359
    nop

    .line 357
    move/from16 v23, v3

    move/from16 v20, v14

    goto/16 :goto_328

    .line 361
    :cond_cb
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimizeFor(I)Z

    move-result v5

    if-eqz v5, :cond_100

    .line 362
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v5

    sget-object v8, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v8, :cond_f2

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v5

    sget-object v8, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v8, :cond_f2

    .line 363
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    invoke-virtual {v5}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->getWidgetsToSolve()Ljava/util/List;

    move-result-object v5

    check-cast v5, Ljava/util/ArrayList;

    iput-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    goto :goto_100

    .line 365
    :cond_f2
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    iget-object v5, v5, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mConstrainedGroup:Ljava/util/List;

    check-cast v5, Ljava/util/ArrayList;

    iput-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 368
    :cond_100
    :goto_100
    invoke-direct/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetChains()V

    .line 369
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v5

    .line 370
    .local v5, "count":I
    const/4 v8, 0x0

    .line 374
    .end local v13    # "countSolve":I
    .local v8, "countSolve":I
    const/4 v13, 0x0

    .line 374
    .local v13, "i":I
    :goto_10b
    if-ge v13, v5, :cond_12a

    .line 375
    move/from16 v19, v8

    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 375
    .end local v8    # "countSolve":I
    .local v19, "countSolve":I
    invoke-virtual {v8, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 376
    .local v8, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move/from16 v20, v14

    instance-of v14, v8, Landroid/support/constraint/solver/widgets/WidgetContainer;

    .line 376
    .end local v14    # "groupSize":I
    .local v20, "groupSize":I
    if-eqz v14, :cond_123

    .line 377
    move-object v14, v8

    check-cast v14, Landroid/support/constraint/solver/widgets/WidgetContainer;

    invoke-virtual {v14}, Landroid/support/constraint/solver/widgets/WidgetContainer;->layout()V

    .line 374
    .end local v8    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_123
    add-int/lit8 v13, v13, 0x1

    move/from16 v8, v19

    move/from16 v14, v20

    goto :goto_10b

    .line 382
    .end local v13    # "i":I
    .end local v19    # "countSolve":I
    .end local v20    # "groupSize":I
    .local v8, "countSolve":I
    .restart local v14    # "groupSize":I
    :cond_12a
    move/from16 v19, v8

    move/from16 v20, v14

    .line 382
    .end local v8    # "countSolve":I
    .end local v14    # "groupSize":I
    .restart local v19    # "countSolve":I
    .restart local v20    # "groupSize":I
    const/4 v8, 0x1

    .line 383
    .local v8, "needsSolving":Z
    :goto_12f
    if-eqz v8, :cond_313

    .line 384
    add-int/lit8 v13, v19, 0x1

    .line 386
    .end local v19    # "countSolve":I
    .local v13, "countSolve":I
    :try_start_133
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v14}, Landroid/support/constraint/solver/LinearSystem;->reset()V

    .line 387
    invoke-direct/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetChains()V

    .line 397
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v1, v14}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->createObjectVariables(Landroid/support/constraint/solver/LinearSystem;)V
    :try_end_140
    .catch Ljava/lang/Exception; {:try_start_133 .. :try_end_140} :catch_17f

    .line 398
    const/4 v14, 0x0

    .line 398
    .local v14, "i":I
    :goto_141
    if-ge v14, v5, :cond_160

    .line 399
    move/from16 v21, v8

    :try_start_145
    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 399
    .end local v8    # "needsSolving":Z
    .local v21, "needsSolving":Z
    invoke-virtual {v8, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :try_end_14d
    .catch Ljava/lang/Exception; {:try_start_145 .. :try_end_14d} :catch_15b

    .line 400
    .local v8, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move/from16 v22, v10

    :try_start_14f
    iget-object v10, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    .line 400
    .end local v10    # "wrap_override":Z
    .local v22, "wrap_override":Z
    invoke-virtual {v8, v10}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->createObjectVariables(Landroid/support/constraint/solver/LinearSystem;)V

    .line 398
    .end local v8    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v14, v14, 0x1

    move/from16 v8, v21

    move/from16 v10, v22

    goto :goto_141

    .line 407
    .end local v14    # "i":I
    .end local v22    # "wrap_override":Z
    .restart local v10    # "wrap_override":Z
    :catch_15b
    move-exception v0

    move/from16 v22, v10

    move-object v8, v0

    .line 407
    .end local v10    # "wrap_override":Z
    .restart local v22    # "wrap_override":Z
    goto :goto_185

    .line 403
    .end local v21    # "needsSolving":Z
    .end local v22    # "wrap_override":Z
    .local v8, "needsSolving":Z
    .restart local v10    # "wrap_override":Z
    :cond_160
    move/from16 v21, v8

    move/from16 v22, v10

    .line 403
    .end local v8    # "needsSolving":Z
    .end local v10    # "wrap_override":Z
    .restart local v21    # "needsSolving":Z
    .restart local v22    # "wrap_override":Z
    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addChildrenToSolver(Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v8
    :try_end_16a
    .catch Ljava/lang/Exception; {:try_start_14f .. :try_end_16a} :catch_17c

    .line 404
    .end local v21    # "needsSolving":Z
    .restart local v8    # "needsSolving":Z
    if-eqz v8, :cond_176

    .line 405
    :try_start_16c
    iget-object v10, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v10}, Landroid/support/constraint/solver/LinearSystem;->minimize()V
    :try_end_171
    .catch Ljava/lang/Exception; {:try_start_16c .. :try_end_171} :catch_172

    goto :goto_176

    .line 407
    :catch_172
    move-exception v0

    move/from16 v21, v8

    goto :goto_17d

    .line 410
    :cond_176
    :goto_176
    nop

    .line 411
    move/from16 v23, v3

    move/from16 v21, v8

    goto :goto_1a0

    .line 407
    .end local v8    # "needsSolving":Z
    .restart local v21    # "needsSolving":Z
    :catch_17c
    move-exception v0

    :goto_17d
    move-object v8, v0

    goto :goto_185

    .line 407
    .end local v21    # "needsSolving":Z
    .end local v22    # "wrap_override":Z
    .restart local v8    # "needsSolving":Z
    .restart local v10    # "wrap_override":Z
    :catch_17f
    move-exception v0

    move/from16 v21, v8

    move/from16 v22, v10

    move-object v8, v0

    .line 408
    .end local v10    # "wrap_override":Z
    .local v8, "e":Ljava/lang/Exception;
    .restart local v21    # "needsSolving":Z
    .restart local v22    # "wrap_override":Z
    :goto_185
    invoke-virtual {v8}, Ljava/lang/Exception;->printStackTrace()V

    .line 409
    sget-object v10, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v14, Ljava/lang/StringBuilder;

    invoke-direct {v14}, Ljava/lang/StringBuilder;-><init>()V

    move/from16 v23, v3

    const-string v3, "EXCEPTION : "

    .line 409
    .end local v3    # "prey":I
    .local v23, "prey":I
    invoke-virtual {v14, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v14, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v10, v3}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 411
    .end local v8    # "e":Ljava/lang/Exception;
    :goto_1a0
    if-eqz v21, :cond_1aa

    .line 412
    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    sget-object v10, Landroid/support/constraint/solver/widgets/Optimizer;->flags:[Z

    invoke-virtual {v1, v8, v10}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->updateChildrenFromSolver(Landroid/support/constraint/solver/LinearSystem;[Z)V

    goto :goto_1f4

    .line 414
    :cond_1aa
    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 415
    const/4 v8, 0x0

    .line 415
    .local v8, "i":I
    :goto_1b0
    if-ge v8, v5, :cond_1f4

    .line 416
    iget-object v10, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 417
    .local v10, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v14, v10, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v18, 0x0

    aget-object v14, v14, v18

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v14, v3, :cond_1d6

    .line 419
    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v3

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWrapWidth()I

    move-result v14

    if-ge v3, v14, :cond_1d6

    .line 420
    sget-object v3, Landroid/support/constraint/solver/widgets/Optimizer;->flags:[Z

    const/4 v14, 0x1

    const/16 v17, 0x2

    aput-boolean v14, v3, v17

    .line 421
    goto :goto_1f4

    .line 423
    :cond_1d6
    const/4 v14, 0x1

    iget-object v3, v10, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v3, v3, v14

    sget-object v14, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v3, v14, :cond_1f1

    .line 425
    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v3

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWrapHeight()I

    move-result v14

    if-ge v3, v14, :cond_1f1

    .line 426
    sget-object v3, Landroid/support/constraint/solver/widgets/Optimizer;->flags:[Z

    const/4 v14, 0x1

    const/16 v17, 0x2

    aput-boolean v14, v3, v17

    .line 427
    goto :goto_1f4

    .line 415
    .end local v10    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_1f1
    add-int/lit8 v8, v8, 0x1

    goto :goto_1b0

    .line 431
    .end local v8    # "i":I
    :cond_1f4
    :goto_1f4
    const/4 v3, 0x0

    .line 433
    .end local v21    # "needsSolving":Z
    .local v3, "needsSolving":Z
    if-eqz v9, :cond_279

    const/16 v8, 0x8

    if-ge v13, v8, :cond_279

    sget-object v10, Landroid/support/constraint/solver/widgets/Optimizer;->flags:[Z

    const/4 v14, 0x2

    aget-boolean v10, v10, v14

    if-eqz v10, :cond_279

    .line 436
    const/4 v10, 0x0

    .line 437
    .local v10, "maxX":I
    const/4 v14, 0x0

    .line 438
    .local v14, "maxY":I
    move v8, v14

    move v14, v10

    const/4 v10, 0x0

    .line 438
    .local v8, "maxY":I
    .local v10, "i":I
    .local v14, "maxX":I
    :goto_207
    if-ge v10, v5, :cond_234

    .line 439
    move/from16 v24, v3

    iget-object v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 439
    .end local v3    # "needsSolving":Z
    .local v24, "needsSolving":Z
    invoke-virtual {v3, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 440
    .local v3, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move/from16 v25, v5

    iget v5, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 440
    .end local v5    # "count":I
    .local v25, "count":I
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v16

    add-int v5, v5, v16

    invoke-static {v14, v5}, Ljava/lang/Math;->max(II)I

    move-result v14

    .line 441
    iget v5, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v16

    add-int v5, v5, v16

    invoke-static {v8, v5}, Ljava/lang/Math;->max(II)I

    move-result v8

    .line 438
    .end local v3    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v10, v10, 0x1

    move/from16 v3, v24

    move/from16 v5, v25

    goto :goto_207

    .line 443
    .end local v10    # "i":I
    .end local v24    # "needsSolving":Z
    .end local v25    # "count":I
    .local v3, "needsSolving":Z
    .restart local v5    # "count":I
    :cond_234
    move/from16 v24, v3

    move/from16 v25, v5

    .line 443
    .end local v3    # "needsSolving":Z
    .end local v5    # "count":I
    .restart local v24    # "needsSolving":Z
    .restart local v25    # "count":I
    iget v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mMinWidth:I

    invoke-static {v3, v14}, Ljava/lang/Math;->max(II)I

    move-result v3

    .line 444
    .end local v14    # "maxX":I
    .local v3, "maxX":I
    iget v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mMinHeight:I

    invoke-static {v5, v8}, Ljava/lang/Math;->max(II)I

    move-result v5

    .line 445
    .end local v8    # "maxY":I
    .local v5, "maxY":I
    sget-object v8, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v12, v8, :cond_25b

    .line 446
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v8

    if-ge v8, v3, :cond_25b

    .line 451
    invoke-virtual {v1, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setWidth(I)V

    .line 452
    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v10, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v14, 0x0

    aput-object v10, v8, v14

    .line 453
    const/4 v10, 0x1

    .line 454
    .end local v22    # "wrap_override":Z
    .local v10, "wrap_override":Z
    const/4 v8, 0x1

    .line 454
    .end local v24    # "needsSolving":Z
    .local v8, "needsSolving":Z
    goto :goto_25f

    .line 457
    .end local v8    # "needsSolving":Z
    .end local v10    # "wrap_override":Z
    .restart local v22    # "wrap_override":Z
    .restart local v24    # "needsSolving":Z
    :cond_25b
    move/from16 v10, v22

    move/from16 v8, v24

    .line 457
    .end local v22    # "wrap_override":Z
    .end local v24    # "needsSolving":Z
    .restart local v8    # "needsSolving":Z
    .restart local v10    # "wrap_override":Z
    :goto_25f
    sget-object v14, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v11, v14, :cond_277

    .line 458
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v14

    if-ge v14, v5, :cond_277

    .line 463
    invoke-virtual {v1, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setHeight(I)V

    .line 464
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v16, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v17, 0x1

    aput-object v16, v14, v17

    .line 465
    const/4 v10, 0x1

    .line 466
    const/4 v3, 0x1

    .line 466
    .end local v5    # "maxY":I
    .end local v8    # "needsSolving":Z
    .local v3, "needsSolving":Z
    goto :goto_281

    .line 471
    .end local v3    # "needsSolving":Z
    .restart local v8    # "needsSolving":Z
    :cond_277
    move v3, v8

    goto :goto_281

    .line 471
    .end local v8    # "needsSolving":Z
    .end local v10    # "wrap_override":Z
    .end local v25    # "count":I
    .restart local v3    # "needsSolving":Z
    .local v5, "count":I
    .restart local v22    # "wrap_override":Z
    :cond_279
    move/from16 v24, v3

    move/from16 v25, v5

    .line 471
    .end local v3    # "needsSolving":Z
    .end local v5    # "count":I
    .restart local v24    # "needsSolving":Z
    .restart local v25    # "count":I
    move/from16 v10, v22

    move/from16 v3, v24

    .line 471
    .end local v22    # "wrap_override":Z
    .end local v24    # "needsSolving":Z
    .restart local v3    # "needsSolving":Z
    .restart local v10    # "wrap_override":Z
    :goto_281
    iget v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mMinWidth:I

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v8

    invoke-static {v5, v8}, Ljava/lang/Math;->max(II)I

    move-result v5

    .line 472
    .local v5, "width":I
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v8

    if-le v5, v8, :cond_29e

    .line 477
    invoke-virtual {v1, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setWidth(I)V

    .line 478
    iget-object v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v14, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v16, 0x0

    aput-object v14, v8, v16

    .line 479
    const/4 v10, 0x1

    .line 480
    const/4 v3, 0x1

    .line 482
    :cond_29e
    iget v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mMinHeight:I

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v14

    invoke-static {v8, v14}, Ljava/lang/Math;->max(II)I

    move-result v8

    .line 483
    .local v8, "height":I
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v14

    if-le v8, v14, :cond_2bb

    .line 488
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setHeight(I)V

    .line 489
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v16, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v17, 0x1

    aput-object v16, v14, v17

    .line 490
    const/4 v10, 0x1

    .line 491
    const/4 v3, 0x1

    .line 494
    :cond_2bb
    if-nez v10, :cond_307

    .line 495
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v16, 0x0

    aget-object v14, v14, v16

    move/from16 v26, v3

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 495
    .end local v3    # "needsSolving":Z
    .local v26, "needsSolving":Z
    if-ne v14, v3, :cond_2e3

    if-lez v4, :cond_2e3

    .line 497
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v3

    if-le v3, v4, :cond_2e3

    .line 503
    const/4 v3, 0x1

    iput-boolean v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidthMeasuredTooSmall:Z

    .line 504
    const/4 v10, 0x1

    .line 505
    iget-object v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v14, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v16, 0x0

    aput-object v14, v3, v16

    .line 506
    invoke-virtual {v1, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setWidth(I)V

    .line 507
    const/4 v3, 0x1

    .line 510
    .end local v26    # "needsSolving":Z
    .restart local v3    # "needsSolving":Z
    move/from16 v26, v3

    .line 510
    .end local v3    # "needsSolving":Z
    .restart local v26    # "needsSolving":Z
    :cond_2e3
    iget-object v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v14, 0x1

    aget-object v3, v3, v14

    sget-object v14, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v3, v14, :cond_304

    if-lez v6, :cond_304

    .line 512
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v3

    if-le v3, v6, :cond_304

    .line 518
    const/4 v3, 0x1

    iput-boolean v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mHeightMeasuredTooSmall:Z

    .line 519
    const/4 v10, 0x1

    .line 520
    iget-object v14, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v16, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v16, v14, v3

    .line 521
    invoke-virtual {v1, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setHeight(I)V

    .line 522
    const/4 v3, 0x1

    .line 526
    .end local v5    # "width":I
    .end local v8    # "height":I
    .end local v26    # "needsSolving":Z
    .restart local v3    # "needsSolving":Z
    move v8, v3

    goto :goto_30b

    .line 526
    .end local v3    # "needsSolving":Z
    .restart local v26    # "needsSolving":Z
    :cond_304
    move/from16 v8, v26

    goto :goto_30b

    .line 526
    .end local v26    # "needsSolving":Z
    .restart local v3    # "needsSolving":Z
    :cond_307
    move/from16 v26, v3

    move/from16 v8, v26

    .line 382
    .end local v3    # "needsSolving":Z
    .local v8, "needsSolving":Z
    :goto_30b
    move/from16 v19, v13

    move/from16 v3, v23

    move/from16 v5, v25

    goto/16 :goto_12f

    .line 534
    .end local v13    # "countSolve":I
    .end local v23    # "prey":I
    .end local v25    # "count":I
    .local v3, "prey":I
    .local v5, "count":I
    .restart local v19    # "countSolve":I
    :cond_313
    move/from16 v23, v3

    move/from16 v25, v5

    move/from16 v21, v8

    move/from16 v22, v10

    .line 534
    .end local v3    # "prey":I
    .end local v5    # "count":I
    .end local v8    # "needsSolving":Z
    .end local v10    # "wrap_override":Z
    .restart local v21    # "needsSolving":Z
    .restart local v22    # "wrap_override":Z
    .restart local v23    # "prey":I
    .restart local v25    # "count":I
    iget-object v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->updateUnresolvedWidgets()V

    .line 357
    .end local v21    # "needsSolving":Z
    .end local v25    # "count":I
    move/from16 v13, v19

    .line 357
    .end local v19    # "countSolve":I
    .end local v22    # "wrap_override":Z
    .restart local v10    # "wrap_override":Z
    .restart local v13    # "countSolve":I
    :goto_328
    add-int/lit8 v7, v7, 0x1

    move/from16 v14, v20

    move/from16 v3, v23

    const/4 v5, 0x0

    const/16 v8, 0x20

    goto/16 :goto_b2

    .line 536
    .end local v7    # "groupIndex":I
    .end local v20    # "groupSize":I
    .end local v23    # "prey":I
    .restart local v3    # "prey":I
    .local v14, "groupSize":I
    :cond_333
    move/from16 v23, v3

    move/from16 v20, v14

    .line 536
    .end local v3    # "prey":I
    .end local v14    # "groupSize":I
    .restart local v20    # "groupSize":I
    .restart local v23    # "prey":I
    move-object v3, v15

    check-cast v3, Ljava/util/ArrayList;

    iput-object v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 538
    iget-object v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v3, :cond_36f

    .line 539
    iget v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mMinWidth:I

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v5

    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    move-result v3

    .line 540
    .local v3, "width":I
    iget v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mMinHeight:I

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v7

    invoke-static {v5, v7}, Ljava/lang/Math;->max(II)I

    move-result v5

    .line 542
    .local v5, "height":I
    iget-object v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSnapshot:Landroid/support/constraint/solver/widgets/Snapshot;

    invoke-virtual {v7, v1}, Landroid/support/constraint/solver/widgets/Snapshot;->applyTo(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 543
    iget v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingLeft:I

    add-int/2addr v7, v3

    iget v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingRight:I

    add-int/2addr v7, v8

    invoke-virtual {v1, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setWidth(I)V

    .line 544
    iget v7, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingTop:I

    add-int/2addr v7, v5

    iget v8, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingBottom:I

    add-int/2addr v7, v8

    invoke-virtual {v1, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setHeight(I)V

    .line 545
    .end local v3    # "width":I
    .end local v5    # "height":I
    nop

    .line 549
    move/from16 v3, v23

    goto :goto_375

    .line 546
    :cond_36f
    iput v2, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mX:I

    .line 547
    move/from16 v3, v23

    iput v3, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mY:I

    .line 549
    .end local v23    # "prey":I
    .local v3, "prey":I
    :goto_375
    if-eqz v10, :cond_381

    .line 550
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v7, 0x0

    aput-object v12, v5, v7

    .line 551
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v7, 0x1

    aput-object v11, v5, v7

    .line 566
    :cond_381
    iget-object v5, v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v5}, Landroid/support/constraint/solver/LinearSystem;->getCache()Landroid/support/constraint/solver/Cache;

    move-result-object v5

    invoke-virtual {v1, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetSolverVariables(Landroid/support/constraint/solver/Cache;)V

    .line 567
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getRootConstraintContainer()Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    move-result-object v5

    if-ne v1, v5, :cond_393

    .line 568
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->updateDrawPosition()V

    .line 570
    :cond_393
    return-void
.end method

.method public optimize()V
    .registers 2

    .line 630
    const/16 v0, 0x8

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimizeFor(I)Z

    move-result v0

    if-nez v0, :cond_d

    .line 631
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->analyze(I)V

    .line 643
    :cond_d
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->solveGraph()V

    .line 653
    return-void
.end method

.method public optimizeFor(I)Z
    .registers 3
    .param p1, "feature"    # I

    .line 131
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    and-int/2addr v0, p1

    if-ne v0, p1, :cond_7

    const/4 v0, 0x1

    goto :goto_8

    :cond_7
    const/4 v0, 0x0

    :goto_8
    return v0
.end method

.method public optimizeForDimensions(II)V
    .registers 5
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 604
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v0, v1, :cond_12

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    if-eqz v0, :cond_12

    .line 605
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->resolve(I)V

    .line 607
    :cond_12
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v0, v1, :cond_24

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    if-eqz v0, :cond_24

    .line 608
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    invoke-virtual {v0, p2}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->resolve(I)V

    .line 610
    :cond_24
    return-void
.end method

.method public optimizeReset()V
    .registers 4

    .line 613
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 614
    .local v0, "count":I
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->resetResolutionNodes()V

    .line 615
    const/4 v1, 0x0

    .line 615
    .local v1, "i":I
    :goto_a
    if-ge v1, v0, :cond_1a

    .line 616
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->resetResolutionNodes()V

    .line 615
    add-int/lit8 v1, v1, 0x1

    goto :goto_a

    .line 618
    .end local v1    # "i":I
    :cond_1a
    return-void
.end method

.method public preOptimize()V
    .registers 2

    .line 573
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->optimizeReset()V

    .line 574
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->analyze(I)V

    .line 575
    return-void
.end method

.method public reset()V
    .registers 3

    .line 146
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    invoke-virtual {v0}, Landroid/support/constraint/solver/LinearSystem;->reset()V

    .line 147
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingLeft:I

    .line 148
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingRight:I

    .line 149
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingTop:I

    .line 150
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingBottom:I

    .line 151
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mWidgetGroups:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->clear()V

    .line 152
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mSkipSolver:Z

    .line 153
    invoke-super {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->reset()V

    .line 154
    return-void
.end method

.method public resetGraph()V
    .registers 5

    .line 590
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    .line 591
    .local v0, "leftNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    .line 597
    .local v1, "topNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->invalidateAnchors()V

    .line 598
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->invalidateAnchors()V

    .line 599
    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-virtual {v0, v3, v2}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 600
    invoke-virtual {v1, v3, v2}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 601
    return-void
.end method

.method public setOptimizationLevel(I)V
    .registers 2
    .param p1, "value"    # I

    .line 113
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mOptimizationLevel:I

    .line 114
    return-void
.end method

.method public setPadding(IIII)V
    .registers 5
    .param p1, "left"    # I
    .param p2, "top"    # I
    .param p3, "right"    # I
    .param p4, "bottom"    # I

    .line 248
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingLeft:I

    .line 249
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingTop:I

    .line 250
    iput p3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingRight:I

    .line 251
    iput p4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mPaddingBottom:I

    .line 252
    return-void
.end method

.method public setRtl(Z)V
    .registers 2
    .param p1, "isRtl"    # Z

    .line 259
    iput-boolean p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mIsRtl:Z

    .line 260
    return-void
.end method

.method public solveGraph()V
    .registers 5

    .line 578
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    .line 579
    .local v0, "leftNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    .line 585
    .local v1, "topNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-virtual {v0, v3, v2}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 586
    invoke-virtual {v1, v3, v2}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 587
    return-void
.end method

.method public updateChildrenFromSolver(Landroid/support/constraint/solver/LinearSystem;[Z)V
    .registers 11
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "flags"    # [Z

    .line 222
    const/4 v0, 0x0

    const/4 v1, 0x2

    aput-boolean v0, p2, v1

    .line 223
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 224
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 225
    .local v2, "count":I
    move v3, v0

    .line 225
    .local v3, "i":I
    :goto_e
    if-ge v3, v2, :cond_47

    .line 226
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 227
    .local v4, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v4, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 228
    iget-object v5, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v5, v5, v0

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v7, 0x1

    if-ne v5, v6, :cond_30

    .line 229
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v5

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWrapWidth()I

    move-result v6

    if-ge v5, v6, :cond_30

    .line 230
    aput-boolean v7, p2, v1

    .line 232
    :cond_30
    iget-object v5, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v5, v5, v7

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v6, :cond_44

    .line 233
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v5

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWrapHeight()I

    move-result v6

    if-ge v5, v6, :cond_44

    .line 234
    aput-boolean v7, p2, v1

    .line 225
    .end local v4    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_44
    add-int/lit8 v3, v3, 0x1

    goto :goto_e

    .line 237
    .end local v3    # "i":I
    :cond_47
    return-void
.end method
