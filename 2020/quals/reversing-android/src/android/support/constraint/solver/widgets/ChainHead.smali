.class public Landroid/support/constraint/solver/widgets/ChainHead;
.super Ljava/lang/Object;
.source "ChainHead.java"


# instance fields
.field private mDefined:Z

.field protected mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mFirstMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mFirstVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mHasComplexMatchWeights:Z

.field protected mHasDefinedWeights:Z

.field protected mHasUndefinedWeights:Z

.field protected mHead:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field private mIsRtl:Z

.field protected mLast:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mLastMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mLastVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field private mOrientation:I

.field protected mTotalWeight:F

.field protected mWeightedMatchConstraintsWidgets:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field protected mWidgetsCount:I

.field protected mWidgetsMatchCount:I


# direct methods
.method public constructor <init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;IZ)V
    .registers 5
    .param p1, "first"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "orientation"    # I
    .param p3, "isRtl"    # Z

    .line 58
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 42
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mTotalWeight:F

    .line 44
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mIsRtl:Z

    .line 59
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 60
    iput p2, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    .line 61
    iput-boolean p3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mIsRtl:Z

    .line 62
    return-void
.end method

.method private defineChainProperties()V
    .registers 14

    .line 79
    iget v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    const/4 v1, 0x2

    mul-int/2addr v0, v1

    .line 80
    .local v0, "offset":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 83
    .local v2, "lastVisited":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 84
    .local v3, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 85
    .local v4, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v5, 0x0

    move-object v6, v4

    move-object v4, v2

    move v2, v5

    .line 86
    .local v2, "done":Z
    .local v4, "lastVisited":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v6, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_e
    const/4 v7, 0x1

    if-nez v2, :cond_d7

    .line 87
    iget v8, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWidgetsCount:I

    add-int/2addr v8, v7

    iput v8, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWidgetsCount:I

    .line 88
    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    const/4 v10, 0x0

    aput-object v10, v8, v9

    .line 89
    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListNextMatchConstraintsWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aput-object v10, v8, v9

    .line 90
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v8

    const/16 v9, 0x8

    if-eq v8, v9, :cond_a6

    .line 92
    iget-object v8, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-nez v8, :cond_31

    .line 93
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 95
    :cond_31
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLastVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 98
    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aget-object v8, v8, v9

    sget-object v9, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v8, v9, :cond_a6

    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aget v8, v8, v9

    if-eqz v8, :cond_56

    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aget v8, v8, v9

    const/4 v9, 0x3

    if-eq v8, v9, :cond_56

    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aget v8, v8, v9

    if-ne v8, v1, :cond_a6

    .line 102
    :cond_56
    iget v8, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWidgetsMatchCount:I

    add-int/2addr v8, v7

    iput v8, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWidgetsMatchCount:I

    .line 103
    iget-object v8, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aget v8, v8, v9

    .line 104
    .local v8, "weight":F
    const/4 v9, 0x0

    cmpl-float v10, v8, v9

    if-lez v10, :cond_71

    .line 105
    iget v10, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mTotalWeight:F

    iget-object v11, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    iget v12, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aget v11, v11, v12

    add-float/2addr v10, v11

    iput v10, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mTotalWeight:F

    .line 108
    :cond_71
    iget v10, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    invoke-static {v3, v10}, Landroid/support/constraint/solver/widgets/ChainHead;->isMatchConstraintEqualityCandidate(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)Z

    move-result v10

    if-eqz v10, :cond_92

    .line 109
    cmpg-float v9, v8, v9

    if-gez v9, :cond_80

    .line 110
    iput-boolean v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHasUndefinedWeights:Z

    goto :goto_82

    .line 112
    :cond_80
    iput-boolean v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHasDefinedWeights:Z

    .line 114
    :goto_82
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWeightedMatchConstraintsWidgets:Ljava/util/ArrayList;

    if-nez v7, :cond_8d

    .line 115
    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    iput-object v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWeightedMatchConstraintsWidgets:Ljava/util/ArrayList;

    .line 117
    :cond_8d
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mWeightedMatchConstraintsWidgets:Ljava/util/ArrayList;

    invoke-virtual {v7, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    :cond_92
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-nez v7, :cond_98

    .line 121
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 123
    :cond_98
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLastMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v7, :cond_a4

    .line 124
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLastMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListNextMatchConstraintsWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v9, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aput-object v3, v7, v9

    .line 126
    :cond_a4
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLastMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 129
    .end local v8    # "weight":F
    :cond_a6
    if-eq v4, v3, :cond_ae

    .line 130
    iget-object v7, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v8, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    aput-object v3, v7, v8

    .line 132
    :cond_ae
    move-object v4, v3

    .line 135
    iget-object v7, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v8, v0, 0x1

    aget-object v7, v7, v8

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 136
    .local v7, "nextAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    if-eqz v7, :cond_cf

    .line 137
    iget-object v6, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 138
    iget-object v8, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v8, v8, v0

    iget-object v8, v8, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v8, :cond_cd

    iget-object v8, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v8, v8, v0

    iget-object v8, v8, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v8, v8, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eq v8, v3, :cond_d0

    .line 140
    :cond_cd
    const/4 v6, 0x0

    goto :goto_d0

    .line 143
    :cond_cf
    const/4 v6, 0x0

    .line 145
    :cond_d0
    :goto_d0
    if-eqz v6, :cond_d4

    .line 146
    move-object v3, v6

    goto :goto_d5

    .line 148
    :cond_d4
    const/4 v2, 0x1

    .line 150
    .end local v7    # "nextAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :goto_d5
    goto/16 :goto_e

    .line 151
    :cond_d7
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLast:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 153
    iget v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mOrientation:I

    if-nez v1, :cond_e6

    iget-boolean v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mIsRtl:Z

    if-eqz v1, :cond_e6

    .line 154
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLast:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHead:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    goto :goto_ea

    .line 156
    :cond_e6
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHead:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 159
    :goto_ea
    iget-boolean v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHasDefinedWeights:Z

    if-eqz v1, :cond_f4

    iget-boolean v1, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHasUndefinedWeights:Z

    if-eqz v1, :cond_f4

    move v5, v7

    nop

    :cond_f4
    iput-boolean v5, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHasComplexMatchWeights:Z

    .line 160
    return-void
.end method

.method private static isMatchConstraintEqualityCandidate(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)Z
    .registers 4
    .param p0, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p1, "orientation"    # I

    .line 72
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v0

    const/16 v1, 0x8

    if-eq v0, v1, :cond_1f

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v0, v0, p1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v1, :cond_1f

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    aget v0, v0, p1

    if-eqz v0, :cond_1d

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    aget v0, v0, p1

    const/4 v1, 0x3

    if-ne v0, v1, :cond_1f

    :cond_1d
    const/4 v0, 0x1

    goto :goto_20

    :cond_1f
    const/4 v0, 0x0

    :goto_20
    return v0
.end method


# virtual methods
.method public define()V
    .registers 2

    .line 195
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mDefined:Z

    if-nez v0, :cond_7

    .line 196
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ChainHead;->defineChainProperties()V

    .line 198
    :cond_7
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mDefined:Z

    .line 199
    return-void
.end method

.method public getFirst()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 163
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getFirstMatchConstraintWidget()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 183
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getFirstVisibleWidget()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 167
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getHead()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 179
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mHead:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getLast()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 171
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLast:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getLastMatchConstraintWidget()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 187
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLastMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getLastVisibleWidget()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 175
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mLastVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getTotalWeight()F
    .registers 2

    .line 191
    iget v0, p0, Landroid/support/constraint/solver/widgets/ChainHead;->mTotalWeight:F

    return v0
.end method
