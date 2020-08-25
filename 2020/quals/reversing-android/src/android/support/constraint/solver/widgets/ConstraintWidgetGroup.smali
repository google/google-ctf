.class public Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;
.super Ljava/lang/Object;
.source "ConstraintWidgetGroup.java"


# instance fields
.field public mConstrainedGroup:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field public final mGroupDimensions:[I

.field mGroupHeight:I

.field mGroupWidth:I

.field public mSkipSolver:Z

.field mStartHorizontalWidgets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field mStartVerticalWidgets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field mUnresolvedWidgets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field mWidgetsToSetHorizontal:Ljava/util/HashSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashSet<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field mWidgetsToSetVertical:Ljava/util/HashSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashSet<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field

.field mWidgetsToSolve:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method constructor <init>(Ljava/util/List;)V
    .registers 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;)V"
        }
    .end annotation

    .line 55
    .local p1, "widgets":Ljava/util/List;, "Ljava/util/List<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupWidth:I

    .line 39
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupHeight:I

    .line 40
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mSkipSolver:Z

    .line 41
    const/4 v1, 0x2

    new-array v1, v1, [I

    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupWidth:I

    aput v2, v1, v0

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupHeight:I

    const/4 v2, 0x1

    aput v0, v1, v2

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupDimensions:[I

    .line 48
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mStartHorizontalWidgets:Ljava/util/List;

    .line 49
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mStartVerticalWidgets:Ljava/util/List;

    .line 50
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetHorizontal:Ljava/util/HashSet;

    .line 51
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetVertical:Ljava/util/HashSet;

    .line 52
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    .line 53
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    .line 56
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mConstrainedGroup:Ljava/util/List;

    .line 57
    return-void
.end method

.method constructor <init>(Ljava/util/List;Z)V
    .registers 6
    .param p2, "skipSolver"    # Z
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;Z)V"
        }
    .end annotation

    .line 59
    .local p1, "widgets":Ljava/util/List;, "Ljava/util/List<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupWidth:I

    .line 39
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupHeight:I

    .line 40
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mSkipSolver:Z

    .line 41
    const/4 v1, 0x2

    new-array v1, v1, [I

    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupWidth:I

    aput v2, v1, v0

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupHeight:I

    const/4 v2, 0x1

    aput v0, v1, v2

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mGroupDimensions:[I

    .line 48
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mStartHorizontalWidgets:Ljava/util/List;

    .line 49
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mStartVerticalWidgets:Ljava/util/List;

    .line 50
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetHorizontal:Ljava/util/HashSet;

    .line 51
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetVertical:Ljava/util/HashSet;

    .line 52
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    .line 53
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    .line 60
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mConstrainedGroup:Ljava/util/List;

    .line 61
    iput-boolean p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mSkipSolver:Z

    .line 62
    return-void
.end method

.method private getWidgetsToSolveTraversal(Ljava/util/ArrayList;Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 8
    .param p2, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ")V"
        }
    .end annotation

    .line 122
    .local p1, "widgetsToSolve":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    iget-boolean v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mGroupsToSolver:Z

    if-eqz v0, :cond_5

    .line 123
    return-void

    .line 125
    :cond_5
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 126
    const/4 v0, 0x1

    iput-boolean v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mGroupsToSolver:Z

    .line 127
    invoke-virtual {p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isFullyResolved()Z

    move-result v0

    if-eqz v0, :cond_12

    .line 128
    return-void

    .line 130
    :cond_12
    instance-of v0, p2, Landroid/support/constraint/solver/widgets/Helper;

    const/4 v1, 0x0

    if-eqz v0, :cond_29

    .line 131
    move-object v0, p2

    check-cast v0, Landroid/support/constraint/solver/widgets/Helper;

    .line 132
    .local v0, "helper":Landroid/support/constraint/solver/widgets/Helper;
    iget v2, v0, Landroid/support/constraint/solver/widgets/Helper;->mWidgetsCount:I

    .line 133
    .local v2, "widgetCount":I
    move v3, v1

    .line 133
    .local v3, "i":I
    :goto_1d
    if-ge v3, v2, :cond_29

    .line 134
    iget-object v4, v0, Landroid/support/constraint/solver/widgets/Helper;->mWidgets:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aget-object v4, v4, v3

    invoke-direct {p0, p1, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->getWidgetsToSolveTraversal(Ljava/util/ArrayList;Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 133
    add-int/lit8 v3, v3, 0x1

    goto :goto_1d

    .line 138
    .end local v0    # "helper":Landroid/support/constraint/solver/widgets/Helper;
    .end local v2    # "widgetCount":I
    .end local v3    # "i":I
    :cond_29
    iget-object v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    array-length v0, v0

    .line 139
    .local v0, "count":I
    nop

    .line 139
    .local v1, "i":I
    :goto_2d
    if-ge v1, v0, :cond_48

    .line 140
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v1

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 141
    .local v2, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v3, 0x0

    .line 142
    .local v3, "targetWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-eqz v2, :cond_45

    .line 143
    iget-object v3, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 148
    if-eqz v2, :cond_45

    invoke-virtual {p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    if-eq v3, v4, :cond_45

    .line 149
    invoke-direct {p0, p1, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->getWidgetsToSolveTraversal(Ljava/util/ArrayList;Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 139
    .end local v2    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "targetWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_45
    add-int/lit8 v1, v1, 0x1

    goto :goto_2d

    .line 152
    .end local v1    # "i":I
    :cond_48
    return-void
.end method

.method private updateResolvedDimension(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 10
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 173
    const/4 v0, 0x0

    .line 173
    .local v0, "start":I
    const/4 v1, 0x0

    .line 174
    .local v1, "end":I
    iget-boolean v2, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasurable:Z

    if-eqz v2, :cond_f4

    .line 176
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isFullyResolved()Z

    move-result v2

    if-eqz v2, :cond_d

    .line 177
    return-void

    .line 180
    :cond_d
    iget-object v2, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v2, :cond_17

    move v2, v4

    goto :goto_18

    :cond_17
    move v2, v3

    .line 183
    .local v2, "rightSide":Z
    :goto_18
    if-eqz v2, :cond_1f

    .line 184
    iget-object v5, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v5, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 184
    .local v5, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_23

    .line 186
    .end local v5    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_1f
    iget-object v5, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v5, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 188
    .restart local v5    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :goto_23
    if-eqz v5, :cond_4d

    .line 189
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-boolean v6, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    if-nez v6, :cond_30

    .line 190
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->updateResolvedDimension(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 192
    :cond_30
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v6, v7, :cond_43

    .line 193
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v6, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    iget-object v7, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    add-int v1, v6, v7

    goto :goto_4d

    .line 194
    :cond_43
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v6, v7, :cond_4d

    .line 195
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v1, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 198
    :cond_4d
    :goto_4d
    if-eqz v2, :cond_57

    .line 199
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    sub-int/2addr v1, v6

    goto :goto_63

    .line 201
    :cond_57
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    add-int/2addr v6, v7

    add-int/2addr v1, v6

    .line 203
    :goto_63
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v6

    sub-int v0, v1, v6

    .line 204
    invoke-virtual {p1, v0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimension(II)V

    .line 206
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_96

    .line 207
    iget-object v3, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v3, v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 208
    .end local v5    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .local v3, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    iget-object v5, v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-boolean v5, v5, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    if-nez v5, :cond_81

    .line 209
    iget-object v5, v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {p0, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->updateResolvedDimension(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 211
    :cond_81
    iget-object v5, v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v5, v5, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    iget-object v6, v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v6, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    add-int/2addr v5, v6

    iget v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    sub-int/2addr v5, v6

    .line 213
    .end local v0    # "start":I
    .local v5, "start":I
    iget v0, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    add-int/2addr v0, v5

    .line 214
    .end local v1    # "end":I
    .local v0, "end":I
    invoke-virtual {p1, v5, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimension(II)V

    .line 215
    iput-boolean v4, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 216
    return-void

    .line 218
    .end local v3    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .local v0, "start":I
    .restart local v1    # "end":I
    .local v5, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_96
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_9e

    move v3, v4

    nop

    .line 220
    .local v3, "bottomSide":Z
    :cond_9e
    if-eqz v3, :cond_a5

    .line 221
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v5, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    goto :goto_a9

    .line 223
    :cond_a5
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v5, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 225
    :goto_a9
    if-eqz v5, :cond_d3

    .line 226
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-boolean v6, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    if-nez v6, :cond_b6

    .line 227
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->updateResolvedDimension(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 229
    :cond_b6
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v6, v7, :cond_c9

    .line 230
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v6, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    iget-object v7, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v7

    add-int v1, v6, v7

    goto :goto_d3

    .line 231
    :cond_c9
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v6, v7, :cond_d3

    .line 232
    iget-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget v1, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 235
    :cond_d3
    :goto_d3
    if-eqz v3, :cond_dd

    .line 236
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    sub-int/2addr v1, v6

    goto :goto_e9

    .line 238
    :cond_dd
    iget-object v6, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v7

    add-int/2addr v6, v7

    add-int/2addr v1, v6

    .line 240
    :goto_e9
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    sub-int v0, v1, v6

    .line 241
    invoke-virtual {p1, v0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimension(II)V

    .line 242
    iput-boolean v4, p1, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 244
    .end local v2    # "rightSide":Z
    .end local v3    # "bottomSide":Z
    .end local v5    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_f4
    return-void
.end method


# virtual methods
.method addWidgetsToSet(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)V
    .registers 4
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "orientation"    # I

    .line 83
    if-nez p2, :cond_8

    .line 84
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetHorizontal:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_10

    .line 85
    :cond_8
    const/4 v0, 0x1

    if-ne p2, v0, :cond_10

    .line 86
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetVertical:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 88
    :cond_10
    :goto_10
    return-void
.end method

.method public getStartWidgets(I)Ljava/util/List;
    .registers 3
    .param p1, "orientation"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)",
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation

    .line 65
    if-nez p1, :cond_5

    .line 66
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mStartHorizontalWidgets:Ljava/util/List;

    return-object v0

    .line 67
    :cond_5
    const/4 v0, 0x1

    if-ne p1, v0, :cond_b

    .line 68
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mStartVerticalWidgets:Ljava/util/List;

    return-object v0

    .line 70
    :cond_b
    const/4 v0, 0x0

    return-object v0
.end method

.method getWidgetsToSet(I)Ljava/util/Set;
    .registers 3
    .param p1, "orientation"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)",
            "Ljava/util/Set<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation

    .line 74
    if-nez p1, :cond_5

    .line 75
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetHorizontal:Ljava/util/HashSet;

    return-object v0

    .line 76
    :cond_5
    const/4 v0, 0x1

    if-ne p1, v0, :cond_b

    .line 77
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSetVertical:Ljava/util/HashSet;

    return-object v0

    .line 79
    :cond_b
    const/4 v0, 0x0

    return-object v0
.end method

.method getWidgetsToSolve()Ljava/util/List;
    .registers 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation

    .line 99
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_b

    .line 100
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    return-object v0

    .line 102
    :cond_b
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mConstrainedGroup:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    .line 103
    .local v0, "size":I
    const/4 v1, 0x0

    .line 103
    .local v1, "i":I
    :goto_12
    if-ge v1, v0, :cond_2a

    .line 104
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mConstrainedGroup:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 105
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-boolean v3, v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasurable:Z

    if-nez v3, :cond_27

    .line 106
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    check-cast v3, Ljava/util/ArrayList;

    invoke-direct {p0, v3, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->getWidgetsToSolveTraversal(Ljava/util/ArrayList;Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 103
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_27
    add-int/lit8 v1, v1, 0x1

    goto :goto_12

    .line 109
    .end local v1    # "i":I
    :cond_2a
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->clear()V

    .line 110
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mConstrainedGroup:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 111
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->removeAll(Ljava/util/Collection;)Z

    .line 112
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mWidgetsToSolve:Ljava/util/List;

    return-object v1
.end method

.method updateUnresolvedWidgets()V
    .registers 4

    .line 158
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    .line 159
    .local v0, "size":I
    const/4 v1, 0x0

    .line 159
    .local v1, "i":I
    :goto_7
    if-ge v1, v0, :cond_17

    .line 160
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->mUnresolvedWidgets:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 163
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-direct {p0, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;->updateResolvedDimension(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 159
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v1, v1, 0x1

    goto :goto_7

    .line 165
    .end local v1    # "i":I
    :cond_17
    return-void
.end method
