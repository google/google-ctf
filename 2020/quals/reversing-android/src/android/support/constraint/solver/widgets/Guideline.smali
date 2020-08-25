.class public Landroid/support/constraint/solver/widgets/Guideline;
.super Landroid/support/constraint/solver/widgets/ConstraintWidget;
.source "Guideline.java"


# static fields
.field public static final HORIZONTAL:I = 0x0

.field public static final RELATIVE_BEGIN:I = 0x1

.field public static final RELATIVE_END:I = 0x2

.field public static final RELATIVE_PERCENT:I = 0x0

.field public static final RELATIVE_UNKNWON:I = -0x1

.field public static final VERTICAL:I = 0x1


# instance fields
.field private mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field private mHead:Landroid/support/constraint/solver/widgets/Rectangle;

.field private mHeadSize:I

.field private mIsPositionRelaxed:Z

.field private mMinimumPosition:I

.field private mOrientation:I

.field protected mRelativeBegin:I

.field protected mRelativeEnd:I

.field protected mRelativePercent:F


# direct methods
.method public constructor <init>()V
    .registers 5

    .line 50
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    .line 38
    const/high16 v0, -0x40800000    # -1.0f

    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    .line 39
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    .line 40
    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    .line 42
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 43
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    .line 44
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mIsPositionRelaxed:Z

    .line 45
    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mMinimumPosition:I

    .line 47
    new-instance v1, Landroid/support/constraint/solver/widgets/Rectangle;

    invoke-direct {v1}, Landroid/support/constraint/solver/widgets/Rectangle;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHead:Landroid/support/constraint/solver/widgets/Rectangle;

    .line 48
    const/16 v1, 0x8

    iput v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    .line 51
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchors:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 52
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchors:Ljava/util/ArrayList;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 53
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    array-length v1, v1

    .line 54
    .local v1, "count":I
    nop

    .line 54
    .local v0, "i":I
    :goto_32
    if-ge v0, v1, :cond_3d

    .line 55
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aput-object v3, v2, v0

    .line 54
    add-int/lit8 v0, v0, 0x1

    goto :goto_32

    .line 57
    .end local v0    # "i":I
    :cond_3d
    return-void
.end method


# virtual methods
.method public addToSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 15
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 250
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    .line 251
    .local v0, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    if-nez v0, :cond_9

    .line 252
    return-void

    .line 254
    :cond_9
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 255
    .local v1, "begin":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 256
    .local v2, "end":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v3, :cond_27

    iget-object v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v3, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v3, v3, v5

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v3, v6, :cond_27

    move v3, v4

    goto :goto_28

    :cond_27
    move v3, v5

    .line 257
    .local v3, "parentWrapContent":Z
    :goto_28
    iget v6, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    if-nez v6, :cond_49

    .line 258
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 259
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 260
    iget-object v6, p0, Landroid/support/constraint/solver/widgets/Guideline;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v6, :cond_47

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/Guideline;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v6, v6, v4

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v6, v7, :cond_47

    goto :goto_48

    :cond_47
    move v4, v5

    :goto_48
    move v3, v4

    .line 262
    :cond_49
    iget v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    const/4 v6, 0x6

    const/4 v7, -0x1

    const/4 v8, 0x5

    if-eq v4, v7, :cond_69

    .line 263
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 264
    .local v4, "guide":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v7

    .line 265
    .local v7, "parentLeft":Landroid/support/constraint/solver/SolverVariable;
    iget v9, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    invoke-virtual {p1, v4, v7, v9, v6}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 266
    if-eqz v3, :cond_68

    .line 267
    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v6

    invoke-virtual {p1, v6, v4, v5, v8}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 269
    .end local v4    # "guide":Landroid/support/constraint/solver/SolverVariable;
    .end local v7    # "parentLeft":Landroid/support/constraint/solver/SolverVariable;
    :cond_68
    goto :goto_af

    :cond_69
    iget v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v4, v7, :cond_8a

    .line 270
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 271
    .restart local v4    # "guide":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v7

    .line 272
    .local v7, "parentRight":Landroid/support/constraint/solver/SolverVariable;
    iget v9, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    neg-int v9, v9

    invoke-virtual {p1, v4, v7, v9, v6}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 273
    if-eqz v3, :cond_89

    .line 274
    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v6

    invoke-virtual {p1, v4, v6, v5, v8}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 275
    invoke-virtual {p1, v7, v4, v5, v8}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 277
    .end local v4    # "guide":Landroid/support/constraint/solver/SolverVariable;
    .end local v7    # "parentRight":Landroid/support/constraint/solver/SolverVariable;
    :cond_89
    goto :goto_af

    :cond_8a
    iget v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    const/high16 v5, -0x40800000    # -1.0f

    cmpl-float v4, v4, v5

    if-eqz v4, :cond_af

    .line 278
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 279
    .restart local v4    # "guide":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v11

    .line 280
    .local v11, "parentLeft":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v12

    .line 281
    .local v12, "parentRight":Landroid/support/constraint/solver/SolverVariable;
    iget v9, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    iget-boolean v10, p0, Landroid/support/constraint/solver/widgets/Guideline;->mIsPositionRelaxed:Z

    .line 282
    move-object v5, p1

    move-object v6, v4

    move-object v7, v11

    move-object v8, v12

    invoke-static/range {v5 .. v10}, Landroid/support/constraint/solver/LinearSystem;->createRowDimensionPercent(Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;FZ)Landroid/support/constraint/solver/ArrayRow;

    move-result-object v5

    .line 281
    invoke-virtual {p1, v5}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 285
    .end local v4    # "guide":Landroid/support/constraint/solver/SolverVariable;
    .end local v11    # "parentLeft":Landroid/support/constraint/solver/SolverVariable;
    .end local v12    # "parentRight":Landroid/support/constraint/solver/SolverVariable;
    :cond_af
    :goto_af
    return-void
.end method

.method public allowedInBarrier()Z
    .registers 2

    .line 61
    const/4 v0, 0x1

    return v0
.end method

.method public analyze(I)V
    .registers 9
    .param p1, "optimizationLevel"    # I

    .line 213
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    .line 214
    .local v0, "constraintWidgetContainer":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-nez v0, :cond_7

    .line 215
    return-void

    .line 217
    :cond_7
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getOrientation()I

    move-result v1

    const/high16 v2, -0x40800000    # -1.0f

    const/4 v3, -0x1

    const/4 v4, 0x0

    const/4 v5, 0x1

    if-ne v1, v5, :cond_b7

    .line 218
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v1, v5, v6, v4}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 219
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v1, v5, v6, v4}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 220
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    if-eq v1, v3, :cond_58

    .line 221
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 222
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_158

    .line 223
    :cond_58
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v1, v3, :cond_82

    .line 224
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    neg-int v3, v3

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 225
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    neg-int v3, v3

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_158

    .line 226
    :cond_82
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    cmpl-float v1, v1, v2

    if-eqz v1, :cond_158

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v1, v2, :cond_158

    .line 227
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    int-to-float v1, v1

    iget v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    mul-float/2addr v1, v2

    float-to-int v1, v1

    .line 228
    .local v1, "position":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget-object v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v3

    invoke-virtual {v2, v5, v3, v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 229
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget-object v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v3

    invoke-virtual {v2, v5, v3, v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 230
    .end local v1    # "position":I
    goto/16 :goto_158

    .line 232
    :cond_b7
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v1, v5, v6, v4}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 233
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v1, v5, v6, v4}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 234
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    if-eq v1, v3, :cond_fc

    .line 235
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 236
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto :goto_158

    .line 237
    :cond_fc
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v1, v3, :cond_125

    .line 238
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    neg-int v3, v3

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 239
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    neg-int v3, v3

    invoke-virtual {v1, v5, v2, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto :goto_158

    .line 240
    :cond_125
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    cmpl-float v1, v1, v2

    if-eqz v1, :cond_158

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v1, v2, :cond_158

    .line 241
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    int-to-float v1, v1

    iget v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    mul-float/2addr v1, v2

    float-to-int v1, v1

    .line 242
    .restart local v1    # "position":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget-object v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v3

    invoke-virtual {v2, v5, v3, v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 243
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget-object v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v3

    invoke-virtual {v2, v5, v3, v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 246
    .end local v1    # "position":I
    :cond_158
    :goto_158
    return-void
.end method

.method public cyclePosition()V
    .registers 4

    .line 356
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_9

    .line 358
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->inferRelativePercentPosition()V

    goto :goto_1c

    .line 359
    :cond_9
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    const/high16 v2, -0x40800000    # -1.0f

    cmpl-float v0, v0, v2

    if-eqz v0, :cond_15

    .line 361
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->inferRelativeEndPosition()V

    goto :goto_1c

    .line 362
    :cond_15
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v0, v1, :cond_1c

    .line 364
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->inferRelativeBeginPosition()V

    .line 366
    :cond_1c
    :goto_1c
    return-void
.end method

.method public getAnchor()Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .registers 2

    .line 107
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0
.end method

.method public getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .registers 4
    .param p1, "anchorType"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 137
    sget-object v0, Landroid/support/constraint/solver/widgets/Guideline$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_28

    goto :goto_1d

    .line 157
    :pswitch_c
    const/4 v0, 0x0

    return-object v0

    .line 147
    :pswitch_e
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    if-nez v0, :cond_1d

    .line 148
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 140
    :pswitch_15
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_1d

    .line 141
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 159
    :cond_1d
    :goto_1d
    new-instance v0, Ljava/lang/AssertionError;

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    nop

    :pswitch_data_28
    .packed-switch 0x1
        :pswitch_15
        :pswitch_15
        :pswitch_e
        :pswitch_e
        :pswitch_c
        :pswitch_c
        :pswitch_c
        :pswitch_c
        :pswitch_c
    .end packed-switch
.end method

.method public getAnchors()Ljava/util/ArrayList;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintAnchor;",
            ">;"
        }
    .end annotation

    .line 164
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchors:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getHead()Landroid/support/constraint/solver/widgets/Rectangle;
    .registers 6

    .line 78
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHead:Landroid/support/constraint/solver/widgets/Rectangle;

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getDrawX()I

    move-result v1

    iget v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    sub-int/2addr v1, v2

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getDrawY()I

    move-result v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    mul-int/lit8 v3, v3, 0x2

    sub-int/2addr v2, v3

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    mul-int/lit8 v3, v3, 0x2

    iget v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    mul-int/lit8 v4, v4, 0x2

    invoke-virtual {v0, v1, v2, v3, v4}, Landroid/support/constraint/solver/widgets/Rectangle;->setBounds(IIII)V

    .line 80
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getOrientation()I

    move-result v0

    if-nez v0, :cond_40

    .line 81
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHead:Landroid/support/constraint/solver/widgets/Rectangle;

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getDrawX()I

    move-result v1

    iget v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    mul-int/lit8 v2, v2, 0x2

    sub-int/2addr v1, v2

    .line 82
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getDrawY()I

    move-result v2

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    sub-int/2addr v2, v3

    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    mul-int/lit8 v3, v3, 0x2

    iget v4, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHeadSize:I

    mul-int/lit8 v4, v4, 0x2

    .line 81
    invoke-virtual {v0, v1, v2, v3, v4}, Landroid/support/constraint/solver/widgets/Rectangle;->setBounds(IIII)V

    .line 85
    :cond_40
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mHead:Landroid/support/constraint/solver/widgets/Rectangle;

    return-object v0
.end method

.method public getOrientation()I
    .registers 2

    .line 121
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    return v0
.end method

.method public getRelativeBegin()I
    .registers 2

    .line 200
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    return v0
.end method

.method public getRelativeBehaviour()I
    .registers 3

    .line 65
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    const/high16 v1, -0x40800000    # -1.0f

    cmpl-float v0, v0, v1

    if-eqz v0, :cond_a

    .line 66
    const/4 v0, 0x0

    return v0

    .line 68
    :cond_a
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_11

    .line 69
    const/4 v0, 0x1

    return v0

    .line 71
    :cond_11
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v0, v1, :cond_17

    .line 72
    const/4 v0, 0x2

    return v0

    .line 74
    :cond_17
    return v1
.end method

.method public getRelativeEnd()I
    .registers 2

    .line 204
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    return v0
.end method

.method public getRelativePercent()F
    .registers 2

    .line 196
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    return v0
.end method

.method public getType()Ljava/lang/String;
    .registers 2

    .line 117
    const-string v0, "Guideline"

    return-object v0
.end method

.method inferRelativeBeginPosition()V
    .registers 3

    .line 340
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getX()I

    move-result v0

    .line 341
    .local v0, "position":I
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    if-nez v1, :cond_c

    .line 342
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getY()I

    move-result v0

    .line 344
    :cond_c
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setGuideBegin(I)V

    .line 345
    return-void
.end method

.method inferRelativeEndPosition()V
    .registers 4

    .line 348
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getX()I

    move-result v1

    sub-int/2addr v0, v1

    .line 349
    .local v0, "position":I
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    if-nez v1, :cond_1f

    .line 350
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v1

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getY()I

    move-result v2

    sub-int v0, v1, v2

    .line 352
    :cond_1f
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setGuideEnd(I)V

    .line 353
    return-void
.end method

.method inferRelativePercentPosition()V
    .registers 4

    .line 332
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getX()I

    move-result v0

    int-to-float v0, v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v1

    int-to-float v1, v1

    div-float/2addr v0, v1

    .line 333
    .local v0, "percent":F
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    if-nez v1, :cond_23

    .line 334
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getY()I

    move-result v1

    int-to-float v1, v1

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v2

    int-to-float v2, v2

    div-float v0, v1, v2

    .line 336
    :cond_23
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setGuidePercent(F)V

    .line 337
    return-void
.end method

.method public setDrawOrigin(II)V
    .registers 7
    .param p1, "x"    # I
    .param p2, "y"    # I

    .line 308
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    const/high16 v1, -0x40800000    # -1.0f

    const/4 v2, -0x1

    const/4 v3, 0x1

    if-ne v0, v3, :cond_3a

    .line 309
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOffsetX:I

    sub-int v0, p1, v0

    .line 310
    .local v0, "position":I
    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    if-eq v3, v2, :cond_14

    .line 311
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setGuideBegin(I)V

    goto :goto_39

    .line 312
    :cond_14
    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v3, v2, :cond_25

    .line 313
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v1

    sub-int/2addr v1, v0

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setGuideEnd(I)V

    goto :goto_39

    .line 314
    :cond_25
    iget v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    cmpl-float v1, v2, v1

    if-eqz v1, :cond_39

    .line 315
    int-to-float v1, v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v2

    int-to-float v2, v2

    div-float/2addr v1, v2

    .line 316
    .local v1, "percent":F
    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setGuidePercent(F)V

    .line 318
    .end local v0    # "position":I
    .end local v1    # "percent":F
    :cond_39
    :goto_39
    goto :goto_6b

    .line 319
    :cond_3a
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOffsetY:I

    sub-int v0, p2, v0

    .line 320
    .restart local v0    # "position":I
    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    if-eq v3, v2, :cond_46

    .line 321
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setGuideBegin(I)V

    goto :goto_6b

    .line 322
    :cond_46
    iget v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    if-eq v3, v2, :cond_57

    .line 323
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v1

    sub-int/2addr v1, v0

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setGuideEnd(I)V

    goto :goto_6b

    .line 324
    :cond_57
    iget v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    cmpl-float v1, v2, v1

    if-eqz v1, :cond_6b

    .line 325
    int-to-float v1, v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v2

    int-to-float v2, v2

    div-float/2addr v1, v2

    .line 326
    .restart local v1    # "percent":F
    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setGuidePercent(F)V

    .line 329
    .end local v0    # "position":I
    .end local v1    # "percent":F
    :cond_6b
    :goto_6b
    return-void
.end method

.method public setGuideBegin(I)V
    .registers 4
    .param p1, "value"    # I

    .line 180
    const/4 v0, -0x1

    if-le p1, v0, :cond_b

    .line 181
    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    .line 182
    iput p1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    .line 183
    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    .line 185
    :cond_b
    return-void
.end method

.method public setGuideEnd(I)V
    .registers 4
    .param p1, "value"    # I

    .line 188
    const/4 v0, -0x1

    if-le p1, v0, :cond_b

    .line 189
    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    .line 190
    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    .line 191
    iput p1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    .line 193
    :cond_b
    return-void
.end method

.method public setGuidePercent(F)V
    .registers 3
    .param p1, "value"    # F

    .line 172
    const/high16 v0, -0x40800000    # -1.0f

    cmpl-float v0, p1, v0

    if-lez v0, :cond_d

    .line 173
    iput p1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativePercent:F

    .line 174
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeBegin:I

    .line 175
    iput v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mRelativeEnd:I

    .line 177
    :cond_d
    return-void
.end method

.method public setGuidePercent(I)V
    .registers 4
    .param p1, "value"    # I

    .line 168
    int-to-float v0, p1

    const/high16 v1, 0x42c80000    # 100.0f

    div-float/2addr v0, v1

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setGuidePercent(F)V

    .line 169
    return-void
.end method

.method public setMinimumPosition(I)V
    .registers 2
    .param p1, "minimum"    # I

    .line 125
    iput p1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mMinimumPosition:I

    .line 126
    return-void
.end method

.method public setOrientation(I)V
    .registers 6
    .param p1, "orientation"    # I

    .line 89
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    if-ne v0, p1, :cond_5

    .line 90
    return-void

    .line 92
    :cond_5
    iput p1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    .line 93
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchors:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 94
    iget v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_16

    .line 95
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    goto :goto_1a

    .line 97
    :cond_16
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 99
    :goto_1a
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 100
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    array-length v0, v0

    .line 101
    .local v0, "count":I
    const/4 v1, 0x0

    .line 101
    .local v1, "i":I
    :goto_25
    if-ge v1, v0, :cond_30

    .line 102
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/Guideline;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v3, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aput-object v3, v2, v1

    .line 101
    add-int/lit8 v1, v1, 0x1

    goto :goto_25

    .line 104
    .end local v1    # "i":I
    :cond_30
    return-void
.end method

.method public setPositionRelaxed(Z)V
    .registers 3
    .param p1, "value"    # Z

    .line 129
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mIsPositionRelaxed:Z

    if-ne v0, p1, :cond_5

    .line 130
    return-void

    .line 132
    :cond_5
    iput-boolean p1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mIsPositionRelaxed:Z

    .line 133
    return-void
.end method

.method public updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 6
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 289
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    if-nez v0, :cond_7

    .line 290
    return-void

    .line 292
    :cond_7
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/Guideline;->mAnchor:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/LinearSystem;->getObjectVariableValue(Ljava/lang/Object;)I

    move-result v0

    .line 293
    .local v0, "value":I
    iget v1, p0, Landroid/support/constraint/solver/widgets/Guideline;->mOrientation:I

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-ne v1, v2, :cond_28

    .line 294
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setX(I)V

    .line 295
    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/Guideline;->setY(I)V

    .line 296
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v1

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setHeight(I)V

    .line 297
    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/Guideline;->setWidth(I)V

    goto :goto_3c

    .line 299
    :cond_28
    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/Guideline;->setX(I)V

    .line 300
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/Guideline;->setY(I)V

    .line 301
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/Guideline;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v1

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setWidth(I)V

    .line 302
    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/Guideline;->setHeight(I)V

    .line 304
    :goto_3c
    return-void
.end method
