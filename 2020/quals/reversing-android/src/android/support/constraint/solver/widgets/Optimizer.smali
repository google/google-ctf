.class public Landroid/support/constraint/solver/widgets/Optimizer;
.super Ljava/lang/Object;
.source "Optimizer.java"


# static fields
.field static final FLAG_CHAIN_DANGLING:I = 0x1

.field static final FLAG_RECOMPUTE_BOUNDS:I = 0x2

.field static final FLAG_USE_OPTIMIZE:I = 0x0

.field public static final OPTIMIZATION_BARRIER:I = 0x2

.field public static final OPTIMIZATION_CHAIN:I = 0x4

.field public static final OPTIMIZATION_DIMENSIONS:I = 0x8

.field public static final OPTIMIZATION_DIRECT:I = 0x1

.field public static final OPTIMIZATION_GROUPS:I = 0x20

.field public static final OPTIMIZATION_NONE:I = 0x0

.field public static final OPTIMIZATION_RATIO:I = 0x10

.field public static final OPTIMIZATION_STANDARD:I = 0x7

.field static flags:[Z


# direct methods
.method static constructor <clinit>()V
    .registers 1

    .line 44
    const/4 v0, 0x3

    new-array v0, v0, [Z

    sput-object v0, Landroid/support/constraint/solver/widgets/Optimizer;->flags:[Z

    return-void
.end method

.method public constructor <init>()V
    .registers 1

    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method static analyze(ILandroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 18
    .param p0, "optimisationLevel"    # I
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 152
    move-object/from16 v0, p1

    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->updateResolutionNodes()V

    .line 154
    iget-object v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    .line 155
    .local v1, "leftNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    .line 156
    .local v2, "topNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    iget-object v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v3

    .line 157
    .local v3, "rightNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    iget-object v4, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v4

    .line 159
    .local v4, "bottomNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    and-int/lit8 v5, p0, 0x8

    const/16 v6, 0x8

    const/4 v7, 0x0

    const/4 v8, 0x1

    if-ne v5, v6, :cond_27

    move v5, v8

    goto :goto_28

    :cond_27
    move v5, v7

    .line 163
    .local v5, "optimiseDimensions":Z
    :goto_28
    iget-object v9, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v9, v9, v7

    sget-object v10, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v9, v10, :cond_38

    .line 164
    invoke-static {v0, v7}, Landroid/support/constraint/solver/widgets/Optimizer;->optimizableMatchConstraint(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)Z

    move-result v9

    if-eqz v9, :cond_38

    move v9, v8

    goto :goto_39

    :cond_38
    move v9, v7

    .line 166
    .local v9, "isOptimizableHorizontalMatch":Z
    :goto_39
    iget v10, v1, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->type:I

    const/4 v12, 0x4

    const/4 v13, 0x0

    const/4 v14, -0x1

    const/4 v11, 0x2

    if-eq v10, v12, :cond_1b7

    iget v10, v3, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->type:I

    if-eq v10, v12, :cond_1b7

    .line 168
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v10, v10, v7

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v10, v7, :cond_fd

    if-eqz v9, :cond_57

    .line 169
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v7

    if-ne v7, v6, :cond_57

    goto/16 :goto_fd

    .line 208
    :cond_57
    if-eqz v9, :cond_1b7

    .line 209
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    .line 215
    .local v7, "width":I
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 216
    invoke-virtual {v3, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 217
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_7f

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_7f

    .line 218
    if-eqz v5, :cond_7a

    .line 219
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v3, v1, v8, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_1b7

    .line 221
    :cond_7a
    invoke-virtual {v3, v1, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_1b7

    .line 223
    :cond_7f
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_9b

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_9b

    .line 224
    if-eqz v5, :cond_96

    .line 225
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v3, v1, v8, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_1b7

    .line 227
    :cond_96
    invoke-virtual {v3, v1, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_1b7

    .line 229
    :cond_9b
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_b8

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_b8

    .line 230
    if-eqz v5, :cond_b2

    .line 231
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v1, v3, v14, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_1b7

    .line 233
    :cond_b2
    neg-int v10, v7

    invoke-virtual {v1, v3, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_1b7

    .line 235
    :cond_b8
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_1b7

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_1b7

    .line 236
    if-eqz v5, :cond_d4

    .line 237
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 238
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v10, v3}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 240
    :cond_d4
    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    cmpl-float v10, v10, v13

    if-nez v10, :cond_e9

    .line 241
    const/4 v10, 0x3

    invoke-virtual {v1, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 242
    invoke-virtual {v3, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 243
    invoke-virtual {v1, v3, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 244
    invoke-virtual {v3, v1, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    goto/16 :goto_1b7

    .line 247
    :cond_e9
    invoke-virtual {v1, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 248
    invoke-virtual {v3, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 249
    neg-int v10, v7

    int-to-float v10, v10

    invoke-virtual {v1, v3, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 250
    int-to-float v10, v7

    invoke-virtual {v3, v1, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 251
    invoke-virtual {v0, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setWidth(I)V

    .line 251
    .end local v7    # "width":I
    goto/16 :goto_1b7

    .line 170
    :cond_fd
    :goto_fd
    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v7, :cond_123

    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v7, :cond_123

    .line 171
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 172
    invoke-virtual {v3, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 173
    if-eqz v5, :cond_11a

    .line 174
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v3, v1, v8, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_1b7

    .line 176
    :cond_11a
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    invoke-virtual {v3, v1, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_1b7

    .line 178
    :cond_123
    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v7, :cond_148

    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v7, :cond_148

    .line 179
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 180
    invoke-virtual {v3, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 181
    if-eqz v5, :cond_140

    .line 182
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v3, v1, v8, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_1b7

    .line 184
    :cond_140
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    invoke-virtual {v3, v1, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto :goto_1b7

    .line 186
    :cond_148
    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v7, :cond_175

    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v7, :cond_175

    .line 187
    invoke-virtual {v1, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 188
    invoke-virtual {v3, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 189
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    neg-int v7, v7

    invoke-virtual {v1, v3, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 190
    if-eqz v5, :cond_16c

    .line 191
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v1, v3, v14, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto :goto_1b7

    .line 193
    :cond_16c
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    neg-int v7, v7

    invoke-virtual {v1, v3, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto :goto_1b7

    .line 195
    :cond_175
    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v7, :cond_1b7

    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v7, :cond_1b7

    .line 196
    invoke-virtual {v1, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 197
    invoke-virtual {v3, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 198
    if-eqz v5, :cond_1a6

    .line 199
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v7, v1}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 200
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v7, v3}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 201
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v1, v3, v14, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    .line 202
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v7

    invoke-virtual {v3, v1, v8, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto :goto_1b7

    .line 204
    :cond_1a6
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    neg-int v7, v7

    int-to-float v7, v7

    invoke-virtual {v1, v3, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 205
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    int-to-float v7, v7

    invoke-virtual {v3, v1, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 259
    :cond_1b7
    :goto_1b7
    iget-object v7, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v7, v7, v8

    sget-object v10, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v7, v10, :cond_1c7

    .line 260
    invoke-static {v0, v8}, Landroid/support/constraint/solver/widgets/Optimizer;->optimizableMatchConstraint(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)Z

    move-result v7

    if-eqz v7, :cond_1c7

    move v15, v8

    goto :goto_1c8

    :cond_1c7
    const/4 v15, 0x0

    :goto_1c8
    move v7, v15

    .line 262
    .local v7, "isOptimizableVerticalMatch":Z
    iget v10, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->type:I

    if-eq v10, v12, :cond_391

    iget v10, v4, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->type:I

    if-eq v10, v12, :cond_391

    .line 265
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v10, v10, v8

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v10, v12, :cond_298

    if-eqz v7, :cond_1e3

    .line 266
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v10

    if-ne v10, v6, :cond_1e3

    goto/16 :goto_298

    .line 318
    :cond_1e3
    if-eqz v7, :cond_391

    .line 319
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    .line 324
    .local v6, "height":I
    invoke-virtual {v2, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 325
    invoke-virtual {v4, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 326
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_20b

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_20b

    .line 327
    if-eqz v5, :cond_206

    .line 328
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v4, v2, v8, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_391

    .line 330
    :cond_206
    invoke-virtual {v4, v2, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_391

    .line 332
    :cond_20b
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_227

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_227

    .line 333
    if-eqz v5, :cond_222

    .line 334
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v4, v2, v8, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_391

    .line 336
    :cond_222
    invoke-virtual {v4, v2, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_391

    .line 338
    :cond_227
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v10, :cond_244

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_244

    .line 339
    if-eqz v5, :cond_23e

    .line 340
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v8

    invoke-virtual {v2, v4, v14, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto/16 :goto_391

    .line 342
    :cond_23e
    neg-int v8, v6

    invoke-virtual {v2, v4, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_391

    .line 344
    :cond_244
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_391

    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v10, v10, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v10, :cond_391

    .line 345
    if-eqz v5, :cond_260

    .line 346
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v10, v2}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 347
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v10

    invoke-virtual {v10, v4}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 349
    :cond_260
    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    cmpl-float v10, v10, v13

    if-nez v10, :cond_275

    .line 350
    const/4 v8, 0x3

    invoke-virtual {v2, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 351
    invoke-virtual {v4, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 352
    invoke-virtual {v2, v4, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 353
    invoke-virtual {v4, v2, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    goto/16 :goto_391

    .line 355
    :cond_275
    invoke-virtual {v2, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 356
    invoke-virtual {v4, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 357
    neg-int v10, v6

    int-to-float v10, v10

    invoke-virtual {v2, v4, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 358
    int-to-float v10, v6

    invoke-virtual {v4, v2, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 359
    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHeight(I)V

    .line 360
    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v10, :cond_391

    .line 361
    iget-object v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v10

    iget v11, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    invoke-virtual {v10, v8, v2, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 361
    .end local v6    # "height":I
    goto/16 :goto_391

    .line 267
    :cond_298
    :goto_298
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v6, :cond_2d8

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v6, :cond_2d8

    .line 268
    invoke-virtual {v2, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 269
    invoke-virtual {v4, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 270
    if-eqz v5, :cond_2b4

    .line 271
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v4, v2, v8, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto :goto_2bb

    .line 273
    :cond_2b4
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    invoke-virtual {v4, v2, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 275
    :goto_2bb
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_391

    .line 276
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v6, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 277
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 278
    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    neg-int v10, v10

    .line 277
    invoke-virtual {v2, v8, v6, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_391

    .line 280
    :cond_2d8
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_30c

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v6, :cond_30c

    .line 281
    invoke-virtual {v2, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 282
    invoke-virtual {v4, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 283
    if-eqz v5, :cond_2f4

    .line 284
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v4, v2, v8, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto :goto_2fb

    .line 286
    :cond_2f4
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    invoke-virtual {v4, v2, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 288
    :goto_2fb
    iget v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v6, :cond_391

    .line 289
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    invoke-virtual {v6, v8, v2, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto/16 :goto_391

    .line 291
    :cond_30c
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v6, :cond_340

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_340

    .line 292
    invoke-virtual {v2, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 293
    invoke-virtual {v4, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 294
    if-eqz v5, :cond_328

    .line 295
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v2, v4, v14, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    goto :goto_330

    .line 297
    :cond_328
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    neg-int v6, v6

    invoke-virtual {v2, v4, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(Landroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 299
    :goto_330
    iget v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v6, :cond_391

    .line 300
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    invoke-virtual {v6, v8, v2, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    goto :goto_391

    .line 302
    :cond_340
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_391

    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v6, :cond_391

    .line 303
    invoke-virtual {v2, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 304
    invoke-virtual {v4, v11}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setType(I)V

    .line 305
    if-eqz v5, :cond_371

    .line 306
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v2, v4, v14, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    .line 307
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v4, v2, v8, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;ILandroid/support/constraint/solver/widgets/ResolutionDimension;)V

    .line 308
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v6, v2}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    .line 309
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;

    move-result-object v6

    invoke-virtual {v6, v4}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V

    goto :goto_382

    .line 311
    :cond_371
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    neg-int v6, v6

    int-to-float v6, v6

    invoke-virtual {v2, v4, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 312
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v6

    int-to-float v6, v6

    invoke-virtual {v4, v2, v6}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->setOpposite(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 314
    :goto_382
    iget v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v6, :cond_391

    .line 315
    iget-object v6, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    iget v10, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    invoke-virtual {v6, v8, v2, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->dependsOn(ILandroid/support/constraint/solver/widgets/ResolutionAnchor;I)V

    .line 367
    :cond_391
    :goto_391
    return-void
.end method

.method static applyChainOptimized(Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;Landroid/support/constraint/solver/LinearSystem;IILandroid/support/constraint/solver/widgets/ChainHead;)Z
    .registers 48
    .param p0, "container"    # Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "orientation"    # I
    .param p3, "offset"    # I
    .param p4, "chainHead"    # Landroid/support/constraint/solver/widgets/ChainHead;

    move-object/from16 v0, p1

    move/from16 v1, p2

    .line 383
    move-object/from16 v2, p4

    iget-object v3, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mFirst:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 384
    .local v3, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v4, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mLast:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 385
    .local v4, "last":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v5, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 386
    .local v5, "firstVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v6, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mLastVisibleWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 387
    .local v6, "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v7, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mHead:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 389
    .local v7, "head":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move-object v8, v3

    .line 390
    .local v8, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v9, 0x0

    .line 391
    .local v9, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v10, 0x0

    .line 393
    .local v10, "done":Z
    const/4 v11, 0x0

    .line 394
    .local v11, "numMatchConstraints":I
    iget v12, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mTotalWeight:F

    .line 395
    .local v12, "totalWeights":F
    iget-object v13, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mFirstMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 396
    .local v13, "firstMatchConstraintsWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v14, v2, Landroid/support/constraint/solver/widgets/ChainHead;->mLastMatchConstraintWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 398
    .local v14, "previousMatchConstraintsWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move-object/from16 v2, p0

    move-object v15, v8

    iget-object v8, v2, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 398
    .end local v8    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v15, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    aget-object v8, v8, v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v16, 0x0

    move-object/from16 v17, v9

    .line 398
    .end local v9    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v17, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-ne v8, v2, :cond_2b

    const/4 v2, 0x1

    goto :goto_2d

    :cond_2b
    move/from16 v2, v16

    .line 399
    .local v2, "isWrapContent":Z
    :goto_2d
    const/4 v8, 0x0

    .line 400
    .local v8, "isChainSpread":Z
    const/16 v18, 0x0

    .line 401
    .local v18, "isChainSpreadInside":Z
    const/16 v19, 0x0

    .line 403
    .local v19, "isChainPacked":Z
    if-nez v1, :cond_54

    .line 404
    iget v9, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    if-nez v9, :cond_3a

    const/4 v9, 0x1

    goto :goto_3c

    :cond_3a
    move/from16 v9, v16

    :goto_3c
    move v8, v9

    .line 405
    iget v9, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    move/from16 v21, v2

    const/4 v2, 0x1

    if-ne v9, v2, :cond_46

    .line 405
    .end local v2    # "isWrapContent":Z
    .local v21, "isWrapContent":Z
    const/4 v2, 0x1

    goto :goto_48

    :cond_46
    move/from16 v2, v16

    .line 406
    .end local v18    # "isChainSpreadInside":Z
    .local v2, "isChainSpreadInside":Z
    :goto_48
    iget v9, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    move/from16 v22, v2

    const/4 v2, 0x2

    if-ne v9, v2, :cond_51

    .line 406
    .end local v2    # "isChainSpreadInside":Z
    .local v22, "isChainSpreadInside":Z
    const/4 v2, 0x1

    goto :goto_53

    :cond_51
    move/from16 v2, v16

    .line 406
    .end local v19    # "isChainPacked":Z
    .local v2, "isChainPacked":Z
    :goto_53
    goto :goto_75

    .line 408
    .end local v21    # "isWrapContent":Z
    .end local v22    # "isChainSpreadInside":Z
    .local v2, "isWrapContent":Z
    .restart local v18    # "isChainSpreadInside":Z
    .restart local v19    # "isChainPacked":Z
    :cond_54
    move/from16 v21, v2

    .line 408
    .end local v2    # "isWrapContent":Z
    .restart local v21    # "isWrapContent":Z
    iget v2, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    if-nez v2, :cond_5c

    const/4 v2, 0x1

    goto :goto_5e

    :cond_5c
    move/from16 v2, v16

    :goto_5e
    move v8, v2

    .line 409
    iget v2, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    const/4 v9, 0x1

    if-ne v2, v9, :cond_66

    const/4 v2, 0x1

    goto :goto_68

    :cond_66
    move/from16 v2, v16

    .line 410
    .end local v18    # "isChainSpreadInside":Z
    .local v2, "isChainSpreadInside":Z
    :goto_68
    iget v9, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    move/from16 v23, v2

    const/4 v2, 0x2

    if-ne v9, v2, :cond_71

    .line 410
    .end local v2    # "isChainSpreadInside":Z
    .local v23, "isChainSpreadInside":Z
    const/4 v2, 0x1

    goto :goto_73

    :cond_71
    move/from16 v2, v16

    .line 417
    .end local v19    # "isChainPacked":Z
    .local v2, "isChainPacked":Z
    :goto_73
    move/from16 v22, v23

    .line 417
    .end local v23    # "isChainSpreadInside":Z
    .restart local v22    # "isChainSpreadInside":Z
    :goto_75
    const/4 v9, 0x0

    .line 418
    .local v9, "totalSize":F
    const/16 v18, 0x0

    .line 419
    .local v18, "totalMargins":F
    move-object/from16 v24, v7

    move v7, v11

    move-object v11, v15

    move v15, v9

    move/from16 v9, v16

    .line 421
    .local v7, "numMatchConstraints":I
    .local v9, "numVisibleWidgets":I
    .local v11, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v15, "totalSize":F
    .local v24, "head":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_7f
    const/16 v19, 0x0

    move-object/from16 v25, v13

    const/16 v13, 0x8

    .line 421
    .end local v13    # "firstMatchConstraintsWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v25, "firstMatchConstraintsWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-nez v10, :cond_14b

    .line 423
    move/from16 v26, v10

    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v10

    .line 423
    .end local v10    # "done":Z
    .local v26, "done":Z
    if-eq v10, v13, :cond_d2

    .line 424
    add-int/lit8 v9, v9, 0x1

    .line 425
    if-nez v1, :cond_9a

    .line 426
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v10

    int-to-float v10, v10

    add-float/2addr v15, v10

    goto :goto_a0

    .line 428
    :cond_9a
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v10

    int-to-float v10, v10

    add-float/2addr v15, v10

    .line 430
    :goto_a0
    if-eq v11, v5, :cond_ac

    .line 431
    iget-object v10, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v10, v10, p3

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v10

    int-to-float v10, v10

    add-float/2addr v15, v10

    .line 433
    :cond_ac
    if-eq v11, v6, :cond_ba

    .line 434
    iget-object v10, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v20, p3, 0x1

    aget-object v10, v10, v20

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v10

    int-to-float v10, v10

    add-float/2addr v15, v10

    .line 436
    :cond_ba
    iget-object v10, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v10, v10, p3

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v10

    int-to-float v10, v10

    add-float v18, v18, v10

    .line 437
    iget-object v10, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v20, p3, 0x1

    aget-object v10, v10, v20

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v10

    int-to-float v10, v10

    add-float v18, v18, v10

    .line 440
    :cond_d2
    iget-object v10, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v10, v10, p3

    .line 442
    .local v10, "begin":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    move/from16 v27, v9

    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v9

    .line 442
    .end local v9    # "numVisibleWidgets":I
    .local v27, "numVisibleWidgets":I
    if-eq v9, v13, :cond_10e

    iget-object v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v9, v9, v1

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v9, v13, :cond_10e

    .line 444
    add-int/lit8 v7, v7, 0x1

    .line 446
    if-nez v1, :cond_f8

    .line 447
    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    if-eqz v9, :cond_ef

    .line 448
    return v16

    .line 449
    :cond_ef
    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    if-nez v9, :cond_f7

    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    if-eqz v9, :cond_106

    .line 450
    :cond_f7
    return v16

    .line 453
    :cond_f8
    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    if-eqz v9, :cond_fd

    .line 454
    return v16

    .line 455
    :cond_fd
    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    if-nez v9, :cond_10d

    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    if-eqz v9, :cond_106

    goto :goto_10d

    .line 459
    :cond_106
    iget v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    cmpl-float v9, v9, v19

    if-eqz v9, :cond_10e

    .line 460
    return v16

    .line 456
    :cond_10d
    :goto_10d
    return v16

    .line 465
    :cond_10e
    iget-object v9, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v13, p3, 0x1

    aget-object v9, v9, v13

    iget-object v9, v9, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 466
    .local v9, "nextAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    if-eqz v9, :cond_134

    .line 467
    iget-object v13, v9, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 468
    .end local v17    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v13, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move/from16 v28, v7

    iget-object v7, v13, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 468
    .end local v7    # "numMatchConstraints":I
    .local v28, "numMatchConstraints":I
    aget-object v7, v7, p3

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v7, :cond_132

    iget-object v7, v13, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v7, v7, p3

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v7, v7, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eq v7, v11, :cond_12f

    goto :goto_132

    .line 474
    :cond_12f
    move-object/from16 v17, v13

    goto :goto_139

    .line 469
    :cond_132
    :goto_132
    const/4 v7, 0x0

    .line 469
    .end local v13    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v7, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    goto :goto_137

    .line 472
    .end local v28    # "numMatchConstraints":I
    .local v7, "numMatchConstraints":I
    .restart local v17    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_134
    move/from16 v28, v7

    .line 472
    .end local v7    # "numMatchConstraints":I
    .restart local v28    # "numMatchConstraints":I
    const/4 v7, 0x0

    .line 474
    :goto_137
    move-object/from16 v17, v7

    :goto_139
    if-eqz v17, :cond_141

    .line 475
    move-object/from16 v7, v17

    .line 479
    .end local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v7, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move-object v11, v7

    move/from16 v10, v26

    goto :goto_143

    .line 477
    .end local v7    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_141
    const/4 v7, 0x1

    .line 479
    .end local v9    # "nextAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v10    # "begin":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v26    # "done":Z
    .local v7, "done":Z
    move v10, v7

    .line 419
    .end local v7    # "done":Z
    .local v10, "done":Z
    :goto_143
    move-object/from16 v13, v25

    move/from16 v9, v27

    move/from16 v7, v28

    goto/16 :goto_7f

    .line 481
    .end local v27    # "numVisibleWidgets":I
    .end local v28    # "numMatchConstraints":I
    .local v7, "numMatchConstraints":I
    .local v9, "numVisibleWidgets":I
    :cond_14b
    move/from16 v26, v10

    .line 481
    .end local v10    # "done":Z
    .restart local v26    # "done":Z
    iget-object v10, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v10, v10, p3

    invoke-virtual {v10}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v10

    .line 482
    .local v10, "firstNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    iget-object v13, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v20, p3, 0x1

    aget-object v13, v13, v20

    invoke-virtual {v13}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v13

    .line 484
    .local v13, "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    move-object/from16 v29, v14

    iget-object v14, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->target:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    .line 484
    .end local v14    # "previousMatchConstraintsWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v29, "previousMatchConstraintsWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-eqz v14, :cond_4ba

    iget-object v14, v13, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->target:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    if-nez v14, :cond_179

    .line 486
    move/from16 v30, v2

    move-object/from16 v32, v6

    move/from16 v39, v7

    move/from16 v33, v8

    move/from16 v40, v9

    move-object/from16 v35, v13

    move-object v13, v0

    move-object v9, v3

    goto/16 :goto_4c8

    .line 490
    :cond_179
    iget-object v14, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->target:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    iget v14, v14, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    const/4 v0, 0x1

    if-ne v14, v0, :cond_4aa

    iget-object v14, v13, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->target:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    iget v14, v14, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-eq v14, v0, :cond_197

    .line 493
    move/from16 v30, v2

    move-object/from16 v32, v6

    move/from16 v39, v7

    move/from16 v33, v8

    move/from16 v40, v9

    move-object/from16 v35, v13

    move-object/from16 v13, p1

    move-object v9, v3

    goto/16 :goto_4b9

    .line 496
    :cond_197
    if-lez v7, :cond_19c

    if-eq v7, v9, :cond_19c

    .line 498
    return v16

    .line 501
    :cond_19c
    const/4 v0, 0x0

    .line 502
    .local v0, "extraMargin":F
    if-nez v2, :cond_1a3

    if-nez v8, :cond_1a3

    if-eqz v22, :cond_1bc

    .line 503
    :cond_1a3
    if-eqz v5, :cond_1ae

    .line 504
    iget-object v14, v5, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v14, v14, p3

    invoke-virtual {v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v14

    int-to-float v0, v14

    .line 506
    :cond_1ae
    if-eqz v6, :cond_1bc

    .line 507
    iget-object v14, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v20, p3, 0x1

    aget-object v14, v14, v20

    invoke-virtual {v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v14

    int-to-float v14, v14

    add-float/2addr v0, v14

    .line 511
    :cond_1bc
    iget-object v14, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->target:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    iget v14, v14, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedOffset:F

    .line 512
    .local v14, "firstOffset":F
    move/from16 v30, v2

    iget-object v2, v13, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->target:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    .line 512
    .end local v2    # "isChainPacked":Z
    .local v30, "isChainPacked":Z
    iget v2, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedOffset:F

    .line 513
    .local v2, "lastOffset":F
    const/16 v20, 0x0

    .line 514
    .local v20, "distance":F
    cmpg-float v23, v14, v2

    if-gez v23, :cond_1d1

    .line 515
    sub-float v23, v2, v14

    sub-float v23, v23, v15

    .line 515
    .end local v20    # "distance":F
    .local v23, "distance":F
    :goto_1d0
    goto :goto_1d6

    .line 517
    .end local v23    # "distance":F
    .restart local v20    # "distance":F
    :cond_1d1
    sub-float v23, v14, v2

    sub-float v23, v23, v15

    goto :goto_1d0

    .line 520
    .end local v20    # "distance":F
    .restart local v23    # "distance":F
    :goto_1d6
    const-wide/16 v27, 0x1

    if-lez v7, :cond_2c4

    if-ne v7, v9, :cond_2c4

    .line 521
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v20

    if-eqz v20, :cond_1f3

    move/from16 v31, v2

    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    .line 521
    .end local v2    # "lastOffset":F
    .local v31, "lastOffset":F
    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v2, v2, v1

    move-object/from16 v32, v6

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 521
    .end local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v32, "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-ne v2, v6, :cond_1f7

    .line 522
    return v16

    .line 524
    .end local v31    # "lastOffset":F
    .end local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v2    # "lastOffset":F
    .restart local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_1f3
    move/from16 v31, v2

    move-object/from16 v32, v6

    .line 524
    .end local v2    # "lastOffset":F
    .end local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v31    # "lastOffset":F
    .restart local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_1f7
    add-float v23, v23, v15

    .line 525
    sub-float v23, v23, v18

    .line 526
    move-object v2, v3

    .line 527
    .end local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    move-object v6, v2

    move v2, v14

    .line 528
    .local v2, "position":F
    .local v6, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_1fe
    if-eqz v6, :cond_2b8

    .line 529
    sget-object v11, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v11, :cond_225

    .line 530
    sget-object v11, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    move/from16 v33, v8

    move/from16 v34, v9

    iget-wide v8, v11, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 530
    .end local v8    # "isChainSpread":Z
    .end local v9    # "numVisibleWidgets":I
    .local v33, "isChainSpread":Z
    .local v34, "numVisibleWidgets":I
    sub-long v8, v8, v27

    iput-wide v8, v11, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 531
    sget-object v8, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    move-object/from16 v35, v13

    move/from16 v36, v14

    iget-wide v13, v8, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    .line 531
    .end local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v14    # "firstOffset":F
    .local v35, "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .local v36, "firstOffset":F
    add-long v13, v13, v27

    iput-wide v13, v8, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    .line 532
    sget-object v8, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v13, v8, Landroid/support/constraint/solver/Metrics;->chainConnectionResolved:J

    add-long v13, v13, v27

    iput-wide v13, v8, Landroid/support/constraint/solver/Metrics;->chainConnectionResolved:J

    goto :goto_22d

    .line 534
    .end local v33    # "isChainSpread":Z
    .end local v34    # "numVisibleWidgets":I
    .end local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v36    # "firstOffset":F
    .restart local v8    # "isChainSpread":Z
    .restart local v9    # "numVisibleWidgets":I
    .restart local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v14    # "firstOffset":F
    :cond_225
    move/from16 v33, v8

    move/from16 v34, v9

    move-object/from16 v35, v13

    move/from16 v36, v14

    .line 534
    .end local v8    # "isChainSpread":Z
    .end local v9    # "numVisibleWidgets":I
    .end local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v14    # "firstOffset":F
    .restart local v33    # "isChainSpread":Z
    .restart local v34    # "numVisibleWidgets":I
    .restart local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v36    # "firstOffset":F
    :goto_22d
    iget-object v8, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aget-object v17, v8, v1

    .line 535
    if-nez v17, :cond_239

    if-ne v6, v4, :cond_236

    goto :goto_239

    .line 557
    :cond_236
    move-object/from16 v13, p1

    goto :goto_2ac

    .line 536
    :cond_239
    :goto_239
    int-to-float v8, v7

    div-float v8, v23, v8

    .line 537
    .local v8, "dimension":F
    cmpl-float v9, v12, v19

    if-lez v9, :cond_254

    .line 538
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    aget v9, v9, v1

    const/high16 v11, -0x40800000    # -1.0f

    cmpl-float v9, v9, v11

    if-nez v9, :cond_24c

    .line 539
    const/4 v8, 0x0

    goto :goto_254

    .line 541
    :cond_24c
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    aget v9, v9, v1

    mul-float v9, v9, v23

    div-float v8, v9, v12

    .line 544
    :cond_254
    :goto_254
    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v9

    const/16 v11, 0x8

    if-ne v9, v11, :cond_25d

    .line 545
    const/4 v8, 0x0

    .line 547
    :cond_25d
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v9, v9, p3

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v9

    int-to-float v9, v9

    add-float/2addr v2, v9

    .line 548
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v9, v9, p3

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v9

    iget-object v11, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    invoke-virtual {v9, v11, v2}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 550
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v11, p3, 0x1

    aget-object v9, v9, v11

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v9

    iget-object v11, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    add-float v13, v2, v8

    invoke-virtual {v9, v11, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 552
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v9, v9, p3

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v9

    move-object/from16 v13, p1

    invoke-virtual {v9, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 553
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v11, p3, 0x1

    aget-object v9, v9, v11

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v9

    invoke-virtual {v9, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 554
    add-float/2addr v2, v8

    .line 555
    iget-object v9, v6, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v11, p3, 0x1

    aget-object v9, v9, v11

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v9

    int-to-float v9, v9

    add-float/2addr v2, v9

    .line 557
    .end local v8    # "dimension":F
    :goto_2ac
    move-object/from16 v6, v17

    .line 527
    move/from16 v8, v33

    move/from16 v9, v34

    move-object/from16 v13, v35

    move/from16 v14, v36

    goto/16 :goto_1fe

    .line 559
    .end local v33    # "isChainSpread":Z
    .end local v34    # "numVisibleWidgets":I
    .end local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v36    # "firstOffset":F
    .local v8, "isChainSpread":Z
    .restart local v9    # "numVisibleWidgets":I
    .restart local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v14    # "firstOffset":F
    :cond_2b8
    move/from16 v33, v8

    move/from16 v34, v9

    move-object/from16 v35, v13

    move/from16 v36, v14

    move-object/from16 v13, p1

    .line 559
    .end local v8    # "isChainSpread":Z
    .end local v9    # "numVisibleWidgets":I
    .end local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v14    # "firstOffset":F
    .restart local v33    # "isChainSpread":Z
    .restart local v34    # "numVisibleWidgets":I
    .restart local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v36    # "firstOffset":F
    const/4 v8, 0x1

    return v8

    .line 563
    .end local v31    # "lastOffset":F
    .end local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v33    # "isChainSpread":Z
    .end local v34    # "numVisibleWidgets":I
    .end local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v36    # "firstOffset":F
    .local v2, "lastOffset":F
    .local v6, "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v8    # "isChainSpread":Z
    .restart local v9    # "numVisibleWidgets":I
    .restart local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v14    # "firstOffset":F
    :cond_2c4
    move/from16 v31, v2

    move-object/from16 v32, v6

    move/from16 v33, v8

    move/from16 v34, v9

    move-object/from16 v35, v13

    move/from16 v36, v14

    move-object/from16 v13, p1

    .line 563
    .end local v2    # "lastOffset":F
    .end local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v8    # "isChainSpread":Z
    .end local v9    # "numVisibleWidgets":I
    .end local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v14    # "firstOffset":F
    .restart local v31    # "lastOffset":F
    .restart local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v33    # "isChainSpread":Z
    .restart local v34    # "numVisibleWidgets":I
    .restart local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v36    # "firstOffset":F
    cmpg-float v2, v23, v19

    if-gez v2, :cond_2db

    .line 564
    const/4 v8, 0x0

    .line 565
    .end local v33    # "isChainSpread":Z
    .restart local v8    # "isChainSpread":Z
    const/16 v22, 0x0

    .line 566
    const/4 v2, 0x1

    .line 566
    .end local v30    # "isChainPacked":Z
    .local v2, "isChainPacked":Z
    goto :goto_2df

    .line 569
    .end local v2    # "isChainPacked":Z
    .end local v8    # "isChainSpread":Z
    .restart local v30    # "isChainPacked":Z
    .restart local v33    # "isChainSpread":Z
    :cond_2db
    move/from16 v2, v30

    move/from16 v8, v33

    .line 569
    .end local v30    # "isChainPacked":Z
    .end local v33    # "isChainSpread":Z
    .restart local v2    # "isChainPacked":Z
    .restart local v8    # "isChainSpread":Z
    :goto_2df
    if-eqz v2, :cond_394

    .line 570
    sub-float v23, v23, v0

    .line 572
    move-object v6, v3

    .line 573
    .end local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v6, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v3, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getBiasPercent(I)F

    move-result v9

    mul-float v9, v9, v23

    add-float v14, v36, v9

    .line 574
    .end local v23    # "distance":F
    .local v14, "distance":F
    move-object v11, v6

    move/from16 v23, v14

    .line 574
    .end local v6    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v14    # "distance":F
    .restart local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v23    # "distance":F
    :goto_2ef
    if-eqz v11, :cond_389

    .line 575
    sget-object v6, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v6, :cond_314

    .line 576
    sget-object v6, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    move/from16 v38, v2

    move-object/from16 v37, v3

    iget-wide v2, v6, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 576
    .end local v2    # "isChainPacked":Z
    .end local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v37, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v38, "isChainPacked":Z
    sub-long v2, v2, v27

    iput-wide v2, v6, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 577
    sget-object v2, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    move/from16 v39, v7

    iget-wide v6, v2, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    .line 577
    .end local v7    # "numMatchConstraints":I
    .local v39, "numMatchConstraints":I
    add-long v6, v6, v27

    iput-wide v6, v2, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    .line 578
    sget-object v2, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v6, v2, Landroid/support/constraint/solver/Metrics;->chainConnectionResolved:J

    add-long v6, v6, v27

    iput-wide v6, v2, Landroid/support/constraint/solver/Metrics;->chainConnectionResolved:J

    goto :goto_31a

    .line 580
    .end local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v38    # "isChainPacked":Z
    .end local v39    # "numMatchConstraints":I
    .restart local v2    # "isChainPacked":Z
    .restart local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v7    # "numMatchConstraints":I
    :cond_314
    move/from16 v38, v2

    move-object/from16 v37, v3

    move/from16 v39, v7

    .line 580
    .end local v2    # "isChainPacked":Z
    .end local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v7    # "numMatchConstraints":I
    .restart local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v38    # "isChainPacked":Z
    .restart local v39    # "numMatchConstraints":I
    :goto_31a
    iget-object v2, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aget-object v17, v2, v1

    .line 581
    if-nez v17, :cond_322

    if-ne v11, v4, :cond_37f

    .line 582
    :cond_322
    const/4 v2, 0x0

    .line 583
    .local v2, "dimension":F
    if-nez v1, :cond_32b

    .line 584
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v3

    int-to-float v2, v3

    goto :goto_330

    .line 586
    :cond_32b
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v3

    int-to-float v2, v3

    .line 588
    :goto_330
    iget-object v3, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v3, v3, p3

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v3

    int-to-float v3, v3

    add-float v3, v23, v3

    .line 589
    .end local v23    # "distance":F
    .local v3, "distance":F
    iget-object v6, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v6, v6, p3

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    iget-object v7, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    invoke-virtual {v6, v7, v3}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 591
    iget-object v6, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v7, p3, 0x1

    aget-object v6, v6, v7

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    iget-object v7, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    add-float v9, v3, v2

    invoke-virtual {v6, v7, v9}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 593
    iget-object v6, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v6, v6, p3

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v6, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 594
    iget-object v6, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v7, p3, 0x1

    aget-object v6, v6, v7

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v6

    invoke-virtual {v6, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 595
    add-float/2addr v3, v2

    .line 596
    iget-object v6, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v7, p3, 0x1

    aget-object v6, v6, v7

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    int-to-float v6, v6

    add-float v23, v3, v6

    .line 598
    .end local v2    # "dimension":F
    .end local v3    # "distance":F
    .restart local v23    # "distance":F
    :cond_37f
    move-object/from16 v11, v17

    .line 574
    move-object/from16 v3, v37

    move/from16 v2, v38

    move/from16 v7, v39

    goto/16 :goto_2ef

    .line 659
    .end local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v38    # "isChainPacked":Z
    .end local v39    # "numMatchConstraints":I
    .local v2, "isChainPacked":Z
    .local v3, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v7    # "numMatchConstraints":I
    :cond_389
    move/from16 v38, v2

    move/from16 v39, v7

    move/from16 v41, v0

    move-object v9, v3

    move/from16 v40, v34

    .line 659
    .end local v2    # "isChainPacked":Z
    .end local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v7    # "numMatchConstraints":I
    .restart local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v38    # "isChainPacked":Z
    .restart local v39    # "numMatchConstraints":I
    goto/16 :goto_4a8

    .line 600
    .end local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v38    # "isChainPacked":Z
    .end local v39    # "numMatchConstraints":I
    .restart local v2    # "isChainPacked":Z
    .restart local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v7    # "numMatchConstraints":I
    :cond_394
    move/from16 v38, v2

    move-object/from16 v37, v3

    move/from16 v39, v7

    .line 600
    .end local v2    # "isChainPacked":Z
    .end local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v7    # "numMatchConstraints":I
    .restart local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v38    # "isChainPacked":Z
    .restart local v39    # "numMatchConstraints":I
    if-nez v8, :cond_3a7

    if-eqz v22, :cond_39f

    goto :goto_3a7

    .line 659
    :cond_39f
    move/from16 v41, v0

    move/from16 v40, v34

    move-object/from16 v9, v37

    goto/16 :goto_4a8

    .line 601
    :cond_3a7
    :goto_3a7
    if-eqz v8, :cond_3ac

    .line 602
    sub-float v23, v23, v0

    goto :goto_3b0

    .line 603
    :cond_3ac
    if-eqz v22, :cond_3b0

    .line 604
    sub-float v23, v23, v0

    .line 606
    :cond_3b0
    :goto_3b0
    move-object/from16 v2, v37

    .line 607
    .end local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v9, v34, 0x1

    int-to-float v3, v9

    div-float v3, v23, v3

    .line 608
    .local v3, "gap":F
    if-eqz v22, :cond_3c9

    .line 609
    move/from16 v6, v34

    const/4 v7, 0x1

    if-le v6, v7, :cond_3c4

    .line 610
    .end local v34    # "numVisibleWidgets":I
    .local v6, "numVisibleWidgets":I
    add-int/lit8 v9, v6, -0x1

    int-to-float v7, v9

    div-float v3, v23, v7

    goto :goto_3cb

    .line 612
    :cond_3c4
    const/high16 v7, 0x40000000    # 2.0f

    div-float v3, v23, v7

    goto :goto_3cb

    .line 615
    .end local v6    # "numVisibleWidgets":I
    .restart local v34    # "numVisibleWidgets":I
    :cond_3c9
    move/from16 v6, v34

    .line 615
    .end local v34    # "numVisibleWidgets":I
    .restart local v6    # "numVisibleWidgets":I
    :goto_3cb
    move/from16 v7, v36

    .line 616
    .end local v23    # "distance":F
    .local v7, "distance":F
    move-object/from16 v9, v37

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v11

    .line 616
    .end local v37    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v9, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/16 v14, 0x8

    if-eq v11, v14, :cond_3d8

    .line 617
    add-float/2addr v7, v3

    .line 619
    :cond_3d8
    if-eqz v22, :cond_3e8

    const/4 v11, 0x1

    if-le v6, v11, :cond_3e8

    .line 620
    iget-object v11, v5, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v11, v11, p3

    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v11

    int-to-float v11, v11

    add-float v7, v36, v11

    .line 622
    :cond_3e8
    if-eqz v8, :cond_3f6

    .line 623
    if-eqz v5, :cond_3f6

    .line 624
    iget-object v11, v5, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v11, v11, p3

    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v11

    int-to-float v11, v11

    add-float/2addr v7, v11

    .line 627
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v7    # "distance":F
    .restart local v11    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v23    # "distance":F
    :cond_3f6
    move-object v11, v2

    move/from16 v23, v7

    :goto_3f9
    if-eqz v11, :cond_4a4

    .line 628
    sget-object v2, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v2, :cond_41a

    .line 629
    sget-object v2, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    move/from16 v40, v6

    iget-wide v6, v2, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 629
    .end local v6    # "numVisibleWidgets":I
    .local v40, "numVisibleWidgets":I
    sub-long v6, v6, v27

    iput-wide v6, v2, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 630
    sget-object v2, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v6, v2, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    add-long v6, v6, v27

    iput-wide v6, v2, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    .line 631
    sget-object v2, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v6, v2, Landroid/support/constraint/solver/Metrics;->chainConnectionResolved:J

    add-long v6, v6, v27

    iput-wide v6, v2, Landroid/support/constraint/solver/Metrics;->chainConnectionResolved:J

    goto :goto_41c

    .line 633
    .end local v40    # "numVisibleWidgets":I
    .restart local v6    # "numVisibleWidgets":I
    :cond_41a
    move/from16 v40, v6

    .line 633
    .end local v6    # "numVisibleWidgets":I
    .restart local v40    # "numVisibleWidgets":I
    :goto_41c
    iget-object v2, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aget-object v2, v2, v1

    .line 634
    .end local v17    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v2, "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-nez v2, :cond_42a

    if-ne v11, v4, :cond_425

    goto :goto_42a

    .line 655
    :cond_425
    move/from16 v41, v0

    .line 655
    .end local v0    # "extraMargin":F
    .local v41, "extraMargin":F
    :cond_427
    const/16 v1, 0x8

    goto :goto_499

    .line 635
    .end local v41    # "extraMargin":F
    .restart local v0    # "extraMargin":F
    :cond_42a
    :goto_42a
    const/4 v6, 0x0

    .line 636
    .local v6, "dimension":F
    if-nez v1, :cond_433

    .line 637
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v7

    int-to-float v6, v7

    goto :goto_438

    .line 639
    :cond_433
    invoke-virtual {v11}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v7

    int-to-float v6, v7

    .line 641
    :goto_438
    if-eq v11, v5, :cond_445

    .line 642
    iget-object v7, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v7, v7, p3

    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v7

    int-to-float v7, v7

    add-float v23, v23, v7

    .line 644
    .end local v23    # "distance":F
    .restart local v7    # "distance":F
    :cond_445
    move/from16 v7, v23

    iget-object v14, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v14, v14, p3

    invoke-virtual {v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v14

    move/from16 v41, v0

    iget-object v0, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    .line 644
    .end local v0    # "extraMargin":F
    .restart local v41    # "extraMargin":F
    invoke-virtual {v14, v0, v7}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 646
    iget-object v0, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v14, p3, 0x1

    aget-object v0, v0, v14

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    iget-object v14, v10, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    add-float v1, v7, v6

    invoke-virtual {v0, v14, v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolve(Landroid/support/constraint/solver/widgets/ResolutionAnchor;F)V

    .line 648
    iget-object v0, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v0, v0, p3

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    invoke-virtual {v0, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 649
    iget-object v0, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v1, p3, 0x1

    aget-object v0, v0, v1

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    invoke-virtual {v0, v13}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 650
    iget-object v0, v11, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v1, p3, 0x1

    aget-object v0, v0, v1

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v0

    int-to-float v0, v0

    add-float/2addr v0, v6

    add-float v23, v7, v0

    .line 651
    .end local v7    # "distance":F
    .restart local v23    # "distance":F
    if-eqz v2, :cond_427

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v0

    const/16 v1, 0x8

    if-eq v0, v1, :cond_499

    .line 652
    add-float v23, v23, v3

    .line 655
    .end local v6    # "dimension":F
    :cond_499
    :goto_499
    move-object v11, v2

    .line 627
    move-object/from16 v17, v2

    move/from16 v6, v40

    move/from16 v0, v41

    move/from16 v1, p2

    goto/16 :goto_3f9

    .line 659
    .end local v2    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v3    # "gap":F
    .end local v40    # "numVisibleWidgets":I
    .end local v41    # "extraMargin":F
    .restart local v0    # "extraMargin":F
    .local v6, "numVisibleWidgets":I
    .restart local v17    # "next":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_4a4
    move/from16 v41, v0

    move/from16 v40, v6

    .line 659
    .end local v0    # "extraMargin":F
    .end local v6    # "numVisibleWidgets":I
    .restart local v40    # "numVisibleWidgets":I
    .restart local v41    # "extraMargin":F
    :goto_4a8
    const/4 v0, 0x1

    return v0

    .line 493
    .end local v23    # "distance":F
    .end local v31    # "lastOffset":F
    .end local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v36    # "firstOffset":F
    .end local v38    # "isChainPacked":Z
    .end local v39    # "numMatchConstraints":I
    .end local v40    # "numVisibleWidgets":I
    .end local v41    # "extraMargin":F
    .local v2, "isChainPacked":Z
    .local v3, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v6, "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v7, "numMatchConstraints":I
    .local v9, "numVisibleWidgets":I
    .restart local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    :cond_4aa
    move/from16 v30, v2

    move-object/from16 v32, v6

    move/from16 v39, v7

    move/from16 v33, v8

    move/from16 v40, v9

    move-object/from16 v35, v13

    move-object/from16 v13, p1

    move-object v9, v3

    .line 493
    .end local v2    # "isChainPacked":Z
    .end local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v7    # "numMatchConstraints":I
    .end local v8    # "isChainSpread":Z
    .end local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .local v9, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v30    # "isChainPacked":Z
    .restart local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v33    # "isChainSpread":Z
    .restart local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v39    # "numMatchConstraints":I
    .restart local v40    # "numVisibleWidgets":I
    :goto_4b9
    return v16

    .line 486
    .end local v30    # "isChainPacked":Z
    .end local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v33    # "isChainSpread":Z
    .end local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .end local v39    # "numMatchConstraints":I
    .end local v40    # "numVisibleWidgets":I
    .restart local v2    # "isChainPacked":Z
    .restart local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v7    # "numMatchConstraints":I
    .restart local v8    # "isChainSpread":Z
    .local v9, "numVisibleWidgets":I
    .restart local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    :cond_4ba
    move/from16 v30, v2

    move-object/from16 v32, v6

    move/from16 v39, v7

    move/from16 v33, v8

    move/from16 v40, v9

    move-object/from16 v35, v13

    move-object v13, v0

    move-object v9, v3

    .line 486
    .end local v2    # "isChainPacked":Z
    .end local v3    # "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v6    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v7    # "numMatchConstraints":I
    .end local v8    # "isChainSpread":Z
    .end local v13    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .local v9, "first":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v30    # "isChainPacked":Z
    .restart local v32    # "lastVisibleWidget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v33    # "isChainSpread":Z
    .restart local v35    # "lastNode":Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .restart local v39    # "numMatchConstraints":I
    .restart local v40    # "numVisibleWidgets":I
    :goto_4c8
    return v16
.end method

.method static checkMatchParent(Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 8
    .param p0, "container"    # Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 57
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v3, 0x2

    if-eq v0, v2, :cond_46

    iget-object v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v0, v0, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_PARENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v1, :cond_46

    .line 60
    iget-object v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 61
    .local v0, "left":I
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getWidth()I

    move-result v1

    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    sub-int/2addr v1, v2

    .line 68
    .local v1, "right":I
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    iput-object v4, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    .line 69
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    iput-object v4, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    .line 70
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {p1, v2, v0}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;I)V

    .line 71
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {p1, v2, v1}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;I)V

    .line 72
    iput v3, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalResolution:I

    .line 74
    invoke-virtual {p2, v0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimension(II)V

    .line 76
    .end local v0    # "left":I
    .end local v1    # "right":I
    :cond_46
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v0, v2, :cond_ab

    iget-object v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v0, v0, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_PARENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v1, :cond_ab

    .line 79
    iget-object v0, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 80
    .local v0, "top":I
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->getHeight()I

    move-result v1

    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    sub-int/2addr v1, v2

    .line 87
    .local v1, "bottom":I
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    iput-object v4, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    .line 88
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    iput-object v4, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    .line 89
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {p1, v2, v0}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;I)V

    .line 90
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {p1, v2, v1}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;I)V

    .line 91
    iget v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-gtz v2, :cond_92

    invoke-virtual {p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v2

    const/16 v4, 0x8

    if-ne v2, v4, :cond_a6

    .line 92
    :cond_92
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    iput-object v4, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    .line 93
    iget-object v2, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    iget v4, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    add-int/2addr v4, v0

    invoke-virtual {p1, v2, v4}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;I)V

    .line 95
    :cond_a6
    iput v3, p2, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalResolution:I

    .line 97
    invoke-virtual {p2, v0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimension(II)V

    .line 99
    .end local v0    # "top":I
    .end local v1    # "bottom":I
    :cond_ab
    return-void
.end method

.method private static optimizableMatchConstraint(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)Z
    .registers 5
    .param p0, "constraintWidget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p1, "orientation"    # I

    .line 111
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v0, v0, p1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v2, 0x0

    if-eq v0, v1, :cond_a

    .line 112
    return v2

    .line 114
    :cond_a
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    const/4 v1, 0x1

    if-eqz v0, :cond_20

    .line 115
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-nez p1, :cond_17

    goto :goto_18

    :cond_17
    move v1, v2

    :goto_18
    aget-object v0, v0, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v1, :cond_1f

    .line 117
    return v2

    .line 120
    :cond_1f
    return v2

    .line 122
    :cond_20
    if-nez p1, :cond_30

    .line 123
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    if-eqz v0, :cond_27

    .line 124
    return v2

    .line 126
    :cond_27
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    if-nez v0, :cond_2f

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    if-eqz v0, :cond_3e

    .line 127
    :cond_2f
    return v2

    .line 130
    :cond_30
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    if-eqz v0, :cond_35

    .line 131
    return v2

    .line 133
    :cond_35
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    if-nez v0, :cond_3f

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    if-eqz v0, :cond_3e

    goto :goto_3f

    .line 137
    :cond_3e
    return v1

    .line 134
    :cond_3f
    :goto_3f
    return v2
.end method

.method static setOptimizedWidget(Landroid/support/constraint/solver/widgets/ConstraintWidget;II)V
    .registers 8
    .param p0, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p1, "orientation"    # I
    .param p2, "resolvedOffset"    # I

    .line 671
    mul-int/lit8 v0, p1, 0x2

    .line 672
    .local v0, "startOffset":I
    add-int/lit8 v1, v0, 0x1

    .line 674
    .local v1, "endOffset":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v0

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    .line 675
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v3

    iget-object v3, v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v3

    iput-object v3, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    .line 676
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v0

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    int-to-float v3, p2

    iput v3, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedOffset:F

    .line 678
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v0

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    const/4 v3, 0x1

    iput v3, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    .line 680
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v1

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v4, v4, v0

    .line 681
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v4

    iput-object v4, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedTarget:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    .line 682
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v1

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    .line 683
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getLength(I)I

    move-result v4

    int-to-float v4, v4

    iput v4, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->resolvedOffset:F

    .line 684
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v1

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v2

    iput v3, v2, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    .line 685
    return-void
.end method
