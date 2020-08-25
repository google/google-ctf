.class public Landroid/support/constraint/solver/ArrayRow;
.super Ljava/lang/Object;
.source "ArrayRow.java"

# interfaces
.implements Landroid/support/constraint/solver/LinearSystem$Row;


# static fields
.field private static final DEBUG:Z = false

.field private static final epsilon:F = 0.001f


# instance fields
.field constantValue:F

.field isSimpleDefinition:Z

.field used:Z

.field variable:Landroid/support/constraint/solver/SolverVariable;

.field public final variables:Landroid/support/constraint/solver/ArrayLinkedVariables;


# direct methods
.method public constructor <init>(Landroid/support/constraint/solver/Cache;)V
    .registers 3
    .param p1, "cache"    # Landroid/support/constraint/solver/Cache;

    .line 33
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 25
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 26
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/ArrayRow;->used:Z

    .line 31
    iput-boolean v0, p0, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    .line 34
    new-instance v0, Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-direct {v0, p0, p1}, Landroid/support/constraint/solver/ArrayLinkedVariables;-><init>(Landroid/support/constraint/solver/ArrayRow;Landroid/support/constraint/solver/Cache;)V

    iput-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    .line 35
    return-void
.end method


# virtual methods
.method public addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 6
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "strength"    # I

    .line 324
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const-string v1, "ep"

    invoke-virtual {p1, p2, v1}, Landroid/support/constraint/solver/LinearSystem;->createErrorVariable(ILjava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-virtual {v0, v1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 325
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const-string v1, "em"

    invoke-virtual {p1, p2, v1}, Landroid/support/constraint/solver/LinearSystem;->createErrorVariable(ILjava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    const/high16 v2, -0x40800000    # -1.0f

    invoke-virtual {v0, v1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 326
    return-object p0
.end method

.method public addError(Landroid/support/constraint/solver/SolverVariable;)V
    .registers 5
    .param p1, "error"    # Landroid/support/constraint/solver/SolverVariable;

    .line 480
    const/high16 v0, 0x3f800000    # 1.0f

    .line 481
    .local v0, "weight":F
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    const/4 v2, 0x1

    if-ne v1, v2, :cond_a

    .line 482
    const/high16 v0, 0x3f800000    # 1.0f

    goto :goto_2c

    .line 483
    :cond_a
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    const/4 v2, 0x2

    if-ne v1, v2, :cond_12

    .line 484
    const/high16 v0, 0x447a0000    # 1000.0f

    goto :goto_2c

    .line 485
    :cond_12
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    const/4 v2, 0x3

    if-ne v1, v2, :cond_1b

    .line 486
    const v0, 0x49742400    # 1000000.0f

    goto :goto_2c

    .line 487
    :cond_1b
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    const/4 v2, 0x4

    if-ne v1, v2, :cond_24

    .line 488
    const v0, 0x4e6e6b28    # 1.0E9f

    goto :goto_2c

    .line 489
    :cond_24
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    const/4 v2, 0x5

    if-ne v1, v2, :cond_2c

    .line 490
    const v0, 0x5368d4a5    # 1.0E12f

    .line 492
    :cond_2c
    :goto_2c
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p1, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 493
    return-void
.end method

.method addSingleError(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 5
    .param p1, "error"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "sign"    # I

    .line 153
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    int-to-float v1, p2

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 154
    return-object p0
.end method

.method chooseSubject(Landroid/support/constraint/solver/LinearSystem;)Z
    .registers 5
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 407
    const/4 v0, 0x0

    .line 408
    .local v0, "addedExtra":Z
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->chooseSubject(Landroid/support/constraint/solver/LinearSystem;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 409
    .local v1, "pivotCandidate":Landroid/support/constraint/solver/SolverVariable;
    if-nez v1, :cond_b

    .line 411
    const/4 v0, 0x1

    goto :goto_e

    .line 413
    :cond_b
    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/ArrayRow;->pivot(Landroid/support/constraint/solver/SolverVariable;)V

    .line 415
    :goto_e
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget v2, v2, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-nez v2, :cond_17

    .line 416
    const/4 v2, 0x1

    iput-boolean v2, p0, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    .line 418
    :cond_17
    return v0
.end method

.method public clear()V
    .registers 2

    .line 455
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->clear()V

    .line 456
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 457
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 458
    return-void
.end method

.method createRowCentering(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 12
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "marginA"    # I
    .param p4, "bias"    # F
    .param p5, "variableC"    # Landroid/support/constraint/solver/SolverVariable;
    .param p6, "variableD"    # Landroid/support/constraint/solver/SolverVariable;
    .param p7, "marginB"    # I

    .line 278
    const/high16 v0, 0x3f800000    # 1.0f

    if-ne p2, p5, :cond_16

    .line 282
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p1, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 283
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p6, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 284
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, -0x40000000    # -2.0f

    invoke-virtual {v0, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 285
    return-object p0

    .line 287
    :cond_16
    const/high16 v1, 0x3f000000    # 0.5f

    cmpl-float v1, p4, v1

    const/high16 v2, -0x40800000    # -1.0f

    if-nez v1, :cond_3c

    .line 294
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p1, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 295
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p2, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 296
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p5, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 297
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p6, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 298
    if-gtz p3, :cond_36

    if-lez p7, :cond_8b

    .line 299
    :cond_36
    neg-int v0, p3

    add-int/2addr v0, p7

    int-to-float v0, v0

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    goto :goto_8b

    .line 301
    :cond_3c
    const/4 v1, 0x0

    cmpg-float v1, p4, v1

    if-gtz v1, :cond_4f

    .line 303
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 304
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p2, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 305
    int-to-float v0, p3

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    goto :goto_8b

    .line 306
    :cond_4f
    cmpl-float v1, p4, v0

    if-ltz v1, :cond_61

    .line 308
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p5, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 309
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p6, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 310
    int-to-float v0, p7

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    goto :goto_8b

    .line 312
    :cond_61
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    sub-float v3, v0, p4

    mul-float/2addr v3, v0

    invoke-virtual {v1, p1, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 313
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    sub-float v3, v0, p4

    mul-float/2addr v3, v2

    invoke-virtual {v1, p2, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 314
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    mul-float/2addr v2, p4

    invoke-virtual {v1, p5, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 315
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    mul-float v2, p4, v0

    invoke-virtual {v1, p6, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 316
    if-gtz p3, :cond_82

    if-lez p7, :cond_8b

    .line 317
    :cond_82
    neg-int v1, p3

    int-to-float v1, v1

    sub-float/2addr v0, p4

    mul-float/2addr v1, v0

    int-to-float v0, p7

    mul-float/2addr v0, p4

    add-float/2addr v1, v0

    iput v1, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 320
    :cond_8b
    :goto_8b
    return-object p0
.end method

.method createRowDefinition(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 4
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "value"    # I

    .line 114
    iput-object p1, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 115
    int-to-float v0, p2

    iput v0, p1, Landroid/support/constraint/solver/SolverVariable;->computedValue:F

    .line 116
    int-to-float v0, p2

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 117
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    .line 118
    return-object p0
.end method

.method createRowDimensionPercent(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;
    .registers 7
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "variableC"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "percent"    # F

    .line 331
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, -0x40800000    # -1.0f

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 332
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, 0x3f800000    # 1.0f

    sub-float/2addr v1, p4

    invoke-virtual {v0, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 333
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p3, p4}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 334
    return-object p0
.end method

.method public createRowDimensionRatio(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;
    .registers 8
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "variableC"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "variableD"    # Landroid/support/constraint/solver/SolverVariable;
    .param p5, "ratio"    # F

    .line 351
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, -0x40800000    # -1.0f

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 352
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-virtual {v0, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 353
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p3, p5}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 354
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    neg-float v1, p5

    invoke-virtual {v0, p4, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 355
    return-object p0
.end method

.method public createRowEqualDimension(FFFLandroid/support/constraint/solver/SolverVariable;ILandroid/support/constraint/solver/SolverVariable;ILandroid/support/constraint/solver/SolverVariable;ILandroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 26
    .param p1, "currentWeight"    # F
    .param p2, "totalWeights"    # F
    .param p3, "nextWeight"    # F
    .param p4, "variableStartA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p5, "marginStartA"    # I
    .param p6, "variableEndA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p7, "marginEndA"    # I
    .param p8, "variableStartB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p9, "marginStartB"    # I
    .param p10, "variableEndB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p11, "marginEndB"    # I

    move-object v0, p0

    move-object/from16 v2, p4

    move/from16 v3, p5

    move-object/from16 v4, p6

    move-object/from16 v5, p8

    move/from16 v6, p9

    move-object/from16 v7, p10

    .line 251
    move/from16 v8, p11

    const/4 v9, 0x0

    cmpl-float v9, p2, v9

    if-eqz v9, :cond_45

    cmpl-float v9, p1, p3

    if-nez v9, :cond_19

    goto :goto_45

    .line 261
    :cond_19
    div-float v9, p1, p2

    .line 262
    .local v9, "cw":F
    div-float v12, p3, p2

    .line 263
    .local v12, "nw":F
    div-float v10, v9, v12

    .line 267
    .local v10, "w":F
    neg-int v11, v3

    sub-int v11, v11, p7

    int-to-float v11, v11

    int-to-float v1, v6

    mul-float/2addr v1, v10

    add-float/2addr v11, v1

    int-to-float v1, v8

    mul-float/2addr v1, v10

    add-float/2addr v11, v1

    iput v11, v0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 268
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v11, 0x3f800000    # 1.0f

    invoke-virtual {v1, v2, v11}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 269
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v11, -0x40800000    # -1.0f

    invoke-virtual {v1, v4, v11}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 270
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, v7, v10}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 271
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    neg-float v11, v10

    invoke-virtual {v1, v5, v11}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 271
    .end local v9    # "cw":F
    .end local v10    # "w":F
    .end local v12    # "nw":F
    goto :goto_65

    .line 255
    :cond_45
    :goto_45
    neg-int v1, v3

    sub-int v1, v1, p7

    add-int/2addr v1, v6

    add-int/2addr v1, v8

    int-to-float v1, v1

    iput v1, v0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 256
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v9, 0x3f800000    # 1.0f

    invoke-virtual {v1, v2, v9}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 257
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v10, -0x40800000    # -1.0f

    invoke-virtual {v1, v4, v10}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 258
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, v7, v9}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 259
    iget-object v1, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, v5, v10}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 273
    :goto_65
    return-object v0
.end method

.method public createRowEqualMatchDimensions(FFFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/ArrayRow;
    .registers 14
    .param p1, "currentWeight"    # F
    .param p2, "totalWeights"    # F
    .param p3, "nextWeight"    # F
    .param p4, "variableStartA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p5, "variableEndA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p6, "variableStartB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p7, "variableEndB"    # Landroid/support/constraint/solver/SolverVariable;

    .line 215
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 216
    cmpl-float v1, p2, v0

    const/high16 v2, -0x40800000    # -1.0f

    const/high16 v3, 0x3f800000    # 1.0f

    if-eqz v1, :cond_4a

    cmpl-float v1, p1, p3

    if-nez v1, :cond_10

    goto :goto_4a

    .line 224
    :cond_10
    cmpl-float v1, p1, v0

    if-nez v1, :cond_1f

    .line 225
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p4, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 226
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p5, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    goto :goto_5e

    .line 227
    :cond_1f
    cmpl-float v0, p3, v0

    if-nez v0, :cond_2e

    .line 228
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p6, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 229
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p7, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    goto :goto_5e

    .line 231
    :cond_2e
    div-float v0, p1, p2

    .line 232
    .local v0, "cw":F
    div-float v1, p3, p2

    .line 233
    .local v1, "nw":F
    div-float v4, v0, v1

    .line 237
    .local v4, "w":F
    iget-object v5, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v5, p4, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 238
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p5, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 239
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, p7, v4}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 240
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    neg-float v3, v4

    invoke-virtual {v2, p6, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 240
    .end local v0    # "cw":F
    .end local v1    # "nw":F
    .end local v4    # "w":F
    goto :goto_5e

    .line 219
    :cond_4a
    :goto_4a
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p4, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 220
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p5, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 221
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p7, v3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 222
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p6, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 243
    :goto_5e
    return-object p0
.end method

.method public createRowEquals(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 5
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "value"    # I

    .line 122
    if-gez p2, :cond_f

    .line 123
    mul-int/lit8 v0, p2, -0x1

    int-to-float v0, v0

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 124
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    goto :goto_19

    .line 126
    :cond_f
    int-to-float v0, p2

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 127
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, -0x40800000    # -1.0f

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 129
    :goto_19
    return-object p0
.end method

.method public createRowEquals(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 8
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I

    .line 133
    const/4 v0, 0x0

    .line 134
    .local v0, "inverse":Z
    if-eqz p3, :cond_c

    .line 135
    move v1, p3

    .line 136
    .local v1, "m":I
    if-gez v1, :cond_9

    .line 137
    mul-int/lit8 v1, v1, -0x1

    .line 138
    const/4 v0, 0x1

    .line 140
    :cond_9
    int-to-float v2, v1

    iput v2, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 142
    .end local v1    # "m":I
    :cond_c
    const/high16 v1, 0x3f800000    # 1.0f

    const/high16 v2, -0x40800000    # -1.0f

    if-nez v0, :cond_1d

    .line 143
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 144
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    goto :goto_27

    .line 146
    :cond_1d
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 147
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p2, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 149
    :goto_27
    return-object p0
.end method

.method public createRowGreaterThan(Landroid/support/constraint/solver/SolverVariable;ILandroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/ArrayRow;
    .registers 6
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # I
    .param p3, "slack"    # Landroid/support/constraint/solver/SolverVariable;

    .line 182
    int-to-float v0, p2

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 183
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, -0x40800000    # -1.0f

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 184
    return-object p0
.end method

.method public createRowGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 9
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "slack"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "margin"    # I

    .line 160
    const/4 v0, 0x0

    .line 161
    .local v0, "inverse":Z
    if-eqz p4, :cond_c

    .line 162
    move v1, p4

    .line 163
    .local v1, "m":I
    if-gez v1, :cond_9

    .line 164
    mul-int/lit8 v1, v1, -0x1

    .line 165
    const/4 v0, 0x1

    .line 167
    :cond_9
    int-to-float v2, v1

    iput v2, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 169
    .end local v1    # "m":I
    :cond_c
    const/high16 v1, 0x3f800000    # 1.0f

    const/high16 v2, -0x40800000    # -1.0f

    if-nez v0, :cond_22

    .line 170
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 171
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 172
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, p3, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    goto :goto_31

    .line 174
    :cond_22
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 175
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p2, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 176
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p3, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 178
    :goto_31
    return-object p0
.end method

.method public createRowLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;
    .registers 9
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "slack"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "margin"    # I

    .line 189
    const/4 v0, 0x0

    .line 190
    .local v0, "inverse":Z
    if-eqz p4, :cond_c

    .line 191
    move v1, p4

    .line 192
    .local v1, "m":I
    if-gez v1, :cond_9

    .line 193
    mul-int/lit8 v1, v1, -0x1

    .line 194
    const/4 v0, 0x1

    .line 196
    :cond_9
    int-to-float v2, v1

    iput v2, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 198
    .end local v1    # "m":I
    :cond_c
    const/high16 v1, 0x3f800000    # 1.0f

    const/high16 v2, -0x40800000    # -1.0f

    if-nez v0, :cond_22

    .line 199
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 200
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 201
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, p3, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    goto :goto_31

    .line 203
    :cond_22
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 204
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, p2, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 205
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, p3, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 207
    :goto_31
    return-object p0
.end method

.method public createRowWithAngle(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;
    .registers 8
    .param p1, "at"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "ab"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "bt"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "bb"    # Landroid/support/constraint/solver/SolverVariable;
    .param p5, "angleComponent"    # F

    .line 369
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, 0x3f000000    # 0.5f

    invoke-virtual {v0, p3, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 370
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p4, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 371
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/high16 v1, -0x41000000    # -0.5f

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 372
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 373
    neg-float v0, p5

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 374
    return-object p0
.end method

.method ensurePositiveConstant()V
    .registers 3

    .line 391
    iget v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    const/4 v1, 0x0

    cmpg-float v0, v0, v1

    if-gez v0, :cond_13

    .line 393
    iget v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    const/high16 v1, -0x40800000    # -1.0f

    mul-float/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 394
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->invert()V

    .line 396
    :cond_13
    return-void
.end method

.method public getKey()Landroid/support/constraint/solver/SolverVariable;
    .registers 2

    .line 497
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    return-object v0
.end method

.method public getPivotCandidate(Landroid/support/constraint/solver/LinearSystem;[Z)Landroid/support/constraint/solver/SolverVariable;
    .registers 5
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "avoid"    # [Z

    .line 450
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/4 v1, 0x0

    invoke-virtual {v0, p2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getPivotCandidate([ZLandroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    return-object v0
.end method

.method hasKeyVariable()Z
    .registers 3

    .line 38
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    if-eqz v0, :cond_15

    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iget-object v0, v0, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v1, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    if-eq v0, v1, :cond_13

    iget v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    const/4 v1, 0x0

    cmpg-float v0, v0, v1

    if-ltz v0, :cond_15

    :cond_13
    const/4 v0, 0x1

    goto :goto_16

    :cond_15
    const/4 v0, 0x0

    :goto_16
    return v0
.end method

.method hasVariable(Landroid/support/constraint/solver/SolverVariable;)Z
    .registers 3
    .param p1, "v"    # Landroid/support/constraint/solver/SolverVariable;

    .line 110
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->containsKey(Landroid/support/constraint/solver/SolverVariable;)Z

    move-result v0

    return v0
.end method

.method public initFromRow(Landroid/support/constraint/solver/LinearSystem$Row;)V
    .registers 8
    .param p1, "row"    # Landroid/support/constraint/solver/LinearSystem$Row;

    .line 466
    instance-of v0, p1, Landroid/support/constraint/solver/ArrayRow;

    if-eqz v0, :cond_2b

    .line 467
    move-object v0, p1

    check-cast v0, Landroid/support/constraint/solver/ArrayRow;

    .line 468
    .local v0, "copiedRow":Landroid/support/constraint/solver/ArrayRow;
    const/4 v1, 0x0

    iput-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 469
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->clear()V

    .line 470
    const/4 v1, 0x0

    .line 470
    .local v1, "i":I
    :goto_10
    iget-object v2, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget v2, v2, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v2, :cond_2b

    .line 471
    iget-object v2, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getVariable(I)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v2

    .line 472
    .local v2, "var":Landroid/support/constraint/solver/SolverVariable;
    iget-object v3, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v3, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getVariableValue(I)F

    move-result v3

    .line 473
    .local v3, "val":F
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/4 v5, 0x1

    invoke-virtual {v4, v2, v3, v5}, Landroid/support/constraint/solver/ArrayLinkedVariables;->add(Landroid/support/constraint/solver/SolverVariable;FZ)V

    .line 470
    .end local v2    # "var":Landroid/support/constraint/solver/SolverVariable;
    .end local v3    # "val":F
    add-int/lit8 v1, v1, 0x1

    goto :goto_10

    .line 476
    .end local v0    # "copiedRow":Landroid/support/constraint/solver/ArrayRow;
    .end local v1    # "i":I
    :cond_2b
    return-void
.end method

.method public isEmpty()Z
    .registers 3

    .line 445
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    if-nez v0, :cond_13

    iget v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-nez v0, :cond_13

    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget v0, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-nez v0, :cond_13

    const/4 v0, 0x1

    goto :goto_14

    :cond_13
    const/4 v0, 0x0

    :goto_14
    return v0
.end method

.method pickPivot(Landroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/SolverVariable;
    .registers 4
    .param p1, "exclude"    # Landroid/support/constraint/solver/SolverVariable;

    .line 422
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, p1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getPivotCandidate([ZLandroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    return-object v0
.end method

.method pivot(Landroid/support/constraint/solver/SolverVariable;)V
    .registers 5
    .param p1, "v"    # Landroid/support/constraint/solver/SolverVariable;

    .line 426
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    const/high16 v1, -0x40800000    # -1.0f

    if-eqz v0, :cond_10

    .line 428
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v0, v2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->put(Landroid/support/constraint/solver/SolverVariable;F)V

    .line 429
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 432
    :cond_10
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    const/4 v2, 0x1

    invoke-virtual {v0, p1, v2}, Landroid/support/constraint/solver/ArrayLinkedVariables;->remove(Landroid/support/constraint/solver/SolverVariable;Z)F

    move-result v0

    mul-float/2addr v0, v1

    .line 433
    .local v0, "amount":F
    iput-object p1, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 434
    const/high16 v1, 0x3f800000    # 1.0f

    cmpl-float v1, v0, v1

    if-nez v1, :cond_21

    .line 435
    return-void

    .line 437
    :cond_21
    iget v1, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    div-float/2addr v1, v0

    iput v1, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 438
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->divideByAmount(F)V

    .line 439
    return-void
.end method

.method public reset()V
    .registers 2

    .line 103
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 104
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->clear()V

    .line 105
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 106
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    .line 107
    return-void
.end method

.method sizeInBytes()I
    .registers 3

    .line 378
    const/4 v0, 0x0

    .line 379
    .local v0, "size":I
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    if-eqz v1, :cond_7

    .line 380
    add-int/lit8 v0, v0, 0x4

    .line 382
    :cond_7
    add-int/lit8 v0, v0, 0x4

    .line 383
    add-int/lit8 v0, v0, 0x4

    .line 385
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->sizeInBytes()I

    move-result v1

    add-int/2addr v0, v1

    .line 386
    return v0
.end method

.method toReadableString()Ljava/lang/String;
    .registers 12

    .line 50
    const-string v0, ""

    .line 51
    .local v0, "s":Ljava/lang/String;
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    if-nez v1, :cond_18

    .line 52
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "0"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    goto :goto_29

    .line 54
    :cond_18
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 56
    :goto_29
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " = "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 57
    const/4 v1, 0x0

    .line 58
    .local v1, "addedVariable":Z
    iget v2, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    const/4 v3, 0x0

    cmpl-float v2, v2, v3

    if-eqz v2, :cond_54

    .line 59
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v4, p0, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 60
    const/4 v1, 0x1

    .line 62
    :cond_54
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget v2, v2, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 63
    .local v2, "count":I
    const/4 v4, 0x0

    .line 63
    .local v4, "i":I
    :goto_59
    if-ge v4, v2, :cond_ea

    .line 64
    iget-object v5, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v5, v4}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getVariable(I)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v5

    .line 65
    .local v5, "v":Landroid/support/constraint/solver/SolverVariable;
    if-nez v5, :cond_65

    .line 66
    goto/16 :goto_e6

    .line 68
    :cond_65
    iget-object v6, p0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v6, v4}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getVariableValue(I)F

    move-result v6

    .line 69
    .local v6, "amount":F
    cmpl-float v7, v6, v3

    if-nez v7, :cond_71

    .line 70
    goto/16 :goto_e6

    .line 72
    :cond_71
    invoke-virtual {v5}, Landroid/support/constraint/solver/SolverVariable;->toString()Ljava/lang/String;

    move-result-object v7

    .line 73
    .local v7, "name":Ljava/lang/String;
    const/high16 v8, -0x40800000    # -1.0f

    if-nez v1, :cond_90

    .line 74
    cmpg-float v9, v6, v3

    if-gez v9, :cond_b8

    .line 75
    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v10, "- "

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 76
    mul-float/2addr v6, v8

    goto :goto_b8

    .line 79
    :cond_90
    cmpl-float v9, v6, v3

    if-lez v9, :cond_a6

    .line 80
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v9, " + "

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    goto :goto_b8

    .line 82
    :cond_a6
    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v10, " - "

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 83
    mul-float/2addr v6, v8

    .line 86
    :cond_b8
    :goto_b8
    const/high16 v8, 0x3f800000    # 1.0f

    cmpl-float v8, v6, v8

    if-nez v8, :cond_ce

    .line 87
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    goto :goto_e5

    .line 89
    :cond_ce
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v9, " "

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 91
    :goto_e5
    const/4 v1, 0x1

    .line 63
    .end local v5    # "v":Landroid/support/constraint/solver/SolverVariable;
    .end local v6    # "amount":F
    .end local v7    # "name":Ljava/lang/String;
    :goto_e6
    add-int/lit8 v4, v4, 0x1

    goto/16 :goto_59

    .line 93
    .end local v4    # "i":I
    :cond_ea
    if-nez v1, :cond_fd

    .line 94
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, "0.0"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 99
    :cond_fd
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .registers 2

    .line 46
    invoke-virtual {p0}, Landroid/support/constraint/solver/ArrayRow;->toReadableString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
