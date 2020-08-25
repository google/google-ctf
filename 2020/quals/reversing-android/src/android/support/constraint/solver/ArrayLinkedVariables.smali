.class public Landroid/support/constraint/solver/ArrayLinkedVariables;
.super Ljava/lang/Object;
.source "ArrayLinkedVariables.java"


# static fields
.field private static final DEBUG:Z = false

.field private static final FULL_NEW_CHECK:Z = false

.field private static final NONE:I = -0x1


# instance fields
.field private ROW_SIZE:I

.field private candidate:Landroid/support/constraint/solver/SolverVariable;

.field currentSize:I

.field private mArrayIndices:[I

.field private mArrayNextIndices:[I

.field private mArrayValues:[F

.field private final mCache:Landroid/support/constraint/solver/Cache;

.field private mDidFillOnce:Z

.field private mHead:I

.field private mLast:I

.field private final mRow:Landroid/support/constraint/solver/ArrayRow;


# direct methods
.method constructor <init>(Landroid/support/constraint/solver/ArrayRow;Landroid/support/constraint/solver/Cache;)V
    .registers 5
    .param p1, "arrayRow"    # Landroid/support/constraint/solver/ArrayRow;
    .param p2, "cache"    # Landroid/support/constraint/solver/Cache;

    .line 100
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 43
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 48
    const/16 v1, 0x8

    iput v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    .line 50
    const/4 v1, 0x0

    iput-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->candidate:Landroid/support/constraint/solver/SolverVariable;

    .line 53
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    new-array v1, v1, [I

    iput-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    .line 56
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    new-array v1, v1, [I

    iput-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    .line 59
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    new-array v1, v1, [F

    iput-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    .line 62
    const/4 v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 78
    iput v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 81
    iput-boolean v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 101
    iput-object p1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    .line 102
    iput-object p2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    .line 108
    return-void
.end method

.method private isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z
    .registers 5
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 491
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    const/4 v1, 0x1

    if-gt v0, v1, :cond_6

    goto :goto_7

    :cond_6
    const/4 v1, 0x0

    :goto_7
    return v1
.end method


# virtual methods
.method final add(Landroid/support/constraint/solver/SolverVariable;FZ)V
    .registers 14
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "value"    # F
    .param p3, "removeFromDefinition"    # Z

    .line 225
    const/4 v0, 0x0

    cmpl-float v1, p2, v0

    if-nez v1, :cond_6

    .line 226
    return-void

    .line 229
    :cond_6
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    const/4 v2, 0x0

    const/4 v3, -0x1

    const/4 v4, 0x1

    if-ne v1, v3, :cond_4b

    .line 230
    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 231
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    aput p2, v0, v1

    .line 232
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    iget v2, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    aput v2, v0, v1

    .line 233
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    aput v3, v0, v1

    .line 234
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    add-int/2addr v0, v4

    iput v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 235
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/SolverVariable;->addToRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 236
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    add-int/2addr v0, v4

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 237
    iget-boolean v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-nez v0, :cond_4a

    .line 239
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    add-int/2addr v0, v4

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 240
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v1, v1

    if-lt v0, v1, :cond_4a

    .line 241
    iput-boolean v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 242
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v0, v0

    sub-int/2addr v0, v4

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 245
    :cond_4a
    return-void

    .line 247
    :cond_4b
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 248
    .local v1, "current":I
    const/4 v5, -0x1

    .line 249
    .local v5, "previous":I
    move v6, v5

    move v5, v1

    move v1, v2

    .line 250
    .local v1, "counter":I
    .local v5, "current":I
    .local v6, "previous":I
    :goto_51
    if-eq v5, v3, :cond_a9

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v7, :cond_a9

    .line 251
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v7, v7, v5

    .line 252
    .local v7, "idx":I
    iget v8, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ne v7, v8, :cond_99

    .line 253
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v3, v2, v5

    add-float/2addr v3, p2

    aput v3, v2, v5

    .line 255
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v2, v2, v5

    cmpl-float v0, v2, v0

    if-nez v0, :cond_98

    .line 256
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    if-ne v5, v0, :cond_79

    .line 257
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v0, v5

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    goto :goto_81

    .line 259
    :cond_79
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v2, v2, v5

    aput v2, v0, v6

    .line 261
    :goto_81
    if-eqz p3, :cond_88

    .line 262
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 264
    :cond_88
    iget-boolean v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-eqz v0, :cond_8e

    .line 266
    iput v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 268
    :cond_8e
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    sub-int/2addr v0, v4

    iput v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 269
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    sub-int/2addr v0, v4

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 271
    :cond_98
    return-void

    .line 273
    :cond_99
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v8, v8, v5

    iget v9, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ge v8, v9, :cond_a2

    .line 274
    move v6, v5

    .line 276
    :cond_a2
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v5, v8, v5

    add-int/lit8 v1, v1, 0x1

    .line 277
    .end local v7    # "idx":I
    goto :goto_51

    .line 282
    :cond_a9
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    add-int/2addr v0, v4

    .line 283
    .local v0, "availableIndice":I
    iget-boolean v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-eqz v7, :cond_be

    .line 286
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    aget v7, v7, v8

    if-ne v7, v3, :cond_bb

    .line 287
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    goto :goto_be

    .line 289
    :cond_bb
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v0, v7

    .line 292
    :cond_be
    :goto_be
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v7, v7

    if-lt v0, v7, :cond_db

    .line 293
    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v8, v8

    if-ge v7, v8, :cond_db

    .line 295
    move v7, v2

    .line 295
    .local v7, "i":I
    :goto_cb
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v8, v8

    if-ge v7, v8, :cond_db

    .line 296
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v8, v8, v7

    if-ne v8, v3, :cond_d8

    .line 297
    move v0, v7

    .line 298
    goto :goto_db

    .line 295
    :cond_d8
    add-int/lit8 v7, v7, 0x1

    goto :goto_cb

    .line 304
    .end local v7    # "i":I
    :cond_db
    :goto_db
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v7, v7

    if-lt v0, v7, :cond_10d

    .line 305
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v0, v7

    .line 306
    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    mul-int/lit8 v7, v7, 0x2

    iput v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    .line 307
    iput-boolean v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 308
    add-int/lit8 v2, v0, -0x1

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 309
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([FI)[F

    move-result-object v2

    iput-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    .line 310
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v2

    iput-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    .line 311
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v2

    iput-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    .line 315
    :cond_10d
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v7, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    aput v7, v2, v0

    .line 316
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aput p2, v2, v0

    .line 317
    if-eq v6, v3, :cond_126

    .line 318
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v3, v3, v6

    aput v3, v2, v0

    .line 319
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aput v0, v2, v6

    goto :goto_12e

    .line 321
    :cond_126
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    aput v3, v2, v0

    .line 322
    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 324
    :goto_12e
    iget v2, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    add-int/2addr v2, v4

    iput v2, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 325
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/SolverVariable;->addToRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 326
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    add-int/2addr v2, v4

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 327
    iget-boolean v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-nez v2, :cond_146

    .line 329
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    add-int/2addr v2, v4

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 331
    :cond_146
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v3, v3

    if-lt v2, v3, :cond_155

    .line 332
    iput-boolean v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 333
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v2, v2

    sub-int/2addr v2, v4

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 335
    :cond_155
    return-void
.end method

.method chooseSubject(Landroid/support/constraint/solver/LinearSystem;)Landroid/support/constraint/solver/SolverVariable;
    .registers 19
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    move-object/from16 v0, p0

    .line 506
    move-object/from16 v1, p1

    const/4 v2, 0x0

    .line 507
    .local v2, "restrictedCandidate":Landroid/support/constraint/solver/SolverVariable;
    const/4 v3, 0x0

    .line 508
    .local v3, "unrestrictedCandidate":Landroid/support/constraint/solver/SolverVariable;
    const/4 v4, 0x0

    .line 509
    .local v4, "unrestrictedCandidateAmount":F
    const/4 v5, 0x0

    .line 510
    .local v5, "restrictedCandidateAmount":F
    const/4 v6, 0x0

    .line 511
    .local v6, "unrestrictedCandidateIsNew":Z
    const/4 v7, 0x0

    .line 512
    .local v7, "restrictedCandidateIsNew":Z
    iget v8, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 513
    .local v8, "current":I
    const/4 v9, 0x0

    .line 514
    .local v9, "counter":I
    const/4 v10, 0x0

    move v11, v7

    move v7, v6

    move v6, v5

    move v5, v4

    move-object v4, v2

    move v2, v10

    .line 515
    .local v2, "candidateAmount":F
    .local v4, "restrictedCandidate":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "unrestrictedCandidateAmount":F
    .local v6, "restrictedCandidateAmount":F
    .local v7, "unrestrictedCandidateIsNew":Z
    .local v11, "restrictedCandidateIsNew":Z
    :goto_14
    const/4 v12, -0x1

    if-eq v8, v12, :cond_a7

    iget v12, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v9, v12, :cond_a7

    .line 516
    iget-object v12, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v12, v12, v8

    .line 517
    .local v12, "amount":F
    const v13, 0x3a83126f    # 0.001f

    .line 518
    .local v13, "epsilon":F
    iget-object v14, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v14, v14, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v15, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v15, v15, v8

    aget-object v14, v14, v15

    .line 519
    .local v14, "variable":Landroid/support/constraint/solver/SolverVariable;
    cmpg-float v15, v12, v10

    if-gez v15, :cond_40

    .line 520
    neg-float v15, v13

    cmpl-float v15, v12, v15

    if-lez v15, :cond_4e

    .line 521
    iget-object v15, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aput v10, v15, v8

    .line 522
    const/4 v12, 0x0

    .line 523
    iget-object v15, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {v14, v15}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    goto :goto_4e

    .line 526
    :cond_40
    cmpg-float v15, v12, v13

    if-gez v15, :cond_4e

    .line 527
    iget-object v15, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aput v10, v15, v8

    .line 528
    const/4 v12, 0x0

    .line 529
    iget-object v15, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {v14, v15}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 532
    :cond_4e
    :goto_4e
    cmpl-float v15, v12, v10

    if-eqz v15, :cond_9f

    .line 533
    iget-object v15, v14, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v10, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    if-ne v15, v10, :cond_79

    .line 534
    if-nez v3, :cond_62

    .line 535
    move-object v3, v14

    .line 536
    move v5, v12

    .line 537
    invoke-direct {v0, v14, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v7

    .line 565
    :cond_60
    :goto_60
    const/4 v10, 0x0

    goto :goto_9f

    .line 538
    :cond_62
    cmpl-float v10, v5, v12

    if-lez v10, :cond_6d

    .line 539
    move-object v3, v14

    .line 540
    move v5, v12

    .line 541
    invoke-direct {v0, v14, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v7

    goto :goto_60

    .line 542
    :cond_6d
    if-nez v7, :cond_60

    invoke-direct {v0, v14, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v10

    if-eqz v10, :cond_60

    .line 543
    move-object v3, v14

    .line 544
    move v5, v12

    .line 545
    const/4 v7, 0x1

    goto :goto_60

    .line 547
    :cond_79
    if-nez v3, :cond_60

    .line 548
    const/4 v10, 0x0

    cmpg-float v15, v12, v10

    if-gez v15, :cond_9f

    .line 549
    if-nez v4, :cond_89

    .line 550
    move-object v4, v14

    .line 551
    move v6, v12

    .line 552
    invoke-direct {v0, v14, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v11

    goto :goto_9f

    .line 553
    :cond_89
    cmpl-float v15, v6, v12

    if-lez v15, :cond_94

    .line 554
    move-object v4, v14

    .line 555
    move v6, v12

    .line 556
    invoke-direct {v0, v14, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v11

    goto :goto_9f

    .line 557
    :cond_94
    if-nez v11, :cond_9f

    invoke-direct {v0, v14, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->isNew(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v15

    if-eqz v15, :cond_9f

    .line 558
    move-object v4, v14

    .line 559
    move v6, v12

    .line 560
    const/4 v11, 0x1

    .line 565
    :cond_9f
    :goto_9f
    iget-object v15, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v8, v15, v8

    add-int/lit8 v9, v9, 0x1

    .line 566
    .end local v12    # "amount":F
    .end local v13    # "epsilon":F
    .end local v14    # "variable":Landroid/support/constraint/solver/SolverVariable;
    goto/16 :goto_14

    .line 567
    :cond_a7
    if-eqz v3, :cond_aa

    .line 568
    return-object v3

    .line 570
    :cond_aa
    return-object v4
.end method

.method public final clear()V
    .registers 6

    .line 385
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 386
    .local v0, "current":I
    const/4 v1, 0x0

    move v2, v0

    move v0, v1

    .line 387
    .local v0, "counter":I
    .local v2, "current":I
    :goto_5
    const/4 v3, -0x1

    if-eq v2, v3, :cond_24

    iget v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v0, v4, :cond_24

    .line 388
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v3, v3, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v4, v4, v2

    aget-object v3, v3, v4

    .line 389
    .local v3, "variable":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v3, :cond_1d

    .line 390
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {v3, v4}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 392
    :cond_1d
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v2, v4, v2

    add-int/lit8 v0, v0, 0x1

    .line 393
    .end local v3    # "variable":Landroid/support/constraint/solver/SolverVariable;
    goto :goto_5

    .line 395
    :cond_24
    iput v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 396
    iput v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 397
    iput-boolean v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 398
    iput v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 399
    return-void
.end method

.method final containsKey(Landroid/support/constraint/solver/SolverVariable;)Z
    .registers 8
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;

    .line 408
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    const/4 v1, -0x1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_7

    .line 409
    return v2

    .line 411
    :cond_7
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 412
    .local v0, "current":I
    move v3, v0

    move v0, v2

    .line 413
    .local v0, "counter":I
    .local v3, "current":I
    :goto_b
    if-eq v3, v1, :cond_22

    iget v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v0, v4, :cond_22

    .line 414
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v4, v4, v3

    iget v5, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ne v4, v5, :cond_1b

    .line 415
    const/4 v1, 0x1

    return v1

    .line 417
    :cond_1b
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v3, v4, v3

    add-int/lit8 v0, v0, 0x1

    goto :goto_b

    .line 419
    :cond_22
    return v2
.end method

.method public display()V
    .registers 7

    .line 779
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 780
    .local v0, "count":I
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "{ "

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->print(Ljava/lang/String;)V

    .line 781
    const/4 v1, 0x0

    .line 781
    .local v1, "i":I
    :goto_a
    if-ge v1, v0, :cond_38

    .line 782
    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getVariable(I)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v2

    .line 783
    .local v2, "v":Landroid/support/constraint/solver/SolverVariable;
    if-nez v2, :cond_13

    .line 784
    goto :goto_35

    .line 786
    :cond_13
    sget-object v3, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v5, " = "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->getVariableValue(I)F

    move-result v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v5, " "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/io/PrintStream;->print(Ljava/lang/String;)V

    .line 781
    .end local v2    # "v":Landroid/support/constraint/solver/SolverVariable;
    :goto_35
    add-int/lit8 v1, v1, 0x1

    goto :goto_a

    .line 788
    .end local v1    # "i":I
    :cond_38
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, " }"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 789
    return-void
.end method

.method divideByAmount(F)V
    .registers 6
    .param p1, "amount"    # F

    .line 458
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 459
    .local v0, "current":I
    const/4 v1, 0x0

    .line 460
    .local v1, "counter":I
    :goto_3
    const/4 v2, -0x1

    if-eq v0, v2, :cond_18

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v2, :cond_18

    .line 461
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v3, v2, v0

    div-float/2addr v3, p1

    aput v3, v2, v0

    .line 462
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v2, v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    .line 464
    :cond_18
    return-void
.end method

.method public final get(Landroid/support/constraint/solver/SolverVariable;)F
    .registers 6
    .param p1, "v"    # Landroid/support/constraint/solver/SolverVariable;

    .line 759
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 760
    .local v0, "current":I
    const/4 v1, 0x0

    .line 761
    .local v1, "counter":I
    :goto_3
    const/4 v2, -0x1

    if-eq v0, v2, :cond_1e

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v2, :cond_1e

    .line 762
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v2, v2, v0

    iget v3, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ne v2, v3, :cond_17

    .line 763
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v2, v2, v0

    return v2

    .line 765
    :cond_17
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v2, v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    .line 767
    :cond_1e
    const/4 v2, 0x0

    return v2
.end method

.method getPivotCandidate()Landroid/support/constraint/solver/SolverVariable;
    .registers 7

    .line 668
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->candidate:Landroid/support/constraint/solver/SolverVariable;

    if-nez v0, :cond_33

    .line 670
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 671
    .local v0, "current":I
    const/4 v1, 0x0

    .line 672
    .local v1, "counter":I
    const/4 v2, 0x0

    .line 673
    .local v2, "pivot":Landroid/support/constraint/solver/SolverVariable;
    :goto_8
    const/4 v3, -0x1

    if-eq v0, v3, :cond_32

    iget v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v3, :cond_32

    .line 674
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v3, v3, v0

    const/4 v4, 0x0

    cmpg-float v3, v3, v4

    if-gez v3, :cond_2b

    .line 678
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v3, v3, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v4, v4, v0

    aget-object v3, v3, v4

    .line 679
    .local v3, "v":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v2, :cond_2a

    iget v4, v2, Landroid/support/constraint/solver/SolverVariable;->strength:I

    iget v5, v3, Landroid/support/constraint/solver/SolverVariable;->strength:I

    if-ge v4, v5, :cond_2b

    .line 680
    :cond_2a
    move-object v2, v3

    .line 683
    .end local v3    # "v":Landroid/support/constraint/solver/SolverVariable;
    :cond_2b
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v3, v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_8

    .line 685
    :cond_32
    return-object v2

    .line 687
    .end local v0    # "current":I
    .end local v1    # "counter":I
    .end local v2    # "pivot":Landroid/support/constraint/solver/SolverVariable;
    :cond_33
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->candidate:Landroid/support/constraint/solver/SolverVariable;

    return-object v0
.end method

.method getPivotCandidate([ZLandroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/SolverVariable;
    .registers 11
    .param p1, "avoid"    # [Z
    .param p2, "exclude"    # Landroid/support/constraint/solver/SolverVariable;

    .line 691
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 692
    .local v0, "current":I
    const/4 v1, 0x0

    .line 693
    .local v1, "counter":I
    const/4 v2, 0x0

    .line 694
    .local v2, "pivot":Landroid/support/constraint/solver/SolverVariable;
    const/4 v3, 0x0

    move-object v4, v2

    move v2, v1

    move v1, v0

    move v0, v3

    .line 695
    .local v0, "value":F
    .local v1, "current":I
    .local v2, "counter":I
    .local v4, "pivot":Landroid/support/constraint/solver/SolverVariable;
    :goto_9
    const/4 v5, -0x1

    if-eq v1, v5, :cond_49

    iget v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v2, v5, :cond_49

    .line 696
    iget-object v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v5, v5, v1

    cmpg-float v5, v5, v3

    if-gez v5, :cond_42

    .line 700
    iget-object v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v5, v5, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v6, v6, v1

    aget-object v5, v5, v6

    .line 701
    .local v5, "v":Landroid/support/constraint/solver/SolverVariable;
    if-eqz p1, :cond_2a

    iget v6, v5, Landroid/support/constraint/solver/SolverVariable;->id:I

    aget-boolean v6, p1, v6

    if-nez v6, :cond_42

    :cond_2a
    if-eq v5, p2, :cond_42

    .line 702
    iget-object v6, v5, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v7, Landroid/support/constraint/solver/SolverVariable$Type;->SLACK:Landroid/support/constraint/solver/SolverVariable$Type;

    if-eq v6, v7, :cond_38

    iget-object v6, v5, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v7, Landroid/support/constraint/solver/SolverVariable$Type;->ERROR:Landroid/support/constraint/solver/SolverVariable$Type;

    if-ne v6, v7, :cond_42

    .line 704
    :cond_38
    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v6, v6, v1

    .line 705
    .local v6, "currentValue":F
    cmpg-float v7, v6, v0

    if-gez v7, :cond_42

    .line 706
    move v0, v6

    .line 707
    move-object v4, v5

    .line 712
    .end local v5    # "v":Landroid/support/constraint/solver/SolverVariable;
    .end local v6    # "currentValue":F
    :cond_42
    iget-object v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v1, v5, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_9

    .line 714
    :cond_49
    return-object v4
.end method

.method final getVariable(I)Landroid/support/constraint/solver/SolverVariable;
    .registers 6
    .param p1, "index"    # I

    .line 724
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 725
    .local v0, "current":I
    const/4 v1, 0x0

    .line 726
    .local v1, "counter":I
    :goto_3
    const/4 v2, -0x1

    if-eq v0, v2, :cond_1e

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v2, :cond_1e

    .line 727
    if-ne v1, p1, :cond_17

    .line 728
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v2, v2, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v3, v3, v0

    aget-object v2, v2, v3

    return-object v2

    .line 730
    :cond_17
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v2, v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    .line 732
    :cond_1e
    const/4 v2, 0x0

    return-object v2
.end method

.method final getVariableValue(I)F
    .registers 5
    .param p1, "index"    # I

    .line 742
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 743
    .local v0, "current":I
    const/4 v1, 0x0

    .line 744
    .local v1, "counter":I
    :goto_3
    const/4 v2, -0x1

    if-eq v0, v2, :cond_18

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v2, :cond_18

    .line 745
    if-ne v1, p1, :cond_11

    .line 746
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v2, v2, v0

    return v2

    .line 748
    :cond_11
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v2, v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    .line 750
    :cond_18
    const/4 v2, 0x0

    return v2
.end method

.method hasAtLeastOnePositiveVariable()Z
    .registers 6

    .line 428
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 429
    .local v0, "current":I
    const/4 v1, 0x0

    move v2, v0

    move v0, v1

    .line 430
    .local v0, "counter":I
    .local v2, "current":I
    :goto_5
    const/4 v3, -0x1

    if-eq v2, v3, :cond_1e

    iget v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v0, v3, :cond_1e

    .line 431
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v3, v3, v2

    const/4 v4, 0x0

    cmpl-float v3, v3, v4

    if-lez v3, :cond_17

    .line 432
    const/4 v1, 0x1

    return v1

    .line 434
    :cond_17
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v2, v3, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_5

    .line 436
    :cond_1e
    return v1
.end method

.method invert()V
    .registers 6

    .line 443
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 444
    .local v0, "current":I
    const/4 v1, 0x0

    .line 445
    .local v1, "counter":I
    :goto_3
    const/4 v2, -0x1

    if-eq v0, v2, :cond_1a

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v1, v2, :cond_1a

    .line 446
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v3, v2, v0

    const/high16 v4, -0x40800000    # -1.0f

    mul-float/2addr v3, v4

    aput v3, v2, v0

    .line 447
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v2, v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    .line 449
    :cond_1a
    return-void
.end method

.method public final put(Landroid/support/constraint/solver/SolverVariable;F)V
    .registers 12
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "value"    # F

    .line 117
    const/4 v0, 0x0

    cmpl-float v0, p2, v0

    const/4 v1, 0x1

    if-nez v0, :cond_a

    .line 118
    invoke-virtual {p0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->remove(Landroid/support/constraint/solver/SolverVariable;Z)F

    .line 119
    return-void

    .line 122
    :cond_a
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    const/4 v2, 0x0

    const/4 v3, -0x1

    if-ne v0, v3, :cond_4e

    .line 123
    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 124
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    aput p2, v0, v2

    .line 125
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    iget v4, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    aput v4, v0, v2

    .line 126
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    aput v3, v0, v2

    .line 127
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    add-int/2addr v0, v1

    iput v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 128
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/SolverVariable;->addToRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 129
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    add-int/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 130
    iget-boolean v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-nez v0, :cond_4d

    .line 132
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    add-int/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 133
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v2, v2

    if-lt v0, v2, :cond_4d

    .line 134
    iput-boolean v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 135
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v0, v0

    sub-int/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 138
    :cond_4d
    return-void

    .line 140
    :cond_4e
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 141
    .local v0, "current":I
    const/4 v4, -0x1

    .line 142
    .local v4, "previous":I
    move v5, v4

    move v4, v0

    move v0, v2

    .line 143
    .local v0, "counter":I
    .local v4, "current":I
    .local v5, "previous":I
    :goto_54
    if-eq v4, v3, :cond_77

    iget v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v0, v6, :cond_77

    .line 144
    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v6, v6, v4

    iget v7, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ne v6, v7, :cond_67

    .line 145
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aput p2, v1, v4

    .line 146
    return-void

    .line 148
    :cond_67
    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v6, v6, v4

    iget v7, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ge v6, v7, :cond_70

    .line 149
    move v5, v4

    .line 151
    :cond_70
    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v4, v6, v4

    add-int/lit8 v0, v0, 0x1

    goto :goto_54

    .line 157
    :cond_77
    iget v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    add-int/2addr v6, v1

    .line 158
    .local v6, "availableIndice":I
    iget-boolean v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-eqz v7, :cond_8c

    .line 161
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    aget v7, v7, v8

    if-ne v7, v3, :cond_89

    .line 162
    iget v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    goto :goto_8c

    .line 164
    :cond_89
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v6, v7

    .line 167
    :cond_8c
    :goto_8c
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v7, v7

    if-lt v6, v7, :cond_a9

    .line 168
    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v8, v8

    if-ge v7, v8, :cond_a9

    .line 170
    move v7, v2

    .line 170
    .local v7, "i":I
    :goto_99
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v8, v8

    if-ge v7, v8, :cond_a9

    .line 171
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v8, v8, v7

    if-ne v8, v3, :cond_a6

    .line 172
    move v6, v7

    .line 173
    goto :goto_a9

    .line 170
    :cond_a6
    add-int/lit8 v7, v7, 0x1

    goto :goto_99

    .line 179
    .end local v7    # "i":I
    :cond_a9
    :goto_a9
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v7, v7

    if-lt v6, v7, :cond_db

    .line 180
    iget-object v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v6, v7

    .line 181
    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    mul-int/lit8 v7, v7, 0x2

    iput v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    .line 182
    iput-boolean v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 183
    add-int/lit8 v2, v6, -0x1

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 184
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([FI)[F

    move-result-object v2

    iput-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    .line 185
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v2

    iput-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    .line 186
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget v7, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->ROW_SIZE:I

    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v2

    iput-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    .line 190
    :cond_db
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    iget v7, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    aput v7, v2, v6

    .line 191
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aput p2, v2, v6

    .line 192
    if-eq v5, v3, :cond_f4

    .line 193
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v3, v3, v5

    aput v3, v2, v6

    .line 194
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aput v6, v2, v5

    goto :goto_fc

    .line 196
    :cond_f4
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    aput v3, v2, v6

    .line 197
    iput v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 199
    :goto_fc
    iget v2, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    add-int/2addr v2, v1

    iput v2, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 200
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/SolverVariable;->addToRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 201
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    add-int/2addr v2, v1

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 202
    iget-boolean v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-nez v2, :cond_114

    .line 204
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    add-int/2addr v2, v1

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 206
    :cond_114
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v3, v3

    if-lt v2, v3, :cond_11d

    .line 207
    iput-boolean v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 209
    :cond_11d
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v3, v3

    if-lt v2, v3, :cond_12c

    .line 210
    iput-boolean v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    .line 211
    iget-object v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v2, v2

    sub-int/2addr v2, v1

    iput v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 213
    :cond_12c
    return-void
.end method

.method public final remove(Landroid/support/constraint/solver/SolverVariable;Z)F
    .registers 10
    .param p1, "variable"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "removeFromDefinition"    # Z

    .line 345
    iget-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->candidate:Landroid/support/constraint/solver/SolverVariable;

    if-ne v0, p1, :cond_7

    .line 346
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->candidate:Landroid/support/constraint/solver/SolverVariable;

    .line 348
    :cond_7
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    const/4 v1, 0x0

    const/4 v2, -0x1

    if-ne v0, v2, :cond_e

    .line 349
    return v1

    .line 351
    :cond_e
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 352
    .local v0, "current":I
    const/4 v3, -0x1

    .line 353
    .local v3, "previous":I
    const/4 v4, 0x0

    .line 354
    .local v4, "counter":I
    :goto_12
    if-eq v0, v2, :cond_5d

    iget v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v4, v5, :cond_5d

    .line 355
    iget-object v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v5, v5, v0

    .line 356
    .local v5, "idx":I
    iget v6, p1, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ne v5, v6, :cond_55

    .line 357
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    if-ne v0, v1, :cond_2b

    .line 358
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v1, v1, v0

    iput v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    goto :goto_33

    .line 360
    :cond_2b
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v6, v6, v0

    aput v6, v1, v3

    .line 363
    :goto_33
    if-eqz p2, :cond_3a

    .line 364
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mRow:Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 366
    :cond_3a
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    add-int/lit8 v1, v1, -0x1

    iput v1, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 367
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    add-int/lit8 v1, v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    .line 368
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aput v2, v1, v0

    .line 369
    iget-boolean v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mDidFillOnce:Z

    if-eqz v1, :cond_50

    .line 371
    iput v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mLast:I

    .line 373
    :cond_50
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v1, v1, v0

    return v1

    .line 375
    :cond_55
    move v3, v0

    .line 376
    iget-object v6, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v0, v6, v0

    add-int/lit8 v4, v4, 0x1

    .line 377
    .end local v5    # "idx":I
    goto :goto_12

    .line 378
    :cond_5d
    return v1
.end method

.method sizeInBytes()I
    .registers 3

    .line 772
    const/4 v0, 0x0

    .line 773
    .local v0, "size":I
    iget-object v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    array-length v1, v1

    mul-int/lit8 v1, v1, 0x4

    mul-int/lit8 v1, v1, 0x3

    add-int/2addr v0, v1

    .line 774
    add-int/lit8 v0, v0, 0x24

    .line 775
    return v0
.end method

.method public toString()Ljava/lang/String;
    .registers 7

    .line 798
    const-string v0, ""

    .line 799
    .local v0, "result":Ljava/lang/String;
    iget v1, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 800
    .local v1, "current":I
    const/4 v2, 0x0

    .line 801
    .local v2, "counter":I
    :goto_5
    const/4 v3, -0x1

    if-eq v1, v3, :cond_55

    iget v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v2, v3, :cond_55

    .line 802
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " -> "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 803
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v4, v4, v1

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v4, " : "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 804
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v4, v4, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v5, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v5, v5, v1

    aget-object v4, v4, v5

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 805
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v1, v3, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_5

    .line 807
    :cond_55
    return-object v0
.end method

.method final updateFromRow(Landroid/support/constraint/solver/ArrayRow;Landroid/support/constraint/solver/ArrayRow;Z)V
    .registers 15
    .param p1, "self"    # Landroid/support/constraint/solver/ArrayRow;
    .param p2, "definition"    # Landroid/support/constraint/solver/ArrayRow;
    .param p3, "removeFromDefinition"    # Z

    .line 583
    iget v0, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 584
    .local v0, "current":I
    const/4 v1, 0x0

    move v2, v0

    move v0, v1

    .line 585
    .local v0, "counter":I
    .local v2, "current":I
    :goto_5
    const/4 v3, -0x1

    if-eq v2, v3, :cond_61

    iget v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v0, v4, :cond_61

    .line 586
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v4, v4, v2

    iget-object v5, p2, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iget v5, v5, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-ne v4, v5, :cond_5a

    .line 587
    iget-object v4, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v4, v4, v2

    .line 588
    .local v4, "value":F
    iget-object v5, p2, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {p0, v5, p3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->remove(Landroid/support/constraint/solver/SolverVariable;Z)F

    .line 590
    iget-object v5, p2, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    check-cast v5, Landroid/support/constraint/solver/ArrayLinkedVariables;

    .line 591
    .local v5, "definitionVariables":Landroid/support/constraint/solver/ArrayLinkedVariables;
    iget v6, v5, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 592
    .local v6, "definitionCurrent":I
    move v7, v6

    move v6, v1

    .line 593
    .local v6, "definitionCounter":I
    .local v7, "definitionCurrent":I
    :goto_27
    if-eq v7, v3, :cond_47

    iget v8, v5, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v6, v8, :cond_47

    .line 594
    iget-object v8, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v8, v8, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v9, v5, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v9, v9, v7

    aget-object v8, v8, v9

    .line 596
    .local v8, "definitionVariable":Landroid/support/constraint/solver/SolverVariable;
    iget-object v9, v5, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v9, v9, v7

    .line 597
    .local v9, "definitionValue":F
    mul-float v10, v9, v4

    invoke-virtual {p0, v8, v10, p3}, Landroid/support/constraint/solver/ArrayLinkedVariables;->add(Landroid/support/constraint/solver/SolverVariable;FZ)V

    .line 598
    iget-object v10, v5, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v7, v10, v7

    add-int/lit8 v6, v6, 0x1

    .line 599
    .end local v8    # "definitionVariable":Landroid/support/constraint/solver/SolverVariable;
    .end local v9    # "definitionValue":F
    goto :goto_27

    .line 600
    :cond_47
    iget v3, p1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    iget v8, p2, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    mul-float/2addr v8, v4

    add-float/2addr v3, v8

    iput v3, p1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 601
    if-eqz p3, :cond_56

    .line 602
    iget-object v3, p2, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v3, p1}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 608
    :cond_56
    iget v2, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 609
    const/4 v0, 0x0

    .line 610
    goto :goto_5

    .line 612
    .end local v4    # "value":F
    .end local v5    # "definitionVariables":Landroid/support/constraint/solver/ArrayLinkedVariables;
    .end local v6    # "definitionCounter":I
    .end local v7    # "definitionCurrent":I
    :cond_5a
    iget-object v3, p0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v2, v3, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_5

    .line 614
    :cond_61
    return-void
.end method

.method updateFromSystem(Landroid/support/constraint/solver/ArrayRow;[Landroid/support/constraint/solver/ArrayRow;)V
    .registers 19
    .param p1, "self"    # Landroid/support/constraint/solver/ArrayRow;
    .param p2, "rows"    # [Landroid/support/constraint/solver/ArrayRow;

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    .line 626
    iget v2, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 627
    .local v2, "current":I
    move v4, v2

    const/4 v2, 0x0

    .line 628
    .local v2, "counter":I
    .local v4, "current":I
    :goto_8
    const/4 v5, -0x1

    if-eq v4, v5, :cond_6d

    iget v6, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v2, v6, :cond_6d

    .line 629
    iget-object v6, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v6, v6, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v7, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v7, v7, v4

    aget-object v6, v6, v7

    .line 630
    .local v6, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget v7, v6, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    if-eq v7, v5, :cond_66

    .line 631
    iget-object v7, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v7, v7, v4

    .line 632
    .local v7, "value":F
    const/4 v8, 0x1

    invoke-virtual {v0, v6, v8}, Landroid/support/constraint/solver/ArrayLinkedVariables;->remove(Landroid/support/constraint/solver/SolverVariable;Z)F

    .line 634
    iget v9, v6, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    aget-object v9, p2, v9

    .line 635
    .local v9, "definition":Landroid/support/constraint/solver/ArrayRow;
    iget-boolean v10, v9, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-nez v10, :cond_55

    .line 636
    iget-object v10, v9, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    check-cast v10, Landroid/support/constraint/solver/ArrayLinkedVariables;

    .line 637
    .local v10, "definitionVariables":Landroid/support/constraint/solver/ArrayLinkedVariables;
    iget v11, v10, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 638
    .local v11, "definitionCurrent":I
    move v12, v11

    const/4 v11, 0x0

    .line 639
    .local v11, "definitionCounter":I
    .local v12, "definitionCurrent":I
    :goto_35
    if-eq v12, v5, :cond_55

    iget v13, v10, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-ge v11, v13, :cond_55

    .line 640
    iget-object v13, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v13, v13, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget-object v14, v10, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayIndices:[I

    aget v14, v14, v12

    aget-object v13, v13, v14

    .line 642
    .local v13, "definitionVariable":Landroid/support/constraint/solver/SolverVariable;
    iget-object v14, v10, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayValues:[F

    aget v14, v14, v12

    .line 643
    .local v14, "definitionValue":F
    mul-float v3, v14, v7

    invoke-virtual {v0, v13, v3, v8}, Landroid/support/constraint/solver/ArrayLinkedVariables;->add(Landroid/support/constraint/solver/SolverVariable;FZ)V

    .line 644
    iget-object v3, v10, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v12, v3, v12

    .line 645
    add-int/lit8 v11, v11, 0x1

    .line 646
    .end local v13    # "definitionVariable":Landroid/support/constraint/solver/SolverVariable;
    .end local v14    # "definitionValue":F
    goto :goto_35

    .line 648
    .end local v10    # "definitionVariables":Landroid/support/constraint/solver/ArrayLinkedVariables;
    .end local v11    # "definitionCounter":I
    .end local v12    # "definitionCurrent":I
    :cond_55
    iget v3, v1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    iget v5, v9, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    mul-float/2addr v5, v7

    add-float/2addr v3, v5

    iput v3, v1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    .line 649
    iget-object v3, v9, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v3, v1}, Landroid/support/constraint/solver/SolverVariable;->removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 654
    iget v4, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mHead:I

    .line 655
    const/4 v2, 0x0

    .line 656
    goto :goto_8

    .line 658
    .end local v7    # "value":F
    .end local v9    # "definition":Landroid/support/constraint/solver/ArrayRow;
    :cond_66
    iget-object v3, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->mArrayNextIndices:[I

    aget v4, v3, v4

    add-int/lit8 v2, v2, 0x1

    .line 659
    .end local v6    # "variable":Landroid/support/constraint/solver/SolverVariable;
    goto :goto_8

    .line 660
    :cond_6d
    return-void
.end method
