.class public Landroid/support/constraint/solver/LinearSystem;
.super Ljava/lang/Object;
.source "LinearSystem.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/solver/LinearSystem$Row;
    }
.end annotation


# static fields
.field private static final DEBUG:Z = false

.field public static final FULL_DEBUG:Z = false

.field private static POOL_SIZE:I

.field public static sMetrics:Landroid/support/constraint/solver/Metrics;


# instance fields
.field private TABLE_SIZE:I

.field public graphOptimizer:Z

.field private mAlreadyTestedCandidates:[Z

.field final mCache:Landroid/support/constraint/solver/Cache;

.field private mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

.field private mMaxColumns:I

.field private mMaxRows:I

.field mNumColumns:I

.field mNumRows:I

.field private mPoolVariables:[Landroid/support/constraint/solver/SolverVariable;

.field private mPoolVariablesCount:I

.field mRows:[Landroid/support/constraint/solver/ArrayRow;

.field private final mTempGoal:Landroid/support/constraint/solver/LinearSystem$Row;

.field private mVariables:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Landroid/support/constraint/solver/SolverVariable;",
            ">;"
        }
    .end annotation
.end field

.field mVariablesID:I

.field private tempClientsCopy:[Landroid/support/constraint/solver/ArrayRow;


# direct methods
.method static constructor <clinit>()V
    .registers 1

    .line 37
    const/16 v0, 0x3e8

    sput v0, Landroid/support/constraint/solver/LinearSystem;->POOL_SIZE:I

    return-void
.end method

.method public constructor <init>()V
    .registers 4

    .line 78
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 42
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 47
    const/4 v1, 0x0

    iput-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    .line 54
    const/16 v2, 0x20

    iput v2, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    .line 55
    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    iput v2, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    .line 56
    iput-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    .line 59
    iput-boolean v0, p0, Landroid/support/constraint/solver/LinearSystem;->graphOptimizer:Z

    .line 62
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    new-array v1, v1, [Z

    iput-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    .line 64
    const/4 v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 65
    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    .line 66
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxRows:I

    .line 70
    sget v1, Landroid/support/constraint/solver/LinearSystem;->POOL_SIZE:I

    new-array v1, v1, [Landroid/support/constraint/solver/SolverVariable;

    iput-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariables:[Landroid/support/constraint/solver/SolverVariable;

    .line 71
    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariablesCount:I

    .line 73
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    new-array v0, v0, [Landroid/support/constraint/solver/ArrayRow;

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->tempClientsCopy:[Landroid/support/constraint/solver/ArrayRow;

    .line 79
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    new-array v0, v0, [Landroid/support/constraint/solver/ArrayRow;

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    .line 80
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->releaseRows()V

    .line 81
    new-instance v0, Landroid/support/constraint/solver/Cache;

    invoke-direct {v0}, Landroid/support/constraint/solver/Cache;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    .line 82
    new-instance v0, Landroid/support/constraint/solver/GoalRow;

    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    invoke-direct {v0, v1}, Landroid/support/constraint/solver/GoalRow;-><init>(Landroid/support/constraint/solver/Cache;)V

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    .line 83
    new-instance v0, Landroid/support/constraint/solver/ArrayRow;

    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    invoke-direct {v0, v1}, Landroid/support/constraint/solver/ArrayRow;-><init>(Landroid/support/constraint/solver/Cache;)V

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mTempGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    .line 84
    return-void
.end method

.method private acquireSolverVariable(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)Landroid/support/constraint/solver/SolverVariable;
    .registers 7
    .param p1, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;
    .param p2, "prefix"    # Ljava/lang/String;

    .line 305
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v0, v0, Landroid/support/constraint/solver/Cache;->solverVariablePool:Landroid/support/constraint/solver/Pools$Pool;

    invoke-interface {v0}, Landroid/support/constraint/solver/Pools$Pool;->acquire()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/SolverVariable;

    .line 306
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    if-nez v0, :cond_16

    .line 307
    new-instance v1, Landroid/support/constraint/solver/SolverVariable;

    invoke-direct {v1, p1, p2}, Landroid/support/constraint/solver/SolverVariable;-><init>(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)V

    move-object v0, v1

    .line 308
    invoke-virtual {v0, p1, p2}, Landroid/support/constraint/solver/SolverVariable;->setType(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)V

    goto :goto_1c

    .line 310
    :cond_16
    invoke-virtual {v0}, Landroid/support/constraint/solver/SolverVariable;->reset()V

    .line 311
    invoke-virtual {v0, p1, p2}, Landroid/support/constraint/solver/SolverVariable;->setType(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)V

    .line 313
    :goto_1c
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariablesCount:I

    sget v2, Landroid/support/constraint/solver/LinearSystem;->POOL_SIZE:I

    if-lt v1, v2, :cond_34

    .line 314
    sget v1, Landroid/support/constraint/solver/LinearSystem;->POOL_SIZE:I

    mul-int/lit8 v1, v1, 0x2

    sput v1, Landroid/support/constraint/solver/LinearSystem;->POOL_SIZE:I

    .line 315
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariables:[Landroid/support/constraint/solver/SolverVariable;

    sget v2, Landroid/support/constraint/solver/LinearSystem;->POOL_SIZE:I

    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Landroid/support/constraint/solver/SolverVariable;

    iput-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariables:[Landroid/support/constraint/solver/SolverVariable;

    .line 317
    :cond_34
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariablesCount:I

    add-int/lit8 v3, v2, 0x1

    iput v3, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariablesCount:I

    aput-object v0, v1, v2

    .line 318
    return-object v0
.end method

.method private addError(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 3
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;

    .line 241
    const/4 v0, 0x0

    invoke-virtual {p1, p0, v0}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    .line 242
    return-void
.end method

.method private final addRow(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 5
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;

    .line 538
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    aget-object v0, v0, v1

    if-eqz v0, :cond_15

    .line 539
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v0, v0, Landroid/support/constraint/solver/Cache;->arrayRowPool:Landroid/support/constraint/solver/Pools$Pool;

    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    aget-object v1, v1, v2

    invoke-interface {v0, v1}, Landroid/support/constraint/solver/Pools$Pool;->release(Ljava/lang/Object;)Z

    .line 541
    :cond_15
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    aput-object p1, v0, v1

    .line 542
    iget-object v0, p1, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    iput v1, v0, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 543
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    .line 544
    iget-object v0, p1, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/SolverVariable;->updateReferencesWithNewDefinition(Landroid/support/constraint/solver/ArrayRow;)V

    .line 550
    return-void
.end method

.method private addSingleError(Landroid/support/constraint/solver/ArrayRow;I)V
    .registers 4
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;
    .param p2, "sign"    # I

    .line 245
    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2, v0}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;II)V

    .line 246
    return-void
.end method

.method private computeValues()V
    .registers 5

    .line 847
    const/4 v0, 0x0

    .line 847
    .local v0, "i":I
    :goto_1
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v0, v1, :cond_12

    .line 848
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v1, v1, v0

    .line 849
    .local v1, "row":Landroid/support/constraint/solver/ArrayRow;
    iget-object v2, v1, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iget v3, v1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    iput v3, v2, Landroid/support/constraint/solver/SolverVariable;->computedValue:F

    .line 847
    .end local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 851
    .end local v0    # "i":I
    :cond_12
    return-void
.end method

.method public static createRowCentering(Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IZ)Landroid/support/constraint/solver/ArrayRow;
    .registers 18
    .param p0, "linearSystem"    # Landroid/support/constraint/solver/LinearSystem;
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "marginA"    # I
    .param p4, "bias"    # F
    .param p5, "variableC"    # Landroid/support/constraint/solver/SolverVariable;
    .param p6, "variableD"    # Landroid/support/constraint/solver/SolverVariable;
    .param p7, "marginB"    # I
    .param p8, "withError"    # Z

    .line 1297
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v8

    .line 1298
    .local v8, "row":Landroid/support/constraint/solver/ArrayRow;
    move-object v0, v8

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move v4, p4

    move-object v5, p5

    move-object v6, p6

    move/from16 v7, p7

    invoke-virtual/range {v0 .. v7}, Landroid/support/constraint/solver/ArrayRow;->createRowCentering(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1300
    if-eqz p8, :cond_18

    .line 1301
    const/4 v1, 0x4

    move-object v2, p0

    invoke-virtual {v8, v2, v1}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    goto :goto_19

    .line 1315
    :cond_18
    move-object v2, p0

    :goto_19
    return-object v8
.end method

.method public static createRowDimensionPercent(Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;FZ)Landroid/support/constraint/solver/ArrayRow;
    .registers 8
    .param p0, "linearSystem"    # Landroid/support/constraint/solver/LinearSystem;
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "variableC"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "percent"    # F
    .param p5, "withError"    # Z

    .line 1230
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1231
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    if-eqz p5, :cond_9

    .line 1232
    invoke-direct {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addError(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1234
    :cond_9
    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/support/constraint/solver/ArrayRow;->createRowDimensionPercent(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    return-object v1
.end method

.method public static createRowEquals(Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IZ)Landroid/support/constraint/solver/ArrayRow;
    .registers 7
    .param p0, "linearSystem"    # Landroid/support/constraint/solver/LinearSystem;
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I
    .param p4, "withError"    # Z

    .line 1201
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1202
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v0, p1, p2, p3}, Landroid/support/constraint/solver/ArrayRow;->createRowEquals(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1203
    if-eqz p4, :cond_d

    .line 1204
    const/4 v1, 0x1

    invoke-direct {p0, v0, v1}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;I)V

    .line 1215
    :cond_d
    return-object v0
.end method

.method public static createRowGreaterThan(Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IZ)Landroid/support/constraint/solver/ArrayRow;
    .registers 9
    .param p0, "linearSystem"    # Landroid/support/constraint/solver/LinearSystem;
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I
    .param p4, "withError"    # Z

    .line 1242
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 1243
    .local v0, "slack":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    .line 1244
    .local v1, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v1, p1, p2, v0, p3}, Landroid/support/constraint/solver/ArrayRow;->createRowGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1245
    if-eqz p4, :cond_1a

    .line 1246
    iget-object v2, v1, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v2

    .line 1247
    .local v2, "slackValue":F
    const/high16 v3, -0x40800000    # -1.0f

    mul-float/2addr v3, v2

    float-to-int v3, v3

    invoke-direct {p0, v1, v3}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;I)V

    .line 1260
    .end local v2    # "slackValue":F
    :cond_1a
    return-object v1
.end method

.method public static createRowLowerThan(Landroid/support/constraint/solver/LinearSystem;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IZ)Landroid/support/constraint/solver/ArrayRow;
    .registers 9
    .param p0, "linearSystem"    # Landroid/support/constraint/solver/LinearSystem;
    .param p1, "variableA"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "variableB"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I
    .param p4, "withError"    # Z

    .line 1268
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 1269
    .local v0, "slack":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    .line 1270
    .local v1, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v1, p1, p2, v0, p3}, Landroid/support/constraint/solver/ArrayRow;->createRowLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1271
    if-eqz p4, :cond_1a

    .line 1272
    iget-object v2, v1, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v0}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v2

    .line 1273
    .local v2, "slackValue":F
    const/high16 v3, -0x40800000    # -1.0f

    mul-float/2addr v3, v2

    float-to-int v3, v3

    invoke-direct {p0, v1, v3}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;I)V

    .line 1286
    .end local v2    # "slackValue":F
    :cond_1a
    return-object v1
.end method

.method private createVariable(Ljava/lang/String;Landroid/support/constraint/solver/SolverVariable$Type;)Landroid/support/constraint/solver/SolverVariable;
    .registers 8
    .param p1, "name"    # Ljava/lang/String;
    .param p2, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;

    .line 263
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_d

    .line 264
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v0, Landroid/support/constraint/solver/Metrics;->variables:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->variables:J

    .line 266
    :cond_d
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    if-lt v0, v1, :cond_18

    .line 267
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->increaseTableSize()V

    .line 269
    :cond_18
    const/4 v0, 0x0

    invoke-direct {p0, p2, v0}, Landroid/support/constraint/solver/LinearSystem;->acquireSolverVariable(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 270
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/SolverVariable;->setName(Ljava/lang/String;)V

    .line 271
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 272
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 273
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    iput v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 274
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    if-nez v1, :cond_3b

    .line 275
    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    iput-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    .line 277
    :cond_3b
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 278
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    aput-object v0, v1, v2

    .line 279
    return-object v0
.end method

.method private displayRows()V
    .registers 5

    .line 859
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->displaySolverVariables()V

    .line 860
    const-string v0, ""

    .line 861
    .local v0, "s":Ljava/lang/String;
    const/4 v1, 0x0

    .line 861
    .local v1, "i":I
    :goto_6
    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v1, v2, :cond_31

    .line 862
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v3, v3, v1

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 863
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\n"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 861
    add-int/lit8 v1, v1, 0x1

    goto :goto_6

    .line 865
    .end local v1    # "i":I
    :cond_31
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\n"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 866
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 867
    return-void
.end method

.method private displaySolverVariables()V
    .registers 3

    .line 941
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Display Rows ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "x"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ")\n"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 951
    .local v0, "s":Ljava/lang/String;
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 952
    return-void
.end method

.method private enforceBFS(Landroid/support/constraint/solver/LinearSystem$Row;)I
    .registers 19
    .param p1, "goal"    # Landroid/support/constraint/solver/LinearSystem$Row;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    move-object/from16 v0, p0

    .line 700
    const/4 v1, 0x0

    .line 712
    .local v1, "tries":I
    const/4 v2, 0x0

    .line 713
    .local v2, "infeasibleSystem":Z
    const/4 v4, 0x0

    .line 713
    .local v4, "i":I
    :goto_5
    iget v5, v0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    const/4 v6, 0x0

    if-ge v4, v5, :cond_26

    .line 714
    iget-object v5, v0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v5, v5, v4

    iget-object v5, v5, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 715
    .local v5, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget-object v7, v5, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v8, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    if-ne v7, v8, :cond_17

    .line 716
    goto :goto_23

    .line 718
    :cond_17
    iget-object v7, v0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v7, v7, v4

    iget v7, v7, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    cmpg-float v7, v7, v6

    if-gez v7, :cond_23

    .line 719
    const/4 v2, 0x1

    .line 720
    goto :goto_26

    .line 713
    .end local v5    # "variable":Landroid/support/constraint/solver/SolverVariable;
    :cond_23
    :goto_23
    add-int/lit8 v4, v4, 0x1

    goto :goto_5

    .line 725
    .end local v4    # "i":I
    :cond_26
    :goto_26
    if-eqz v2, :cond_d3

    .line 733
    const/4 v4, 0x0

    .line 734
    .local v4, "done":Z
    const/4 v1, 0x0

    .line 735
    :goto_2a
    if-nez v4, :cond_d3

    .line 736
    sget-object v5, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    const-wide/16 v7, 0x1

    if-eqz v5, :cond_39

    .line 737
    sget-object v5, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v9, v5, Landroid/support/constraint/solver/Metrics;->bfs:J

    add-long/2addr v9, v7

    iput-wide v9, v5, Landroid/support/constraint/solver/Metrics;->bfs:J

    .line 739
    :cond_39
    add-int/lit8 v1, v1, 0x1

    .line 743
    const v5, 0x7f7fffff    # Float.MAX_VALUE

    .line 744
    .local v5, "min":F
    const/4 v9, 0x0

    .line 745
    .local v9, "strength":I
    const/4 v10, -0x1

    .line 746
    .local v10, "pivotRowIndex":I
    const/4 v11, -0x1

    .line 748
    .local v11, "pivotColumnIndex":I
    move v12, v9

    move v9, v5

    const/4 v5, 0x0

    .line 748
    .local v5, "i":I
    .local v9, "min":F
    .local v12, "strength":I
    :goto_44
    iget v13, v0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v5, v13, :cond_9c

    .line 749
    iget-object v13, v0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v13, v13, v5

    .line 750
    .local v13, "current":Landroid/support/constraint/solver/ArrayRow;
    iget-object v14, v13, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 751
    .local v14, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget-object v15, v14, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v3, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    if-ne v15, v3, :cond_55

    .line 754
    goto :goto_96

    .line 756
    :cond_55
    iget-boolean v3, v13, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-eqz v3, :cond_5a

    .line 757
    goto :goto_96

    .line 759
    :cond_5a
    iget v3, v13, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    cmpg-float v3, v3, v6

    if-gez v3, :cond_96

    .line 764
    const/4 v3, 0x1

    .line 764
    .local v3, "j":I
    :goto_61
    iget v15, v0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    if-ge v3, v15, :cond_96

    .line 765
    iget-object v15, v0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v15, v15, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    aget-object v15, v15, v3

    .line 766
    .local v15, "candidate":Landroid/support/constraint/solver/SolverVariable;
    iget-object v7, v13, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v7, v15}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v7

    .line 767
    .local v7, "a_j":F
    cmpg-float v8, v7, v6

    if-gtz v8, :cond_76

    .line 768
    goto :goto_90

    .line 773
    :cond_76
    const/4 v8, 0x0

    .line 773
    .local v8, "k":I
    :goto_77
    const/4 v6, 0x7

    if-ge v8, v6, :cond_90

    .line 774
    iget-object v6, v15, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    aget v6, v6, v8

    div-float/2addr v6, v7

    .line 775
    .local v6, "value":F
    cmpg-float v16, v6, v9

    if-gez v16, :cond_85

    if-eq v8, v12, :cond_87

    :cond_85
    if-le v8, v12, :cond_8c

    .line 776
    :cond_87
    move v9, v6

    .line 777
    move v10, v5

    .line 778
    move v11, v3

    .line 779
    move v6, v8

    .line 773
    .end local v12    # "strength":I
    .local v6, "strength":I
    move v12, v6

    .line 773
    .end local v6    # "strength":I
    .restart local v12    # "strength":I
    :cond_8c
    add-int/lit8 v8, v8, 0x1

    const/4 v6, 0x0

    goto :goto_77

    .line 764
    .end local v7    # "a_j":F
    .end local v8    # "k":I
    .end local v15    # "candidate":Landroid/support/constraint/solver/SolverVariable;
    :cond_90
    :goto_90
    add-int/lit8 v3, v3, 0x1

    const/4 v6, 0x0

    const-wide/16 v7, 0x1

    goto :goto_61

    .line 748
    .end local v3    # "j":I
    .end local v13    # "current":Landroid/support/constraint/solver/ArrayRow;
    .end local v14    # "variable":Landroid/support/constraint/solver/SolverVariable;
    :cond_96
    :goto_96
    add-int/lit8 v5, v5, 0x1

    const/4 v6, 0x0

    const-wide/16 v7, 0x1

    goto :goto_44

    .line 786
    .end local v5    # "i":I
    :cond_9c
    const/4 v3, -0x1

    if-eq v10, v3, :cond_c7

    .line 788
    iget-object v5, v0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v5, v5, v10

    .line 793
    .local v5, "pivotEquation":Landroid/support/constraint/solver/ArrayRow;
    iget-object v6, v5, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iput v3, v6, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 794
    sget-object v3, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v3, :cond_b4

    .line 795
    sget-object v3, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v6, v3, Landroid/support/constraint/solver/Metrics;->pivots:J

    const-wide/16 v13, 0x1

    add-long/2addr v6, v13

    iput-wide v6, v3, Landroid/support/constraint/solver/Metrics;->pivots:J

    .line 797
    :cond_b4
    iget-object v3, v0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v3, v3, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    aget-object v3, v3, v11

    invoke-virtual {v5, v3}, Landroid/support/constraint/solver/ArrayRow;->pivot(Landroid/support/constraint/solver/SolverVariable;)V

    .line 798
    iget-object v3, v5, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iput v10, v3, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 799
    iget-object v3, v5, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v3, v5}, Landroid/support/constraint/solver/SolverVariable;->updateReferencesWithNewDefinition(Landroid/support/constraint/solver/ArrayRow;)V

    .line 805
    .end local v5    # "pivotEquation":Landroid/support/constraint/solver/ArrayRow;
    goto :goto_c8

    .line 806
    :cond_c7
    const/4 v4, 0x1

    .line 808
    :goto_c8
    iget v3, v0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    div-int/lit8 v3, v3, 0x2

    if-le v1, v3, :cond_d0

    .line 810
    const/4 v3, 0x1

    .line 812
    .end local v4    # "done":Z
    .end local v9    # "min":F
    .end local v10    # "pivotRowIndex":I
    .end local v11    # "pivotColumnIndex":I
    .end local v12    # "strength":I
    .local v3, "done":Z
    move v4, v3

    .line 735
    .end local v3    # "done":Z
    .restart local v4    # "done":Z
    :cond_d0
    const/4 v6, 0x0

    goto/16 :goto_2a

    .line 843
    .end local v4    # "done":Z
    :cond_d3
    return v1
.end method

.method private getDisplaySize(I)Ljava/lang/String;
    .registers 6
    .param p1, "n"    # I

    .line 955
    mul-int/lit8 v0, p1, 0x4

    div-int/lit16 v0, v0, 0x400

    div-int/lit16 v0, v0, 0x400

    .line 956
    .local v0, "mb":I
    if-lez v0, :cond_1f

    .line 957
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, ""

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, " Mb"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    return-object v1

    .line 959
    :cond_1f
    mul-int/lit8 v1, p1, 0x4

    div-int/lit16 v1, v1, 0x400

    .line 960
    .local v1, "kb":I
    if-lez v1, :cond_3c

    .line 961
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, ""

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " Kb"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2

    .line 963
    :cond_3c
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, ""

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    mul-int/lit8 v3, p1, 0x4

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " bytes"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2
.end method

.method private getDisplayStrength(I)Ljava/lang/String;
    .registers 3
    .param p1, "strength"    # I

    .line 971
    const/4 v0, 0x1

    if-ne p1, v0, :cond_6

    .line 972
    const-string v0, "LOW"

    return-object v0

    .line 974
    :cond_6
    const/4 v0, 0x2

    if-ne p1, v0, :cond_c

    .line 975
    const-string v0, "MEDIUM"

    return-object v0

    .line 977
    :cond_c
    const/4 v0, 0x3

    if-ne p1, v0, :cond_12

    .line 978
    const-string v0, "HIGH"

    return-object v0

    .line 980
    :cond_12
    const/4 v0, 0x4

    if-ne p1, v0, :cond_18

    .line 981
    const-string v0, "HIGHEST"

    return-object v0

    .line 983
    :cond_18
    const/4 v0, 0x5

    if-ne p1, v0, :cond_1e

    .line 984
    const-string v0, "EQUALITY"

    return-object v0

    .line 986
    :cond_1e
    const/4 v0, 0x6

    if-ne p1, v0, :cond_24

    .line 987
    const-string v0, "FIXED"

    return-object v0

    .line 989
    :cond_24
    const-string v0, "NONE"

    return-object v0
.end method

.method public static getMetrics()Landroid/support/constraint/solver/Metrics;
    .registers 1

    .line 91
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    return-object v0
.end method

.method private increaseTableSize()V
    .registers 6

    .line 112
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    mul-int/lit8 v0, v0, 0x2

    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    .line 113
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/ArrayRow;

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    .line 114
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Landroid/support/constraint/solver/SolverVariable;

    iput-object v1, v0, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    .line 115
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    new-array v0, v0, [Z

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    .line 116
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    .line 117
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxRows:I

    .line 118
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_54

    .line 119
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v0, Landroid/support/constraint/solver/Metrics;->tableSizeIncrease:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->tableSizeIncrease:J

    .line 120
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    sget-object v1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v1, Landroid/support/constraint/solver/Metrics;->maxTableSize:J

    iget v3, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    int-to-long v3, v3

    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v1

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->maxTableSize:J

    .line 121
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    sget-object v1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v1, Landroid/support/constraint/solver/Metrics;->maxTableSize:J

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->lastTableSize:J

    .line 123
    :cond_54
    return-void
.end method

.method private final optimize(Landroid/support/constraint/solver/LinearSystem$Row;Z)I
    .registers 19
    .param p1, "goal"    # Landroid/support/constraint/solver/LinearSystem$Row;
    .param p2, "b"    # Z

    move-object/from16 v0, p0

    .line 559
    sget-object v1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    const-wide/16 v2, 0x1

    if-eqz v1, :cond_f

    .line 560
    sget-object v1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v4, v1, Landroid/support/constraint/solver/Metrics;->optimize:J

    add-long/2addr v4, v2

    iput-wide v4, v1, Landroid/support/constraint/solver/Metrics;->optimize:J

    .line 562
    :cond_f
    const/4 v1, 0x0

    .line 563
    .local v1, "done":Z
    const/4 v4, 0x0

    .line 564
    .local v4, "tries":I
    const/4 v5, 0x0

    move v6, v5

    .line 564
    .local v6, "i":I
    :goto_13
    iget v7, v0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    if-ge v6, v7, :cond_1e

    .line 565
    iget-object v7, v0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    aput-boolean v5, v7, v6

    .line 564
    add-int/lit8 v6, v6, 0x1

    goto :goto_13

    .line 576
    .end local v6    # "i":I
    :cond_1e
    :goto_1e
    if-nez v1, :cond_c2

    .line 577
    sget-object v6, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v6, :cond_2b

    .line 578
    sget-object v6, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v7, v6, Landroid/support/constraint/solver/Metrics;->iterations:J

    add-long/2addr v7, v2

    iput-wide v7, v6, Landroid/support/constraint/solver/Metrics;->iterations:J

    .line 580
    :cond_2b
    add-int/lit8 v4, v4, 0x1

    .line 585
    iget v6, v0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    mul-int/lit8 v6, v6, 0x2

    if-lt v4, v6, :cond_34

    .line 586
    return v4

    .line 589
    :cond_34
    invoke-interface/range {p1 .. p1}, Landroid/support/constraint/solver/LinearSystem$Row;->getKey()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v6

    const/4 v7, 0x1

    if-eqz v6, :cond_45

    .line 590
    iget-object v6, v0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    invoke-interface/range {p1 .. p1}, Landroid/support/constraint/solver/LinearSystem$Row;->getKey()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v8

    iget v8, v8, Landroid/support/constraint/solver/SolverVariable;->id:I

    aput-boolean v7, v6, v8

    .line 592
    :cond_45
    iget-object v6, v0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    move-object/from16 v8, p1

    invoke-interface {v8, v0, v6}, Landroid/support/constraint/solver/LinearSystem$Row;->getPivotCandidate(Landroid/support/constraint/solver/LinearSystem;[Z)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v6

    .line 597
    .local v6, "pivotCandidate":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v6, :cond_5e

    .line 598
    iget-object v9, v0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    iget v10, v6, Landroid/support/constraint/solver/SolverVariable;->id:I

    aget-boolean v9, v9, v10

    if-eqz v9, :cond_58

    .line 599
    return v4

    .line 601
    :cond_58
    iget-object v9, v0, Landroid/support/constraint/solver/LinearSystem;->mAlreadyTestedCandidates:[Z

    iget v10, v6, Landroid/support/constraint/solver/SolverVariable;->id:I

    aput-boolean v7, v9, v10

    .line 605
    :cond_5e
    if-eqz v6, :cond_bf

    .line 619
    const v7, 0x7f7fffff    # Float.MAX_VALUE

    .line 620
    .local v7, "min":F
    const/4 v9, -0x1

    .line 622
    .local v9, "pivotRowIndex":I
    move v10, v7

    move v7, v5

    .line 622
    .local v7, "i":I
    .local v10, "min":F
    :goto_66
    iget v11, v0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v7, v11, :cond_9a

    .line 623
    iget-object v11, v0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v11, v11, v7

    .line 624
    .local v11, "current":Landroid/support/constraint/solver/ArrayRow;
    iget-object v12, v11, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 625
    .local v12, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget-object v13, v12, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v14, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    if-ne v13, v14, :cond_77

    .line 627
    goto :goto_97

    .line 629
    :cond_77
    iget-boolean v13, v11, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-eqz v13, :cond_7c

    .line 630
    goto :goto_97

    .line 633
    :cond_7c
    invoke-virtual {v11, v6}, Landroid/support/constraint/solver/ArrayRow;->hasVariable(Landroid/support/constraint/solver/SolverVariable;)Z

    move-result v13

    if-eqz v13, :cond_97

    .line 639
    iget-object v13, v11, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v13, v6}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v13

    .line 640
    .local v13, "a_j":F
    const/4 v14, 0x0

    cmpg-float v14, v13, v14

    if-gez v14, :cond_97

    .line 641
    iget v14, v11, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    neg-float v14, v14

    div-float/2addr v14, v13

    .line 642
    .local v14, "value":F
    cmpg-float v15, v14, v10

    if-gez v15, :cond_97

    .line 643
    move v10, v14

    .line 644
    move v9, v7

    .line 622
    .end local v11    # "current":Landroid/support/constraint/solver/ArrayRow;
    .end local v12    # "variable":Landroid/support/constraint/solver/SolverVariable;
    .end local v13    # "a_j":F
    .end local v14    # "value":F
    :cond_97
    :goto_97
    add-int/lit8 v7, v7, 0x1

    goto :goto_66

    .line 651
    .end local v7    # "i":I
    :cond_9a
    const/4 v7, -0x1

    if-le v9, v7, :cond_bd

    .line 656
    iget-object v11, v0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v11, v11, v9

    .line 657
    .local v11, "pivotEquation":Landroid/support/constraint/solver/ArrayRow;
    iget-object v12, v11, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iput v7, v12, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 658
    sget-object v7, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v7, :cond_b0

    .line 659
    sget-object v7, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v12, v7, Landroid/support/constraint/solver/Metrics;->pivots:J

    add-long/2addr v12, v2

    iput-wide v12, v7, Landroid/support/constraint/solver/Metrics;->pivots:J

    .line 661
    :cond_b0
    invoke-virtual {v11, v6}, Landroid/support/constraint/solver/ArrayRow;->pivot(Landroid/support/constraint/solver/SolverVariable;)V

    .line 662
    iget-object v7, v11, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iput v9, v7, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 663
    iget-object v7, v11, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v7, v11}, Landroid/support/constraint/solver/SolverVariable;->updateReferencesWithNewDefinition(Landroid/support/constraint/solver/ArrayRow;)V

    .line 679
    .end local v11    # "pivotEquation":Landroid/support/constraint/solver/ArrayRow;
    goto :goto_be

    .line 682
    :cond_bd
    const/4 v1, 0x1

    .line 685
    .end local v9    # "pivotRowIndex":I
    .end local v10    # "min":F
    :goto_be
    goto :goto_c0

    .line 688
    :cond_bf
    const/4 v1, 0x1

    .line 690
    .end local v6    # "pivotCandidate":Landroid/support/constraint/solver/SolverVariable;
    :goto_c0
    goto/16 :goto_1e

    .line 691
    :cond_c2
    move-object/from16 v8, p1

    return v4
.end method

.method private releaseRows()V
    .registers 5

    .line 129
    const/4 v0, 0x0

    .line 129
    .local v0, "i":I
    :goto_1
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    array-length v1, v1

    if-ge v0, v1, :cond_1b

    .line 130
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v1, v1, v0

    .line 131
    .local v1, "row":Landroid/support/constraint/solver/ArrayRow;
    if-eqz v1, :cond_13

    .line 132
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v2, v2, Landroid/support/constraint/solver/Cache;->arrayRowPool:Landroid/support/constraint/solver/Pools$Pool;

    invoke-interface {v2, v1}, Landroid/support/constraint/solver/Pools$Pool;->release(Ljava/lang/Object;)Z

    .line 134
    :cond_13
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    const/4 v3, 0x0

    aput-object v3, v2, v0

    .line 129
    .end local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 136
    .end local v0    # "i":I
    :cond_1b
    return-void
.end method

.method private final updateRowFromVariables(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 4
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;

    .line 448
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-lez v0, :cond_14

    .line 449
    iget-object v0, p1, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    invoke-virtual {v0, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->updateFromSystem(Landroid/support/constraint/solver/ArrayRow;[Landroid/support/constraint/solver/ArrayRow;)V

    .line 450
    iget-object v0, p1, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget v0, v0, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-nez v0, :cond_14

    .line 451
    const/4 v0, 0x1

    iput-boolean v0, p1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    .line 454
    :cond_14
    return-void
.end method


# virtual methods
.method public addCenterPoint(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintWidget;FI)V
    .registers 26
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p3, "angle"    # F
    .param p4, "radius"    # I

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p3

    .line 1329
    move/from16 v4, p4

    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v5

    invoke-virtual {v0, v5}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v5

    .line 1330
    .local v5, "Al":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v13

    .line 1331
    .local v13, "At":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v14

    .line 1332
    .local v14, "Ar":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v15

    .line 1334
    .local v15, "Ab":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v2, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v16

    .line 1335
    .local v16, "Bl":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v2, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v17

    .line 1336
    .local v17, "Bt":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v2, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v18

    .line 1337
    .local v18, "Br":Landroid/support/constraint/solver/SolverVariable;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v2, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v19

    .line 1339
    .local v19, "Bb":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v6

    .line 1340
    .local v6, "row":Landroid/support/constraint/solver/ArrayRow;
    float-to-double v7, v3

    invoke-static {v7, v8}, Ljava/lang/Math;->sin(D)D

    move-result-wide v7

    int-to-double v9, v4

    mul-double/2addr v7, v9

    double-to-float v12, v7

    .line 1341
    .local v12, "angleComponent":F
    move-object v7, v6

    move-object v8, v13

    move-object v9, v15

    move-object/from16 v10, v17

    move-object/from16 v11, v19

    move/from16 v20, v12

    .line 1341
    .end local v12    # "angleComponent":F
    .local v20, "angleComponent":F
    invoke-virtual/range {v7 .. v12}, Landroid/support/constraint/solver/ArrayRow;->createRowWithAngle(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;

    .line 1342
    invoke-virtual {v0, v6}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1343
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v12

    .line 1344
    .end local v6    # "row":Landroid/support/constraint/solver/ArrayRow;
    .local v12, "row":Landroid/support/constraint/solver/ArrayRow;
    float-to-double v6, v3

    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    move-result-wide v6

    int-to-double v8, v4

    mul-double/2addr v6, v8

    double-to-float v11, v6

    .line 1345
    .end local v20    # "angleComponent":F
    .local v11, "angleComponent":F
    move-object v6, v12

    move-object v7, v5

    move-object v8, v14

    move-object/from16 v9, v16

    move-object/from16 v10, v18

    move/from16 v20, v11

    .line 1345
    .end local v11    # "angleComponent":F
    .restart local v20    # "angleComponent":F
    invoke-virtual/range {v6 .. v11}, Landroid/support/constraint/solver/ArrayRow;->createRowWithAngle(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;

    .line 1346
    invoke-virtual {v0, v12}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1347
    return-void
.end method

.method public addCentering(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V
    .registers 20
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "m1"    # I
    .param p4, "bias"    # F
    .param p5, "c"    # Landroid/support/constraint/solver/SolverVariable;
    .param p6, "d"    # Landroid/support/constraint/solver/SolverVariable;
    .param p7, "m2"    # I
    .param p8, "strength"    # I

    move-object v0, p0

    .line 1098
    move/from16 v1, p8

    invoke-virtual {v0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v10

    .line 1099
    .local v10, "row":Landroid/support/constraint/solver/ArrayRow;
    move-object v2, v10

    move-object v3, p1

    move-object v4, p2

    move v5, p3

    move v6, p4

    move-object/from16 v7, p5

    move-object/from16 v8, p6

    move/from16 v9, p7

    invoke-virtual/range {v2 .. v9}, Landroid/support/constraint/solver/ArrayRow;->createRowCentering(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1100
    const/4 v2, 0x6

    if-eq v1, v2, :cond_1b

    .line 1101
    invoke-virtual {v10, v0, v1}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1103
    :cond_1b
    invoke-virtual {v0, v10}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1104
    return-void
.end method

.method public addConstraint(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 11
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;

    .line 461
    if-nez p1, :cond_3

    .line 462
    return-void

    .line 464
    :cond_3
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    const-wide/16 v1, 0x1

    if-eqz v0, :cond_1b

    .line 465
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v3, v0, Landroid/support/constraint/solver/Metrics;->constraints:J

    add-long/2addr v3, v1

    iput-wide v3, v0, Landroid/support/constraint/solver/Metrics;->constraints:J

    .line 466
    iget-boolean v0, p1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-eqz v0, :cond_1b

    .line 467
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v3, v0, Landroid/support/constraint/solver/Metrics;->simpleconstraints:J

    add-long/2addr v3, v1

    iput-wide v3, v0, Landroid/support/constraint/solver/Metrics;->simpleconstraints:J

    .line 470
    :cond_1b
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    const/4 v3, 0x1

    add-int/2addr v0, v3

    iget v4, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxRows:I

    if-ge v0, v4, :cond_2a

    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/2addr v0, v3

    iget v4, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    if-lt v0, v4, :cond_2d

    .line 471
    :cond_2a
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->increaseTableSize()V

    .line 477
    :cond_2d
    const/4 v0, 0x0

    .line 478
    .local v0, "added":Z
    iget-boolean v4, p1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-nez v4, :cond_8b

    .line 480
    invoke-direct {p0, p1}, Landroid/support/constraint/solver/LinearSystem;->updateRowFromVariables(Landroid/support/constraint/solver/ArrayRow;)V

    .line 482
    invoke-virtual {p1}, Landroid/support/constraint/solver/ArrayRow;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_3c

    .line 483
    return-void

    .line 487
    :cond_3c
    invoke-virtual {p1}, Landroid/support/constraint/solver/ArrayRow;->ensurePositiveConstant()V

    .line 494
    invoke-virtual {p1, p0}, Landroid/support/constraint/solver/ArrayRow;->chooseSubject(Landroid/support/constraint/solver/LinearSystem;)Z

    move-result v4

    if-eqz v4, :cond_84

    .line 496
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createExtraVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 497
    .local v4, "extra":Landroid/support/constraint/solver/SolverVariable;
    iput-object v4, p1, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    .line 498
    invoke-direct {p0, p1}, Landroid/support/constraint/solver/LinearSystem;->addRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 499
    const/4 v0, 0x1

    .line 500
    iget-object v5, p0, Landroid/support/constraint/solver/LinearSystem;->mTempGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-interface {v5, p1}, Landroid/support/constraint/solver/LinearSystem$Row;->initFromRow(Landroid/support/constraint/solver/LinearSystem$Row;)V

    .line 501
    iget-object v5, p0, Landroid/support/constraint/solver/LinearSystem;->mTempGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-direct {p0, v5, v3}, Landroid/support/constraint/solver/LinearSystem;->optimize(Landroid/support/constraint/solver/LinearSystem$Row;Z)I

    .line 502
    iget v5, v4, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    const/4 v6, -0x1

    if-ne v5, v6, :cond_84

    .line 506
    iget-object v5, p1, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    if-ne v5, v4, :cond_76

    .line 508
    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/ArrayRow;->pickPivot(Landroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v5

    .line 509
    .local v5, "pivotCandidate":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v5, :cond_76

    .line 510
    sget-object v6, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v6, :cond_73

    .line 511
    sget-object v6, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v7, v6, Landroid/support/constraint/solver/Metrics;->pivots:J

    add-long/2addr v7, v1

    iput-wide v7, v6, Landroid/support/constraint/solver/Metrics;->pivots:J

    .line 513
    :cond_73
    invoke-virtual {p1, v5}, Landroid/support/constraint/solver/ArrayRow;->pivot(Landroid/support/constraint/solver/SolverVariable;)V

    .line 516
    .end local v5    # "pivotCandidate":Landroid/support/constraint/solver/SolverVariable;
    :cond_76
    iget-boolean v1, p1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-nez v1, :cond_7f

    .line 517
    iget-object v1, p1, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v1, p1}, Landroid/support/constraint/solver/SolverVariable;->updateReferencesWithNewDefinition(Landroid/support/constraint/solver/ArrayRow;)V

    .line 519
    :cond_7f
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    sub-int/2addr v1, v3

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    .line 523
    .end local v4    # "extra":Landroid/support/constraint/solver/SolverVariable;
    :cond_84
    invoke-virtual {p1}, Landroid/support/constraint/solver/ArrayRow;->hasKeyVariable()Z

    move-result v1

    if-nez v1, :cond_8b

    .line 529
    return-void

    .line 532
    :cond_8b
    if-nez v0, :cond_90

    .line 533
    invoke-direct {p0, p1}, Landroid/support/constraint/solver/LinearSystem;->addRow(Landroid/support/constraint/solver/ArrayRow;)V

    .line 535
    :cond_90
    return-void
.end method

.method public addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;
    .registers 7
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I
    .param p4, "strength"    # I

    .line 1128
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1129
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v0, p1, p2, p3}, Landroid/support/constraint/solver/ArrayRow;->createRowEquals(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1130
    const/4 v1, 0x6

    if-eq p4, v1, :cond_d

    .line 1131
    invoke-virtual {v0, p0, p4}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1133
    :cond_d
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1134
    return-object v0
.end method

.method public addEquality(Landroid/support/constraint/solver/SolverVariable;I)V
    .registers 6
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "value"    # I

    .line 1146
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 1147
    .local v0, "idx":I
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    const/4 v2, -0x1

    if-eq v1, v2, :cond_2b

    .line 1148
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v1, v1, v0

    .line 1149
    .local v1, "row":Landroid/support/constraint/solver/ArrayRow;
    iget-boolean v2, v1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-eqz v2, :cond_13

    .line 1150
    int-to-float v2, p2

    iput v2, v1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    goto :goto_2a

    .line 1152
    :cond_13
    iget-object v2, v1, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget v2, v2, Landroid/support/constraint/solver/ArrayLinkedVariables;->currentSize:I

    if-nez v2, :cond_20

    .line 1153
    const/4 v2, 0x1

    iput-boolean v2, v1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    .line 1154
    int-to-float v2, p2

    iput v2, v1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    goto :goto_2a

    .line 1156
    :cond_20
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v2

    .line 1157
    .local v2, "newRow":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v2, p1, p2}, Landroid/support/constraint/solver/ArrayRow;->createRowEquals(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1158
    invoke-virtual {p0, v2}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1161
    .end local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    .end local v2    # "newRow":Landroid/support/constraint/solver/ArrayRow;
    :goto_2a
    goto :goto_35

    .line 1162
    :cond_2b
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    .line 1163
    .restart local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v1, p1, p2}, Landroid/support/constraint/solver/ArrayRow;->createRowDefinition(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1164
    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1166
    .end local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    :goto_35
    return-void
.end method

.method public addEquality(Landroid/support/constraint/solver/SolverVariable;II)V
    .registers 7
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "value"    # I
    .param p3, "strength"    # I

    .line 1178
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 1179
    .local v0, "idx":I
    iget v1, p1, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    const/4 v2, -0x1

    if-eq v1, v2, :cond_21

    .line 1180
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v1, v1, v0

    .line 1181
    .local v1, "row":Landroid/support/constraint/solver/ArrayRow;
    iget-boolean v2, v1, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-eqz v2, :cond_13

    .line 1182
    int-to-float v2, p2

    iput v2, v1, Landroid/support/constraint/solver/ArrayRow;->constantValue:F

    goto :goto_20

    .line 1184
    :cond_13
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v2

    .line 1185
    .local v2, "newRow":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v2, p1, p2}, Landroid/support/constraint/solver/ArrayRow;->createRowEquals(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1186
    invoke-virtual {v2, p0, p3}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1187
    invoke-virtual {p0, v2}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1189
    .end local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    .end local v2    # "newRow":Landroid/support/constraint/solver/ArrayRow;
    :goto_20
    goto :goto_2e

    .line 1190
    :cond_21
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    .line 1191
    .restart local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {v1, p1, p2}, Landroid/support/constraint/solver/ArrayRow;->createRowDefinition(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1192
    invoke-virtual {v1, p0, p3}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1193
    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1195
    .end local v1    # "row":Landroid/support/constraint/solver/ArrayRow;
    :goto_2e
    return-void
.end method

.method public addGreaterBarrier(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Z)V
    .registers 9
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "hasMatchConstraintWidgets"    # Z

    .line 1029
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1030
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 1031
    .local v1, "slack":Landroid/support/constraint/solver/SolverVariable;
    const/4 v2, 0x0

    iput v2, v1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 1032
    invoke-virtual {v0, p1, p2, v1, v2}, Landroid/support/constraint/solver/ArrayRow;->createRowGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1033
    if-eqz p3, :cond_1e

    .line 1035
    iget-object v2, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v2

    .line 1036
    .local v2, "slackValue":F
    const/high16 v3, -0x40800000    # -1.0f

    mul-float/2addr v3, v2

    float-to-int v3, v3

    const/4 v4, 0x1

    invoke-virtual {p0, v0, v3, v4}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;II)V

    .line 1038
    .end local v2    # "slackValue":F
    :cond_1e
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1039
    return-void
.end method

.method public addGreaterThan(Landroid/support/constraint/solver/SolverVariable;I)V
    .registers 6
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # I

    .line 1018
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1019
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 1020
    .local v1, "slack":Landroid/support/constraint/solver/SolverVariable;
    const/4 v2, 0x0

    iput v2, v1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 1021
    invoke-virtual {v0, p1, p2, v1}, Landroid/support/constraint/solver/ArrayRow;->createRowGreaterThan(Landroid/support/constraint/solver/SolverVariable;ILandroid/support/constraint/solver/SolverVariable;)Landroid/support/constraint/solver/ArrayRow;

    .line 1022
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1023
    return-void
.end method

.method public addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V
    .registers 9
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I
    .param p4, "strength"    # I

    .line 1003
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1004
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 1005
    .local v1, "slack":Landroid/support/constraint/solver/SolverVariable;
    const/4 v2, 0x0

    iput v2, v1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 1006
    invoke-virtual {v0, p1, p2, v1, p3}, Landroid/support/constraint/solver/ArrayRow;->createRowGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1007
    const/4 v2, 0x6

    if-eq p4, v2, :cond_1e

    .line 1008
    iget-object v2, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v2

    .line 1009
    .local v2, "slackValue":F
    const/high16 v3, -0x40800000    # -1.0f

    mul-float/2addr v3, v2

    float-to-int v3, v3

    invoke-virtual {p0, v0, v3, p4}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;II)V

    .line 1011
    .end local v2    # "slackValue":F
    :cond_1e
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1012
    return-void
.end method

.method public addLowerBarrier(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Z)V
    .registers 9
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "hasMatchConstraintWidgets"    # Z

    .line 1067
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1068
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 1069
    .local v1, "slack":Landroid/support/constraint/solver/SolverVariable;
    const/4 v2, 0x0

    iput v2, v1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 1070
    invoke-virtual {v0, p1, p2, v1, v2}, Landroid/support/constraint/solver/ArrayRow;->createRowLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1071
    if-eqz p3, :cond_1e

    .line 1073
    iget-object v2, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v2

    .line 1074
    .local v2, "slackValue":F
    const/high16 v3, -0x40800000    # -1.0f

    mul-float/2addr v3, v2

    float-to-int v3, v3

    const/4 v4, 0x1

    invoke-virtual {p0, v0, v3, v4}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;II)V

    .line 1076
    .end local v2    # "slackValue":F
    :cond_1e
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1077
    return-void
.end method

.method public addLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V
    .registers 9
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "margin"    # I
    .param p4, "strength"    # I

    .line 1052
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v0

    .line 1053
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createSlackVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 1054
    .local v1, "slack":Landroid/support/constraint/solver/SolverVariable;
    const/4 v2, 0x0

    iput v2, v1, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 1055
    invoke-virtual {v0, p1, p2, v1, p3}, Landroid/support/constraint/solver/ArrayRow;->createRowLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1056
    const/4 v2, 0x6

    if-eq p4, v2, :cond_1e

    .line 1057
    iget-object v2, v0, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->get(Landroid/support/constraint/solver/SolverVariable;)F

    move-result v2

    .line 1058
    .local v2, "slackValue":F
    const/high16 v3, -0x40800000    # -1.0f

    mul-float/2addr v3, v2

    float-to-int v3, v3

    invoke-virtual {p0, v0, v3, p4}, Landroid/support/constraint/solver/LinearSystem;->addSingleError(Landroid/support/constraint/solver/ArrayRow;II)V

    .line 1060
    .end local v2    # "slackValue":F
    :cond_1e
    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1061
    return-void
.end method

.method public addRatio(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;FI)V
    .registers 14
    .param p1, "a"    # Landroid/support/constraint/solver/SolverVariable;
    .param p2, "b"    # Landroid/support/constraint/solver/SolverVariable;
    .param p3, "c"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "d"    # Landroid/support/constraint/solver/SolverVariable;
    .param p5, "ratio"    # F
    .param p6, "strength"    # I

    .line 1110
    invoke-virtual {p0}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v6

    .line 1111
    .local v6, "row":Landroid/support/constraint/solver/ArrayRow;
    move-object v0, v6

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move v5, p5

    invoke-virtual/range {v0 .. v5}, Landroid/support/constraint/solver/ArrayRow;->createRowDimensionRatio(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;

    .line 1112
    const/4 v0, 0x6

    if-eq p6, v0, :cond_13

    .line 1113
    invoke-virtual {v6, p0, p6}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/LinearSystem;I)Landroid/support/constraint/solver/ArrayRow;

    .line 1115
    :cond_13
    invoke-virtual {p0, v6}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 1116
    return-void
.end method

.method addSingleError(Landroid/support/constraint/solver/ArrayRow;II)V
    .registers 6
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;
    .param p2, "sign"    # I
    .param p3, "strength"    # I

    .line 249
    const/4 v0, 0x0

    .line 258
    .local v0, "prefix":Ljava/lang/String;
    invoke-virtual {p0, p3, v0}, Landroid/support/constraint/solver/LinearSystem;->createErrorVariable(ILjava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 259
    .local v1, "error":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {p1, v1, p2}, Landroid/support/constraint/solver/ArrayRow;->addSingleError(Landroid/support/constraint/solver/SolverVariable;I)Landroid/support/constraint/solver/ArrayRow;

    .line 260
    return-void
.end method

.method public createErrorVariable(ILjava/lang/String;)Landroid/support/constraint/solver/SolverVariable;
    .registers 8
    .param p1, "strength"    # I
    .param p2, "prefix"    # Ljava/lang/String;

    .line 283
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_d

    .line 284
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v0, Landroid/support/constraint/solver/Metrics;->errors:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->errors:J

    .line 286
    :cond_d
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    if-lt v0, v1, :cond_18

    .line 287
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->increaseTableSize()V

    .line 289
    :cond_18
    sget-object v0, Landroid/support/constraint/solver/SolverVariable$Type;->ERROR:Landroid/support/constraint/solver/SolverVariable$Type;

    invoke-direct {p0, v0, p2}, Landroid/support/constraint/solver/LinearSystem;->acquireSolverVariable(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 290
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 291
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 292
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    iput v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 293
    iput p1, v0, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 294
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    aput-object v0, v1, v2

    .line 295
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-interface {v1, v0}, Landroid/support/constraint/solver/LinearSystem$Row;->addError(Landroid/support/constraint/solver/SolverVariable;)V

    .line 296
    return-object v0
.end method

.method public createExtraVariable()Landroid/support/constraint/solver/SolverVariable;
    .registers 6

    .line 226
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_d

    .line 227
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v0, Landroid/support/constraint/solver/Metrics;->extravariables:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->extravariables:J

    .line 229
    :cond_d
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    if-lt v0, v1, :cond_18

    .line 230
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->increaseTableSize()V

    .line 232
    :cond_18
    sget-object v0, Landroid/support/constraint/solver/SolverVariable$Type;->SLACK:Landroid/support/constraint/solver/SolverVariable$Type;

    const/4 v1, 0x0

    invoke-direct {p0, v0, v1}, Landroid/support/constraint/solver/LinearSystem;->acquireSolverVariable(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 233
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 234
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 235
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    iput v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 236
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    aput-object v0, v1, v2

    .line 237
    return-object v0
.end method

.method public createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;
    .registers 6
    .param p1, "anchor"    # Ljava/lang/Object;

    .line 170
    if-nez p1, :cond_4

    .line 171
    const/4 v0, 0x0

    return-object v0

    .line 173
    :cond_4
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    if-lt v0, v1, :cond_f

    .line 174
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->increaseTableSize()V

    .line 176
    :cond_f
    const/4 v0, 0x0

    .line 177
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    instance-of v1, p1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v1, :cond_64

    .line 178
    move-object v1, p1

    check-cast v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getSolverVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 179
    if-nez v0, :cond_2c

    .line 180
    move-object v1, p1

    check-cast v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    invoke-virtual {v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 181
    move-object v1, p1

    check-cast v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getSolverVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 183
    :cond_2c
    iget v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    const/4 v2, -0x1

    if-eq v1, v2, :cond_41

    iget v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    iget v3, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    if-gt v1, v3, :cond_41

    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v3, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    aget-object v1, v1, v3

    if-nez v1, :cond_64

    .line 186
    :cond_41
    iget v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    if-eq v1, v2, :cond_48

    .line 187
    invoke-virtual {v0}, Landroid/support/constraint/solver/SolverVariable;->reset()V

    .line 189
    :cond_48
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 190
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 191
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    iput v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 192
    sget-object v1, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    iput-object v1, v0, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    .line 193
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    aput-object v0, v1, v2

    .line 196
    :cond_64
    return-object v0
.end method

.method public createRow()Landroid/support/constraint/solver/ArrayRow;
    .registers 4

    .line 200
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v0, v0, Landroid/support/constraint/solver/Cache;->arrayRowPool:Landroid/support/constraint/solver/Pools$Pool;

    invoke-interface {v0}, Landroid/support/constraint/solver/Pools$Pool;->acquire()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/ArrayRow;

    .line 201
    .local v0, "row":Landroid/support/constraint/solver/ArrayRow;
    if-nez v0, :cond_15

    .line 202
    new-instance v1, Landroid/support/constraint/solver/ArrayRow;

    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    invoke-direct {v1, v2}, Landroid/support/constraint/solver/ArrayRow;-><init>(Landroid/support/constraint/solver/Cache;)V

    move-object v0, v1

    goto :goto_18

    .line 204
    :cond_15
    invoke-virtual {v0}, Landroid/support/constraint/solver/ArrayRow;->reset()V

    .line 206
    :goto_18
    invoke-static {}, Landroid/support/constraint/solver/SolverVariable;->increaseErrorId()V

    .line 207
    return-object v0
.end method

.method public createSlackVariable()Landroid/support/constraint/solver/SolverVariable;
    .registers 6

    .line 211
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_d

    .line 212
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v0, Landroid/support/constraint/solver/Metrics;->slackvariables:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->slackvariables:J

    .line 214
    :cond_d
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    if-lt v0, v1, :cond_18

    .line 215
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->increaseTableSize()V

    .line 217
    :cond_18
    sget-object v0, Landroid/support/constraint/solver/SolverVariable$Type;->SLACK:Landroid/support/constraint/solver/SolverVariable$Type;

    const/4 v1, 0x0

    invoke-direct {p0, v0, v1}, Landroid/support/constraint/solver/LinearSystem;->acquireSolverVariable(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 218
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 219
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 220
    iget v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    iput v1, v0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 221
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    aput-object v0, v1, v2

    .line 222
    return-object v0
.end method

.method displayReadableRows()V
    .registers 5

    .line 870
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->displaySolverVariables()V

    .line 871
    const-string v0, " #  "

    .line 872
    .local v0, "s":Ljava/lang/String;
    const/4 v1, 0x0

    .line 872
    .local v1, "i":I
    :goto_6
    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v1, v2, :cond_35

    .line 873
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v3, v3, v1

    invoke-virtual {v3}, Landroid/support/constraint/solver/ArrayRow;->toReadableString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 874
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\n #  "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 872
    add-int/lit8 v1, v1, 0x1

    goto :goto_6

    .line 876
    .end local v1    # "i":I
    :cond_35
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    if-eqz v1, :cond_4f

    .line 877
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\n"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 879
    :cond_4f
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 880
    return-void
.end method

.method displaySystemInformations()V
    .registers 8

    .line 916
    const/4 v0, 0x0

    .line 917
    .local v0, "count":I
    const/4 v1, 0x0

    .line 918
    .local v1, "rowSize":I
    const/4 v2, 0x0

    move v3, v1

    move v1, v2

    .line 918
    .local v1, "i":I
    .local v3, "rowSize":I
    :goto_5
    iget v4, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    if-ge v1, v4, :cond_1b

    .line 919
    iget-object v4, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v4, v4, v1

    if-eqz v4, :cond_18

    .line 920
    iget-object v4, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v4, v4, v1

    invoke-virtual {v4}, Landroid/support/constraint/solver/ArrayRow;->sizeInBytes()I

    move-result v4

    add-int/2addr v3, v4

    .line 918
    :cond_18
    add-int/lit8 v1, v1, 0x1

    goto :goto_5

    .line 923
    .end local v1    # "i":I
    :cond_1b
    const/4 v1, 0x0

    .line 924
    .local v1, "actualRowSize":I
    nop

    .line 924
    .local v2, "i":I
    :goto_1d
    iget v4, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v2, v4, :cond_33

    .line 925
    iget-object v4, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v4, v4, v2

    if-eqz v4, :cond_30

    .line 926
    iget-object v4, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v4, v4, v2

    invoke-virtual {v4}, Landroid/support/constraint/solver/ArrayRow;->sizeInBytes()I

    move-result v4

    add-int/2addr v1, v4

    .line 924
    :cond_30
    add-int/lit8 v2, v2, 0x1

    goto :goto_1d

    .line 930
    .end local v2    # "i":I
    :cond_33
    sget-object v2, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Linear System -> Table size: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v5, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, " ("

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v5, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    iget v6, p0, Landroid/support/constraint/solver/LinearSystem;->TABLE_SIZE:I

    mul-int/2addr v5, v6

    .line 931
    invoke-direct {p0, v5}, Landroid/support/constraint/solver/LinearSystem;->getDisplaySize(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ") -- row sizes: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 932
    invoke-direct {p0, v3}, Landroid/support/constraint/solver/LinearSystem;->getDisplaySize(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ", actual size: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 933
    invoke-direct {p0, v1}, Landroid/support/constraint/solver/LinearSystem;->getDisplaySize(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " rows: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v5, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, "/"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v5, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxRows:I

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, " cols: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v5, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, "/"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v5, p0, Landroid/support/constraint/solver/LinearSystem;->mMaxColumns:I

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, " "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, " occupied cells, "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 936
    invoke-direct {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->getDisplaySize(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    .line 930
    invoke-virtual {v2, v4}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 938
    return-void
.end method

.method public displayVariablesReadableRows()V
    .registers 5

    .line 884
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->displaySolverVariables()V

    .line 885
    const-string v0, ""

    .line 886
    .local v0, "s":Ljava/lang/String;
    const/4 v1, 0x0

    .line 886
    .local v1, "i":I
    :goto_6
    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v1, v2, :cond_41

    .line 887
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v2, v2, v1

    iget-object v2, v2, Landroid/support/constraint/solver/ArrayRow;->variable:Landroid/support/constraint/solver/SolverVariable;

    iget-object v2, v2, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    sget-object v3, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    if-ne v2, v3, :cond_3e

    .line 888
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v3, v3, v1

    invoke-virtual {v3}, Landroid/support/constraint/solver/ArrayRow;->toReadableString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 889
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\n"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 886
    :cond_3e
    add-int/lit8 v1, v1, 0x1

    goto :goto_6

    .line 892
    .end local v1    # "i":I
    :cond_41
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\n"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 893
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 894
    return-void
.end method

.method public fillMetrics(Landroid/support/constraint/solver/Metrics;)V
    .registers 2
    .param p1, "metrics"    # Landroid/support/constraint/solver/Metrics;

    .line 87
    sput-object p1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    .line 88
    return-void
.end method

.method public getCache()Landroid/support/constraint/solver/Cache;
    .registers 2

    .line 967
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    return-object v0
.end method

.method getGoal()Landroid/support/constraint/solver/LinearSystem$Row;
    .registers 2

    .line 329
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    return-object v0
.end method

.method public getMemoryUsed()I
    .registers 4

    .line 898
    const/4 v0, 0x0

    .line 899
    .local v0, "actualRowSize":I
    const/4 v1, 0x0

    .line 899
    .local v1, "i":I
    :goto_2
    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v1, v2, :cond_18

    .line 900
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v2, v2, v1

    if-eqz v2, :cond_15

    .line 901
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v2, v2, v1

    invoke-virtual {v2}, Landroid/support/constraint/solver/ArrayRow;->sizeInBytes()I

    move-result v2

    add-int/2addr v0, v2

    .line 899
    :cond_15
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    .line 904
    .end local v1    # "i":I
    :cond_18
    return v0
.end method

.method public getNumEquations()I
    .registers 2

    .line 908
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    return v0
.end method

.method public getNumVariables()I
    .registers 2

    .line 910
    iget v0, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    return v0
.end method

.method public getObjectVariableValue(Ljava/lang/Object;)I
    .registers 5
    .param p1, "anchor"    # Ljava/lang/Object;

    .line 344
    move-object v0, p1

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getSolverVariable()Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 345
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v0, :cond_10

    .line 346
    iget v1, v0, Landroid/support/constraint/solver/SolverVariable;->computedValue:F

    const/high16 v2, 0x3f000000    # 0.5f

    add-float/2addr v1, v2

    float-to-int v1, v1

    return v1

    .line 348
    :cond_10
    const/4 v1, 0x0

    return v1
.end method

.method getRow(I)Landroid/support/constraint/solver/ArrayRow;
    .registers 3
    .param p1, "n"    # I

    .line 332
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v0, v0, p1

    return-object v0
.end method

.method getValueFor(Ljava/lang/String;)F
    .registers 4
    .param p1, "name"    # Ljava/lang/String;

    .line 336
    sget-object v0, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    invoke-virtual {p0, p1, v0}, Landroid/support/constraint/solver/LinearSystem;->getVariable(Ljava/lang/String;Landroid/support/constraint/solver/SolverVariable$Type;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 337
    .local v0, "v":Landroid/support/constraint/solver/SolverVariable;
    if-nez v0, :cond_a

    .line 338
    const/4 v1, 0x0

    return v1

    .line 340
    :cond_a
    iget v1, v0, Landroid/support/constraint/solver/SolverVariable;->computedValue:F

    return v1
.end method

.method getVariable(Ljava/lang/String;Landroid/support/constraint/solver/SolverVariable$Type;)Landroid/support/constraint/solver/SolverVariable;
    .registers 4
    .param p1, "name"    # Ljava/lang/String;
    .param p2, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;

    .line 359
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    if-nez v0, :cond_b

    .line 360
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    .line 362
    :cond_b
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/SolverVariable;

    .line 363
    .local v0, "variable":Landroid/support/constraint/solver/SolverVariable;
    if-nez v0, :cond_19

    .line 364
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/solver/LinearSystem;->createVariable(Ljava/lang/String;Landroid/support/constraint/solver/SolverVariable$Type;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 366
    :cond_19
    return-object v0
.end method

.method public minimize()V
    .registers 7
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 377
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    const-wide/16 v1, 0x1

    if-eqz v0, :cond_d

    .line 378
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v3, v0, Landroid/support/constraint/solver/Metrics;->minimize:J

    add-long/2addr v3, v1

    iput-wide v3, v0, Landroid/support/constraint/solver/Metrics;->minimize:J

    .line 383
    :cond_d
    iget-boolean v0, p0, Landroid/support/constraint/solver/LinearSystem;->graphOptimizer:Z

    if-eqz v0, :cond_46

    .line 384
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_1c

    .line 385
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v3, v0, Landroid/support/constraint/solver/Metrics;->graphOptimizer:J

    add-long/2addr v3, v1

    iput-wide v3, v0, Landroid/support/constraint/solver/Metrics;->graphOptimizer:J

    .line 387
    :cond_1c
    const/4 v0, 0x1

    .line 388
    .local v0, "fullySolved":Z
    const/4 v3, 0x0

    .line 388
    .local v3, "i":I
    :goto_1e
    iget v4, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v3, v4, :cond_2f

    .line 389
    iget-object v4, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v4, v4, v3

    .line 390
    .local v4, "r":Landroid/support/constraint/solver/ArrayRow;
    iget-boolean v5, v4, Landroid/support/constraint/solver/ArrayRow;->isSimpleDefinition:Z

    if-nez v5, :cond_2c

    .line 391
    const/4 v0, 0x0

    .line 392
    goto :goto_2f

    .line 388
    .end local v4    # "r":Landroid/support/constraint/solver/ArrayRow;
    :cond_2c
    add-int/lit8 v3, v3, 0x1

    goto :goto_1e

    .line 395
    .end local v3    # "i":I
    :cond_2f
    :goto_2f
    if-nez v0, :cond_37

    .line 396
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/LinearSystem;->minimizeGoal(Landroid/support/constraint/solver/LinearSystem$Row;)V

    goto :goto_45

    .line 398
    :cond_37
    sget-object v3, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v3, :cond_42

    .line 399
    sget-object v3, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v4, v3, Landroid/support/constraint/solver/Metrics;->fullySolved:J

    add-long/2addr v4, v1

    iput-wide v4, v3, Landroid/support/constraint/solver/Metrics;->fullySolved:J

    .line 401
    :cond_42
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->computeValues()V

    .line 403
    .end local v0    # "fullySolved":Z
    :goto_45
    goto :goto_4b

    .line 404
    :cond_46
    iget-object v0, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->minimizeGoal(Landroid/support/constraint/solver/LinearSystem$Row;)V

    .line 409
    :goto_4b
    return-void
.end method

.method minimizeGoal(Landroid/support/constraint/solver/LinearSystem$Row;)V
    .registers 7
    .param p1, "goal"    # Landroid/support/constraint/solver/LinearSystem$Row;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 416
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    if-eqz v0, :cond_2b

    .line 417
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v0, Landroid/support/constraint/solver/Metrics;->minimizeGoal:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->minimizeGoal:J

    .line 418
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    sget-object v1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v1, Landroid/support/constraint/solver/Metrics;->maxVariables:J

    iget v3, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    int-to-long v3, v3

    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v1

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->maxVariables:J

    .line 419
    sget-object v0, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    sget-object v1, Landroid/support/constraint/solver/LinearSystem;->sMetrics:Landroid/support/constraint/solver/Metrics;

    iget-wide v1, v1, Landroid/support/constraint/solver/Metrics;->maxRows:J

    iget v3, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    int-to-long v3, v3

    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v1

    iput-wide v1, v0, Landroid/support/constraint/solver/Metrics;->maxRows:J

    .line 426
    :cond_2b
    move-object v0, p1

    check-cast v0, Landroid/support/constraint/solver/ArrayRow;

    invoke-direct {p0, v0}, Landroid/support/constraint/solver/LinearSystem;->updateRowFromVariables(Landroid/support/constraint/solver/ArrayRow;)V

    .line 430
    invoke-direct {p0, p1}, Landroid/support/constraint/solver/LinearSystem;->enforceBFS(Landroid/support/constraint/solver/LinearSystem$Row;)I

    .line 435
    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Landroid/support/constraint/solver/LinearSystem;->optimize(Landroid/support/constraint/solver/LinearSystem$Row;Z)I

    .line 440
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->computeValues()V

    .line 441
    return-void
.end method

.method public reset()V
    .registers 5

    .line 142
    const/4 v0, 0x0

    move v1, v0

    .line 142
    .local v1, "i":I
    :goto_2
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v2, v2, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    array-length v2, v2

    if-ge v1, v2, :cond_17

    .line 143
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v2, v2, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    aget-object v2, v2, v1

    .line 144
    .local v2, "variable":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v2, :cond_14

    .line 145
    invoke-virtual {v2}, Landroid/support/constraint/solver/SolverVariable;->reset()V

    .line 142
    .end local v2    # "variable":Landroid/support/constraint/solver/SolverVariable;
    :cond_14
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    .line 148
    .end local v1    # "i":I
    :cond_17
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->solverVariablePool:Landroid/support/constraint/solver/Pools$Pool;

    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariables:[Landroid/support/constraint/solver/SolverVariable;

    iget v3, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariablesCount:I

    invoke-interface {v1, v2, v3}, Landroid/support/constraint/solver/Pools$Pool;->releaseAll([Ljava/lang/Object;I)V

    .line 149
    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mPoolVariablesCount:I

    .line 151
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mCache:Landroid/support/constraint/solver/Cache;

    iget-object v1, v1, Landroid/support/constraint/solver/Cache;->mIndexedVariables:[Landroid/support/constraint/solver/SolverVariable;

    const/4 v2, 0x0

    invoke-static {v1, v2}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    .line 152
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    if-eqz v1, :cond_35

    .line 153
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mVariables:Ljava/util/HashMap;

    invoke-virtual {v1}, Ljava/util/HashMap;->clear()V

    .line 155
    :cond_35
    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mVariablesID:I

    .line 156
    iget-object v1, p0, Landroid/support/constraint/solver/LinearSystem;->mGoal:Landroid/support/constraint/solver/LinearSystem$Row;

    invoke-interface {v1}, Landroid/support/constraint/solver/LinearSystem$Row;->clear()V

    .line 157
    const/4 v1, 0x1

    iput v1, p0, Landroid/support/constraint/solver/LinearSystem;->mNumColumns:I

    .line 158
    move v1, v0

    .line 158
    .restart local v1    # "i":I
    :goto_40
    iget v2, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    if-ge v1, v2, :cond_4d

    .line 159
    iget-object v2, p0, Landroid/support/constraint/solver/LinearSystem;->mRows:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v2, v2, v1

    iput-boolean v0, v2, Landroid/support/constraint/solver/ArrayRow;->used:Z

    .line 158
    add-int/lit8 v1, v1, 0x1

    goto :goto_40

    .line 161
    .end local v1    # "i":I
    :cond_4d
    invoke-direct {p0}, Landroid/support/constraint/solver/LinearSystem;->releaseRows()V

    .line 162
    iput v0, p0, Landroid/support/constraint/solver/LinearSystem;->mNumRows:I

    .line 163
    return-void
.end method
