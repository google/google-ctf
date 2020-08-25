.class public Landroid/support/constraint/solver/GoalRow;
.super Landroid/support/constraint/solver/ArrayRow;
.source "GoalRow.java"


# direct methods
.method public constructor <init>(Landroid/support/constraint/solver/Cache;)V
    .registers 2
    .param p1, "cache"    # Landroid/support/constraint/solver/Cache;

    .line 22
    invoke-direct {p0, p1}, Landroid/support/constraint/solver/ArrayRow;-><init>(Landroid/support/constraint/solver/Cache;)V

    .line 23
    return-void
.end method


# virtual methods
.method public addError(Landroid/support/constraint/solver/SolverVariable;)V
    .registers 3
    .param p1, "error"    # Landroid/support/constraint/solver/SolverVariable;

    .line 27
    invoke-super {p0, p1}, Landroid/support/constraint/solver/ArrayRow;->addError(Landroid/support/constraint/solver/SolverVariable;)V

    .line 30
    iget v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p1, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 31
    return-void
.end method
