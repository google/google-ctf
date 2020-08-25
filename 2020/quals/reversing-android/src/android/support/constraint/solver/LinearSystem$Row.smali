.class interface abstract Landroid/support/constraint/solver/LinearSystem$Row;
.super Ljava/lang/Object;
.source "LinearSystem.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/constraint/solver/LinearSystem;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x608
    name = "Row"
.end annotation


# virtual methods
.method public abstract addError(Landroid/support/constraint/solver/SolverVariable;)V
.end method

.method public abstract clear()V
.end method

.method public abstract getKey()Landroid/support/constraint/solver/SolverVariable;
.end method

.method public abstract getPivotCandidate(Landroid/support/constraint/solver/LinearSystem;[Z)Landroid/support/constraint/solver/SolverVariable;
.end method

.method public abstract initFromRow(Landroid/support/constraint/solver/LinearSystem$Row;)V
.end method

.method public abstract isEmpty()Z
.end method
