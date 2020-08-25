.class public Landroid/support/constraint/solver/widgets/ResolutionNode;
.super Ljava/lang/Object;
.source "ResolutionNode.java"


# static fields
.field public static final REMOVED:I = 0x2

.field public static final RESOLVED:I = 0x1

.field public static final UNRESOLVED:I


# instance fields
.field dependents:Ljava/util/HashSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashSet<",
            "Landroid/support/constraint/solver/widgets/ResolutionNode;",
            ">;"
        }
    .end annotation
.end field

.field state:I


# direct methods
.method public constructor <init>()V
    .registers 3

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    new-instance v0, Ljava/util/HashSet;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(I)V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->dependents:Ljava/util/HashSet;

    .line 35
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->state:I

    return-void
.end method


# virtual methods
.method public addDependent(Landroid/support/constraint/solver/widgets/ResolutionNode;)V
    .registers 3
    .param p1, "node"    # Landroid/support/constraint/solver/widgets/ResolutionNode;

    .line 38
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->dependents:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 39
    return-void
.end method

.method public didResolve()V
    .registers 3

    .line 63
    const/4 v0, 0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->state:I

    .line 70
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->dependents:Ljava/util/HashSet;

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_19

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/support/constraint/solver/widgets/ResolutionNode;

    .line 71
    .local v1, "node":Landroid/support/constraint/solver/widgets/ResolutionNode;
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionNode;->resolve()V

    .line 72
    .end local v1    # "node":Landroid/support/constraint/solver/widgets/ResolutionNode;
    goto :goto_9

    .line 73
    :cond_19
    return-void
.end method

.method public invalidate()V
    .registers 3

    .line 47
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->state:I

    .line 48
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->dependents:Ljava/util/HashSet;

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_19

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/support/constraint/solver/widgets/ResolutionNode;

    .line 49
    .local v1, "node":Landroid/support/constraint/solver/widgets/ResolutionNode;
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionNode;->invalidate()V

    .line 50
    .end local v1    # "node":Landroid/support/constraint/solver/widgets/ResolutionNode;
    goto :goto_9

    .line 51
    :cond_19
    return-void
.end method

.method public invalidateAnchors()V
    .registers 3

    .line 54
    instance-of v0, p0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    if-eqz v0, :cond_7

    .line 55
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->state:I

    .line 57
    :cond_7
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->dependents:Ljava/util/HashSet;

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1d

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/support/constraint/solver/widgets/ResolutionNode;

    .line 58
    .local v1, "node":Landroid/support/constraint/solver/widgets/ResolutionNode;
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionNode;->invalidateAnchors()V

    .line 59
    .end local v1    # "node":Landroid/support/constraint/solver/widgets/ResolutionNode;
    goto :goto_d

    .line 60
    :cond_1d
    return-void
.end method

.method public isResolved()Z
    .registers 3

    .line 76
    iget v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->state:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_6

    goto :goto_7

    :cond_6
    const/4 v1, 0x0

    :goto_7
    return v1
.end method

.method public remove(Landroid/support/constraint/solver/widgets/ResolutionDimension;)V
    .registers 2
    .param p1, "resolutionDimension"    # Landroid/support/constraint/solver/widgets/ResolutionDimension;

    .line 85
    return-void
.end method

.method public reset()V
    .registers 2

    .line 42
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->state:I

    .line 43
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ResolutionNode;->dependents:Ljava/util/HashSet;

    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 44
    return-void
.end method

.method public resolve()V
    .registers 1

    .line 81
    return-void
.end method
