.class public Landroid/support/constraint/Constraints;
.super Landroid/view/ViewGroup;
.source "Constraints.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/Constraints$LayoutParams;
    }
.end annotation


# static fields
.field public static final TAG:Ljava/lang/String; = "Constraints"


# instance fields
.field myConstraintSet:Landroid/support/constraint/ConstraintSet;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .registers 3
    .param p1, "context"    # Landroid/content/Context;

    .line 41
    invoke-direct {p0, p1}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;)V

    .line 42
    const/16 v0, 0x8

    invoke-super {p0, v0}, Landroid/view/ViewGroup;->setVisibility(I)V

    .line 43
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .registers 4
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;

    .line 46
    invoke-direct {p0, p1, p2}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 47
    invoke-direct {p0, p2}, Landroid/support/constraint/Constraints;->init(Landroid/util/AttributeSet;)V

    .line 48
    const/16 v0, 0x8

    invoke-super {p0, v0}, Landroid/view/ViewGroup;->setVisibility(I)V

    .line 49
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .registers 5
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;
    .param p3, "defStyleAttr"    # I

    .line 52
    invoke-direct {p0, p1, p2, p3}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 53
    invoke-direct {p0, p2}, Landroid/support/constraint/Constraints;->init(Landroid/util/AttributeSet;)V

    .line 54
    const/16 v0, 0x8

    invoke-super {p0, v0}, Landroid/view/ViewGroup;->setVisibility(I)V

    .line 55
    return-void
.end method

.method private init(Landroid/util/AttributeSet;)V
    .registers 4
    .param p1, "attrs"    # Landroid/util/AttributeSet;

    .line 135
    const-string v0, "Constraints"

    const-string v1, " ################# init"

    invoke-static {v0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 136
    return-void
.end method


# virtual methods
.method protected generateDefaultLayoutParams()Landroid/support/constraint/Constraints$LayoutParams;
    .registers 3

    .line 131
    new-instance v0, Landroid/support/constraint/Constraints$LayoutParams;

    const/4 v1, -0x2

    invoke-direct {v0, v1, v1}, Landroid/support/constraint/Constraints$LayoutParams;-><init>(II)V

    return-object v0
.end method

.method protected bridge synthetic generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .registers 2

    .line 35
    invoke-virtual {p0}, Landroid/support/constraint/Constraints;->generateDefaultLayoutParams()Landroid/support/constraint/Constraints$LayoutParams;

    move-result-object v0

    return-object v0
.end method

.method public generateLayoutParams(Landroid/util/AttributeSet;)Landroid/support/constraint/Constraints$LayoutParams;
    .registers 4
    .param p1, "attrs"    # Landroid/util/AttributeSet;

    .line 62
    new-instance v0, Landroid/support/constraint/Constraints$LayoutParams;

    invoke-virtual {p0}, Landroid/support/constraint/Constraints;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {v0, v1, p1}, Landroid/support/constraint/Constraints$LayoutParams;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-object v0
.end method

.method public bridge synthetic generateLayoutParams(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;
    .registers 2

    .line 35
    invoke-virtual {p0, p1}, Landroid/support/constraint/Constraints;->generateLayoutParams(Landroid/util/AttributeSet;)Landroid/support/constraint/Constraints$LayoutParams;

    move-result-object p1

    return-object p1
.end method

.method protected generateLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Landroid/view/ViewGroup$LayoutParams;
    .registers 3
    .param p1, "p"    # Landroid/view/ViewGroup$LayoutParams;

    .line 143
    new-instance v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    invoke-direct {v0, p1}, Landroid/support/constraint/ConstraintLayout$LayoutParams;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    return-object v0
.end method

.method public getConstraintSet()Landroid/support/constraint/ConstraintSet;
    .registers 2

    .line 147
    iget-object v0, p0, Landroid/support/constraint/Constraints;->myConstraintSet:Landroid/support/constraint/ConstraintSet;

    if-nez v0, :cond_b

    .line 148
    new-instance v0, Landroid/support/constraint/ConstraintSet;

    invoke-direct {v0}, Landroid/support/constraint/ConstraintSet;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/Constraints;->myConstraintSet:Landroid/support/constraint/ConstraintSet;

    .line 151
    :cond_b
    iget-object v0, p0, Landroid/support/constraint/Constraints;->myConstraintSet:Landroid/support/constraint/ConstraintSet;

    invoke-virtual {v0, p0}, Landroid/support/constraint/ConstraintSet;->clone(Landroid/support/constraint/Constraints;)V

    .line 152
    iget-object v0, p0, Landroid/support/constraint/Constraints;->myConstraintSet:Landroid/support/constraint/ConstraintSet;

    return-object v0
.end method

.method protected onLayout(ZIIII)V
    .registers 6
    .param p1, "changed"    # Z
    .param p2, "l"    # I
    .param p3, "t"    # I
    .param p4, "r"    # I
    .param p5, "b"    # I

    .line 159
    return-void
.end method
