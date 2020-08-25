.class public Landroid/support/constraint/solver/widgets/Rectangle;
.super Ljava/lang/Object;
.source "Rectangle.java"


# instance fields
.field public height:I

.field public width:I

.field public x:I

.field public y:I


# direct methods
.method public constructor <init>()V
    .registers 1

    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public contains(II)Z
    .registers 5
    .param p1, "x"    # I
    .param p2, "y"    # I

    .line 46
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    if-lt p1, v0, :cond_18

    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/Rectangle;->width:I

    add-int/2addr v0, v1

    if-ge p1, v0, :cond_18

    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    if-lt p2, v0, :cond_18

    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/Rectangle;->height:I

    add-int/2addr v0, v1

    if-ge p2, v0, :cond_18

    const/4 v0, 0x1

    goto :goto_19

    :cond_18
    const/4 v0, 0x0

    :goto_19
    return v0
.end method

.method public getCenterX()I
    .registers 3

    .line 50
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/Rectangle;->width:I

    add-int/2addr v0, v1

    div-int/lit8 v0, v0, 0x2

    return v0
.end method

.method public getCenterY()I
    .registers 3

    .line 51
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/Rectangle;->height:I

    add-int/2addr v0, v1

    div-int/lit8 v0, v0, 0x2

    return v0
.end method

.method grow(II)V
    .registers 5
    .param p1, "w"    # I
    .param p2, "h"    # I

    .line 34
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    sub-int/2addr v0, p1

    iput v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    .line 35
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    sub-int/2addr v0, p2

    iput v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    .line 36
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->width:I

    mul-int/lit8 v1, p1, 0x2

    add-int/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->width:I

    .line 37
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->height:I

    mul-int/lit8 v1, p2, 0x2

    add-int/2addr v0, v1

    iput v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->height:I

    .line 38
    return-void
.end method

.method intersects(Landroid/support/constraint/solver/widgets/Rectangle;)Z
    .registers 5
    .param p1, "bounds"    # Landroid/support/constraint/solver/widgets/Rectangle;

    .line 41
    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    iget v1, p1, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    if-lt v0, v1, :cond_20

    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    iget v1, p1, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    iget v2, p1, Landroid/support/constraint/solver/widgets/Rectangle;->width:I

    add-int/2addr v1, v2

    if-ge v0, v1, :cond_20

    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    iget v1, p1, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    if-lt v0, v1, :cond_20

    iget v0, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    iget v1, p1, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    iget v2, p1, Landroid/support/constraint/solver/widgets/Rectangle;->height:I

    add-int/2addr v1, v2

    if-ge v0, v1, :cond_20

    const/4 v0, 0x1

    goto :goto_21

    :cond_20
    const/4 v0, 0x0

    :goto_21
    return v0
.end method

.method public setBounds(IIII)V
    .registers 5
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I

    .line 28
    iput p1, p0, Landroid/support/constraint/solver/widgets/Rectangle;->x:I

    .line 29
    iput p2, p0, Landroid/support/constraint/solver/widgets/Rectangle;->y:I

    .line 30
    iput p3, p0, Landroid/support/constraint/solver/widgets/Rectangle;->width:I

    .line 31
    iput p4, p0, Landroid/support/constraint/solver/widgets/Rectangle;->height:I

    .line 32
    return-void
.end method
