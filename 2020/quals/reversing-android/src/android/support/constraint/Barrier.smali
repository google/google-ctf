.class public Landroid/support/constraint/Barrier;
.super Landroid/support/constraint/ConstraintHelper;
.source "Barrier.java"


# static fields
.field public static final BOTTOM:I = 0x3

.field public static final END:I = 0x6

.field public static final LEFT:I = 0x0

.field public static final RIGHT:I = 0x1

.field public static final START:I = 0x5

.field public static final TOP:I = 0x2


# instance fields
.field private mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

.field private mIndicatedType:I

.field private mResolvedType:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .registers 3
    .param p1, "context"    # Landroid/content/Context;

    .line 115
    invoke-direct {p0, p1}, Landroid/support/constraint/ConstraintHelper;-><init>(Landroid/content/Context;)V

    .line 116
    const/16 v0, 0x8

    invoke-super {p0, v0}, Landroid/support/constraint/ConstraintHelper;->setVisibility(I)V

    .line 117
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .registers 4
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;

    .line 120
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/ConstraintHelper;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 121
    const/16 v0, 0x8

    invoke-super {p0, v0}, Landroid/support/constraint/ConstraintHelper;->setVisibility(I)V

    .line 122
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .registers 5
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;
    .param p3, "defStyleAttr"    # I

    .line 125
    invoke-direct {p0, p1, p2, p3}, Landroid/support/constraint/ConstraintHelper;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 126
    const/16 v0, 0x8

    invoke-super {p0, v0}, Landroid/support/constraint/ConstraintHelper;->setVisibility(I)V

    .line 127
    return-void
.end method


# virtual methods
.method public allowsGoneWidget()Z
    .registers 2

    .line 204
    iget-object v0, p0, Landroid/support/constraint/Barrier;->mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/Barrier;->allowsGoneWidget()Z

    move-result v0

    return v0
.end method

.method public getType()I
    .registers 2

    .line 135
    iget v0, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    return v0
.end method

.method protected init(Landroid/util/AttributeSet;)V
    .registers 9
    .param p1, "attrs"    # Landroid/util/AttributeSet;

    .line 181
    invoke-super {p0, p1}, Landroid/support/constraint/ConstraintHelper;->init(Landroid/util/AttributeSet;)V

    .line 182
    new-instance v0, Landroid/support/constraint/solver/widgets/Barrier;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/Barrier;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/Barrier;->mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

    .line 183
    if-eqz p1, :cond_3f

    .line 184
    invoke-virtual {p0}, Landroid/support/constraint/Barrier;->getContext()Landroid/content/Context;

    move-result-object v0

    sget-object v1, Landroid/support/constraint/R$styleable;->ConstraintLayout_Layout:[I

    invoke-virtual {v0, p1, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v0

    .line 185
    .local v0, "a":Landroid/content/res/TypedArray;
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result v1

    .line 186
    .local v1, "N":I
    const/4 v2, 0x0

    move v3, v2

    .line 186
    .local v3, "i":I
    :goto_1c
    if-ge v3, v1, :cond_3f

    .line 187
    invoke-virtual {v0, v3}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v4

    .line 188
    .local v4, "attr":I
    sget v5, Landroid/support/constraint/R$styleable;->ConstraintLayout_Layout_barrierDirection:I

    if-ne v4, v5, :cond_2e

    .line 189
    invoke-virtual {v0, v4, v2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v5

    invoke-virtual {p0, v5}, Landroid/support/constraint/Barrier;->setType(I)V

    goto :goto_3c

    .line 190
    :cond_2e
    sget v5, Landroid/support/constraint/R$styleable;->ConstraintLayout_Layout_barrierAllowsGoneWidgets:I

    if-ne v4, v5, :cond_3c

    .line 191
    iget-object v5, p0, Landroid/support/constraint/Barrier;->mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

    const/4 v6, 0x1

    invoke-virtual {v0, v4, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v6

    invoke-virtual {v5, v6}, Landroid/support/constraint/solver/widgets/Barrier;->setAllowsGoneWidget(Z)V

    .line 186
    .end local v4    # "attr":I
    :cond_3c
    :goto_3c
    add-int/lit8 v3, v3, 0x1

    goto :goto_1c

    .line 195
    .end local v0    # "a":Landroid/content/res/TypedArray;
    .end local v1    # "N":I
    .end local v3    # "i":I
    :cond_3f
    iget-object v0, p0, Landroid/support/constraint/Barrier;->mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

    iput-object v0, p0, Landroid/support/constraint/Barrier;->mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

    .line 196
    invoke-virtual {p0}, Landroid/support/constraint/Barrier;->validateParams()V

    .line 197
    return-void
.end method

.method public setAllowsGoneWidget(Z)V
    .registers 3
    .param p1, "supportGone"    # Z

    .line 200
    iget-object v0, p0, Landroid/support/constraint/Barrier;->mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/Barrier;->setAllowsGoneWidget(Z)V

    .line 201
    return-void
.end method

.method public setType(I)V
    .registers 9
    .param p1, "type"    # I

    .line 144
    iput p1, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    .line 145
    iput p1, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    .line 146
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/4 v1, 0x6

    const/4 v2, 0x5

    const/4 v3, 0x0

    const/4 v4, 0x1

    const/16 v5, 0x11

    if-ge v0, v5, :cond_1c

    .line 149
    iget v0, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    if-ne v0, v2, :cond_15

    .line 150
    iput v3, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    goto :goto_4a

    .line 151
    :cond_15
    iget v0, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    if-ne v0, v1, :cond_4a

    .line 152
    iput v4, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    goto :goto_4a

    .line 156
    :cond_1c
    invoke-virtual {p0}, Landroid/support/constraint/Barrier;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v0

    .line 157
    .local v0, "config":Landroid/content/res/Configuration;
    invoke-virtual {v0}, Landroid/content/res/Configuration;->getLayoutDirection()I

    move-result v5

    if-ne v4, v5, :cond_2c

    move v5, v4

    goto :goto_2d

    :cond_2c
    move v5, v3

    .line 158
    .local v5, "isRtl":Z
    :goto_2d
    if-eqz v5, :cond_3d

    .line 159
    iget v6, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    if-ne v6, v2, :cond_36

    .line 160
    iput v4, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    goto :goto_4a

    .line 161
    :cond_36
    iget v2, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    if-ne v2, v1, :cond_4a

    .line 162
    iput v3, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    goto :goto_4a

    .line 165
    :cond_3d
    iget v6, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    if-ne v6, v2, :cond_44

    .line 166
    iput v3, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    goto :goto_4a

    .line 167
    :cond_44
    iget v2, p0, Landroid/support/constraint/Barrier;->mIndicatedType:I

    if-ne v2, v1, :cond_4a

    .line 168
    iput v4, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    .line 172
    .end local v0    # "config":Landroid/content/res/Configuration;
    .end local v5    # "isRtl":Z
    :cond_4a
    :goto_4a
    iget-object v0, p0, Landroid/support/constraint/Barrier;->mBarrier:Landroid/support/constraint/solver/widgets/Barrier;

    iget v1, p0, Landroid/support/constraint/Barrier;->mResolvedType:I

    invoke-virtual {v0, v1}, Landroid/support/constraint/solver/widgets/Barrier;->setBarrierType(I)V

    .line 173
    return-void
.end method
