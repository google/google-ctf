.class public abstract Landroid/support/constraint/ConstraintHelper;
.super Landroid/view/View;
.source "ConstraintHelper.java"


# instance fields
.field protected mCount:I

.field protected mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

.field protected mIds:[I

.field private mReferenceIds:Ljava/lang/String;

.field protected mUseViewMeasure:Z

.field protected myContext:Landroid/content/Context;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .registers 3
    .param p1, "context"    # Landroid/content/Context;

    .line 64
    invoke-direct {p0, p1}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    .line 40
    const/16 v0, 0x20

    new-array v0, v0, [I

    iput-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    .line 57
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintHelper;->mUseViewMeasure:Z

    .line 65
    iput-object p1, p0, Landroid/support/constraint/ConstraintHelper;->myContext:Landroid/content/Context;

    .line 66
    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/support/constraint/ConstraintHelper;->init(Landroid/util/AttributeSet;)V

    .line 67
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .registers 4
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;

    .line 70
    invoke-direct {p0, p1, p2}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 40
    const/16 v0, 0x20

    new-array v0, v0, [I

    iput-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    .line 57
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintHelper;->mUseViewMeasure:Z

    .line 71
    iput-object p1, p0, Landroid/support/constraint/ConstraintHelper;->myContext:Landroid/content/Context;

    .line 72
    invoke-virtual {p0, p2}, Landroid/support/constraint/ConstraintHelper;->init(Landroid/util/AttributeSet;)V

    .line 73
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .registers 5
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;
    .param p3, "defStyleAttr"    # I

    .line 76
    invoke-direct {p0, p1, p2, p3}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 40
    const/16 v0, 0x20

    new-array v0, v0, [I

    iput-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    .line 57
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintHelper;->mUseViewMeasure:Z

    .line 77
    iput-object p1, p0, Landroid/support/constraint/ConstraintHelper;->myContext:Landroid/content/Context;

    .line 78
    invoke-virtual {p0, p2}, Landroid/support/constraint/ConstraintHelper;->init(Landroid/util/AttributeSet;)V

    .line 79
    return-void
.end method

.method private addID(Ljava/lang/String;)V
    .registers 8
    .param p1, "idString"    # Ljava/lang/String;

    .line 168
    if-nez p1, :cond_3

    .line 169
    return-void

    .line 171
    :cond_3
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->myContext:Landroid/content/Context;

    if-nez v0, :cond_8

    .line 172
    return-void

    .line 174
    :cond_8
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p1

    .line 175
    const/4 v0, 0x0

    move v1, v0

    .line 177
    .local v1, "tag":I
    const/4 v2, 0x0

    :try_start_f
    const-class v3, Landroid/support/constraint/R$id;

    .line 178
    .local v3, "res":Ljava/lang/Class;
    invoke-virtual {v3, p1}, Ljava/lang/Class;->getField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v4

    .line 179
    .local v4, "field":Ljava/lang/reflect/Field;
    invoke-virtual {v4, v2}, Ljava/lang/reflect/Field;->getInt(Ljava/lang/Object;)I

    move-result v5
    :try_end_19
    .catch Ljava/lang/Exception; {:try_start_f .. :try_end_19} :catch_1b

    move v1, v5

    .line 183
    .end local v3    # "res":Ljava/lang/Class;
    .end local v4    # "field":Ljava/lang/reflect/Field;
    goto :goto_1c

    .line 181
    :catch_1b
    move-exception v3

    .line 184
    :goto_1c
    if-nez v1, :cond_30

    .line 185
    iget-object v3, p0, Landroid/support/constraint/ConstraintHelper;->myContext:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    const-string v4, "id"

    iget-object v5, p0, Landroid/support/constraint/ConstraintHelper;->myContext:Landroid/content/Context;

    .line 186
    invoke-virtual {v5}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v5

    .line 185
    invoke-virtual {v3, p1, v4, v5}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    move-result v1

    .line 188
    :cond_30
    if-nez v1, :cond_57

    invoke-virtual {p0}, Landroid/support/constraint/ConstraintHelper;->isInEditMode()Z

    move-result v3

    if-eqz v3, :cond_57

    invoke-virtual {p0}, Landroid/support/constraint/ConstraintHelper;->getParent()Landroid/view/ViewParent;

    move-result-object v3

    instance-of v3, v3, Landroid/support/constraint/ConstraintLayout;

    if-eqz v3, :cond_57

    .line 189
    invoke-virtual {p0}, Landroid/support/constraint/ConstraintHelper;->getParent()Landroid/view/ViewParent;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/ConstraintLayout;

    .line 190
    .local v3, "constraintLayout":Landroid/support/constraint/ConstraintLayout;
    invoke-virtual {v3, v0, p1}, Landroid/support/constraint/ConstraintLayout;->getDesignInformation(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    .line 191
    .local v0, "value":Ljava/lang/Object;
    if-eqz v0, :cond_57

    instance-of v4, v0, Ljava/lang/Integer;

    if-eqz v4, :cond_57

    .line 192
    move-object v4, v0

    check-cast v4, Ljava/lang/Integer;

    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v1

    .line 196
    .end local v0    # "value":Ljava/lang/Object;
    .end local v3    # "constraintLayout":Landroid/support/constraint/ConstraintLayout;
    :cond_57
    if-eqz v1, :cond_5d

    .line 197
    invoke-virtual {p0, v1, v2}, Landroid/support/constraint/ConstraintHelper;->setTag(ILjava/lang/Object;)V

    goto :goto_78

    .line 199
    :cond_5d
    const-string v0, "ConstraintHelper"

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Could not find id of \""

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\""

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 201
    :goto_78
    return-void
.end method

.method private setIds(Ljava/lang/String;)V
    .registers 5
    .param p1, "idList"    # Ljava/lang/String;

    .line 207
    if-nez p1, :cond_3

    .line 208
    return-void

    .line 210
    :cond_3
    const/4 v0, 0x0

    .line 212
    .local v0, "begin":I
    :goto_4
    const/16 v1, 0x2c

    invoke-virtual {p1, v1, v0}, Ljava/lang/String;->indexOf(II)I

    move-result v1

    .line 213
    .local v1, "end":I
    const/4 v2, -0x1

    if-ne v1, v2, :cond_16

    .line 214
    invoke-virtual {p1, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v2

    invoke-direct {p0, v2}, Landroid/support/constraint/ConstraintHelper;->addID(Ljava/lang/String;)V

    .line 215
    nop

    .line 220
    .end local v1    # "end":I
    return-void

    .line 217
    .restart local v1    # "end":I
    :cond_16
    invoke-virtual {p1, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    invoke-direct {p0, v2}, Landroid/support/constraint/ConstraintHelper;->addID(Ljava/lang/String;)V

    .line 218
    add-int/lit8 v0, v1, 0x1

    .line 219
    .end local v1    # "end":I
    goto :goto_4
.end method


# virtual methods
.method public getReferencedIds()[I
    .registers 3

    .line 103
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    iget v1, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v0

    return-object v0
.end method

.method protected init(Landroid/util/AttributeSet;)V
    .registers 7
    .param p1, "attrs"    # Landroid/util/AttributeSet;

    .line 85
    if-eqz p1, :cond_29

    .line 86
    invoke-virtual {p0}, Landroid/support/constraint/ConstraintHelper;->getContext()Landroid/content/Context;

    move-result-object v0

    sget-object v1, Landroid/support/constraint/R$styleable;->ConstraintLayout_Layout:[I

    invoke-virtual {v0, p1, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v0

    .line 87
    .local v0, "a":Landroid/content/res/TypedArray;
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result v1

    .line 88
    .local v1, "N":I
    const/4 v2, 0x0

    .line 88
    .local v2, "i":I
    :goto_11
    if-ge v2, v1, :cond_29

    .line 89
    invoke-virtual {v0, v2}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v3

    .line 90
    .local v3, "attr":I
    sget v4, Landroid/support/constraint/R$styleable;->ConstraintLayout_Layout_constraint_referenced_ids:I

    if-ne v3, v4, :cond_26

    .line 91
    invoke-virtual {v0, v3}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v4

    iput-object v4, p0, Landroid/support/constraint/ConstraintHelper;->mReferenceIds:Ljava/lang/String;

    .line 92
    iget-object v4, p0, Landroid/support/constraint/ConstraintHelper;->mReferenceIds:Ljava/lang/String;

    invoke-direct {p0, v4}, Landroid/support/constraint/ConstraintHelper;->setIds(Ljava/lang/String;)V

    .line 88
    .end local v3    # "attr":I
    :cond_26
    add-int/lit8 v2, v2, 0x1

    goto :goto_11

    .line 96
    .end local v0    # "a":Landroid/content/res/TypedArray;
    .end local v1    # "N":I
    .end local v2    # "i":I
    :cond_29
    return-void
.end method

.method public onDraw(Landroid/graphics/Canvas;)V
    .registers 2
    .param p1, "canvas"    # Landroid/graphics/Canvas;

    .line 135
    return-void
.end method

.method protected onMeasure(II)V
    .registers 4
    .param p1, "widthMeasureSpec"    # I
    .param p2, "heightMeasureSpec"    # I

    .line 142
    iget-boolean v0, p0, Landroid/support/constraint/ConstraintHelper;->mUseViewMeasure:Z

    if-eqz v0, :cond_8

    .line 143
    invoke-super {p0, p1, p2}, Landroid/view/View;->onMeasure(II)V

    goto :goto_c

    .line 145
    :cond_8
    const/4 v0, 0x0

    invoke-virtual {p0, v0, v0}, Landroid/support/constraint/ConstraintHelper;->setMeasuredDimension(II)V

    .line 147
    :goto_c
    return-void
.end method

.method public setReferencedIds([I)V
    .registers 5
    .param p1, "ids"    # [I

    .line 111
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    .line 112
    nop

    .line 112
    .local v0, "i":I
    :goto_4
    array-length v1, p1

    if-ge v0, v1, :cond_10

    .line 113
    aget v1, p1, v0

    const/4 v2, 0x0

    invoke-virtual {p0, v1, v2}, Landroid/support/constraint/ConstraintHelper;->setTag(ILjava/lang/Object;)V

    .line 112
    add-int/lit8 v0, v0, 0x1

    goto :goto_4

    .line 115
    .end local v0    # "i":I
    :cond_10
    return-void
.end method

.method public setTag(ILjava/lang/Object;)V
    .registers 5
    .param p1, "tag"    # I
    .param p2, "value"    # Ljava/lang/Object;

    .line 122
    iget v0, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    add-int/lit8 v0, v0, 0x1

    iget-object v1, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    array-length v1, v1

    if-le v0, v1, :cond_16

    .line 123
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    iget-object v1, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    array-length v1, v1

    mul-int/lit8 v1, v1, 0x2

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v0

    iput-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    .line 125
    :cond_16
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    iget v1, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    aput p1, v0, v1

    .line 126
    iget v0, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    .line 127
    return-void
.end method

.method public updatePostLayout(Landroid/support/constraint/ConstraintLayout;)V
    .registers 2
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 253
    return-void
.end method

.method public updatePostMeasure(Landroid/support/constraint/ConstraintLayout;)V
    .registers 2
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 261
    return-void
.end method

.method public updatePreLayout(Landroid/support/constraint/ConstraintLayout;)V
    .registers 7
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 229
    invoke-virtual {p0}, Landroid/support/constraint/ConstraintHelper;->isInEditMode()Z

    move-result v0

    if-eqz v0, :cond_b

    .line 230
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mReferenceIds:Ljava/lang/String;

    invoke-direct {p0, v0}, Landroid/support/constraint/ConstraintHelper;->setIds(Ljava/lang/String;)V

    .line 232
    :cond_b
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

    if-nez v0, :cond_10

    .line 233
    return-void

    .line 235
    :cond_10
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/Helper;->removeAllIds()V

    .line 236
    const/4 v0, 0x0

    .line 236
    .local v0, "i":I
    :goto_16
    iget v1, p0, Landroid/support/constraint/ConstraintHelper;->mCount:I

    if-ge v0, v1, :cond_30

    .line 237
    iget-object v1, p0, Landroid/support/constraint/ConstraintHelper;->mIds:[I

    aget v1, v1, v0

    .line 238
    .local v1, "id":I
    invoke-virtual {p1, v1}, Landroid/support/constraint/ConstraintLayout;->getViewById(I)Landroid/view/View;

    move-result-object v2

    .line 239
    .local v2, "view":Landroid/view/View;
    if-eqz v2, :cond_2d

    .line 240
    iget-object v3, p0, Landroid/support/constraint/ConstraintHelper;->mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

    invoke-virtual {p1, v2}, Landroid/support/constraint/ConstraintLayout;->getViewWidget(Landroid/view/View;)Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    invoke-virtual {v3, v4}, Landroid/support/constraint/solver/widgets/Helper;->add(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 236
    .end local v1    # "id":I
    .end local v2    # "view":Landroid/view/View;
    :cond_2d
    add-int/lit8 v0, v0, 0x1

    goto :goto_16

    .line 243
    .end local v0    # "i":I
    :cond_30
    return-void
.end method

.method public validateParams()V
    .registers 4

    .line 154
    iget-object v0, p0, Landroid/support/constraint/ConstraintHelper;->mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

    if-nez v0, :cond_5

    .line 155
    return-void

    .line 157
    :cond_5
    invoke-virtual {p0}, Landroid/support/constraint/ConstraintHelper;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    .line 158
    .local v0, "params":Landroid/view/ViewGroup$LayoutParams;
    instance-of v1, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    if-eqz v1, :cond_14

    .line 159
    move-object v1, v0

    check-cast v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 160
    .local v1, "layoutParams":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    iget-object v2, p0, Landroid/support/constraint/ConstraintHelper;->mHelperWidget:Landroid/support/constraint/solver/widgets/Helper;

    iput-object v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 162
    .end local v1    # "layoutParams":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    :cond_14
    return-void
.end method
