.class public Landroid/support/constraint/Placeholder;
.super Landroid/view/View;
.source "Placeholder.java"


# instance fields
.field private mContent:Landroid/view/View;

.field private mContentId:I

.field private mEmptyVisibility:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .registers 4
    .param p1, "context"    # Landroid/content/Context;

    .line 49
    invoke-direct {p0, p1}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    .line 44
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    .line 45
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 46
    const/4 v1, 0x4

    iput v1, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    .line 50
    invoke-direct {p0, v0}, Landroid/support/constraint/Placeholder;->init(Landroid/util/AttributeSet;)V

    .line 51
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .registers 4
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;

    .line 54
    invoke-direct {p0, p1, p2}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 44
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    .line 45
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 46
    const/4 v0, 0x4

    iput v0, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    .line 55
    invoke-direct {p0, p2}, Landroid/support/constraint/Placeholder;->init(Landroid/util/AttributeSet;)V

    .line 56
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .registers 5
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;
    .param p3, "defStyleAttr"    # I

    .line 59
    invoke-direct {p0, p1, p2, p3}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 44
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    .line 45
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 46
    const/4 v0, 0x4

    iput v0, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    .line 60
    invoke-direct {p0, p2}, Landroid/support/constraint/Placeholder;->init(Landroid/util/AttributeSet;)V

    .line 61
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .registers 6
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;
    .param p3, "defStyleAttr"    # I
    .param p4, "defStyleRes"    # I

    .line 64
    invoke-direct {p0, p1, p2, p3}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 44
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    .line 45
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 46
    const/4 v0, 0x4

    iput v0, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    .line 65
    invoke-direct {p0, p2}, Landroid/support/constraint/Placeholder;->init(Landroid/util/AttributeSet;)V

    .line 66
    return-void
.end method

.method private init(Landroid/util/AttributeSet;)V
    .registers 7
    .param p1, "attrs"    # Landroid/util/AttributeSet;

    .line 69
    iget v0, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    invoke-super {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 70
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    .line 71
    if-eqz p1, :cond_3b

    .line 72
    invoke-virtual {p0}, Landroid/support/constraint/Placeholder;->getContext()Landroid/content/Context;

    move-result-object v0

    sget-object v1, Landroid/support/constraint/R$styleable;->ConstraintLayout_placeholder:[I

    invoke-virtual {v0, p1, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v0

    .line 73
    .local v0, "a":Landroid/content/res/TypedArray;
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result v1

    .line 74
    .local v1, "N":I
    const/4 v2, 0x0

    .line 74
    .local v2, "i":I
    :goto_19
    if-ge v2, v1, :cond_3b

    .line 75
    invoke-virtual {v0, v2}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v3

    .line 76
    .local v3, "attr":I
    sget v4, Landroid/support/constraint/R$styleable;->ConstraintLayout_placeholder_content:I

    if-ne v3, v4, :cond_2c

    .line 77
    iget v4, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    invoke-virtual {v0, v3, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    goto :goto_38

    .line 79
    :cond_2c
    sget v4, Landroid/support/constraint/R$styleable;->ConstraintLayout_placeholder_emptyVisibility:I

    if-ne v3, v4, :cond_38

    .line 80
    iget v4, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    invoke-virtual {v0, v3, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    .line 74
    .end local v3    # "attr":I
    :cond_38
    :goto_38
    add-int/lit8 v2, v2, 0x1

    goto :goto_19

    .line 85
    .end local v0    # "a":Landroid/content/res/TypedArray;
    .end local v1    # "N":I
    .end local v2    # "i":I
    :cond_3b
    return-void
.end method


# virtual methods
.method public getContent()Landroid/view/View;
    .registers 2

    .line 113
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    return-object v0
.end method

.method public getEmptyVisibility()I
    .registers 2

    .line 104
    iget v0, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    return v0
.end method

.method public onDraw(Landroid/graphics/Canvas;)V
    .registers 11
    .param p1, "canvas"    # Landroid/graphics/Canvas;

    .line 121
    invoke-virtual {p0}, Landroid/support/constraint/Placeholder;->isInEditMode()Z

    move-result v0

    if-eqz v0, :cond_6b

    .line 122
    const/16 v0, 0xdf

    invoke-virtual {p1, v0, v0, v0}, Landroid/graphics/Canvas;->drawRGB(III)V

    .line 123
    new-instance v0, Landroid/graphics/Paint;

    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V

    .line 124
    .local v0, "paint":Landroid/graphics/Paint;
    const/16 v1, 0xff

    const/16 v2, 0xd2

    invoke-virtual {v0, v1, v2, v2, v2}, Landroid/graphics/Paint;->setARGB(IIII)V

    .line 125
    sget-object v1, Landroid/graphics/Paint$Align;->CENTER:Landroid/graphics/Paint$Align;

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setTextAlign(Landroid/graphics/Paint$Align;)V

    .line 126
    sget-object v1, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    const/4 v2, 0x0

    invoke-static {v1, v2}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 128
    new-instance v1, Landroid/graphics/Rect;

    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 129
    .local v1, "r":Landroid/graphics/Rect;
    invoke-virtual {p1, v1}, Landroid/graphics/Canvas;->getClipBounds(Landroid/graphics/Rect;)Z

    .line 130
    invoke-virtual {v1}, Landroid/graphics/Rect;->height()I

    move-result v3

    int-to-float v3, v3

    invoke-virtual {v0, v3}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 131
    invoke-virtual {v1}, Landroid/graphics/Rect;->height()I

    move-result v3

    .line 132
    .local v3, "cHeight":I
    invoke-virtual {v1}, Landroid/graphics/Rect;->width()I

    move-result v4

    .line 133
    .local v4, "cWidth":I
    sget-object v5, Landroid/graphics/Paint$Align;->LEFT:Landroid/graphics/Paint$Align;

    invoke-virtual {v0, v5}, Landroid/graphics/Paint;->setTextAlign(Landroid/graphics/Paint$Align;)V

    .line 134
    const-string v5, "?"

    .line 135
    .local v5, "text":Ljava/lang/String;
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    move-result v6

    invoke-virtual {v0, v5, v2, v6, v1}, Landroid/graphics/Paint;->getTextBounds(Ljava/lang/String;IILandroid/graphics/Rect;)V

    .line 136
    int-to-float v2, v4

    const/high16 v6, 0x40000000    # 2.0f

    div-float/2addr v2, v6

    invoke-virtual {v1}, Landroid/graphics/Rect;->width()I

    move-result v7

    int-to-float v7, v7

    div-float/2addr v7, v6

    sub-float/2addr v2, v7

    iget v7, v1, Landroid/graphics/Rect;->left:I

    int-to-float v7, v7

    sub-float/2addr v2, v7

    .line 137
    .local v2, "x":F
    int-to-float v7, v3

    div-float/2addr v7, v6

    invoke-virtual {v1}, Landroid/graphics/Rect;->height()I

    move-result v8

    int-to-float v8, v8

    div-float/2addr v8, v6

    add-float/2addr v7, v8

    iget v6, v1, Landroid/graphics/Rect;->bottom:I

    int-to-float v6, v6

    sub-float/2addr v7, v6

    .line 138
    .local v7, "y":F
    invoke-virtual {p1, v5, v2, v7, v0}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V

    .line 140
    .end local v0    # "paint":Landroid/graphics/Paint;
    .end local v1    # "r":Landroid/graphics/Rect;
    .end local v2    # "x":F
    .end local v3    # "cHeight":I
    .end local v4    # "cWidth":I
    .end local v5    # "text":Ljava/lang/String;
    .end local v7    # "y":F
    :cond_6b
    return-void
.end method

.method public setContentId(I)V
    .registers 4
    .param p1, "id"    # I

    .line 169
    iget v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    if-ne v0, p1, :cond_5

    .line 170
    return-void

    .line 172
    :cond_5
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    if-eqz v0, :cond_1c

    .line 173
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 174
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 175
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 176
    .local v0, "layoutParamsContent":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    iput-boolean v1, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isInPlaceholder:Z

    .line 177
    const/4 v1, 0x0

    iput-object v1, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 180
    .end local v0    # "layoutParamsContent":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    :cond_1c
    iput p1, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    .line 181
    const/4 v0, -0x1

    if-eq p1, v0, :cond_32

    .line 182
    invoke-virtual {p0}, Landroid/support/constraint/Placeholder;->getParent()Landroid/view/ViewParent;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    invoke-virtual {v0, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    .line 183
    .local v0, "v":Landroid/view/View;
    if-eqz v0, :cond_32

    .line 184
    const/16 v1, 0x8

    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 187
    .end local v0    # "v":Landroid/view/View;
    :cond_32
    return-void
.end method

.method public setEmptyVisibility(I)V
    .registers 2
    .param p1, "visibility"    # I

    .line 95
    iput p1, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    .line 96
    return-void
.end method

.method public updatePostMeasure(Landroid/support/constraint/ConstraintLayout;)V
    .registers 6
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 194
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    if-nez v0, :cond_5

    .line 195
    return-void

    .line 197
    :cond_5
    invoke-virtual {p0}, Landroid/support/constraint/Placeholder;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 198
    .local v0, "layoutParams":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    iget-object v1, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 199
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v1

    check-cast v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 200
    .local v1, "layoutParamsContent":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    iget-object v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    const/4 v3, 0x0

    invoke-virtual {v2, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVisibility(I)V

    .line 201
    iget-object v2, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v3

    invoke-virtual {v2, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setWidth(I)V

    .line 202
    iget-object v2, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v3

    invoke-virtual {v2, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHeight(I)V

    .line 203
    iget-object v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    const/16 v3, 0x8

    invoke-virtual {v2, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVisibility(I)V

    .line 204
    return-void
.end method

.method public updatePreLayout(Landroid/support/constraint/ConstraintLayout;)V
    .registers 5
    .param p1, "container"    # Landroid/support/constraint/ConstraintLayout;

    .line 147
    iget v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    const/4 v1, -0x1

    if-ne v0, v1, :cond_10

    .line 148
    invoke-virtual {p0}, Landroid/support/constraint/Placeholder;->isInEditMode()Z

    move-result v0

    if-nez v0, :cond_10

    .line 149
    iget v0, p0, Landroid/support/constraint/Placeholder;->mEmptyVisibility:I

    invoke-virtual {p0, v0}, Landroid/support/constraint/Placeholder;->setVisibility(I)V

    .line 153
    :cond_10
    iget v0, p0, Landroid/support/constraint/Placeholder;->mContentId:I

    invoke-virtual {p1, v0}, Landroid/support/constraint/ConstraintLayout;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iput-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 154
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    if-eqz v0, :cond_30

    .line 155
    iget-object v0, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    .line 156
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 157
    .local v0, "layoutParamsContent":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    const/4 v1, 0x1

    iput-boolean v1, v0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isInPlaceholder:Z

    .line 158
    iget-object v1, p0, Landroid/support/constraint/Placeholder;->mContent:Landroid/view/View;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 159
    invoke-virtual {p0, v2}, Landroid/support/constraint/Placeholder;->setVisibility(I)V

    .line 161
    .end local v0    # "layoutParamsContent":Landroid/support/constraint/ConstraintLayout$LayoutParams;
    :cond_30
    return-void
.end method
