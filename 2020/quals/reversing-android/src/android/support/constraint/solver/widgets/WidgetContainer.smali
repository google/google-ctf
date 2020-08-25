.class public Landroid/support/constraint/solver/widgets/WidgetContainer;
.super Landroid/support/constraint/solver/widgets/ConstraintWidget;
.source "WidgetContainer.java"


# instance fields
.field protected mChildren:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .registers 2

    .line 35
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    .line 26
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 36
    return-void
.end method

.method public constructor <init>(II)V
    .registers 4
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 57
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>(II)V

    .line 26
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 58
    return-void
.end method

.method public constructor <init>(IIII)V
    .registers 6
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I

    .line 47
    invoke-direct {p0, p1, p2, p3, p4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>(IIII)V

    .line 26
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    .line 48
    return-void
.end method

.method public static getBounds(Ljava/util/ArrayList;)Landroid/support/constraint/solver/widgets/Rectangle;
    .registers 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;)",
            "Landroid/support/constraint/solver/widgets/Rectangle;"
        }
    .end annotation

    .line 205
    .local p0, "widgets":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    new-instance v0, Landroid/support/constraint/solver/widgets/Rectangle;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/Rectangle;-><init>()V

    .line 206
    .local v0, "bounds":Landroid/support/constraint/solver/widgets/Rectangle;
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-nez v1, :cond_c

    .line 207
    return-object v0

    .line 209
    :cond_c
    const v1, 0x7fffffff

    .line 210
    .local v1, "minX":I
    const/4 v2, 0x0

    .line 211
    .local v2, "maxX":I
    const v3, 0x7fffffff

    .line 212
    .local v3, "minY":I
    const/4 v4, 0x0

    .line 213
    .local v4, "maxY":I
    const/4 v5, 0x0

    .line 213
    .local v5, "i":I
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v6

    .line 213
    .local v6, "widgetsSize":I
    :goto_19
    if-ge v5, v6, :cond_4c

    .line 214
    invoke-virtual {p0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 215
    .local v7, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getX()I

    move-result v8

    if-ge v8, v1, :cond_2b

    .line 216
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getX()I

    move-result v1

    .line 218
    :cond_2b
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getY()I

    move-result v8

    if-ge v8, v3, :cond_35

    .line 219
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getY()I

    move-result v3

    .line 221
    :cond_35
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getRight()I

    move-result v8

    if-le v8, v2, :cond_3f

    .line 222
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getRight()I

    move-result v2

    .line 224
    :cond_3f
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getBottom()I

    move-result v8

    if-le v8, v4, :cond_49

    .line 225
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getBottom()I

    move-result v4

    .line 213
    .end local v7    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_49
    add-int/lit8 v5, v5, 0x1

    goto :goto_19

    .line 228
    .end local v5    # "i":I
    .end local v6    # "widgetsSize":I
    :cond_4c
    sub-int v5, v2, v1

    sub-int v6, v4, v3

    invoke-virtual {v0, v1, v3, v5, v6}, Landroid/support/constraint/solver/widgets/Rectangle;->setBounds(IIII)V

    .line 229
    return-object v0
.end method


# virtual methods
.method public add(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 3
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 72
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    if-eqz v0, :cond_14

    .line 74
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/WidgetContainer;

    .line 75
    .local v0, "container":Landroid/support/constraint/solver/widgets/WidgetContainer;
    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/WidgetContainer;->remove(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 77
    .end local v0    # "container":Landroid/support/constraint/solver/widgets/WidgetContainer;
    :cond_14
    invoke-virtual {p1, p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setParent(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 78
    return-void
.end method

.method public varargs add([Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 5
    .param p1, "widgets"    # [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 86
    array-length v0, p1

    .line 87
    .local v0, "count":I
    const/4 v1, 0x0

    .line 87
    .local v1, "i":I
    :goto_2
    if-ge v1, v0, :cond_c

    .line 88
    aget-object v2, p1, v1

    invoke-virtual {p0, v2}, Landroid/support/constraint/solver/widgets/WidgetContainer;->add(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 87
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    .line 90
    .end local v1    # "i":I
    :cond_c
    return-void
.end method

.method public findWidget(FF)Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 12
    .param p1, "x"    # F
    .param p2, "y"    # F

    .line 145
    const/4 v0, 0x0

    .line 146
    .local v0, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getDrawX()I

    move-result v1

    .line 147
    .local v1, "l":I
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getDrawY()I

    move-result v2

    .line 148
    .local v2, "t":I
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getWidth()I

    move-result v3

    add-int/2addr v3, v1

    .line 149
    .local v3, "r":I
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getHeight()I

    move-result v4

    add-int/2addr v4, v2

    .line 150
    .local v4, "b":I
    int-to-float v5, v1

    cmpl-float v5, p1, v5

    if-ltz v5, :cond_28

    int-to-float v5, v3

    cmpg-float v5, p1, v5

    if-gtz v5, :cond_28

    int-to-float v5, v2

    cmpl-float v5, p2, v5

    if-ltz v5, :cond_28

    int-to-float v5, v4

    cmpg-float v5, p2, v5

    if-gtz v5, :cond_28

    .line 151
    move-object v0, p0

    .line 153
    :cond_28
    const/4 v5, 0x0

    .line 153
    .local v5, "i":I
    iget-object v6, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v6

    .line 153
    .local v6, "mChildrenSize":I
    :goto_2f
    if-ge v5, v6, :cond_74

    .line 154
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 155
    .local v7, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    instance-of v8, v7, Landroid/support/constraint/solver/widgets/WidgetContainer;

    if-eqz v8, :cond_48

    .line 156
    move-object v8, v7

    check-cast v8, Landroid/support/constraint/solver/widgets/WidgetContainer;

    invoke-virtual {v8, p1, p2}, Landroid/support/constraint/solver/widgets/WidgetContainer;->findWidget(FF)Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v8

    .line 157
    .local v8, "f":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-eqz v8, :cond_47

    .line 158
    move-object v0, v8

    .line 160
    .end local v8    # "f":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_47
    goto :goto_71

    .line 161
    :cond_48
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDrawX()I

    move-result v1

    .line 162
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDrawY()I

    move-result v2

    .line 163
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v8

    add-int/2addr v8, v1

    .line 164
    .end local v3    # "r":I
    .local v8, "r":I
    invoke-virtual {v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v3

    add-int/2addr v3, v2

    .line 165
    .end local v4    # "b":I
    .local v3, "b":I
    int-to-float v4, v1

    cmpl-float v4, p1, v4

    if-ltz v4, :cond_6f

    int-to-float v4, v8

    cmpg-float v4, p1, v4

    if-gtz v4, :cond_6f

    int-to-float v4, v2

    cmpl-float v4, p2, v4

    if-ltz v4, :cond_6f

    int-to-float v4, v3

    cmpg-float v4, p2, v4

    if-gtz v4, :cond_6f

    .line 166
    move-object v0, v7

    .line 153
    .end local v7    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v8    # "r":I
    .local v3, "r":I
    .restart local v4    # "b":I
    :cond_6f
    move v4, v3

    move v3, v8

    :goto_71
    add-int/lit8 v5, v5, 0x1

    goto :goto_2f

    .line 170
    .end local v5    # "i":I
    .end local v6    # "mChildrenSize":I
    :cond_74
    return-object v0
.end method

.method public findWidgets(IIII)Ljava/util/ArrayList;
    .registers 15
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IIII)",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation

    .line 183
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 184
    .local v0, "found":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    new-instance v1, Landroid/support/constraint/solver/widgets/Rectangle;

    invoke-direct {v1}, Landroid/support/constraint/solver/widgets/Rectangle;-><init>()V

    .line 185
    .local v1, "area":Landroid/support/constraint/solver/widgets/Rectangle;
    invoke-virtual {v1, p1, p2, p3, p4}, Landroid/support/constraint/solver/widgets/Rectangle;->setBounds(IIII)V

    .line 186
    const/4 v2, 0x0

    .line 186
    .local v2, "i":I
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v3

    .line 186
    .local v3, "mChildrenSize":I
    :goto_14
    if-ge v2, v3, :cond_42

    .line 187
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 188
    .local v4, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    new-instance v5, Landroid/support/constraint/solver/widgets/Rectangle;

    invoke-direct {v5}, Landroid/support/constraint/solver/widgets/Rectangle;-><init>()V

    .line 189
    .local v5, "bounds":Landroid/support/constraint/solver/widgets/Rectangle;
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDrawX()I

    move-result v6

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDrawY()I

    move-result v7

    .line 190
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v8

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v9

    .line 189
    invoke-virtual {v5, v6, v7, v8, v9}, Landroid/support/constraint/solver/widgets/Rectangle;->setBounds(IIII)V

    .line 191
    invoke-virtual {v1, v5}, Landroid/support/constraint/solver/widgets/Rectangle;->intersects(Landroid/support/constraint/solver/widgets/Rectangle;)Z

    move-result v6

    if-eqz v6, :cond_3f

    .line 192
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 186
    .end local v4    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v5    # "bounds":Landroid/support/constraint/solver/widgets/Rectangle;
    :cond_3f
    add-int/lit8 v2, v2, 0x1

    goto :goto_14

    .line 195
    .end local v2    # "i":I
    .end local v3    # "mChildrenSize":I
    :cond_42
    return-object v0
.end method

.method public getChildren()Ljava/util/ArrayList;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;"
        }
    .end annotation

    .line 108
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getRootConstraintContainer()Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    .registers 5

    .line 117
    move-object v0, p0

    .line 118
    .local v0, "item":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    .line 119
    .local v1, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v2, 0x0

    .line 120
    .local v2, "container":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    instance-of v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v3, :cond_d

    .line 121
    move-object v2, p0

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    .line 123
    :cond_d
    :goto_d
    if-eqz v1, :cond_1c

    .line 124
    move-object v0, v1

    .line 125
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    .line 126
    instance-of v3, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v3, :cond_d

    .line 127
    move-object v2, v0

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    goto :goto_d

    .line 130
    :cond_1c
    return-object v2
.end method

.method public layout()V
    .registers 5

    .line 277
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->updateDrawPosition()V

    .line 278
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    if-nez v0, :cond_8

    .line 279
    return-void

    .line 281
    :cond_8
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 282
    .local v0, "count":I
    const/4 v1, 0x0

    .line 282
    .local v1, "i":I
    :goto_f
    if-ge v1, v0, :cond_26

    .line 283
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 284
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    instance-of v3, v2, Landroid/support/constraint/solver/widgets/WidgetContainer;

    if-eqz v3, :cond_23

    .line 285
    move-object v3, v2

    check-cast v3, Landroid/support/constraint/solver/widgets/WidgetContainer;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/WidgetContainer;->layout()V

    .line 282
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_23
    add-int/lit8 v1, v1, 0x1

    goto :goto_f

    .line 288
    .end local v1    # "i":I
    :cond_26
    return-void
.end method

.method public remove(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 3
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 98
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 99
    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setParent(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 100
    return-void
.end method

.method public removeAllChildren()V
    .registers 2

    .line 301
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 302
    return-void
.end method

.method public reset()V
    .registers 2

    .line 62
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 63
    invoke-super {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->reset()V

    .line 64
    return-void
.end method

.method public resetSolverVariables(Landroid/support/constraint/solver/Cache;)V
    .registers 5
    .param p1, "cache"    # Landroid/support/constraint/solver/Cache;

    .line 292
    invoke-super {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->resetSolverVariables(Landroid/support/constraint/solver/Cache;)V

    .line 293
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 294
    .local v0, "count":I
    const/4 v1, 0x0

    .line 294
    .local v1, "i":I
    :goto_a
    if-ge v1, v0, :cond_1a

    .line 295
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 296
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v2, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->resetSolverVariables(Landroid/support/constraint/solver/Cache;)V

    .line 294
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v1, v1, 0x1

    goto :goto_a

    .line 298
    .end local v1    # "i":I
    :cond_1a
    return-void
.end method

.method public setOffset(II)V
    .registers 8
    .param p1, "x"    # I
    .param p2, "y"    # I

    .line 245
    invoke-super {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setOffset(II)V

    .line 246
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 247
    .local v0, "count":I
    const/4 v1, 0x0

    .line 247
    .local v1, "i":I
    :goto_a
    if-ge v1, v0, :cond_22

    .line 248
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 249
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getRootX()I

    move-result v3

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getRootY()I

    move-result v4

    invoke-virtual {v2, v3, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setOffset(II)V

    .line 247
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v1, v1, 0x1

    goto :goto_a

    .line 251
    .end local v1    # "i":I
    :cond_22
    return-void
.end method

.method public updateDrawPosition()V
    .registers 6

    .line 259
    invoke-super {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->updateDrawPosition()V

    .line 260
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    if-nez v0, :cond_8

    .line 261
    return-void

    .line 263
    :cond_8
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 264
    .local v0, "count":I
    const/4 v1, 0x0

    .line 264
    .local v1, "i":I
    :goto_f
    if-ge v1, v0, :cond_2e

    .line 265
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/WidgetContainer;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 266
    .local v2, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getDrawX()I

    move-result v3

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/WidgetContainer;->getDrawY()I

    move-result v4

    invoke-virtual {v2, v3, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setOffset(II)V

    .line 267
    instance-of v3, v2, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-nez v3, :cond_2b

    .line 268
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->updateDrawPosition()V

    .line 264
    .end local v2    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_2b
    add-int/lit8 v1, v1, 0x1

    goto :goto_f

    .line 271
    .end local v1    # "i":I
    :cond_2e
    return-void
.end method
