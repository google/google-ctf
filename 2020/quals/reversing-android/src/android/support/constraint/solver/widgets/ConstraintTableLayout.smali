.class public Landroid/support/constraint/solver/widgets/ConstraintTableLayout;
.super Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
.source "ConstraintTableLayout.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;,
        Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;
    }
.end annotation


# static fields
.field public static final ALIGN_CENTER:I = 0x0

.field private static final ALIGN_FULL:I = 0x3

.field public static final ALIGN_LEFT:I = 0x1

.field public static final ALIGN_RIGHT:I = 0x2


# instance fields
.field private mHorizontalGuidelines:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/Guideline;",
            ">;"
        }
    .end annotation
.end field

.field private mHorizontalSlices:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;",
            ">;"
        }
    .end annotation
.end field

.field private mNumCols:I

.field private mNumRows:I

.field private mPadding:I

.field private mVerticalGrowth:Z

.field private mVerticalGuidelines:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/Guideline;",
            ">;"
        }
    .end annotation
.end field

.field private mVerticalSlices:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;",
            ">;"
        }
    .end annotation
.end field

.field private system:Landroid/support/constraint/solver/LinearSystem;


# direct methods
.method public constructor <init>()V
    .registers 2

    .line 66
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;-><init>()V

    .line 28
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    .line 29
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    .line 30
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    .line 31
    const/16 v0, 0x8

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    .line 52
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    .line 53
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalSlices:Ljava/util/ArrayList;

    .line 55
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    .line 56
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    .line 403
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    .line 67
    return-void
.end method

.method public constructor <init>(II)V
    .registers 4
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 88
    invoke-direct {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;-><init>(II)V

    .line 28
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    .line 29
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    .line 30
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    .line 31
    const/16 v0, 0x8

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    .line 52
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    .line 53
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalSlices:Ljava/util/ArrayList;

    .line 55
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    .line 56
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    .line 403
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    .line 89
    return-void
.end method

.method public constructor <init>(IIII)V
    .registers 6
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I

    .line 78
    invoke-direct {p0, p1, p2, p3, p4}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;-><init>(IIII)V

    .line 28
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    .line 29
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    .line 30
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    .line 31
    const/16 v0, 0x8

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    .line 52
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    .line 53
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalSlices:Ljava/util/ArrayList;

    .line 55
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    .line 56
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    .line 403
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    .line 79
    return-void
.end method

.method private setChildrenConnections()V
    .registers 16

    .line 481
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 482
    .local v0, "count":I
    const/4 v1, 0x0

    .line 483
    .local v1, "index":I
    const/4 v2, 0x0

    .line 483
    .local v2, "i":I
    :goto_8
    if-ge v2, v0, :cond_e7

    .line 484
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 485
    .local v3, "target":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getContainerItemSkip()I

    move-result v4

    add-int/2addr v1, v4

    .line 487
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    rem-int v4, v1, v4

    .line 488
    .local v4, "col":I
    iget v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    div-int v5, v1, v5

    .line 490
    .local v5, "row":I
    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalSlices:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;

    .line 491
    .local v6, "horizontalSlice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;

    .line 492
    .local v7, "verticalSlice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    iget-object v8, v7, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->left:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 493
    .local v8, "targetLeft":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v9, v7, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->right:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 494
    .local v9, "targetRight":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v10, v6, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;->top:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 495
    .local v10, "targetTop":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget-object v11, v6, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;->bottom:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 497
    .local v11, "targetBottom":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 498
    invoke-virtual {v8, v13}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    iget v14, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    invoke-virtual {v12, v13, v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z

    .line 499
    instance-of v12, v9, Landroid/support/constraint/solver/widgets/Guideline;

    if-eqz v12, :cond_5e

    .line 500
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 501
    invoke-virtual {v9, v13}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    iget v14, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    invoke-virtual {v12, v13, v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z

    goto :goto_6f

    .line 503
    :cond_5e
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 504
    invoke-virtual {v9, v13}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    iget v14, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    invoke-virtual {v12, v13, v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z

    .line 508
    :goto_6f
    iget v12, v7, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    packed-switch v12, :pswitch_data_e8

    goto :goto_a9

    .line 510
    :pswitch_75
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 512
    goto :goto_a9

    .line 521
    :pswitch_7b
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->WEAK:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    invoke-virtual {v12, v13}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->setStrength(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 523
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    invoke-virtual {v12, v13}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->setStrength(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    goto :goto_a9

    .line 514
    :pswitch_92
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    invoke-virtual {v12, v13}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->setStrength(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 516
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->WEAK:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    invoke-virtual {v12, v13}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->setStrength(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 519
    nop

    .line 528
    :goto_a9
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 529
    invoke-virtual {v10, v13}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    iget v14, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    invoke-virtual {v12, v13, v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z

    .line 530
    instance-of v12, v11, Landroid/support/constraint/solver/widgets/Guideline;

    if-eqz v12, :cond_d0

    .line 531
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 532
    invoke-virtual {v11, v13}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    iget v14, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    invoke-virtual {v12, v13, v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z

    goto :goto_e1

    .line 534
    :cond_d0
    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3, v12}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v12

    sget-object v13, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 535
    invoke-virtual {v11, v13}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    iget v14, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    invoke-virtual {v12, v13, v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z

    .line 538
    :goto_e1
    add-int/lit8 v1, v1, 0x1

    .line 483
    .end local v3    # "target":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v4    # "col":I
    .end local v5    # "row":I
    .end local v6    # "horizontalSlice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;
    .end local v7    # "verticalSlice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    .end local v8    # "targetLeft":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v9    # "targetRight":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v10    # "targetTop":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .end local v11    # "targetBottom":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v2, v2, 0x1

    goto/16 :goto_8

    .line 540
    .end local v2    # "i":I
    :cond_e7
    return-void

    :pswitch_data_e8
    .packed-switch 0x1
        :pswitch_92
        :pswitch_7b
        :pswitch_75
    .end packed-switch
.end method

.method private setHorizontalSlices()V
    .registers 9

    .line 453
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 454
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    int-to-float v0, v0

    const/high16 v1, 0x42c80000    # 100.0f

    div-float/2addr v1, v0

    .line 455
    .local v1, "increment":F
    move v0, v1

    .line 456
    .local v0, "percent":F
    move-object v2, p0

    .line 457
    .local v2, "previous":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v3, 0x0

    move v4, v0

    move v0, v3

    .line 457
    .local v0, "i":I
    .local v4, "percent":F
    :goto_10
    iget v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    if-ge v0, v5, :cond_45

    .line 458
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;

    invoke-direct {v5, p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;-><init>(Landroid/support/constraint/solver/widgets/ConstraintTableLayout;)V

    .line 459
    .local v5, "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;
    iput-object v2, v5, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;->top:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 460
    iget v6, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    add-int/lit8 v6, v6, -0x1

    if-ge v0, v6, :cond_39

    .line 461
    new-instance v6, Landroid/support/constraint/solver/widgets/Guideline;

    invoke-direct {v6}, Landroid/support/constraint/solver/widgets/Guideline;-><init>()V

    .line 462
    .local v6, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    invoke-virtual {v6, v3}, Landroid/support/constraint/solver/widgets/Guideline;->setOrientation(I)V

    .line 463
    invoke-virtual {v6, p0}, Landroid/support/constraint/solver/widgets/Guideline;->setParent(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 464
    float-to-int v7, v4

    invoke-virtual {v6, v7}, Landroid/support/constraint/solver/widgets/Guideline;->setGuidePercent(I)V

    .line 465
    add-float/2addr v4, v1

    .line 466
    iput-object v6, v5, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;->bottom:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 467
    iget-object v7, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 468
    .end local v6    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    goto :goto_3b

    .line 469
    :cond_39
    iput-object p0, v5, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;->bottom:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 471
    :goto_3b
    iget-object v2, v5, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;->bottom:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 472
    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalSlices:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 457
    .end local v5    # "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$HorizontalSlice;
    add-int/lit8 v0, v0, 0x1

    goto :goto_10

    .line 474
    .end local v0    # "i":I
    :cond_45
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->updateDebugSolverNames()V

    .line 475
    return-void
.end method

.method private setVerticalSlices()V
    .registers 8

    .line 424
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 425
    move-object v0, p0

    .line 426
    .local v0, "previous":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    int-to-float v1, v1

    const/high16 v2, 0x42c80000    # 100.0f

    div-float/2addr v2, v1

    .line 427
    .local v2, "increment":F
    move v1, v2

    .line 428
    .local v1, "percent":F
    const/4 v3, 0x0

    .line 428
    .local v3, "i":I
    :goto_e
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    if-ge v3, v4, :cond_43

    .line 429
    new-instance v4, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;

    invoke-direct {v4, p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;-><init>(Landroid/support/constraint/solver/widgets/ConstraintTableLayout;)V

    .line 430
    .local v4, "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    iput-object v0, v4, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->left:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 431
    iget v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    const/4 v6, 0x1

    sub-int/2addr v5, v6

    if-ge v3, v5, :cond_37

    .line 432
    new-instance v5, Landroid/support/constraint/solver/widgets/Guideline;

    invoke-direct {v5}, Landroid/support/constraint/solver/widgets/Guideline;-><init>()V

    .line 433
    .local v5, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    invoke-virtual {v5, v6}, Landroid/support/constraint/solver/widgets/Guideline;->setOrientation(I)V

    .line 434
    invoke-virtual {v5, p0}, Landroid/support/constraint/solver/widgets/Guideline;->setParent(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 435
    float-to-int v6, v1

    invoke-virtual {v5, v6}, Landroid/support/constraint/solver/widgets/Guideline;->setGuidePercent(I)V

    .line 436
    add-float/2addr v1, v2

    .line 437
    iput-object v5, v4, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->right:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 438
    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 439
    .end local v5    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    goto :goto_39

    .line 440
    :cond_37
    iput-object p0, v4, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->right:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 442
    :goto_39
    iget-object v0, v4, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->right:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 443
    iget-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 428
    .end local v4    # "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    add-int/lit8 v3, v3, 0x1

    goto :goto_e

    .line 445
    .end local v3    # "i":I
    :cond_43
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->updateDebugSolverNames()V

    .line 446
    return-void
.end method

.method private updateDebugSolverNames()V
    .registers 8

    .line 406
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    if-nez v0, :cond_5

    .line 407
    return-void

    .line 409
    :cond_5
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 410
    .local v0, "num":I
    const/4 v1, 0x0

    move v2, v1

    .line 410
    .local v2, "i":I
    :goto_d
    if-ge v2, v0, :cond_37

    .line 411
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/Guideline;

    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->getDebugName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v6, ".VG"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v3, v4, v5}, Landroid/support/constraint/solver/widgets/Guideline;->setDebugSolverName(Landroid/support/constraint/solver/LinearSystem;Ljava/lang/String;)V

    .line 410
    add-int/lit8 v2, v2, 0x1

    goto :goto_d

    .line 413
    .end local v2    # "i":I
    :cond_37
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 414
    nop

    .line 414
    .local v1, "i":I
    :goto_3e
    if-ge v1, v0, :cond_68

    .line 415
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/Guideline;

    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->getDebugName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ".HG"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v3, v4}, Landroid/support/constraint/solver/widgets/Guideline;->setDebugSolverName(Landroid/support/constraint/solver/LinearSystem;Ljava/lang/String;)V

    .line 414
    add-int/lit8 v1, v1, 0x1

    goto :goto_3e

    .line 417
    .end local v1    # "i":I
    :cond_68
    return-void
.end method


# virtual methods
.method public addToSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 10
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 316
    invoke-super {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 317
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 318
    .local v0, "count":I
    if-nez v0, :cond_c

    .line 319
    return-void

    .line 321
    :cond_c
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setTableDimensions()V

    .line 324
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    if-ne p1, v1, :cond_72

    .line 325
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    .line 326
    .local v1, "num":I
    const/4 v2, 0x0

    move v3, v2

    .line 326
    .local v3, "i":I
    :goto_1b
    const/4 v4, 0x1

    if-ge v3, v1, :cond_3a

    .line 327
    iget-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/support/constraint/solver/widgets/Guideline;

    .line 328
    .local v5, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    nop

    .line 329
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v6

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v6, v7, :cond_30

    goto :goto_31

    .line 328
    :cond_30
    move v4, v2

    :goto_31
    invoke-virtual {v5, v4}, Landroid/support/constraint/solver/widgets/Guideline;->setPositionRelaxed(Z)V

    .line 330
    invoke-virtual {v5, p1}, Landroid/support/constraint/solver/widgets/Guideline;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 326
    .end local v5    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    add-int/lit8 v3, v3, 0x1

    goto :goto_1b

    .line 332
    .end local v3    # "i":I
    :cond_3a
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v1

    .line 333
    move v3, v2

    .line 333
    .restart local v3    # "i":I
    :goto_41
    if-ge v3, v1, :cond_61

    .line 334
    iget-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/support/constraint/solver/widgets/Guideline;

    .line 335
    .restart local v5    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    nop

    .line 336
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v6

    sget-object v7, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v6, v7, :cond_56

    .line 335
    move v6, v4

    goto :goto_58

    .line 336
    :cond_56
    nop

    .line 335
    move v6, v2

    :goto_58
    invoke-virtual {v5, v6}, Landroid/support/constraint/solver/widgets/Guideline;->setPositionRelaxed(Z)V

    .line 337
    invoke-virtual {v5, p1}, Landroid/support/constraint/solver/widgets/Guideline;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 333
    .end local v5    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    add-int/lit8 v3, v3, 0x1

    goto :goto_41

    .line 339
    .end local v3    # "i":I
    :cond_61
    nop

    .line 339
    .local v2, "i":I
    :goto_62
    if-ge v2, v0, :cond_72

    .line 340
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 341
    .local v3, "child":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v3, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->addToSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 339
    .end local v3    # "child":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v2, v2, 0x1

    goto :goto_62

    .line 344
    .end local v1    # "num":I
    .end local v2    # "i":I
    :cond_72
    return-void
.end method

.method public computeGuidelinesPercentPositions()V
    .registers 5

    .line 580
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 581
    .local v0, "num":I
    const/4 v1, 0x0

    move v2, v1

    .line 581
    .local v2, "i":I
    :goto_8
    if-ge v2, v0, :cond_18

    .line 582
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/Guideline;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/Guideline;->inferRelativePercentPosition()V

    .line 581
    add-int/lit8 v2, v2, 0x1

    goto :goto_8

    .line 584
    .end local v2    # "i":I
    :cond_18
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 585
    nop

    .line 585
    .local v1, "i":I
    :goto_1f
    if-ge v1, v0, :cond_2f

    .line 586
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/Guideline;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/Guideline;->inferRelativePercentPosition()V

    .line 585
    add-int/lit8 v1, v1, 0x1

    goto :goto_1f

    .line 588
    .end local v1    # "i":I
    :cond_2f
    return-void
.end method

.method public cycleColumnAlignment(I)V
    .registers 4
    .param p1, "column"    # I

    .line 252
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;

    .line 253
    .local v0, "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    packed-switch v1, :pswitch_data_1e

    goto :goto_19

    .line 258
    :pswitch_e
    const/4 v1, 0x1

    iput v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    .line 259
    goto :goto_19

    .line 255
    :pswitch_12
    const/4 v1, 0x0

    iput v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    .line 256
    goto :goto_19

    .line 261
    :pswitch_16
    const/4 v1, 0x2

    iput v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    .line 264
    :goto_19
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setChildrenConnections()V

    .line 265
    return-void

    nop

    :pswitch_data_1e
    .packed-switch 0x0
        :pswitch_16
        :pswitch_12
        :pswitch_e
    .end packed-switch
.end method

.method public getColumnAlignmentRepresentation(I)Ljava/lang/String;
    .registers 5
    .param p1, "column"    # I

    .line 158
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;

    .line 159
    .local v0, "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    const/4 v2, 0x1

    if-ne v1, v2, :cond_10

    .line 160
    const-string v1, "L"

    return-object v1

    .line 161
    :cond_10
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    if-nez v1, :cond_17

    .line 162
    const-string v1, "C"

    return-object v1

    .line 163
    :cond_17
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    const/4 v2, 0x3

    if-ne v1, v2, :cond_1f

    .line 164
    const-string v1, "F"

    return-object v1

    .line 165
    :cond_1f
    iget v1, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    const/4 v2, 0x2

    if-ne v1, v2, :cond_27

    .line 166
    const-string v1, "R"

    return-object v1

    .line 168
    :cond_27
    const-string v1, "!"

    return-object v1
.end method

.method public getColumnsAlignmentRepresentation()Ljava/lang/String;
    .registers 7

    .line 134
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 135
    .local v0, "numSlices":I
    const-string v1, ""

    .line 136
    .local v1, "result":Ljava/lang/String;
    const/4 v2, 0x0

    .line 136
    .local v2, "i":I
    :goto_9
    if-ge v2, v0, :cond_70

    .line 137
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;

    .line 138
    .local v3, "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    iget v4, v3, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    const/4 v5, 0x1

    if-ne v4, v5, :cond_2a

    .line 139
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "L"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_6d

    .line 140
    :cond_2a
    iget v4, v3, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    if-nez v4, :cond_40

    .line 141
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "C"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_6d

    .line 142
    :cond_40
    iget v4, v3, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    const/4 v5, 0x3

    if-ne v4, v5, :cond_57

    .line 143
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "F"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_6d

    .line 144
    :cond_57
    iget v4, v3, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    const/4 v5, 0x2

    if-ne v4, v5, :cond_6d

    .line 145
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "R"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 136
    .end local v3    # "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    :cond_6d
    :goto_6d
    add-int/lit8 v2, v2, 0x1

    goto :goto_9

    .line 148
    .end local v2    # "i":I
    :cond_70
    return-object v1
.end method

.method public getHorizontalGuidelines()Ljava/util/ArrayList;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/Guideline;",
            ">;"
        }
    .end annotation

    .line 306
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getNumCols()I
    .registers 2

    .line 116
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    return v0
.end method

.method public getNumRows()I
    .registers 2

    .line 107
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    return v0
.end method

.method public getPadding()I
    .registers 2

    .line 125
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    return v0
.end method

.method public getType()Ljava/lang/String;
    .registers 2

    .line 98
    const-string v0, "ConstraintTableLayout"

    return-object v0
.end method

.method public getVerticalGuidelines()Ljava/util/ArrayList;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/Guideline;",
            ">;"
        }
    .end annotation

    .line 296
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    return-object v0
.end method

.method public handlesInternalConstraints()Z
    .registers 2

    .line 573
    const/4 v0, 0x1

    return v0
.end method

.method public isVerticalGrowth()Z
    .registers 2

    .line 208
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    return v0
.end method

.method public setColumnAlignment(II)V
    .registers 4
    .param p1, "column"    # I
    .param p2, "alignment"    # I

    .line 239
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    if-ge p1, v0, :cond_15

    .line 240
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalSlices:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;

    .line 241
    .local v0, "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    iput p2, v0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;->alignment:I

    .line 242
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setChildrenConnections()V

    .line 244
    .end local v0    # "slice":Landroid/support/constraint/solver/widgets/ConstraintTableLayout$VerticalSlice;
    :cond_15
    return-void
.end method

.method public setColumnAlignment(Ljava/lang/String;)V
    .registers 7
    .param p1, "alignment"    # Ljava/lang/String;

    .line 273
    const/4 v0, 0x0

    .line 273
    .local v0, "i":I
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v1

    .line 273
    .local v1, "n":I
    :goto_5
    if-ge v0, v1, :cond_35

    .line 274
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    move-result v2

    .line 275
    .local v2, "c":C
    const/16 v3, 0x4c

    if-ne v2, v3, :cond_14

    .line 276
    const/4 v3, 0x1

    invoke-virtual {p0, v0, v3}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setColumnAlignment(II)V

    goto :goto_32

    .line 277
    :cond_14
    const/16 v3, 0x43

    const/4 v4, 0x0

    if-ne v2, v3, :cond_1d

    .line 278
    invoke-virtual {p0, v0, v4}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setColumnAlignment(II)V

    goto :goto_32

    .line 279
    :cond_1d
    const/16 v3, 0x46

    if-ne v2, v3, :cond_26

    .line 280
    const/4 v3, 0x3

    invoke-virtual {p0, v0, v3}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setColumnAlignment(II)V

    goto :goto_32

    .line 281
    :cond_26
    const/16 v3, 0x52

    if-ne v2, v3, :cond_2f

    .line 282
    const/4 v3, 0x2

    invoke-virtual {p0, v0, v3}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setColumnAlignment(II)V

    goto :goto_32

    .line 284
    :cond_2f
    invoke-virtual {p0, v0, v4}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setColumnAlignment(II)V

    .line 273
    .end local v2    # "c":C
    :goto_32
    add-int/lit8 v0, v0, 0x1

    goto :goto_5

    .line 287
    .end local v0    # "i":I
    .end local v1    # "n":I
    :cond_35
    return-void
.end method

.method public setDebugSolverName(Landroid/support/constraint/solver/LinearSystem;Ljava/lang/String;)V
    .registers 3
    .param p1, "s"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "name"    # Ljava/lang/String;

    .line 398
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->system:Landroid/support/constraint/solver/LinearSystem;

    .line 399
    invoke-super {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->setDebugSolverName(Landroid/support/constraint/solver/LinearSystem;Ljava/lang/String;)V

    .line 400
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->updateDebugSolverNames()V

    .line 401
    return-void
.end method

.method public setNumCols(I)V
    .registers 3
    .param p1, "num"    # I

    .line 179
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    if-eqz v0, :cond_10

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    if-eq v0, p1, :cond_10

    .line 180
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    .line 181
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setVerticalSlices()V

    .line 182
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setTableDimensions()V

    .line 184
    :cond_10
    return-void
.end method

.method public setNumRows(I)V
    .registers 3
    .param p1, "num"    # I

    .line 194
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    if-nez v0, :cond_10

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    if-eq v0, p1, :cond_10

    .line 195
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    .line 196
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setHorizontalSlices()V

    .line 197
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setTableDimensions()V

    .line 199
    :cond_10
    return-void
.end method

.method public setPadding(I)V
    .registers 3
    .param p1, "padding"    # I

    .line 226
    const/4 v0, 0x1

    if-le p1, v0, :cond_5

    .line 227
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mPadding:I

    .line 229
    :cond_5
    return-void
.end method

.method public setTableDimensions()V
    .registers 7

    .line 351
    const/4 v0, 0x0

    .line 352
    .local v0, "extra":I
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    .line 353
    .local v1, "count":I
    const/4 v2, 0x0

    .line 353
    .local v2, "i":I
    :goto_8
    if-ge v2, v1, :cond_1a

    .line 354
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mChildren:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 355
    .local v3, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getContainerItemSkip()I

    move-result v4

    add-int/2addr v0, v4

    .line 353
    .end local v3    # "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    add-int/lit8 v2, v2, 0x1

    goto :goto_8

    .line 357
    .end local v2    # "i":I
    :cond_1a
    add-int/2addr v1, v0

    .line 358
    iget-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    const/4 v3, 0x1

    if-eqz v2, :cond_48

    .line 359
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    if-nez v2, :cond_27

    .line 360
    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setNumCols(I)V

    .line 362
    :cond_27
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    div-int v2, v1, v2

    .line 363
    .local v2, "rows":I
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    mul-int/2addr v4, v2

    if-ge v4, v1, :cond_32

    .line 364
    add-int/lit8 v2, v2, 0x1

    .line 366
    :cond_32
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    if-ne v4, v2, :cond_42

    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    .line 367
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v4

    iget v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    sub-int/2addr v5, v3

    if-ne v4, v5, :cond_42

    .line 368
    return-void

    .line 370
    :cond_42
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    .line 371
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setHorizontalSlices()V

    .line 372
    .end local v2    # "rows":I
    goto :goto_6f

    .line 373
    :cond_48
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    if-nez v2, :cond_4f

    .line 374
    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setNumRows(I)V

    .line 376
    :cond_4f
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    div-int v2, v1, v2

    .line 377
    .local v2, "cols":I
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    mul-int/2addr v4, v2

    if-ge v4, v1, :cond_5a

    .line 378
    add-int/lit8 v2, v2, 0x1

    .line 380
    :cond_5a
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    if-ne v4, v2, :cond_6a

    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    .line 381
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v4

    iget v5, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumRows:I

    sub-int/2addr v5, v3

    if-ne v4, v5, :cond_6a

    .line 382
    return-void

    .line 384
    :cond_6a
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mNumCols:I

    .line 385
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setVerticalSlices()V

    .line 387
    .end local v2    # "cols":I
    :goto_6f
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->setChildrenConnections()V

    .line 388
    return-void
.end method

.method public setVerticalGrowth(Z)V
    .registers 2
    .param p1, "value"    # Z

    .line 217
    iput-boolean p1, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGrowth:Z

    .line 218
    return-void
.end method

.method public updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 6
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 549
    invoke-super {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 552
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mSystem:Landroid/support/constraint/solver/LinearSystem;

    if-ne p1, v0, :cond_36

    .line 553
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 554
    .local v0, "num":I
    const/4 v1, 0x0

    move v2, v1

    .line 554
    .local v2, "i":I
    :goto_f
    if-ge v2, v0, :cond_1f

    .line 555
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mVerticalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/Guideline;

    .line 556
    .local v3, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    invoke-virtual {v3, p1}, Landroid/support/constraint/solver/widgets/Guideline;->updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 554
    .end local v3    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    add-int/lit8 v2, v2, 0x1

    goto :goto_f

    .line 558
    .end local v2    # "i":I
    :cond_1f
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v0

    .line 559
    nop

    .line 559
    .local v1, "i":I
    :goto_26
    if-ge v1, v0, :cond_36

    .line 560
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintTableLayout;->mHorizontalGuidelines:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/support/constraint/solver/widgets/Guideline;

    .line 561
    .local v2, "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    invoke-virtual {v2, p1}, Landroid/support/constraint/solver/widgets/Guideline;->updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V

    .line 559
    .end local v2    # "guideline":Landroid/support/constraint/solver/widgets/Guideline;
    add-int/lit8 v1, v1, 0x1

    goto :goto_26

    .line 564
    .end local v0    # "num":I
    .end local v1    # "i":I
    :cond_36
    return-void
.end method
