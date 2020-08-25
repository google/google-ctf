.class public Landroid/support/constraint/ConstraintLayout$LayoutParams;
.super Landroid/view/ViewGroup$MarginLayoutParams;
.source "ConstraintLayout.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/constraint/ConstraintLayout;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "LayoutParams"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/ConstraintLayout$LayoutParams$Table;
    }
.end annotation


# static fields
.field public static final BASELINE:I = 0x5

.field public static final BOTTOM:I = 0x4

.field public static final CHAIN_PACKED:I = 0x2

.field public static final CHAIN_SPREAD:I = 0x0

.field public static final CHAIN_SPREAD_INSIDE:I = 0x1

.field public static final END:I = 0x7

.field public static final HORIZONTAL:I = 0x0

.field public static final LEFT:I = 0x1

.field public static final MATCH_CONSTRAINT:I = 0x0

.field public static final MATCH_CONSTRAINT_PERCENT:I = 0x2

.field public static final MATCH_CONSTRAINT_SPREAD:I = 0x0

.field public static final MATCH_CONSTRAINT_WRAP:I = 0x1

.field public static final PARENT_ID:I = 0x0

.field public static final RIGHT:I = 0x2

.field public static final START:I = 0x6

.field public static final TOP:I = 0x3

.field public static final UNSET:I = -0x1

.field public static final VERTICAL:I = 0x1


# instance fields
.field public baselineToBaseline:I

.field public bottomToBottom:I

.field public bottomToTop:I

.field public circleAngle:F

.field public circleConstraint:I

.field public circleRadius:I

.field public constrainedHeight:Z

.field public constrainedWidth:Z

.field public dimensionRatio:Ljava/lang/String;

.field dimensionRatioSide:I

.field dimensionRatioValue:F

.field public editorAbsoluteX:I

.field public editorAbsoluteY:I

.field public endToEnd:I

.field public endToStart:I

.field public goneBottomMargin:I

.field public goneEndMargin:I

.field public goneLeftMargin:I

.field public goneRightMargin:I

.field public goneStartMargin:I

.field public goneTopMargin:I

.field public guideBegin:I

.field public guideEnd:I

.field public guidePercent:F

.field public helped:Z

.field public horizontalBias:F

.field public horizontalChainStyle:I

.field horizontalDimensionFixed:Z

.field public horizontalWeight:F

.field isGuideline:Z

.field isHelper:Z

.field isInPlaceholder:Z

.field public leftToLeft:I

.field public leftToRight:I

.field public matchConstraintDefaultHeight:I

.field public matchConstraintDefaultWidth:I

.field public matchConstraintMaxHeight:I

.field public matchConstraintMaxWidth:I

.field public matchConstraintMinHeight:I

.field public matchConstraintMinWidth:I

.field public matchConstraintPercentHeight:F

.field public matchConstraintPercentWidth:F

.field needsBaseline:Z

.field public orientation:I

.field resolveGoneLeftMargin:I

.field resolveGoneRightMargin:I

.field resolvedGuideBegin:I

.field resolvedGuideEnd:I

.field resolvedGuidePercent:F

.field resolvedHorizontalBias:F

.field resolvedLeftToLeft:I

.field resolvedLeftToRight:I

.field resolvedRightToLeft:I

.field resolvedRightToRight:I

.field public rightToLeft:I

.field public rightToRight:I

.field public startToEnd:I

.field public startToStart:I

.field public topToBottom:I

.field public topToTop:I

.field public verticalBias:F

.field public verticalChainStyle:I

.field verticalDimensionFixed:Z

.field public verticalWeight:F

.field widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;


# direct methods
.method public constructor <init>(II)V
    .registers 9
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 3040
    invoke-direct {p0, p1, p2}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(II)V

    .line 2166
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    .line 2171
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    .line 2176
    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    .line 2181
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    .line 2186
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    .line 2191
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    .line 2196
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    .line 2201
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    .line 2206
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    .line 2211
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    .line 2216
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    .line 2221
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    .line 2226
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    .line 2231
    const/4 v2, 0x0

    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    .line 2236
    const/4 v3, 0x0

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    .line 2241
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    .line 2246
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    .line 2251
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    .line 2256
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    .line 2261
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    .line 2266
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    .line 2271
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    .line 2276
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    .line 2281
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    .line 2286
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    .line 2291
    const/high16 v4, 0x3f000000    # 0.5f

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    .line 2296
    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    .line 2301
    const/4 v5, 0x0

    iput-object v5, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    .line 2306
    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    .line 2311
    const/4 v3, 0x1

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2317
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    .line 2323
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    .line 2335
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    .line 2347
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    .line 2360
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 2373
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 2379
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    .line 2385
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    .line 2391
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    .line 2397
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    .line 2402
    const/high16 v1, 0x3f800000    # 1.0f

    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    .line 2407
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    .line 2413
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    .line 2419
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    .line 2421
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    .line 2430
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 2439
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 2442
    iput-boolean v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 2443
    iput-boolean v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 2445
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->needsBaseline:Z

    .line 2446
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 2447
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isHelper:Z

    .line 2448
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isInPlaceholder:Z

    .line 2450
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 2451
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 2452
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 2453
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 2454
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 2455
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 2456
    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 2462
    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2470
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->helped:Z

    .line 3041
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .registers 22
    .param p1, "c"    # Landroid/content/Context;
    .param p2, "attrs"    # Landroid/util/AttributeSet;

    move-object/from16 v1, p0

    .line 2649
    invoke-direct/range {p0 .. p2}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 2166
    const/4 v2, -0x1

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    .line 2171
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    .line 2176
    const/high16 v3, -0x40800000    # -1.0f

    iput v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    .line 2181
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    .line 2186
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    .line 2191
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    .line 2196
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    .line 2201
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    .line 2206
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    .line 2211
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    .line 2216
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    .line 2221
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    .line 2226
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    .line 2231
    const/4 v4, 0x0

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    .line 2236
    const/4 v5, 0x0

    iput v5, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    .line 2241
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    .line 2246
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    .line 2251
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    .line 2256
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    .line 2261
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    .line 2266
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    .line 2271
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    .line 2276
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    .line 2281
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    .line 2286
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    .line 2291
    const/high16 v6, 0x3f000000    # 0.5f

    iput v6, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    .line 2296
    iput v6, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    .line 2301
    const/4 v7, 0x0

    iput-object v7, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    .line 2306
    iput v5, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    .line 2311
    const/4 v7, 0x1

    iput v7, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2317
    iput v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    .line 2323
    iput v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    .line 2335
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    .line 2347
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    .line 2360
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 2373
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 2379
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    .line 2385
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    .line 2391
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    .line 2397
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    .line 2402
    const/high16 v3, 0x3f800000    # 1.0f

    iput v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    .line 2407
    iput v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    .line 2413
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    .line 2419
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    .line 2421
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    .line 2430
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 2439
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 2442
    iput-boolean v7, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 2443
    iput-boolean v7, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 2445
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->needsBaseline:Z

    .line 2446
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 2447
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isHelper:Z

    .line 2448
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isInPlaceholder:Z

    .line 2450
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 2451
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 2452
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 2453
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 2454
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 2455
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 2456
    iput v6, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 2462
    new-instance v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    iput-object v3, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2470
    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->helped:Z

    .line 2650
    sget-object v3, Landroid/support/constraint/R$styleable;->ConstraintLayout_Layout:[I

    move-object/from16 v6, p1

    move-object/from16 v8, p2

    invoke-virtual {v6, v8, v3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v3

    .line 2651
    .local v3, "a":Landroid/content/res/TypedArray;
    invoke-virtual {v3}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result v9

    .line 2652
    .local v9, "N":I
    move v10, v4

    .line 2652
    .local v10, "i":I
    :goto_a0
    if-ge v10, v9, :cond_466

    .line 2653
    invoke-virtual {v3, v10}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v11

    .line 2654
    .local v11, "attr":I
    sget-object v12, Landroid/support/constraint/ConstraintLayout$LayoutParams$Table;->map:Landroid/util/SparseIntArray;

    invoke-virtual {v12, v11}, Landroid/util/SparseIntArray;->get(I)I

    move-result v12

    .line 2655
    .local v12, "look":I
    const/4 v13, -0x2

    packed-switch v12, :pswitch_data_46e

    .line 2652
    .end local v11    # "attr":I
    .end local v12    # "look":I
    :cond_b0
    :goto_b0
    :pswitch_b0
    move v13, v5

    move v5, v7

    move v7, v2

    move v2, v4

    goto/16 :goto_45e

    .line 2746
    .restart local v11    # "attr":I
    .restart local v12    # "look":I
    :pswitch_b6
    iget v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    invoke-virtual {v3, v11, v13}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v13

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    .line 2747
    goto :goto_b0

    .line 2742
    :pswitch_bf
    iget v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    invoke-virtual {v3, v11, v13}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v13

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    .line 2743
    goto :goto_b0

    .line 2892
    :pswitch_c8
    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v13

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    .line 2893
    goto :goto_b0

    .line 2888
    :pswitch_cf
    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v13

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    .line 2889
    goto :goto_b0

    .line 2884
    :pswitch_d6
    iget v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    invoke-virtual {v3, v11, v13}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v13

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    .line 2885
    goto :goto_b0

    .line 2880
    :pswitch_df
    iget v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    invoke-virtual {v3, v11, v13}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v13

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    .line 2881
    goto :goto_b0

    .line 2830
    :pswitch_e8
    invoke-virtual {v3, v11}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v13

    iput-object v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    .line 2831
    const/high16 v13, 0x7fc00000    # Float.NaN

    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    .line 2832
    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2833
    iget-object v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    if-eqz v13, :cond_b0

    .line 2834
    iget-object v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    invoke-virtual {v13}, Ljava/lang/String;->length()I

    move-result v13

    .line 2835
    .local v13, "len":I
    iget-object v14, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    const/16 v15, 0x2c

    invoke-virtual {v14, v15}, Ljava/lang/String;->indexOf(I)I

    move-result v14

    .line 2836
    .local v14, "commaIndex":I
    if-lez v14, :cond_12a

    add-int/lit8 v15, v13, -0x1

    if-ge v14, v15, :cond_12a

    .line 2837
    iget-object v15, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    invoke-virtual {v15, v4, v14}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v15

    .line 2838
    .local v15, "dimension":Ljava/lang/String;
    const-string v2, "W"

    invoke-virtual {v15, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_11d

    .line 2839
    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    goto :goto_127

    .line 2840
    :cond_11d
    const-string v2, "H"

    invoke-virtual {v15, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_127

    .line 2841
    iput v7, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2843
    :cond_127
    :goto_127
    add-int/lit8 v14, v14, 0x1

    .line 2844
    .end local v15    # "dimension":Ljava/lang/String;
    goto :goto_12b

    .line 2845
    :cond_12a
    const/4 v14, 0x0

    .line 2847
    :goto_12b
    iget-object v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    const/16 v15, 0x3a

    invoke-virtual {v2, v15}, Ljava/lang/String;->indexOf(I)I

    move-result v2

    .line 2848
    .local v2, "colonIndex":I
    if-ltz v2, :cond_188

    add-int/lit8 v15, v13, -0x1

    if-ge v2, v15, :cond_188

    .line 2849
    iget-object v15, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    invoke-virtual {v15, v14, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v15

    .line 2850
    .local v15, "nominator":Ljava/lang/String;
    iget-object v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    add-int/lit8 v7, v2, 0x1

    invoke-virtual {v4, v7}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v4

    .line 2851
    .local v4, "denominator":Ljava/lang/String;
    invoke-virtual {v15}, Ljava/lang/String;->length()I

    move-result v7

    if-lez v7, :cond_185

    invoke-virtual {v4}, Ljava/lang/String;->length()I

    move-result v7

    if-lez v7, :cond_185

    .line 2853
    :try_start_153
    invoke-static {v15}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v7

    .line 2854
    .local v7, "nominatorValue":F
    invoke-static {v4}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v16

    .line 2855
    .local v16, "denominatorValue":F
    cmpl-float v17, v7, v5

    if-lez v17, :cond_17e

    cmpl-float v17, v16, v5

    if-lez v17, :cond_17e

    .line 2856
    iget v5, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I
    :try_end_165
    .catch Ljava/lang/NumberFormatException; {:try_start_153 .. :try_end_165} :catch_181

    move/from16 v18, v2

    const/4 v2, 0x1

    if-ne v5, v2, :cond_175

    .line 2857
    .end local v2    # "colonIndex":I
    .local v18, "colonIndex":I
    div-float v2, v16, v7

    :try_start_16c
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    goto :goto_180

    .line 2862
    .end local v7    # "nominatorValue":F
    .end local v16    # "denominatorValue":F
    :catch_173
    move-exception v0

    goto :goto_184

    .line 2859
    .restart local v7    # "nominatorValue":F
    .restart local v16    # "denominatorValue":F
    :cond_175
    div-float v2, v7, v16

    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F
    :try_end_17d
    .catch Ljava/lang/NumberFormatException; {:try_start_16c .. :try_end_17d} :catch_173

    .line 2859
    .end local v7    # "nominatorValue":F
    .end local v16    # "denominatorValue":F
    goto :goto_180

    .line 2864
    .end local v18    # "colonIndex":I
    .restart local v2    # "colonIndex":I
    :cond_17e
    move/from16 v18, v2

    .line 2864
    .end local v2    # "colonIndex":I
    .restart local v18    # "colonIndex":I
    :goto_180
    goto :goto_187

    .line 2862
    .end local v18    # "colonIndex":I
    .restart local v2    # "colonIndex":I
    :catch_181
    move-exception v0

    move/from16 v18, v2

    .line 2862
    .end local v2    # "colonIndex":I
    .end local v4    # "denominator":Ljava/lang/String;
    .end local v15    # "nominator":Ljava/lang/String;
    .restart local v18    # "colonIndex":I
    :goto_184
    goto :goto_187

    .line 2866
    .end local v18    # "colonIndex":I
    .restart local v2    # "colonIndex":I
    :cond_185
    move/from16 v18, v2

    .line 2866
    .end local v2    # "colonIndex":I
    .restart local v18    # "colonIndex":I
    :goto_187
    goto :goto_19e

    .line 2867
    .end local v18    # "colonIndex":I
    .restart local v2    # "colonIndex":I
    :cond_188
    move/from16 v18, v2

    .line 2867
    .end local v2    # "colonIndex":I
    .restart local v18    # "colonIndex":I
    iget-object v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    invoke-virtual {v2, v14}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v2

    .line 2868
    .local v2, "r":Ljava/lang/String;
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v4

    if-lez v4, :cond_19e

    .line 2870
    :try_start_196
    invoke-static {v2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F
    :try_end_19c
    .catch Ljava/lang/NumberFormatException; {:try_start_196 .. :try_end_19c} :catch_19d

    .line 2873
    goto :goto_19e

    .line 2871
    :catch_19d
    move-exception v0

    .line 2876
    .end local v2    # "r":Ljava/lang/String;
    .end local v13    # "len":I
    .end local v14    # "commaIndex":I
    .end local v18    # "colonIndex":I
    :cond_19e
    :goto_19e
    goto :goto_1eb

    .line 2985
    :pswitch_19f
    goto :goto_1eb

    .line 2981
    :pswitch_1a0
    goto :goto_1eb

    .line 2977
    :pswitch_1a1
    goto :goto_1eb

    .line 2973
    :pswitch_1a2
    goto :goto_1eb

    .line 2968
    :pswitch_1a3
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v2

    const/4 v4, 0x0

    invoke-static {v4, v2}, Ljava/lang/Math;->max(FF)F

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    .line 2969
    goto :goto_1eb

    .line 2958
    :pswitch_1b1
    :try_start_1b1
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I
    :try_end_1b9
    .catch Ljava/lang/Exception; {:try_start_1b1 .. :try_end_1b9} :catch_1ba

    .line 2964
    goto :goto_1eb

    .line 2959
    :catch_1ba
    move-exception v0

    move-object v2, v0

    .line 2960
    .local v2, "e":Ljava/lang/Exception;
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    .line 2961
    .local v4, "value":I
    if-ne v4, v13, :cond_1c6

    .line 2962
    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    .line 2965
    .end local v2    # "e":Ljava/lang/Exception;
    .end local v4    # "value":I
    :cond_1c6
    goto :goto_1eb

    .line 2947
    :pswitch_1c7
    :try_start_1c7
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I
    :try_end_1cf
    .catch Ljava/lang/Exception; {:try_start_1c7 .. :try_end_1cf} :catch_1d0

    .line 2953
    goto :goto_1eb

    .line 2948
    :catch_1d0
    move-exception v0

    move-object v2, v0

    .line 2949
    .restart local v2    # "e":Ljava/lang/Exception;
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    .line 2950
    .restart local v4    # "value":I
    if-ne v4, v13, :cond_1dc

    .line 2951
    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    .line 2954
    .end local v2    # "e":Ljava/lang/Exception;
    .end local v4    # "value":I
    :cond_1dc
    goto :goto_1eb

    .line 2942
    :pswitch_1dd
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v2

    const/4 v4, 0x0

    invoke-static {v4, v2}, Ljava/lang/Math;->max(FF)F

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    .line 2943
    nop

    .line 2652
    .end local v11    # "attr":I
    .end local v12    # "look":I
    :goto_1eb
    const/4 v2, 0x0

    const/4 v5, 0x1

    goto/16 :goto_409

    .line 2932
    .restart local v11    # "attr":I
    .restart local v12    # "look":I
    :pswitch_1ef
    :try_start_1ef
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I
    :try_end_1f7
    .catch Ljava/lang/Exception; {:try_start_1ef .. :try_end_1f7} :catch_1f8

    .line 2938
    goto :goto_1eb

    .line 2933
    :catch_1f8
    move-exception v0

    move-object v2, v0

    .line 2934
    .restart local v2    # "e":Ljava/lang/Exception;
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    .line 2935
    .restart local v4    # "value":I
    if-ne v4, v13, :cond_204

    .line 2936
    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    .line 2939
    .end local v2    # "e":Ljava/lang/Exception;
    .end local v4    # "value":I
    :cond_204
    goto :goto_1eb

    .line 2921
    :pswitch_205
    :try_start_205
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v2

    iput v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I
    :try_end_20d
    .catch Ljava/lang/Exception; {:try_start_205 .. :try_end_20d} :catch_20e

    .line 2927
    goto :goto_1eb

    .line 2922
    :catch_20e
    move-exception v0

    move-object v2, v0

    .line 2923
    .restart local v2    # "e":Ljava/lang/Exception;
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    .line 2924
    .restart local v4    # "value":I
    if-ne v4, v13, :cond_21a

    .line 2925
    iput v13, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    .line 2928
    .end local v2    # "e":Ljava/lang/Exception;
    .end local v4    # "value":I
    :cond_21a
    goto :goto_1eb

    .line 2912
    :pswitch_21b
    const/4 v2, 0x0

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 2913
    iget v2, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    const/4 v4, 0x1

    if-ne v2, v4, :cond_22f

    .line 2914
    const-string v2, "ConstraintLayout"

    const-string v4, "layout_constraintHeight_default=\"wrap\" is deprecated.\nUse layout_height=\"WRAP_CONTENT\" and layout_constrainedHeight=\"true\" instead."

    invoke-static {v2, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_1eb

    .line 2652
    .end local v11    # "attr":I
    .end local v12    # "look":I
    :cond_22f
    move v5, v4

    const/4 v2, 0x0

    goto/16 :goto_409

    .line 2904
    .restart local v11    # "attr":I
    .restart local v12    # "look":I
    :pswitch_233
    const/4 v2, 0x0

    invoke-virtual {v3, v11, v2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 2905
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    const/4 v5, 0x1

    if-ne v4, v5, :cond_409

    .line 2906
    const-string v4, "ConstraintLayout"

    const-string v7, "layout_constraintWidth_default=\"wrap\" is deprecated.\nUse layout_width=\"WRAP_CONTENT\" and layout_constrainedWidth=\"true\" instead."

    invoke-static {v4, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto/16 :goto_409

    .line 2826
    :pswitch_248
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    .line 2827
    goto/16 :goto_409

    .line 2822
    :pswitch_254
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    .line 2823
    goto/16 :goto_409

    .line 2900
    :pswitch_260
    move v2, v4

    move v5, v7

    iget-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v4

    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 2901
    goto/16 :goto_409

    .line 2896
    :pswitch_26c
    move v2, v4

    move v5, v7

    iget-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v4

    iput-boolean v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 2897
    goto/16 :goto_409

    .line 2818
    :pswitch_278
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    .line 2819
    goto/16 :goto_409

    .line 2814
    :pswitch_284
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    .line 2815
    goto/16 :goto_409

    .line 2810
    :pswitch_290
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    .line 2811
    goto/16 :goto_409

    .line 2806
    :pswitch_29c
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    .line 2807
    goto/16 :goto_409

    .line 2802
    :pswitch_2a8
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    .line 2803
    goto/16 :goto_409

    .line 2798
    :pswitch_2b4
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    .line 2799
    goto/16 :goto_409

    .line 2791
    :pswitch_2c0
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    .line 2792
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    const/4 v7, -0x1

    if-ne v4, v7, :cond_40a

    .line 2793
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    goto/16 :goto_40a

    .line 2784
    :pswitch_2d7
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    .line 2785
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    if-ne v4, v7, :cond_40a

    .line 2786
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    goto/16 :goto_40a

    .line 2777
    :pswitch_2ee
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    .line 2778
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    if-ne v4, v7, :cond_40a

    .line 2779
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    goto/16 :goto_40a

    .line 2770
    :pswitch_305
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    .line 2771
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    if-ne v4, v7, :cond_40a

    .line 2772
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    goto/16 :goto_40a

    .line 2717
    :pswitch_31c
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    .line 2718
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    if-ne v4, v7, :cond_40a

    .line 2719
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    goto/16 :goto_40a

    .line 2710
    :pswitch_333
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    .line 2711
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    if-ne v4, v7, :cond_40a

    .line 2712
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    goto/16 :goto_40a

    .line 2703
    :pswitch_34a
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    .line 2704
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    if-ne v4, v7, :cond_40a

    .line 2705
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    goto/16 :goto_40a

    .line 2696
    :pswitch_361
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    .line 2697
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    if-ne v4, v7, :cond_40a

    .line 2698
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    goto/16 :goto_40a

    .line 2689
    :pswitch_378
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    .line 2690
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    if-ne v4, v7, :cond_40a

    .line 2691
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    goto/16 :goto_40a

    .line 2682
    :pswitch_38f
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    .line 2683
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    if-ne v4, v7, :cond_40a

    .line 2684
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    goto/16 :goto_40a

    .line 2675
    :pswitch_3a6
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    .line 2676
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    if-ne v4, v7, :cond_40a

    .line 2677
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    goto :goto_40a

    .line 2668
    :pswitch_3bc
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    .line 2669
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    if-ne v4, v7, :cond_40a

    .line 2670
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    goto :goto_40a

    .line 2661
    :pswitch_3d2
    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    .line 2662
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    if-ne v4, v7, :cond_40a

    .line 2663
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    goto :goto_409

    .line 2760
    :pswitch_3e8
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    .line 2761
    goto :goto_409

    .line 2755
    :pswitch_3f3
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    .line 2756
    goto :goto_409

    .line 2750
    :pswitch_3fe
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    .line 2751
    nop

    .line 2652
    .end local v11    # "attr":I
    .end local v12    # "look":I
    :cond_409
    :goto_409
    const/4 v7, -0x1

    :cond_40a
    :goto_40a
    const/4 v13, 0x0

    goto :goto_45e

    .line 2735
    .restart local v11    # "attr":I
    .restart local v12    # "look":I
    :pswitch_40c
    move v2, v4

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v4

    const/high16 v7, 0x43b40000    # 360.0f

    rem-float/2addr v4, v7

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    .line 2736
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    const/4 v13, 0x0

    cmpg-float v4, v4, v13

    if-gez v4, :cond_434

    .line 2737
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    sub-float v4, v7, v4

    rem-float/2addr v4, v7

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    goto :goto_434

    .line 2731
    :pswitch_428
    move v2, v4

    move v13, v5

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    .line 2732
    nop

    .line 2652
    .end local v11    # "attr":I
    .end local v12    # "look":I
    :cond_434
    :goto_434
    const/4 v7, -0x1

    goto :goto_45e

    .line 2724
    .restart local v11    # "attr":I
    .restart local v12    # "look":I
    :pswitch_436
    move v2, v4

    move v13, v5

    move v5, v7

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    .line 2725
    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    const/4 v7, -0x1

    if-ne v4, v7, :cond_45e

    .line 2726
    invoke-virtual {v3, v11, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    goto :goto_45e

    .line 2765
    :pswitch_44d
    move v13, v5

    move v5, v7

    move v7, v2

    move v2, v4

    iget v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    invoke-virtual {v3, v11, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v4

    iput v4, v1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    .line 2766
    goto :goto_45e

    .line 2658
    :pswitch_45a
    move v13, v5

    move v5, v7

    move v7, v2

    move v2, v4

    .line 2652
    .end local v11    # "attr":I
    .end local v12    # "look":I
    :cond_45e
    :goto_45e
    add-int/lit8 v10, v10, 0x1

    move v4, v2

    move v2, v7

    move v7, v5

    move v5, v13

    goto/16 :goto_a0

    .line 2993
    .end local v10    # "i":I
    :cond_466
    invoke-virtual {v3}, Landroid/content/res/TypedArray;->recycle()V

    .line 2994
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/ConstraintLayout$LayoutParams;->validate()V

    .line 2995
    return-void

    nop

    :pswitch_data_46e
    .packed-switch 0x0
        :pswitch_45a
        :pswitch_44d
        :pswitch_436
        :pswitch_428
        :pswitch_40c
        :pswitch_3fe
        :pswitch_3f3
        :pswitch_3e8
        :pswitch_3d2
        :pswitch_3bc
        :pswitch_3a6
        :pswitch_38f
        :pswitch_378
        :pswitch_361
        :pswitch_34a
        :pswitch_333
        :pswitch_31c
        :pswitch_305
        :pswitch_2ee
        :pswitch_2d7
        :pswitch_2c0
        :pswitch_2b4
        :pswitch_2a8
        :pswitch_29c
        :pswitch_290
        :pswitch_284
        :pswitch_278
        :pswitch_26c
        :pswitch_260
        :pswitch_254
        :pswitch_248
        :pswitch_233
        :pswitch_21b
        :pswitch_205
        :pswitch_1ef
        :pswitch_1dd
        :pswitch_1c7
        :pswitch_1b1
        :pswitch_1a3
        :pswitch_1a2
        :pswitch_1a1
        :pswitch_1a0
        :pswitch_19f
        :pswitch_b0
        :pswitch_e8
        :pswitch_df
        :pswitch_d6
        :pswitch_cf
        :pswitch_c8
        :pswitch_bf
        :pswitch_b6
    .end packed-switch
.end method

.method public constructor <init>(Landroid/support/constraint/ConstraintLayout$LayoutParams;)V
    .registers 8
    .param p1, "source"    # Landroid/support/constraint/ConstraintLayout$LayoutParams;

    .line 2478
    invoke-direct {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    .line 2166
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    .line 2171
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    .line 2176
    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    .line 2181
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    .line 2186
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    .line 2191
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    .line 2196
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    .line 2201
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    .line 2206
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    .line 2211
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    .line 2216
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    .line 2221
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    .line 2226
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    .line 2231
    const/4 v2, 0x0

    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    .line 2236
    const/4 v3, 0x0

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    .line 2241
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    .line 2246
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    .line 2251
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    .line 2256
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    .line 2261
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    .line 2266
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    .line 2271
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    .line 2276
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    .line 2281
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    .line 2286
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    .line 2291
    const/high16 v4, 0x3f000000    # 0.5f

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    .line 2296
    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    .line 2301
    const/4 v5, 0x0

    iput-object v5, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    .line 2306
    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    .line 2311
    const/4 v3, 0x1

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2317
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    .line 2323
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    .line 2335
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    .line 2347
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    .line 2360
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 2373
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 2379
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    .line 2385
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    .line 2391
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    .line 2397
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    .line 2402
    const/high16 v1, 0x3f800000    # 1.0f

    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    .line 2407
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    .line 2413
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    .line 2419
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    .line 2421
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    .line 2430
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 2439
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 2442
    iput-boolean v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 2443
    iput-boolean v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 2445
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->needsBaseline:Z

    .line 2446
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 2447
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isHelper:Z

    .line 2448
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isInPlaceholder:Z

    .line 2450
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 2451
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 2452
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 2453
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 2454
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 2455
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 2456
    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 2462
    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2470
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->helped:Z

    .line 2479
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    .line 2480
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    .line 2481
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    .line 2482
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    .line 2483
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    .line 2484
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    .line 2485
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    .line 2486
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    .line 2487
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    .line 2488
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    .line 2489
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    .line 2490
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    .line 2491
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    .line 2492
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    .line 2493
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    .line 2494
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    .line 2495
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    .line 2496
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    .line 2497
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    .line 2498
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    .line 2499
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    .line 2500
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    .line 2501
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    .line 2502
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    .line 2503
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    .line 2504
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    .line 2505
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    .line 2506
    iget-object v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    iput-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    .line 2507
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    .line 2508
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2509
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    .line 2510
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    .line 2511
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    .line 2512
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    .line 2513
    iget-boolean v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 2514
    iget-boolean v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 2515
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 2516
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 2517
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    .line 2518
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    .line 2519
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    .line 2520
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    .line 2521
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    .line 2522
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    .line 2523
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    .line 2524
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    .line 2525
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    .line 2526
    iget-boolean v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 2527
    iget-boolean v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 2528
    iget-boolean v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->needsBaseline:Z

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->needsBaseline:Z

    .line 2529
    iget-boolean v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 2530
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 2531
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 2532
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 2533
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 2534
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 2535
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 2536
    iget v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 2537
    iget-object v0, p1, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iput-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2538
    return-void
.end method

.method public constructor <init>(Landroid/view/ViewGroup$LayoutParams;)V
    .registers 8
    .param p1, "source"    # Landroid/view/ViewGroup$LayoutParams;

    .line 3044
    invoke-direct {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    .line 2166
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    .line 2171
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    .line 2176
    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    .line 2181
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    .line 2186
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    .line 2191
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    .line 2196
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    .line 2201
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToTop:I

    .line 2206
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->topToBottom:I

    .line 2211
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToTop:I

    .line 2216
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->bottomToBottom:I

    .line 2221
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->baselineToBaseline:I

    .line 2226
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleConstraint:I

    .line 2231
    const/4 v2, 0x0

    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleRadius:I

    .line 2236
    const/4 v3, 0x0

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->circleAngle:F

    .line 2241
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    .line 2246
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    .line 2251
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    .line 2256
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    .line 2261
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    .line 2266
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneTopMargin:I

    .line 2271
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    .line 2276
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneBottomMargin:I

    .line 2281
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    .line 2286
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    .line 2291
    const/high16 v4, 0x3f000000    # 0.5f

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    .line 2296
    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalBias:F

    .line 2301
    const/4 v5, 0x0

    iput-object v5, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatio:Ljava/lang/String;

    .line 2306
    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioValue:F

    .line 2311
    const/4 v3, 0x1

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->dimensionRatioSide:I

    .line 2317
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalWeight:F

    .line 2323
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalWeight:F

    .line 2335
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalChainStyle:I

    .line 2347
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalChainStyle:I

    .line 2360
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 2373
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 2379
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinWidth:I

    .line 2385
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMinHeight:I

    .line 2391
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxWidth:I

    .line 2397
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintMaxHeight:I

    .line 2402
    const/high16 v1, 0x3f800000    # 1.0f

    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentWidth:F

    .line 2407
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintPercentHeight:F

    .line 2413
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteX:I

    .line 2419
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->editorAbsoluteY:I

    .line 2421
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    .line 2430
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 2439
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 2442
    iput-boolean v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 2443
    iput-boolean v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 2445
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->needsBaseline:Z

    .line 2446
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 2447
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isHelper:Z

    .line 2448
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isInPlaceholder:Z

    .line 2450
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 2451
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 2452
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 2453
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 2454
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 2455
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 2456
    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 2462
    new-instance v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2470
    iput-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->helped:Z

    .line 3045
    return-void
.end method


# virtual methods
.method public reset()V
    .registers 2

    .line 2465
    iget-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v0, :cond_9

    .line 2466
    iget-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->reset()V

    .line 2468
    :cond_9
    return-void
.end method

.method public resolveLayoutDirection(I)V
    .registers 10
    .param p1, "layoutDirection"    # I
    .annotation build Landroid/annotation/TargetApi;
        value = 0x11
    .end annotation

    .line 3053
    iget v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftMargin:I

    .line 3054
    .local v0, "preLeftMargin":I
    iget v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightMargin:I

    .line 3056
    .local v1, "preRightMargin":I
    invoke-super {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;->resolveLayoutDirection(I)V

    .line 3058
    const/4 v2, -0x1

    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 3059
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 3060
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 3061
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 3063
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 3064
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 3065
    iget v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneLeftMargin:I

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 3066
    iget v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneRightMargin:I

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 3067
    iget v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 3069
    iget v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideBegin:I

    .line 3070
    iget v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideEnd:I

    .line 3071
    iget v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuidePercent:F

    .line 3073
    invoke-virtual {p0}, Landroid/support/constraint/ConstraintLayout$LayoutParams;->getLayoutDirection()I

    move-result v3

    const/4 v4, 0x1

    if-ne v4, v3, :cond_35

    move v3, v4

    goto :goto_36

    :cond_35
    const/4 v3, 0x0

    .line 3075
    .local v3, "isRtl":Z
    :goto_36
    if-eqz v3, :cond_ac

    .line 3076
    const/4 v5, 0x0

    .line 3077
    .local v5, "startEndDefined":Z
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    if-eq v6, v2, :cond_43

    .line 3078
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 3079
    const/4 v5, 0x1

    goto :goto_4c

    .line 3080
    :cond_43
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    if-eq v6, v2, :cond_4c

    .line 3081
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 3082
    const/4 v5, 0x1

    .line 3084
    :cond_4c
    :goto_4c
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    if-eq v6, v2, :cond_55

    .line 3085
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 3086
    const/4 v5, 0x1

    .line 3088
    :cond_55
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    if-eq v6, v2, :cond_5e

    .line 3089
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 3090
    const/4 v5, 0x1

    .line 3092
    :cond_5e
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    if-eq v6, v2, :cond_66

    .line 3093
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 3095
    :cond_66
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    if-eq v6, v2, :cond_6e

    .line 3096
    iget v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 3098
    :cond_6e
    const/high16 v6, 0x3f800000    # 1.0f

    if-eqz v5, :cond_78

    .line 3099
    iget v7, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalBias:F

    sub-float v7, v6, v7

    iput v7, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedHorizontalBias:F

    .line 3103
    :cond_78
    iget-boolean v7, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    if-eqz v7, :cond_ab

    iget v7, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    if-ne v7, v4, :cond_ab

    .line 3104
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    const/high16 v7, -0x40800000    # -1.0f

    cmpl-float v4, v4, v7

    if-eqz v4, :cond_92

    .line 3105
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    sub-float/2addr v6, v4

    iput v6, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuidePercent:F

    .line 3106
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideBegin:I

    .line 3107
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideEnd:I

    goto :goto_ab

    .line 3108
    :cond_92
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    if-eq v4, v2, :cond_9f

    .line 3109
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideEnd:I

    .line 3110
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideBegin:I

    .line 3111
    iput v7, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuidePercent:F

    goto :goto_ab

    .line 3112
    :cond_9f
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    if-eq v4, v2, :cond_ab

    .line 3113
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideBegin:I

    .line 3114
    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuideEnd:I

    .line 3115
    iput v7, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedGuidePercent:F

    .line 3118
    .end local v5    # "startEndDefined":Z
    :cond_ab
    :goto_ab
    goto :goto_dc

    .line 3119
    :cond_ac
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    if-eq v4, v2, :cond_b4

    .line 3120
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 3122
    :cond_b4
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    if-eq v4, v2, :cond_bc

    .line 3123
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 3125
    :cond_bc
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    if-eq v4, v2, :cond_c4

    .line 3126
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 3128
    :cond_c4
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    if-eq v4, v2, :cond_cc

    .line 3129
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 3131
    :cond_cc
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    if-eq v4, v2, :cond_d4

    .line 3132
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneStartMargin:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneLeftMargin:I

    .line 3134
    :cond_d4
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    if-eq v4, v2, :cond_dc

    .line 3135
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->goneEndMargin:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolveGoneRightMargin:I

    .line 3139
    :cond_dc
    :goto_dc
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToStart:I

    if-ne v4, v2, :cond_12e

    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->endToEnd:I

    if-ne v4, v2, :cond_12e

    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToStart:I

    if-ne v4, v2, :cond_12e

    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->startToEnd:I

    if-ne v4, v2, :cond_12e

    .line 3141
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    if-eq v4, v2, :cond_fd

    .line 3142
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToLeft:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToLeft:I

    .line 3143
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightMargin:I

    if-gtz v4, :cond_10d

    if-lez v1, :cond_10d

    .line 3144
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightMargin:I

    goto :goto_10d

    .line 3146
    :cond_fd
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    if-eq v4, v2, :cond_10d

    .line 3147
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightToRight:I

    iput v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedRightToRight:I

    .line 3148
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightMargin:I

    if-gtz v4, :cond_10d

    if-lez v1, :cond_10d

    .line 3149
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->rightMargin:I

    .line 3152
    :cond_10d
    :goto_10d
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    if-eq v4, v2, :cond_11e

    .line 3153
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToLeft:I

    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToLeft:I

    .line 3154
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftMargin:I

    if-gtz v2, :cond_12e

    if-lez v0, :cond_12e

    .line 3155
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftMargin:I

    goto :goto_12e

    .line 3157
    :cond_11e
    iget v4, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    if-eq v4, v2, :cond_12e

    .line 3158
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftToRight:I

    iput v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->resolvedLeftToRight:I

    .line 3159
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftMargin:I

    if-gtz v2, :cond_12e

    if-lez v0, :cond_12e

    .line 3160
    iput v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->leftMargin:I

    .line 3164
    :cond_12e
    :goto_12e
    return-void
.end method

.method public validate()V
    .registers 6

    .line 2998
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 2999
    const/4 v1, 0x1

    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 3000
    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 3001
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->width:I

    const/4 v3, -0x2

    if-ne v2, v3, :cond_15

    iget-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    if-eqz v2, :cond_15

    .line 3002
    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 3003
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    .line 3005
    :cond_15
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->height:I

    if-ne v2, v3, :cond_21

    iget-boolean v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    if-eqz v2, :cond_21

    .line 3006
    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 3007
    iput v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    .line 3009
    :cond_21
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->width:I

    const/4 v4, -0x1

    if-eqz v2, :cond_2a

    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->width:I

    if-ne v2, v4, :cond_38

    .line 3010
    :cond_2a
    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 3014
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->width:I

    if-nez v2, :cond_38

    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultWidth:I

    if-ne v2, v1, :cond_38

    .line 3015
    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->width:I

    .line 3016
    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedWidth:Z

    .line 3019
    :cond_38
    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->height:I

    if-eqz v2, :cond_40

    iget v2, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->height:I

    if-ne v2, v4, :cond_4e

    .line 3020
    :cond_40
    iput-boolean v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 3024
    iget v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->height:I

    if-nez v0, :cond_4e

    iget v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->matchConstraintDefaultHeight:I

    if-ne v0, v1, :cond_4e

    .line 3025
    iput v3, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->height:I

    .line 3026
    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->constrainedHeight:Z

    .line 3029
    :cond_4e
    iget v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guidePercent:F

    const/high16 v2, -0x40800000    # -1.0f

    cmpl-float v0, v0, v2

    if-nez v0, :cond_5e

    iget v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideBegin:I

    if-ne v0, v4, :cond_5e

    iget v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->guideEnd:I

    if-eq v0, v4, :cond_7a

    .line 3030
    :cond_5e
    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->isGuideline:Z

    .line 3031
    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->horizontalDimensionFixed:Z

    .line 3032
    iput-boolean v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->verticalDimensionFixed:Z

    .line 3033
    iget-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    instance-of v0, v0, Landroid/support/constraint/solver/widgets/Guideline;

    if-nez v0, :cond_71

    .line 3034
    new-instance v0, Landroid/support/constraint/solver/widgets/Guideline;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/Guideline;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 3036
    :cond_71
    iget-object v0, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->widget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    check-cast v0, Landroid/support/constraint/solver/widgets/Guideline;

    iget v1, p0, Landroid/support/constraint/ConstraintLayout$LayoutParams;->orientation:I

    invoke-virtual {v0, v1}, Landroid/support/constraint/solver/widgets/Guideline;->setOrientation(I)V

    .line 3038
    :cond_7a
    return-void
.end method
