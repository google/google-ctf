.class public Landroid/support/constraint/solver/widgets/ConstraintWidget;
.super Ljava/lang/Object;
.source "ConstraintWidget.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;,
        Landroid/support/constraint/solver/widgets/ConstraintWidget$ContentAlignment;
    }
.end annotation


# static fields
.field protected static final ANCHOR_BASELINE:I = 0x4

.field protected static final ANCHOR_BOTTOM:I = 0x3

.field protected static final ANCHOR_LEFT:I = 0x0

.field protected static final ANCHOR_RIGHT:I = 0x1

.field protected static final ANCHOR_TOP:I = 0x2

.field private static final AUTOTAG_CENTER:Z = false

.field public static final CHAIN_PACKED:I = 0x2

.field public static final CHAIN_SPREAD:I = 0x0

.field public static final CHAIN_SPREAD_INSIDE:I = 0x1

.field public static DEFAULT_BIAS:F = 0.0f

.field static final DIMENSION_HORIZONTAL:I = 0x0

.field static final DIMENSION_VERTICAL:I = 0x1

.field protected static final DIRECT:I = 0x2

.field public static final GONE:I = 0x8

.field public static final HORIZONTAL:I = 0x0

.field public static final INVISIBLE:I = 0x4

.field public static final MATCH_CONSTRAINT_PERCENT:I = 0x2

.field public static final MATCH_CONSTRAINT_RATIO:I = 0x3

.field public static final MATCH_CONSTRAINT_RATIO_RESOLVED:I = 0x4

.field public static final MATCH_CONSTRAINT_SPREAD:I = 0x0

.field public static final MATCH_CONSTRAINT_WRAP:I = 0x1

.field protected static final SOLVER:I = 0x1

.field public static final UNKNOWN:I = -0x1

.field public static final VERTICAL:I = 0x1

.field public static final VISIBLE:I = 0x0

.field private static final WRAP:I = -0x2


# instance fields
.field protected mAnchors:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintAnchor;",
            ">;"
        }
    .end annotation
.end field

.field mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mBaselineDistance:I

.field mBelongingGroup:Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

.field mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mBottomHasCentered:Z

.field mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field private mCircleConstraintAngle:F

.field private mCompanionWidget:Ljava/lang/Object;

.field private mContainerItemSkip:I

.field private mDebugName:Ljava/lang/String;

.field protected mDimensionRatio:F

.field protected mDimensionRatioSide:I

.field mDistToBottom:I

.field mDistToLeft:I

.field mDistToRight:I

.field mDistToTop:I

.field private mDrawHeight:I

.field private mDrawWidth:I

.field private mDrawX:I

.field private mDrawY:I

.field mGroupsToSolver:Z

.field mHeight:I

.field mHorizontalBiasPercent:F

.field mHorizontalChainFixedPosition:Z

.field mHorizontalChainStyle:I

.field mHorizontalNextWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field public mHorizontalResolution:I

.field mHorizontalWrapVisited:Z

.field mIsHeightWrapContent:Z

.field mIsWidthWrapContent:Z

.field mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mLeftHasCentered:Z

.field protected mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field protected mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

.field protected mListNextMatchConstraintsWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field mMatchConstraintDefaultHeight:I

.field mMatchConstraintDefaultWidth:I

.field mMatchConstraintMaxHeight:I

.field mMatchConstraintMaxWidth:I

.field mMatchConstraintMinHeight:I

.field mMatchConstraintMinWidth:I

.field mMatchConstraintPercentHeight:F

.field mMatchConstraintPercentWidth:F

.field private mMaxDimension:[I

.field protected mMinHeight:I

.field protected mMinWidth:I

.field protected mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field protected mOffsetX:I

.field protected mOffsetY:I

.field mOptimizerMeasurable:Z

.field mOptimizerMeasured:Z

.field mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field mRelX:I

.field mRelY:I

.field mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

.field mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

.field mResolvedDimensionRatio:F

.field mResolvedDimensionRatioSide:I

.field mResolvedMatchConstraintDefault:[I

.field mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mRightHasCentered:Z

.field mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field mTopHasCentered:Z

.field private mType:Ljava/lang/String;

.field mVerticalBiasPercent:F

.field mVerticalChainFixedPosition:Z

.field mVerticalChainStyle:I

.field mVerticalNextWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field public mVerticalResolution:I

.field mVerticalWrapVisited:Z

.field private mVisibility:I

.field mWeight:[F

.field mWidth:I

.field private mWrapHeight:I

.field private mWrapWidth:I

.field protected mX:I

.field protected mY:I


# direct methods
.method static constructor <clinit>()V
    .registers 1

    .line 209
    const/high16 v0, 0x3f000000    # 0.5f

    sput v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    return-void
.end method

.method public constructor <init>()V
    .registers 10

    .line 407
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 68
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalResolution:I

    .line 69
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalResolution:I

    .line 76
    const/4 v1, 0x0

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    .line 77
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    .line 78
    const/4 v2, 0x2

    new-array v3, v2, [I

    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    .line 80
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    .line 81
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    .line 82
    const/high16 v3, 0x3f800000    # 1.0f

    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentWidth:F

    .line 83
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    .line 84
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    .line 85
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentHeight:F

    .line 89
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 90
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 95
    const/4 v3, 0x0

    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBelongingGroup:Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    .line 97
    new-array v4, v2, [I

    fill-array-data v4, :array_106

    iput-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    .line 98
    const/4 v4, 0x0

    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCircleConstraintAngle:F

    .line 148
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 149
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 150
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 151
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 152
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 153
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 154
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 155
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 163
    const/4 v5, 0x6

    new-array v5, v5, [Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aput-object v6, v5, v1

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v7, 0x1

    aput-object v6, v5, v7

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aput-object v6, v5, v2

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v8, 0x3

    aput-object v6, v5, v8

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v8, 0x4

    aput-object v6, v5, v8

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v8, 0x5

    aput-object v6, v5, v8

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 164
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    .line 169
    new-array v5, v2, [Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v6, v5, v1

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v6, v5, v7

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 172
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 175
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 176
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 177
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    .line 178
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    .line 181
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 182
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 183
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelX:I

    .line 184
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelY:I

    .line 187
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 188
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 189
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    .line 190
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    .line 193
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    .line 194
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    .line 197
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    .line 210
    sget v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    .line 211
    sget v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    .line 219
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mContainerItemSkip:I

    .line 222
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    .line 224
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    .line 225
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    .line 237
    iput-boolean v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasurable:Z

    .line 238
    iput-boolean v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 239
    iput-boolean v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mGroupsToSolver:Z

    .line 242
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    .line 243
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    .line 247
    new-array v0, v2, [F

    fill-array-data v0, :array_10e

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    .line 249
    new-array v0, v2, [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aput-object v3, v0, v1

    aput-object v3, v0, v7

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListNextMatchConstraintsWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 250
    new-array v0, v2, [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aput-object v3, v0, v1

    aput-object v3, v0, v7

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 252
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalNextWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 253
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalNextWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 408
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->addAnchors()V

    .line 409
    return-void

    :array_106
    .array-data 4
        0x7fffffff
        0x7fffffff
    .end array-data

    :array_10e
    .array-data 4
        -0x40800000    # -1.0f
        -0x40800000    # -1.0f
    .end array-data
.end method

.method public constructor <init>(II)V
    .registers 4
    .param p1, "width"    # I
    .param p2, "height"    # I

    .line 435
    const/4 v0, 0x0

    invoke-direct {p0, v0, v0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;-><init>(IIII)V

    .line 436
    return-void
.end method

.method public constructor <init>(IIII)V
    .registers 14
    .param p1, "x"    # I
    .param p2, "y"    # I
    .param p3, "width"    # I
    .param p4, "height"    # I

    .line 419
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 68
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalResolution:I

    .line 69
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalResolution:I

    .line 76
    const/4 v1, 0x0

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    .line 77
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    .line 78
    const/4 v2, 0x2

    new-array v3, v2, [I

    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    .line 80
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    .line 81
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    .line 82
    const/high16 v3, 0x3f800000    # 1.0f

    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentWidth:F

    .line 83
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    .line 84
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    .line 85
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentHeight:F

    .line 89
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 90
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 95
    const/4 v3, 0x0

    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBelongingGroup:Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    .line 97
    new-array v4, v2, [I

    fill-array-data v4, :array_112

    iput-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    .line 98
    const/4 v4, 0x0

    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCircleConstraintAngle:F

    .line 148
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 149
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 150
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 151
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 152
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 153
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 154
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 155
    new-instance v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-direct {v5, p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 163
    const/4 v5, 0x6

    new-array v5, v5, [Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aput-object v6, v5, v1

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v7, 0x1

    aput-object v6, v5, v7

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aput-object v6, v5, v2

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v8, 0x3

    aput-object v6, v5, v8

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v8, 0x4

    aput-object v6, v5, v8

    iget-object v6, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    const/4 v8, 0x5

    aput-object v6, v5, v8

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 164
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    .line 169
    new-array v5, v2, [Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v6, v5, v1

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v6, v5, v7

    iput-object v5, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 172
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 175
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 176
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 177
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    .line 178
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    .line 181
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 182
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 183
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelX:I

    .line 184
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelY:I

    .line 187
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 188
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 189
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    .line 190
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    .line 193
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    .line 194
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    .line 197
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    .line 210
    sget v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    .line 211
    sget v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    .line 219
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mContainerItemSkip:I

    .line 222
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    .line 224
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    .line 225
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    .line 237
    iput-boolean v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasurable:Z

    .line 238
    iput-boolean v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 239
    iput-boolean v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mGroupsToSolver:Z

    .line 242
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    .line 243
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    .line 247
    new-array v0, v2, [F

    fill-array-data v0, :array_11a

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    .line 249
    new-array v0, v2, [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aput-object v3, v0, v1

    aput-object v3, v0, v7

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListNextMatchConstraintsWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 250
    new-array v0, v2, [Landroid/support/constraint/solver/widgets/ConstraintWidget;

    aput-object v3, v0, v1

    aput-object v3, v0, v7

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mNextChainWidget:[Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 252
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalNextWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 253
    iput-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalNextWidget:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 420
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 421
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 422
    iput p3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 423
    iput p4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 424
    invoke-direct {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->addAnchors()V

    .line 425
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->forceUpdateDrawPosition()V

    .line 426
    return-void

    nop

    :array_112
    .array-data 4
        0x7fffffff
        0x7fffffff
    .end array-data

    :array_11a
    .array-data 4
        -0x40800000    # -1.0f
        -0x40800000    # -1.0f
    .end array-data
.end method

.method private addAnchors()V
    .registers 3

    .line 456
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 457
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 458
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 459
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 460
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 461
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 462
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 463
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 464
    return-void
.end method

.method private applyConstraints(Landroid/support/constraint/solver/LinearSystem;ZLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;ZLandroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;IIIIFZZIIIFZ)V
    .registers 64
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "parentWrapContent"    # Z
    .param p3, "parentMin"    # Landroid/support/constraint/solver/SolverVariable;
    .param p4, "parentMax"    # Landroid/support/constraint/solver/SolverVariable;
    .param p5, "dimensionBehaviour"    # Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .param p6, "wrapContent"    # Z
    .param p7, "beginAnchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p8, "endAnchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p9, "beginPosition"    # I
    .param p10, "dimension"    # I
    .param p11, "minDimension"    # I
    .param p12, "maxDimension"    # I
    .param p13, "bias"    # F
    .param p14, "useRatio"    # Z
    .param p15, "inChain"    # Z
    .param p16, "matchConstraintDefault"    # I
    .param p17, "matchMinDimension"    # I
    .param p18, "matchMaxDimension"    # I
    .param p19, "matchPercentDimension"    # F
    .param p20, "applyPosition"    # Z

    move-object/from16 v0, p0

    move-object/from16 v10, p1

    move-object/from16 v11, p3

    move-object/from16 v12, p4

    move-object/from16 v13, p7

    move-object/from16 v14, p8

    move/from16 v9, p11

    move/from16 v8, p12

    .line 2612
    invoke-virtual {v10, v13}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v7

    .line 2613
    .local v7, "begin":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v10, v14}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v6

    .line 2614
    .local v6, "end":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v5

    .line 2615
    .local v5, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 2617
    .local v4, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    iget-boolean v1, v10, Landroid/support/constraint/solver/LinearSystem;->graphOptimizer:Z

    const/4 v2, 0x1

    if-eqz v1, :cond_6b

    .line 2618
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget v1, v1, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-ne v1, v2, :cond_6b

    .line 2619
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    iget v1, v1, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-ne v1, v2, :cond_6b

    .line 2620
    invoke-static {}, Landroid/support/constraint/solver/LinearSystem;->getMetrics()Landroid/support/constraint/solver/Metrics;

    move-result-object v1

    if-eqz v1, :cond_51

    .line 2621
    invoke-static {}, Landroid/support/constraint/solver/LinearSystem;->getMetrics()Landroid/support/constraint/solver/Metrics;

    move-result-object v1

    move-object/from16 v18, v4

    iget-wide v3, v1, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    .line 2621
    .end local v4    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v18, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    const-wide/16 v15, 0x1

    add-long/2addr v3, v15

    iput-wide v3, v1, Landroid/support/constraint/solver/Metrics;->resolvedWidgets:J

    goto :goto_53

    .line 2623
    .end local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v4    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_51
    move-object/from16 v18, v4

    .line 2623
    .end local v4    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    :goto_53
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    invoke-virtual {v1, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 2624
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    invoke-virtual {v1, v10}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 2625
    if-nez p15, :cond_6a

    if-eqz p2, :cond_6a

    .line 2626
    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-virtual {v10, v12, v6, v2, v1}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2628
    :cond_6a
    return-void

    .line 2631
    .end local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v4    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_6b
    move-object/from16 v18, v4

    .line 2631
    .end local v4    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    invoke-static {}, Landroid/support/constraint/solver/LinearSystem;->getMetrics()Landroid/support/constraint/solver/Metrics;

    move-result-object v1

    if-eqz v1, :cond_7e

    .line 2632
    invoke-static {}, Landroid/support/constraint/solver/LinearSystem;->getMetrics()Landroid/support/constraint/solver/Metrics;

    move-result-object v1

    iget-wide v3, v1, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    const-wide/16 v15, 0x1

    add-long/2addr v3, v15

    iput-wide v3, v1, Landroid/support/constraint/solver/Metrics;->nonresolvedWidgets:J

    .line 2635
    :cond_7e
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v15

    .line 2636
    .local v15, "isBeginConnected":Z
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v16

    .line 2637
    .local v16, "isEndConnected":Z
    iget-object v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v20

    .line 2639
    .local v20, "isCenterConnected":Z
    const/4 v1, 0x0

    .line 2641
    .local v1, "variableSize":Z
    const/4 v3, 0x0

    .line 2642
    .local v3, "numConnections":I
    if-eqz v15, :cond_92

    add-int/lit8 v3, v3, 0x1

    .line 2643
    :cond_92
    if-eqz v16, :cond_96

    add-int/lit8 v3, v3, 0x1

    .line 2644
    :cond_96
    if-eqz v20, :cond_9a

    add-int/lit8 v3, v3, 0x1

    .line 2646
    .end local v3    # "numConnections":I
    .local v4, "numConnections":I
    :cond_9a
    move v4, v3

    if-eqz p14, :cond_9f

    .line 2647
    const/4 v3, 0x3

    .line 2647
    .end local p16    # "matchConstraintDefault":I
    .local v3, "matchConstraintDefault":I
    goto :goto_a1

    .line 2649
    .end local v3    # "matchConstraintDefault":I
    .restart local p16    # "matchConstraintDefault":I
    :cond_9f
    move/from16 v3, p16

    .line 2649
    .end local p16    # "matchConstraintDefault":I
    .restart local v3    # "matchConstraintDefault":I
    :goto_a1
    sget-object v21, Landroid/support/constraint/solver/widgets/ConstraintWidget$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintWidget$DimensionBehaviour:[I

    invoke-virtual/range {p5 .. p5}, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->ordinal()I

    move-result v22

    aget v21, v21, v22

    const/4 v2, 0x4

    packed-switch v21, :pswitch_data_3fc

    goto :goto_b9

    .line 2660
    :pswitch_ae
    const/4 v1, 0x1

    .line 2661
    if-ne v3, v2, :cond_b9

    .line 2662
    const/4 v1, 0x0

    goto :goto_b9

    .line 2657
    :pswitch_b3
    const/4 v1, 0x0

    .line 2658
    goto :goto_b9

    .line 2654
    :pswitch_b5
    const/4 v1, 0x0

    .line 2655
    goto :goto_b9

    .line 2651
    :pswitch_b7
    const/4 v1, 0x0

    .line 2652
    nop

    .line 2667
    :cond_b9
    :goto_b9
    iget v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    move/from16 v25, v1

    const/16 v1, 0x8

    .line 2667
    .end local v1    # "variableSize":Z
    .local v25, "variableSize":Z
    if-ne v2, v1, :cond_c6

    .line 2668
    const/4 v1, 0x0

    .line 2669
    .end local p10    # "dimension":I
    .local v1, "dimension":I
    const/4 v2, 0x0

    .line 2673
    .end local v25    # "variableSize":Z
    .local v2, "variableSize":Z
    move/from16 v25, v2

    goto :goto_c8

    .line 2673
    .end local v1    # "dimension":I
    .end local v2    # "variableSize":Z
    .restart local v25    # "variableSize":Z
    .restart local p10    # "dimension":I
    :cond_c6
    move/from16 v1, p10

    .line 2673
    .end local p10    # "dimension":I
    .restart local v1    # "dimension":I
    :goto_c8
    if-eqz p20, :cond_e9

    .line 2674
    if-nez v15, :cond_d8

    if-nez v16, :cond_d8

    if-nez v20, :cond_d8

    .line 2675
    move/from16 v2, p9

    invoke-virtual {v10, v7, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;I)V

    .line 2682
    move/from16 v27, v4

    goto :goto_eb

    .line 2676
    :cond_d8
    move/from16 v2, p9

    if-eqz v15, :cond_e9

    if-nez v16, :cond_e9

    .line 2677
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v2

    move/from16 v27, v4

    const/4 v4, 0x6

    invoke-virtual {v10, v7, v5, v2, v4}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    goto :goto_eb

    .line 2682
    :cond_e9
    move/from16 v27, v4

    .line 2682
    .end local v4    # "numConnections":I
    .local v27, "numConnections":I
    :goto_eb
    const/4 v4, 0x3

    if-nez v25, :cond_11a

    .line 2683
    if-eqz p6, :cond_105

    .line 2684
    const/4 v2, 0x0

    invoke-virtual {v10, v6, v7, v2, v4}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2685
    if-lez v9, :cond_fb

    .line 2686
    const/4 v2, 0x6

    invoke-virtual {v10, v6, v7, v9, v2}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    goto :goto_fc

    .line 2688
    :cond_fb
    const/4 v2, 0x6

    :goto_fc
    const v4, 0x7fffffff

    if-ge v8, v4, :cond_109

    .line 2689
    invoke-virtual {v10, v6, v7, v8, v2}, Landroid/support/constraint/solver/LinearSystem;->addLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    goto :goto_109

    .line 2692
    :cond_105
    const/4 v2, 0x6

    invoke-virtual {v10, v6, v7, v1, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2743
    :cond_109
    :goto_109
    move/from16 v17, p17

    move v13, v1

    move/from16 v32, v3

    move-object/from16 v35, v5

    move-object v9, v6

    move-object/from16 v33, v18

    move/from16 v0, v27

    const/4 v6, 0x6

    move/from16 v18, p18

    goto/16 :goto_210

    .line 2695
    :cond_11a
    const/4 v2, -0x2

    move/from16 v4, p17

    if-ne v4, v2, :cond_120

    .line 2696
    move v4, v1

    .line 2698
    .end local p17    # "matchMinDimension":I
    .local v4, "matchMinDimension":I
    :cond_120
    move-object/from16 v28, v5

    move/from16 v5, p18

    if-ne v5, v2, :cond_128

    .line 2699
    .end local v5    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v28, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    move v2, v1

    .line 2702
    .end local p18    # "matchMaxDimension":I
    .local v2, "matchMaxDimension":I
    move v5, v2

    .line 2702
    .end local v2    # "matchMaxDimension":I
    .local v5, "matchMaxDimension":I
    :cond_128
    if-lez v4, :cond_133

    .line 2703
    const/4 v2, 0x6

    invoke-virtual {v10, v6, v7, v4, v2}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2704
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    move-result v1

    goto :goto_134

    .line 2706
    :cond_133
    const/4 v2, 0x6

    :goto_134
    if-lez v5, :cond_13d

    .line 2707
    invoke-virtual {v10, v6, v7, v5, v2}, Landroid/support/constraint/solver/LinearSystem;->addLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2708
    invoke-static {v1, v5}, Ljava/lang/Math;->min(II)I

    move-result v1

    .line 2710
    :cond_13d
    const/4 v2, 0x1

    if-ne v3, v2, :cond_162

    .line 2711
    if-eqz p2, :cond_155

    .line 2712
    const/4 v2, 0x6

    invoke-virtual {v10, v6, v7, v1, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2733
    .end local v1    # "dimension":I
    .end local v3    # "matchConstraintDefault":I
    .end local v4    # "matchMinDimension":I
    .end local v5    # "matchMaxDimension":I
    .end local v6    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v27    # "numConnections":I
    .end local v28    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "numConnections":I
    .local v8, "dimension":I
    .local v9, "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "matchMaxDimension":I
    .local v32, "matchConstraintDefault":I
    .local v33, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v34, "matchMinDimension":I
    .local v35, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :goto_146
    move v8, v1

    move/from16 v32, v3

    move/from16 v34, v4

    move v13, v5

    move-object v9, v6

    move-object/from16 v33, v18

    move/from16 v0, v27

    move-object/from16 v35, v28

    goto/16 :goto_1ee

    .line 2713
    .end local v0    # "numConnections":I
    .end local v8    # "dimension":I
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v13    # "matchMaxDimension":I
    .end local v32    # "matchConstraintDefault":I
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v34    # "matchMinDimension":I
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v1    # "dimension":I
    .restart local v3    # "matchConstraintDefault":I
    .restart local v4    # "matchMinDimension":I
    .restart local v5    # "matchMaxDimension":I
    .restart local v6    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v27    # "numConnections":I
    .restart local v28    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_155
    const/4 v2, 0x6

    if-eqz p15, :cond_15d

    .line 2714
    const/4 v2, 0x4

    invoke-virtual {v10, v6, v7, v1, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    goto :goto_146

    .line 2716
    :cond_15d
    const/4 v2, 0x1

    invoke-virtual {v10, v6, v7, v1, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    goto :goto_146

    .line 2718
    :cond_162
    const/4 v2, 0x2

    if-ne v3, v2, :cond_1e1

    .line 2719
    const/16 v17, 0x0

    .line 2720
    .local v17, "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    const/16 v19, 0x0

    .line 2721
    .local v19, "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v2

    move/from16 v29, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 2721
    .end local v1    # "dimension":I
    .local v29, "dimension":I
    if-eq v2, v1, :cond_199

    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v1, v2, :cond_17c

    goto :goto_199

    .line 2726
    :cond_17c
    iget-object v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 2727
    .end local v17    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .local v1, "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-object/from16 v30, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 2727
    .end local v1    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .local v30, "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 2729
    .end local v19    # "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    .local v1, "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v17, v1

    goto :goto_1b7

    .line 2723
    .end local v1    # "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    .end local v30    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v17    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v19    # "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    :cond_199
    :goto_199
    iget-object v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 2724
    .end local v17    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .local v1, "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    iget-object v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-object/from16 v31, v1

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 2724
    .end local v1    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .local v31, "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v2, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 2729
    .end local v19    # "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    .local v1, "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v17, v1

    move-object/from16 v30, v31

    .line 2729
    .end local v1    # "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    .end local v31    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    .local v17, "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    .restart local v30    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    :goto_1b7
    invoke-virtual/range {p1 .. p1}, Landroid/support/constraint/solver/LinearSystem;->createRow()Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    move/from16 v2, v29

    .line 2729
    .end local v29    # "dimension":I
    .local v2, "dimension":I
    move v8, v2

    const/4 v0, 0x2

    const/16 v19, 0x6

    const/16 v22, 0x0

    move-object v2, v6

    .line 2729
    .end local v2    # "dimension":I
    .restart local v8    # "dimension":I
    move/from16 v32, v3

    move-object v3, v7

    .line 2729
    .end local v3    # "matchConstraintDefault":I
    .restart local v32    # "matchConstraintDefault":I
    move/from16 v34, v4

    move-object/from16 v33, v18

    move/from16 v0, v27

    move-object/from16 v4, v17

    .line 2729
    .end local v4    # "matchMinDimension":I
    .end local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v27    # "numConnections":I
    .restart local v0    # "numConnections":I
    .restart local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v34    # "matchMinDimension":I
    move v13, v5

    move-object/from16 v35, v28

    move-object/from16 v5, v30

    .line 2729
    .end local v5    # "matchMaxDimension":I
    .end local v28    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v13    # "matchMaxDimension":I
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    move-object v9, v6

    move/from16 v6, p19

    .line 2729
    .end local v6    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual/range {v1 .. v6}, Landroid/support/constraint/solver/ArrayRow;->createRowDimensionRatio(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;F)Landroid/support/constraint/solver/ArrayRow;

    move-result-object v1

    invoke-virtual {v10, v1}, Landroid/support/constraint/solver/LinearSystem;->addConstraint(Landroid/support/constraint/solver/ArrayRow;)V

    .line 2730
    const/16 v25, 0x0

    .line 2730
    .end local v17    # "percentEnd":Landroid/support/constraint/solver/SolverVariable;
    .end local v30    # "percentBegin":Landroid/support/constraint/solver/SolverVariable;
    goto :goto_1ee

    .line 2733
    .end local v0    # "numConnections":I
    .end local v8    # "dimension":I
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v13    # "matchMaxDimension":I
    .end local v32    # "matchConstraintDefault":I
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v34    # "matchMinDimension":I
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v1, "dimension":I
    .restart local v3    # "matchConstraintDefault":I
    .restart local v4    # "matchMinDimension":I
    .restart local v5    # "matchMaxDimension":I
    .restart local v6    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v27    # "numConnections":I
    .restart local v28    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_1e1
    move v8, v1

    move/from16 v32, v3

    move/from16 v34, v4

    move v13, v5

    move-object v9, v6

    move-object/from16 v33, v18

    move/from16 v0, v27

    move-object/from16 v35, v28

    .line 2733
    .end local v1    # "dimension":I
    .end local v3    # "matchConstraintDefault":I
    .end local v4    # "matchMinDimension":I
    .end local v5    # "matchMaxDimension":I
    .end local v6    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v18    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v27    # "numConnections":I
    .end local v28    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v0    # "numConnections":I
    .restart local v8    # "dimension":I
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v13    # "matchMaxDimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v34    # "matchMinDimension":I
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :goto_1ee
    if-eqz v25, :cond_208

    const/4 v1, 0x2

    if-eq v0, v1, :cond_208

    if-nez p14, :cond_208

    .line 2734
    const/16 v25, 0x0

    .line 2735
    move/from16 v4, v34

    invoke-static {v4, v8}, Ljava/lang/Math;->max(II)I

    move-result v1

    .line 2736
    .end local v34    # "matchMinDimension":I
    .local v1, "d":I
    .restart local v4    # "matchMinDimension":I
    if-lez v13, :cond_203

    .line 2737
    invoke-static {v13, v1}, Ljava/lang/Math;->min(II)I

    move-result v1

    .line 2739
    :cond_203
    const/4 v6, 0x6

    invoke-virtual {v10, v9, v7, v1, v6}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2739
    .end local v1    # "d":I
    goto :goto_20b

    .line 2743
    .end local v4    # "matchMinDimension":I
    .restart local v34    # "matchMinDimension":I
    :cond_208
    move/from16 v4, v34

    const/4 v6, 0x6

    .line 2743
    .end local v8    # "dimension":I
    .end local v34    # "matchMinDimension":I
    .local v13, "dimension":I
    .local v17, "matchMinDimension":I
    .local v18, "matchMaxDimension":I
    :goto_20b
    move/from16 v17, v4

    move/from16 v18, v13

    move v13, v8

    :goto_210
    if-eqz p20, :cond_3dd

    if-eqz p15, :cond_227

    .line 2749
    move/from16 v37, v0

    move v4, v6

    move-object v5, v9

    move-object v2, v12

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v6, v33

    move-object/from16 v0, v35

    move-object/from16 v1, p7

    const/4 v3, 0x0

    move-object v13, v7

    goto/16 :goto_3ee

    .line 2758
    :cond_227
    const/4 v1, 0x5

    if-nez v15, :cond_247

    if-nez v16, :cond_247

    if-nez v20, :cond_247

    .line 2760
    if-eqz p2, :cond_235

    .line 2761
    const/4 v8, 0x0

    invoke-virtual {v10, v12, v9, v8, v1}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    goto :goto_251

    .line 2854
    :cond_235
    move/from16 v37, v0

    move v4, v6

    move-object v5, v9

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v6, v33

    move-object/from16 v0, v35

    move-object/from16 v1, p7

    const/4 v12, 0x0

    .line 2854
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v32    # "matchConstraintDefault":I
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "end":Landroid/support/constraint/solver/SolverVariable;
    .local v6, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "begin":Landroid/support/constraint/solver/SolverVariable;
    .local v36, "dimension":I
    .local v37, "numConnections":I
    .local v38, "matchConstraintDefault":I
    :goto_244
    move-object v13, v7

    goto/16 :goto_3d1

    .line 2763
    .end local v5    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v36    # "dimension":I
    .end local v37    # "numConnections":I
    .end local v38    # "matchConstraintDefault":I
    .local v0, "numConnections":I
    .restart local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "dimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_247
    const/4 v8, 0x0

    if-eqz v15, :cond_261

    if-nez v16, :cond_261

    .line 2765
    if-eqz p2, :cond_251

    .line 2766
    invoke-virtual {v10, v12, v9, v8, v1}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2854
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v32    # "matchConstraintDefault":I
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v5    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v36    # "dimension":I
    .restart local v37    # "numConnections":I
    .restart local v38    # "matchConstraintDefault":I
    :cond_251
    :goto_251
    move/from16 v37, v0

    move v4, v6

    move v12, v8

    move-object v5, v9

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v6, v33

    move-object/from16 v0, v35

    move-object/from16 v1, p7

    goto :goto_244

    .line 2768
    .end local v5    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v36    # "dimension":I
    .end local v37    # "numConnections":I
    .end local v38    # "matchConstraintDefault":I
    .local v0, "numConnections":I
    .restart local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "dimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_261
    if-nez v15, :cond_285

    if-eqz v16, :cond_285

    .line 2769
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v2

    neg-int v2, v2

    move-object/from16 v5, v33

    invoke-virtual {v10, v9, v5, v2, v6}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2770
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    if-eqz p2, :cond_274

    .line 2771
    invoke-virtual {v10, v7, v11, v8, v1}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2854
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v32    # "matchConstraintDefault":I
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v36    # "dimension":I
    .restart local v37    # "numConnections":I
    .restart local v38    # "matchConstraintDefault":I
    :cond_274
    move/from16 v37, v0

    move v4, v6

    move v12, v8

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v0, v35

    move-object/from16 v1, p7

    move-object v6, v5

    move-object v13, v7

    move-object v5, v9

    goto/16 :goto_3d1

    .line 2773
    .end local v5    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v36    # "dimension":I
    .end local v37    # "numConnections":I
    .end local v38    # "matchConstraintDefault":I
    .local v0, "numConnections":I
    .restart local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "dimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_285
    move-object/from16 v5, v33

    .line 2773
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    if-eqz v15, :cond_3c2

    if-eqz v16, :cond_3c2

    .line 2777
    const/4 v1, 0x0

    .line 2778
    .local v1, "applyBoundsCheck":Z
    const/4 v2, 0x0

    .line 2779
    .local v2, "applyCentering":Z
    const/4 v3, 0x5

    .line 2781
    .local v3, "centeringStrength":I
    if-eqz v25, :cond_328

    .line 2783
    if-eqz p2, :cond_29b

    move-object v4, v9

    move/from16 v9, p11

    if-nez v9, :cond_29e

    .line 2784
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v4, "end":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v10, v4, v7, v8, v6}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    goto :goto_29e

    .line 2787
    .end local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    :cond_29b
    move-object v4, v9

    move/from16 v9, p11

    .line 2787
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    :cond_29e
    :goto_29e
    move/from16 v36, v13

    move/from16 v13, v32

    if-nez v13, :cond_2db

    .line 2788
    .end local v32    # "matchConstraintDefault":I
    .local v13, "matchConstraintDefault":I
    .restart local v36    # "dimension":I
    const/16 v19, 0x6

    .line 2789
    .local v19, "strength":I
    if-gtz v18, :cond_2b2

    if-lez v17, :cond_2ab

    goto :goto_2b2

    .line 2793
    .local v1, "strength":I
    .local v19, "applyBoundsCheck":Z
    :cond_2ab
    :goto_2ab
    move/from16 v42, v19

    move/from16 v19, v1

    move/from16 v1, v42

    goto :goto_2b6

    .line 2790
    .local v1, "applyBoundsCheck":Z
    .local v19, "strength":I
    :cond_2b2
    :goto_2b2
    const/16 v19, 0x4

    .line 2791
    const/4 v1, 0x1

    goto :goto_2ab

    .line 2793
    .local v1, "strength":I
    .local v19, "applyBoundsCheck":Z
    :goto_2b6
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    move/from16 v37, v0

    move-object/from16 v0, v35

    invoke-virtual {v10, v7, v0, v6, v1}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2794
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v37    # "numConnections":I
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    neg-int v6, v6

    invoke-virtual {v10, v4, v5, v6, v1}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2795
    if-gtz v18, :cond_2cd

    if-lez v17, :cond_2cf

    .line 2796
    :cond_2cd
    const/4 v1, 0x1

    .line 2798
    .end local v2    # "applyCentering":Z
    .local v1, "applyCentering":Z
    move v2, v1

    .line 2819
    .end local v1    # "applyCentering":Z
    .restart local v2    # "applyCentering":Z
    :cond_2cf
    move/from16 v22, v3

    move/from16 v38, v13

    move/from16 v39, v19

    move-object/from16 v13, p0

    move/from16 v19, v2

    goto/16 :goto_33c

    .line 2798
    .end local v19    # "applyBoundsCheck":Z
    .end local v37    # "numConnections":I
    .local v0, "numConnections":I
    .local v1, "applyBoundsCheck":Z
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_2db
    move/from16 v37, v0

    move-object/from16 v0, v35

    .line 2798
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v37    # "numConnections":I
    const/4 v6, 0x1

    if-ne v13, v6, :cond_2f0

    .line 2799
    const/4 v2, 0x1

    .line 2800
    const/4 v1, 0x1

    .line 2801
    const/4 v3, 0x6

    .line 2819
    move/from16 v39, v1

    move/from16 v19, v2

    move/from16 v22, v3

    move/from16 v38, v13

    move-object/from16 v13, p0

    goto :goto_33c

    .line 2802
    :cond_2f0
    const/4 v6, 0x3

    if-ne v13, v6, :cond_31d

    .line 2803
    const/4 v2, 0x1

    .line 2804
    const/4 v1, 0x1

    .line 2805
    const/4 v6, 0x4

    .line 2806
    .local v6, "strength":I
    if-nez p14, :cond_307

    move/from16 v38, v13

    move-object/from16 v13, p0

    iget v8, v13, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2806
    .end local v13    # "matchConstraintDefault":I
    .restart local v38    # "matchConstraintDefault":I
    move/from16 v39, v1

    const/4 v1, -0x1

    .line 2806
    .end local v1    # "applyBoundsCheck":Z
    .local v39, "applyBoundsCheck":Z
    if-eq v8, v1, :cond_30d

    if-gtz v18, :cond_30d

    .line 2809
    const/4 v6, 0x6

    goto :goto_30d

    .line 2811
    .end local v38    # "matchConstraintDefault":I
    .end local v39    # "applyBoundsCheck":Z
    .restart local v1    # "applyBoundsCheck":Z
    .restart local v13    # "matchConstraintDefault":I
    :cond_307
    move/from16 v39, v1

    move/from16 v38, v13

    move-object/from16 v13, p0

    .line 2811
    .end local v1    # "applyBoundsCheck":Z
    .end local v13    # "matchConstraintDefault":I
    .restart local v38    # "matchConstraintDefault":I
    .restart local v39    # "applyBoundsCheck":Z
    :cond_30d
    :goto_30d
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v1

    invoke-virtual {v10, v7, v0, v1, v6}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2812
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v1

    neg-int v1, v1

    invoke-virtual {v10, v4, v5, v1, v6}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2813
    .end local v6    # "strength":I
    goto :goto_338

    .line 2819
    .end local v38    # "matchConstraintDefault":I
    .end local v39    # "applyBoundsCheck":Z
    .restart local v1    # "applyBoundsCheck":Z
    .restart local v13    # "matchConstraintDefault":I
    :cond_31d
    move/from16 v38, v13

    move-object/from16 v13, p0

    move/from16 v39, v1

    move/from16 v19, v2

    move/from16 v22, v3

    .line 2819
    .end local v13    # "matchConstraintDefault":I
    .restart local v38    # "matchConstraintDefault":I
    goto :goto_33c

    .line 2816
    .end local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v36    # "dimension":I
    .end local v37    # "numConnections":I
    .end local v38    # "matchConstraintDefault":I
    .local v0, "numConnections":I
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "dimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_328
    move/from16 v37, v0

    move-object v4, v9

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v0, v35

    move/from16 v9, p11

    move-object/from16 v13, p0

    .line 2816
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v13    # "dimension":I
    .end local v32    # "matchConstraintDefault":I
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v36    # "dimension":I
    .restart local v37    # "numConnections":I
    .restart local v38    # "matchConstraintDefault":I
    const/4 v2, 0x1

    .line 2819
    move/from16 v39, v1

    .line 2819
    .end local v1    # "applyBoundsCheck":Z
    .end local v2    # "applyCentering":Z
    .end local v3    # "centeringStrength":I
    .local v19, "applyCentering":Z
    .local v22, "centeringStrength":I
    .restart local v39    # "applyBoundsCheck":Z
    :goto_338
    move/from16 v19, v2

    move/from16 v22, v3

    :goto_33c
    const/16 v23, 0x5

    .line 2820
    .local v23, "startStrength":I
    const/16 v24, 0x5

    .line 2821
    .local v24, "endStrength":I
    move/from16 v26, p2

    .line 2822
    .local v26, "applyStartConstraint":Z
    move/from16 v27, p2

    .line 2823
    .local v27, "applyEndConstraint":Z
    if-eqz v19, :cond_383

    .line 2824
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v6

    .line 2825
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v8

    .line 2824
    move-object v1, v10

    move-object v2, v7

    move-object v3, v0

    move-object/from16 v40, v4

    move v4, v6

    .line 2824
    .end local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v40, "end":Landroid/support/constraint/solver/SolverVariable;
    move-object v6, v5

    move/from16 v5, p13

    .line 2824
    .end local v5    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v6, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v41, v6

    const/4 v13, 0x6

    .line 2824
    .end local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v41, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    move-object v13, v7

    move-object/from16 v7, v40

    .line 2824
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "begin":Landroid/support/constraint/solver/SolverVariable;
    const/4 v12, 0x0

    move/from16 v9, v22

    invoke-virtual/range {v1 .. v9}, Landroid/support/constraint/solver/LinearSystem;->addCentering(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;IFLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2826
    move-object/from16 v1, p7

    iget-object v2, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    instance-of v2, v2, Landroid/support/constraint/solver/widgets/Barrier;

    .line 2827
    .local v2, "isBeginAnchorBarrier":Z
    iget-object v3, v14, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v3, v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    instance-of v3, v3, Landroid/support/constraint/solver/widgets/Barrier;

    .line 2829
    .local v3, "isEndAnchorBarrier":Z
    if-eqz v2, :cond_37a

    if-nez v3, :cond_37a

    .line 2830
    const/16 v24, 0x6

    .line 2831
    const/16 v27, 0x1

    goto :goto_38b

    .line 2832
    :cond_37a
    if-nez v2, :cond_38b

    if-eqz v3, :cond_38b

    .line 2833
    const/16 v23, 0x6

    .line 2834
    const/16 v26, 0x1

    .line 2834
    .end local v2    # "isBeginAnchorBarrier":Z
    .end local v3    # "isEndAnchorBarrier":Z
    goto :goto_38b

    .line 2837
    .end local v13    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .end local v40    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v41    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v5    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    :cond_383
    move-object/from16 v1, p7

    move-object/from16 v40, v4

    move-object/from16 v41, v5

    move-object v13, v7

    const/4 v12, 0x0

    .line 2837
    .end local v4    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v5    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v13    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v40    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v41    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_38b
    :goto_38b
    if-eqz v39, :cond_391

    .line 2838
    const/16 v23, 0x6

    .line 2839
    const/16 v24, 0x6

    .line 2842
    .end local v23    # "startStrength":I
    .end local v24    # "endStrength":I
    .local v2, "startStrength":I
    .local v3, "endStrength":I
    :cond_391
    move/from16 v2, v23

    move/from16 v3, v24

    if-nez v25, :cond_399

    if-nez v26, :cond_39b

    :cond_399
    if-eqz v39, :cond_3a2

    .line 2843
    :cond_39b
    invoke-virtual/range {p7 .. p7}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v4

    invoke-virtual {v10, v13, v0, v4, v2}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2845
    :cond_3a2
    if-nez v25, :cond_3a6

    if-nez v27, :cond_3a8

    :cond_3a6
    if-eqz v39, :cond_3b5

    .line 2846
    :cond_3a8
    invoke-virtual/range {p8 .. p8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v4

    neg-int v4, v4

    move-object/from16 v5, v40

    move-object/from16 v6, v41

    invoke-virtual {v10, v5, v6, v4, v3}, Landroid/support/constraint/solver/LinearSystem;->addLowerThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    goto :goto_3b9

    .line 2849
    :cond_3b5
    move-object/from16 v5, v40

    move-object/from16 v6, v41

    .line 2849
    .end local v40    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v41    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    :goto_3b9
    if-eqz p2, :cond_3c0

    .line 2850
    const/4 v4, 0x6

    invoke-virtual {v10, v13, v11, v12, v4}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2850
    .end local v2    # "startStrength":I
    .end local v3    # "endStrength":I
    .end local v19    # "applyCentering":Z
    .end local v22    # "centeringStrength":I
    .end local v26    # "applyStartConstraint":Z
    .end local v27    # "applyEndConstraint":Z
    .end local v39    # "applyBoundsCheck":Z
    goto :goto_3d1

    .line 2854
    :cond_3c0
    const/4 v4, 0x6

    goto :goto_3d1

    .line 2854
    .end local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v36    # "dimension":I
    .end local v37    # "numConnections":I
    .end local v38    # "matchConstraintDefault":I
    .local v0, "numConnections":I
    .local v5, "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "dimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_3c2
    move/from16 v37, v0

    move v4, v6

    move v12, v8

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v0, v35

    move-object/from16 v1, p7

    move-object v6, v5

    move-object v13, v7

    move-object v5, v9

    .line 2854
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v32    # "matchConstraintDefault":I
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v5, "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v36    # "dimension":I
    .restart local v37    # "numConnections":I
    .restart local v38    # "matchConstraintDefault":I
    :goto_3d1
    if-eqz p2, :cond_3da

    .line 2855
    move v3, v12

    move-object/from16 v2, p4

    invoke-virtual {v10, v2, v5, v3, v4}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    goto :goto_3dc

    .line 2857
    :cond_3da
    move-object/from16 v2, p4

    :goto_3dc
    return-void

    .line 2749
    .end local v5    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v36    # "dimension":I
    .end local v37    # "numConnections":I
    .end local v38    # "matchConstraintDefault":I
    .local v0, "numConnections":I
    .restart local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "dimension":I
    .restart local v32    # "matchConstraintDefault":I
    .restart local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    :cond_3dd
    move/from16 v37, v0

    move v4, v6

    move-object v5, v9

    move-object v2, v12

    move/from16 v36, v13

    move/from16 v38, v32

    move-object/from16 v6, v33

    move-object/from16 v0, v35

    move-object/from16 v1, p7

    const/4 v3, 0x0

    move-object v13, v7

    .line 2749
    .end local v7    # "begin":Landroid/support/constraint/solver/SolverVariable;
    .end local v9    # "end":Landroid/support/constraint/solver/SolverVariable;
    .end local v32    # "matchConstraintDefault":I
    .end local v33    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .end local v35    # "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v0, "beginTarget":Landroid/support/constraint/solver/SolverVariable;
    .restart local v5    # "end":Landroid/support/constraint/solver/SolverVariable;
    .restart local v6    # "endTarget":Landroid/support/constraint/solver/SolverVariable;
    .local v13, "begin":Landroid/support/constraint/solver/SolverVariable;
    .restart local v36    # "dimension":I
    .restart local v37    # "numConnections":I
    .restart local v38    # "matchConstraintDefault":I
    :goto_3ee
    move/from16 v7, v37

    const/4 v8, 0x2

    if-ge v7, v8, :cond_3fb

    .line 2749
    .end local v37    # "numConnections":I
    .local v7, "numConnections":I
    if-eqz p2, :cond_3fb

    .line 2750
    invoke-virtual {v10, v13, v11, v3, v4}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2751
    invoke-virtual {v10, v2, v5, v3, v4}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2753
    :cond_3fb
    return-void

    :pswitch_data_3fc
    .packed-switch 0x1
        :pswitch_b7
        :pswitch_b5
        :pswitch_b3
        :pswitch_ae
    .end packed-switch
.end method

.method private isChainHead(I)Z
    .registers 6
    .param p1, "orientation"    # I

    .line 2313
    mul-int/lit8 v0, p1, 0x2

    .line 2314
    .local v0, "offset":I
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v1, v1, v0

    iget-object v1, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v1, :cond_36

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v1, v1, v0

    iget-object v1, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v1, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v2, v2, v0

    if-eq v1, v2, :cond_36

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v2, v0, 0x1

    aget-object v1, v1, v2

    iget-object v1, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v1, :cond_36

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v2, v0, 0x1

    aget-object v1, v1, v2

    iget-object v1, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v1, v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    add-int/lit8 v3, v0, 0x1

    aget-object v2, v2, v3

    if-ne v1, v2, :cond_36

    const/4 v1, 0x1

    goto :goto_37

    :cond_36
    const/4 v1, 0x0

    :goto_37
    return v1
.end method


# virtual methods
.method public addToSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 59
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    move-object/from16 v15, p0

    .line 2337
    move-object/from16 v13, p1

    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v36

    .line 2338
    .local v36, "left":Landroid/support/constraint/solver/SolverVariable;
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v12

    .line 2339
    .local v12, "right":Landroid/support/constraint/solver/SolverVariable;
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v11

    .line 2340
    .local v11, "top":Landroid/support/constraint/solver/SolverVariable;
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v10

    .line 2341
    .local v10, "bottom":Landroid/support/constraint/solver/SolverVariable;
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v9

    .line 2343
    .local v9, "baseline":Landroid/support/constraint/solver/SolverVariable;
    const/4 v0, 0x0

    .line 2344
    .local v0, "inHorizontalChain":Z
    const/4 v1, 0x0

    .line 2345
    .local v1, "inVerticalChain":Z
    const/4 v2, 0x0

    .line 2346
    .local v2, "horizontalParentWrapContent":Z
    const/4 v3, 0x0

    .line 2348
    .local v3, "verticalParentWrapContent":Z
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    const/16 v5, 0x8

    const/4 v8, 0x0

    const/4 v7, 0x1

    if-eqz v4, :cond_b6

    .line 2349
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v4, :cond_3e

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v4, v4, v8

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v4, v6, :cond_3e

    move v4, v7

    goto :goto_3f

    :cond_3e
    move v4, v8

    :goto_3f
    move v2, v4

    .line 2350
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v4, :cond_50

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v4, v4, v7

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v4, v6, :cond_50

    move v4, v7

    goto :goto_51

    :cond_50
    move v4, v8

    :goto_51
    move v3, v4

    .line 2353
    invoke-direct {v15, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isChainHead(I)Z

    move-result v4

    if-eqz v4, :cond_61

    .line 2354
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    check-cast v4, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    invoke-virtual {v4, v15, v8}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)V

    .line 2355
    const/4 v0, 0x1

    goto :goto_65

    .line 2357
    :cond_61
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isInHorizontalChain()Z

    move-result v0

    .line 2361
    :goto_65
    invoke-direct {v15, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isChainHead(I)Z

    move-result v4

    if-eqz v4, :cond_74

    .line 2362
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    check-cast v4, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    invoke-virtual {v4, v15, v7}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->addChain(Landroid/support/constraint/solver/widgets/ConstraintWidget;I)V

    .line 2363
    const/4 v1, 0x1

    goto :goto_78

    .line 2365
    :cond_74
    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isInVerticalChain()Z

    move-result v1

    .line 2368
    :goto_78
    if-eqz v2, :cond_95

    iget v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    if-eq v4, v5, :cond_95

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v4, :cond_95

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v4, :cond_95

    .line 2370
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 2371
    .local v4, "parentRight":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v13, v4, v12, v8, v7}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2374
    .end local v4    # "parentRight":Landroid/support/constraint/solver/SolverVariable;
    :cond_95
    if-eqz v3, :cond_b6

    iget v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    if-eq v4, v5, :cond_b6

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v4, :cond_b6

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v4, :cond_b6

    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-nez v4, :cond_b6

    .line 2376
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v4, v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 2377
    .local v4, "parentBottom":Landroid/support/constraint/solver/SolverVariable;
    invoke-virtual {v13, v4, v10, v8, v7}, Landroid/support/constraint/solver/LinearSystem;->addGreaterThan(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)V

    .line 2381
    .end local v4    # "parentBottom":Landroid/support/constraint/solver/SolverVariable;
    :cond_b6
    move/from16 v37, v0

    move/from16 v38, v1

    move v1, v3

    .line 2381
    .end local v0    # "inHorizontalChain":Z
    .end local v3    # "verticalParentWrapContent":Z
    .local v1, "verticalParentWrapContent":Z
    .local v37, "inHorizontalChain":Z
    .local v38, "inVerticalChain":Z
    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 2382
    .local v0, "width":I
    iget v3, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    if-ge v0, v3, :cond_c3

    .line 2383
    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    .line 2385
    :cond_c3
    iget v3, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 2386
    .local v3, "height":I
    iget v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    if-ge v3, v4, :cond_cb

    .line 2387
    iget v3, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    .line 2391
    :cond_cb
    iget-object v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v4, v4, v8

    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v4, v6, :cond_d5

    move v4, v7

    goto :goto_d6

    :cond_d5
    move v4, v8

    .line 2393
    .local v4, "horizontalDimensionFixed":Z
    :goto_d6
    iget-object v6, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v6, v6, v7

    sget-object v14, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v6, v14, :cond_e0

    move v6, v7

    goto :goto_e1

    :cond_e0
    move v6, v8

    .line 2398
    .local v6, "verticalDimensionFixed":Z
    :goto_e1
    const/4 v14, 0x0

    .line 2399
    .local v14, "useRatio":Z
    iget v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    iput v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2400
    iget v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    iput v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2402
    iget v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    .line 2403
    .local v7, "matchConstraintDefaultWidth":I
    iget v8, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    .line 2405
    .local v8, "matchConstraintDefaultHeight":I
    iget v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    const/16 v16, 0x0

    cmpl-float v5, v5, v16

    move-object/from16 v42, v12

    .line 2405
    .end local v12    # "right":Landroid/support/constraint/solver/SolverVariable;
    .local v42, "right":Landroid/support/constraint/solver/SolverVariable;
    if-lez v5, :cond_1a1

    iget v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    const/16 v12, 0x8

    if-eq v5, v12, :cond_1a1

    .line 2406
    const/4 v14, 0x1

    .line 2407
    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x0

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v12, :cond_10b

    if-nez v7, :cond_10b

    .line 2409
    const/4 v7, 0x3

    .line 2411
    :cond_10b
    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x1

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v12, :cond_117

    if-nez v8, :cond_117

    .line 2413
    const/4 v8, 0x3

    .line 2416
    :cond_117
    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x0

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move/from16 v44, v0

    const/4 v0, 0x3

    .line 2416
    .end local v0    # "width":I
    .local v44, "width":I
    if-ne v5, v12, :cond_135

    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x1

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v12, :cond_135

    if-ne v7, v0, :cond_135

    if-ne v8, v0, :cond_135

    .line 2420
    invoke-virtual {v15, v2, v1, v4, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setupDimensionRatio(ZZZZ)V

    goto/16 :goto_1a3

    .line 2421
    :cond_135
    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x0

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v12, :cond_167

    if-ne v7, v0, :cond_167

    .line 2423
    const/4 v0, 0x0

    iput v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2424
    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    iget v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    int-to-float v5, v5

    mul-float/2addr v0, v5

    float-to-int v0, v0

    .line 2425
    .end local v44    # "width":I
    .restart local v0    # "width":I
    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x1

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v5, v12, :cond_15c

    .line 2426
    const/4 v5, 0x4

    .line 2427
    .end local v7    # "matchConstraintDefaultWidth":I
    .local v5, "matchConstraintDefaultWidth":I
    const/4 v14, 0x0

    .line 2444
    move/from16 v46, v0

    move/from16 v47, v3

    move/from16 v41, v5

    goto :goto_162

    .line 2444
    .end local v5    # "matchConstraintDefaultWidth":I
    .restart local v7    # "matchConstraintDefaultWidth":I
    :cond_15c
    move/from16 v46, v0

    move/from16 v47, v3

    move/from16 v41, v7

    .line 2444
    .end local v0    # "width":I
    .end local v3    # "height":I
    .end local v7    # "matchConstraintDefaultWidth":I
    .end local v8    # "matchConstraintDefaultHeight":I
    .end local v14    # "useRatio":Z
    .local v41, "matchConstraintDefaultWidth":I
    .local v44, "matchConstraintDefaultHeight":I
    .local v45, "useRatio":Z
    .local v46, "width":I
    .local v47, "height":I
    :goto_162
    move/from16 v44, v8

    move/from16 v45, v14

    goto :goto_1ad

    .line 2429
    .end local v41    # "matchConstraintDefaultWidth":I
    .end local v45    # "useRatio":Z
    .end local v46    # "width":I
    .end local v47    # "height":I
    .restart local v3    # "height":I
    .restart local v7    # "matchConstraintDefaultWidth":I
    .restart local v8    # "matchConstraintDefaultHeight":I
    .restart local v14    # "useRatio":Z
    .local v44, "width":I
    :cond_167
    iget-object v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v12, 0x1

    aget-object v5, v5, v12

    sget-object v12, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v5, v12, :cond_1a3

    if-ne v8, v0, :cond_1a3

    .line 2431
    const/4 v0, 0x1

    iput v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2432
    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    const/4 v5, -0x1

    if-ne v0, v5, :cond_181

    .line 2434
    const/high16 v0, 0x3f800000    # 1.0f

    iget v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    div-float/2addr v0, v5

    iput v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2436
    :cond_181
    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    iget v5, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    int-to-float v5, v5

    mul-float/2addr v0, v5

    float-to-int v0, v0

    .line 2437
    .end local v3    # "height":I
    .local v0, "height":I
    iget-object v3, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v5, 0x0

    aget-object v3, v3, v5

    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-eq v3, v5, :cond_19e

    .line 2438
    const/4 v3, 0x4

    .line 2439
    .end local v8    # "matchConstraintDefaultHeight":I
    .local v3, "matchConstraintDefaultHeight":I
    const/4 v14, 0x0

    .line 2444
    move/from16 v47, v0

    move/from16 v41, v7

    move/from16 v45, v14

    move/from16 v46, v44

    move/from16 v44, v3

    goto :goto_1ad

    .line 2444
    .end local v3    # "matchConstraintDefaultHeight":I
    .restart local v8    # "matchConstraintDefaultHeight":I
    :cond_19e
    move/from16 v47, v0

    goto :goto_1a5

    .line 2444
    .end local v44    # "width":I
    .local v0, "width":I
    .local v3, "height":I
    :cond_1a1
    move/from16 v44, v0

    .line 2444
    .end local v0    # "width":I
    .restart local v44    # "width":I
    :cond_1a3
    :goto_1a3
    move/from16 v47, v3

    .line 2444
    .end local v3    # "height":I
    .end local v7    # "matchConstraintDefaultWidth":I
    .end local v8    # "matchConstraintDefaultHeight":I
    .end local v14    # "useRatio":Z
    .restart local v41    # "matchConstraintDefaultWidth":I
    .local v44, "matchConstraintDefaultHeight":I
    .restart local v45    # "useRatio":Z
    .restart local v46    # "width":I
    .restart local v47    # "height":I
    :goto_1a5
    move/from16 v41, v7

    move/from16 v45, v14

    move/from16 v46, v44

    move/from16 v44, v8

    :goto_1ad
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    const/4 v3, 0x0

    aput v41, v0, v3

    .line 2445
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedMatchConstraintDefault:[I

    const/4 v7, 0x1

    aput v44, v0, v7

    .line 2447
    if-eqz v45, :cond_1c6

    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-eqz v0, :cond_1c3

    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    const/4 v12, -0x1

    if-ne v0, v12, :cond_1c7

    goto :goto_1c4

    :cond_1c3
    const/4 v12, -0x1

    :goto_1c4
    move v14, v7

    goto :goto_1c8

    :cond_1c6
    const/4 v12, -0x1

    :cond_1c7
    const/4 v14, 0x0

    .line 2451
    .local v14, "useHorizontalRatio":Z
    :goto_1c8
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v3, 0x0

    aget-object v0, v0, v3

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v3, :cond_1d7

    instance-of v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v0, :cond_1d7

    move v0, v7

    goto :goto_1d8

    :cond_1d7
    const/4 v0, 0x0

    :goto_1d8
    move/from16 v39, v6

    move v6, v0

    .line 2454
    .local v6, "wrapContent":Z
    .local v39, "verticalDimensionFixed":Z
    const/4 v0, 0x1

    .line 2455
    .local v0, "applyPosition":Z
    iget-object v3, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v3

    if-eqz v3, :cond_1e5

    .line 2456
    const/4 v0, 0x0

    .line 2459
    .end local v0    # "applyPosition":Z
    .local v22, "applyPosition":Z
    :cond_1e5
    move/from16 v22, v0

    iget v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalResolution:I

    const/4 v8, 0x2

    const/16 v23, 0x0

    if-eq v0, v8, :cond_265

    .line 2460
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v0, :cond_1fb

    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    goto :goto_1fd

    :cond_1fb
    move-object/from16 v0, v23

    :goto_1fd
    move/from16 v43, v4

    move-object v4, v0

    .line 2461
    .local v4, "parentMax":Landroid/support/constraint/solver/SolverVariable;
    .local v43, "horizontalDimensionFixed":Z
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v0, :cond_20e

    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v13, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    move-object v3, v0

    goto :goto_210

    :cond_20e
    move-object/from16 v3, v23

    .line 2462
    .local v3, "parentMin":Landroid/support/constraint/solver/SolverVariable;
    :goto_210
    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/16 v16, 0x0

    aget-object v5, v0, v16

    iget-object v0, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v8, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget v12, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    move-object/from16 v49, v11

    iget v11, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    .line 2462
    .end local v11    # "top":Landroid/support/constraint/solver/SolverVariable;
    .local v49, "top":Landroid/support/constraint/solver/SolverVariable;
    iget-object v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    aget v17, v7, v16

    iget v7, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    move-object/from16 v50, v3

    iget v3, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    .line 2462
    .end local v3    # "parentMin":Landroid/support/constraint/solver/SolverVariable;
    .local v50, "parentMin":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v51, v4

    iget v4, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    .line 2462
    .end local v4    # "parentMax":Landroid/support/constraint/solver/SolverVariable;
    .local v51, "parentMax":Landroid/support/constraint/solver/SolverVariable;
    move/from16 v52, v6

    iget v6, v15, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentWidth:F

    .line 2462
    .end local v6    # "wrapContent":Z
    .local v52, "wrapContent":Z
    move-object/from16 v18, v0

    move-object v0, v15

    move/from16 v40, v1

    move-object v1, v13

    .line 2462
    .end local v1    # "verticalParentWrapContent":Z
    .local v40, "verticalParentWrapContent":Z
    move/from16 v53, v2

    .line 2462
    .end local v2    # "horizontalParentWrapContent":Z
    .local v53, "horizontalParentWrapContent":Z
    move/from16 v19, v7

    move-object/from16 v7, v18

    move/from16 v24, v16

    move-object/from16 v54, v9

    move v9, v12

    .line 2462
    .end local v9    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .local v54, "baseline":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v48, v10

    move/from16 v10, v46

    .line 2462
    .end local v10    # "bottom":Landroid/support/constraint/solver/SolverVariable;
    .local v48, "bottom":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v12, v49

    .line 2462
    .end local v49    # "top":Landroid/support/constraint/solver/SolverVariable;
    .local v12, "top":Landroid/support/constraint/solver/SolverVariable;
    move-object/from16 v55, v12

    move/from16 v12, v17

    .line 2462
    .end local v12    # "top":Landroid/support/constraint/solver/SolverVariable;
    .local v55, "top":Landroid/support/constraint/solver/SolverVariable;
    move/from16 v13, v19

    move/from16 v15, v37

    move/from16 v16, v41

    move/from16 v17, v3

    move/from16 v18, v4

    move/from16 v19, v6

    move/from16 v20, v22

    move-object/from16 v3, v50

    move-object/from16 v4, v51

    move/from16 v6, v52

    invoke-direct/range {v0 .. v20}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->applyConstraints(Landroid/support/constraint/solver/LinearSystem;ZLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;ZLandroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;IIIIFZZIIIFZ)V

    .line 2462
    .end local v50    # "parentMin":Landroid/support/constraint/solver/SolverVariable;
    .end local v51    # "parentMax":Landroid/support/constraint/solver/SolverVariable;
    .end local v52    # "wrapContent":Z
    .restart local v6    # "wrapContent":Z
    goto :goto_273

    .line 2468
    .end local v40    # "verticalParentWrapContent":Z
    .end local v43    # "horizontalDimensionFixed":Z
    .end local v48    # "bottom":Landroid/support/constraint/solver/SolverVariable;
    .end local v53    # "horizontalParentWrapContent":Z
    .end local v54    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .end local v55    # "top":Landroid/support/constraint/solver/SolverVariable;
    .restart local v1    # "verticalParentWrapContent":Z
    .restart local v2    # "horizontalParentWrapContent":Z
    .local v4, "horizontalDimensionFixed":Z
    .restart local v9    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .restart local v10    # "bottom":Landroid/support/constraint/solver/SolverVariable;
    .restart local v11    # "top":Landroid/support/constraint/solver/SolverVariable;
    :cond_265
    move/from16 v40, v1

    move/from16 v53, v2

    move/from16 v43, v4

    move-object/from16 v54, v9

    move-object/from16 v48, v10

    move-object/from16 v55, v11

    const/16 v24, 0x0

    .line 2468
    .end local v1    # "verticalParentWrapContent":Z
    .end local v2    # "horizontalParentWrapContent":Z
    .end local v4    # "horizontalDimensionFixed":Z
    .end local v9    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .end local v10    # "bottom":Landroid/support/constraint/solver/SolverVariable;
    .end local v11    # "top":Landroid/support/constraint/solver/SolverVariable;
    .restart local v40    # "verticalParentWrapContent":Z
    .restart local v43    # "horizontalDimensionFixed":Z
    .restart local v48    # "bottom":Landroid/support/constraint/solver/SolverVariable;
    .restart local v53    # "horizontalParentWrapContent":Z
    .restart local v54    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .restart local v55    # "top":Landroid/support/constraint/solver/SolverVariable;
    :goto_273
    move-object/from16 v7, p0

    iget v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalResolution:I

    const/4 v1, 0x2

    if-ne v0, v1, :cond_27b

    .line 2475
    return-void

    .line 2478
    :cond_27b
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v2, :cond_28b

    instance-of v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v0, :cond_28b

    move/from16 v21, v1

    goto :goto_28d

    :cond_28b
    move/from16 v21, v24

    .line 2481
    .end local v6    # "wrapContent":Z
    .local v21, "wrapContent":Z
    :goto_28d
    if-eqz v45, :cond_29b

    iget v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-eq v0, v1, :cond_298

    iget v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    const/4 v2, -0x1

    if-ne v0, v2, :cond_29b

    :cond_298
    move/from16 v29, v1

    goto :goto_29d

    :cond_29b
    move/from16 v29, v24

    .line 2484
    .local v29, "useVerticalRatio":Z
    :goto_29d
    iget v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v0, :cond_2de

    .line 2485
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    iget v0, v0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-ne v0, v1, :cond_2bb

    .line 2486
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    move-object/from16 v8, p1

    invoke-virtual {v0, v8}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->addResolvedValue(Landroid/support/constraint/solver/LinearSystem;)V

    .line 2497
    move-object/from16 v10, v54

    move-object/from16 v9, v55

    goto :goto_2e4

    .line 2488
    :cond_2bb
    move-object/from16 v8, p1

    invoke-virtual/range {p0 .. p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getBaselineDistance()I

    move-result v0

    const/4 v2, 0x6

    move-object/from16 v10, v54

    move-object/from16 v9, v55

    invoke-virtual {v8, v10, v9, v0, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2489
    .end local v54    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .end local v55    # "top":Landroid/support/constraint/solver/SolverVariable;
    .local v9, "top":Landroid/support/constraint/solver/SolverVariable;
    .local v10, "baseline":Landroid/support/constraint/solver/SolverVariable;
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_2e4

    .line 2490
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v8, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 2491
    .local v0, "baselineTarget":Landroid/support/constraint/solver/SolverVariable;
    const/4 v3, 0x0

    .line 2492
    .local v3, "baselineMargin":I
    invoke-virtual {v8, v10, v0, v3, v2}, Landroid/support/constraint/solver/LinearSystem;->addEquality(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;II)Landroid/support/constraint/solver/ArrayRow;

    .line 2493
    const/4 v0, 0x0

    .line 2497
    .end local v3    # "baselineMargin":I
    .end local v22    # "applyPosition":Z
    .local v0, "applyPosition":Z
    move v11, v0

    goto :goto_2e6

    .line 2497
    .end local v0    # "applyPosition":Z
    .end local v9    # "top":Landroid/support/constraint/solver/SolverVariable;
    .end local v10    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .restart local v22    # "applyPosition":Z
    .restart local v54    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .restart local v55    # "top":Landroid/support/constraint/solver/SolverVariable;
    :cond_2de
    move-object/from16 v10, v54

    move-object/from16 v9, v55

    move-object/from16 v8, p1

    .line 2497
    .end local v54    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    .end local v55    # "top":Landroid/support/constraint/solver/SolverVariable;
    .restart local v9    # "top":Landroid/support/constraint/solver/SolverVariable;
    .restart local v10    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    :cond_2e4
    :goto_2e4
    move/from16 v11, v22

    .line 2497
    .end local v22    # "applyPosition":Z
    .local v11, "applyPosition":Z
    :goto_2e6
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v0, :cond_2f5

    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v8, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    move-object/from16 v19, v0

    goto :goto_2f7

    :cond_2f5
    move-object/from16 v19, v23

    .line 2498
    .local v19, "parentMax":Landroid/support/constraint/solver/SolverVariable;
    :goto_2f7
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v0, :cond_306

    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v8, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    move-object/from16 v18, v0

    goto :goto_308

    :cond_306
    move-object/from16 v18, v23

    .line 2499
    .local v18, "parentMin":Landroid/support/constraint/solver/SolverVariable;
    :goto_308
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v20, v0, v1

    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v2, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget v3, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    iget v4, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    iget-object v5, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    aget v27, v5, v1

    iget v5, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    iget v6, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    iget v12, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    iget v13, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentHeight:F

    move-object v15, v7

    move-object/from16 v16, v8

    move/from16 v17, v40

    move-object/from16 v22, v0

    move-object/from16 v23, v2

    move/from16 v24, v3

    move/from16 v25, v47

    move/from16 v26, v4

    move/from16 v28, v5

    move/from16 v30, v38

    move/from16 v31, v44

    move/from16 v32, v6

    move/from16 v33, v12

    move/from16 v34, v13

    move/from16 v35, v11

    invoke-direct/range {v15 .. v35}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->applyConstraints(Landroid/support/constraint/solver/LinearSystem;ZLandroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;ZLandroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;IIIIFZZIIIFZ)V

    .line 2504
    if-eqz v45, :cond_364

    .line 2505
    const/4 v12, 0x6

    .line 2506
    .local v12, "strength":I
    iget v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-ne v0, v1, :cond_356

    .line 2507
    iget v5, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    move-object v0, v8

    move-object/from16 v1, v48

    move-object v2, v9

    move-object/from16 v3, v42

    move-object/from16 v4, v36

    move v6, v12

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/LinearSystem;->addRatio(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;FI)V

    goto :goto_364

    .line 2509
    :cond_356
    iget v5, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    move-object v0, v8

    move-object/from16 v1, v42

    move-object/from16 v2, v36

    move-object/from16 v3, v48

    move-object v4, v9

    move v6, v12

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/LinearSystem;->addRatio(Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;Landroid/support/constraint/solver/SolverVariable;FI)V

    .line 2513
    .end local v12    # "strength":I
    :cond_364
    :goto_364
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_38a

    .line 2514
    iget-object v0, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    iget v1, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCircleConstraintAngle:F

    const/high16 v2, 0x42b40000    # 90.0f

    add-float/2addr v1, v2

    float-to-double v1, v1

    invoke-static {v1, v2}, Ljava/lang/Math;->toRadians(D)D

    move-result-wide v1

    double-to-float v1, v1

    iget-object v2, v7, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getMargin()I

    move-result v2

    invoke-virtual {v8, v7, v0, v1, v2}, Landroid/support/constraint/solver/LinearSystem;->addCenterPoint(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintWidget;FI)V

    .line 2522
    :cond_38a
    return-void
.end method

.method public allowedInBarrier()Z
    .registers 3

    .line 1677
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    const/16 v1, 0x8

    if-eq v0, v1, :cond_8

    const/4 v0, 0x1

    goto :goto_9

    :cond_8
    const/4 v0, 0x0

    :goto_9
    return v0
.end method

.method public analyze(I)V
    .registers 2
    .param p1, "optimizationLevel"    # I

    .line 353
    invoke-static {p1, p0}, Landroid/support/constraint/solver/widgets/Optimizer;->analyze(ILandroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 354
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V
    .registers 10
    .param p1, "constraintFrom"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p2, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p3, "constraintTo"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 1759
    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    invoke-virtual/range {v0 .. v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 1760
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;I)V
    .registers 11
    .param p1, "constraintFrom"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p2, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p3, "constraintTo"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p4, "margin"    # I

    .line 1744
    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    invoke-virtual/range {v0 .. v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V

    .line 1746
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V
    .registers 13
    .param p1, "constraintFrom"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p2, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p3, "constraintTo"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p4, "margin"    # I
    .param p5, "strength"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 1776
    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    move-object v5, p5

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1778
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V
    .registers 26
    .param p1, "constraintFrom"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p2, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p3, "constraintTo"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p4, "margin"    # I
    .param p5, "strength"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    .param p6, "creator"    # I

    move-object/from16 v7, p0

    move-object/from16 v8, p1

    move-object/from16 v9, p2

    move-object/from16 v10, p3

    .line 1794
    move/from16 v11, p6

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v0, :cond_10e

    .line 1797
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_b9

    .line 1798
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v13

    .line 1799
    .local v13, "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v14

    .line 1800
    .local v14, "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v15

    .line 1801
    .local v15, "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    .line 1802
    .local v6, "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/16 v16, 0x0

    .line 1803
    .local v16, "centerX":Z
    const/16 v17, 0x0

    .line 1804
    .local v17, "centerY":Z
    if-eqz v13, :cond_36

    invoke-virtual {v13}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-nez v0, :cond_3e

    :cond_36
    if-eqz v14, :cond_40

    .line 1805
    invoke-virtual {v14}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_40

    .line 1814
    :cond_3e
    move-object v12, v6

    goto :goto_57

    .line 1808
    :cond_40
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v4, 0x0

    move-object v0, v7

    move-object v2, v9

    move-object/from16 v5, p5

    move-object v12, v6

    move v6, v11

    .line 1808
    .end local v6    # "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .local v12, "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1810
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1812
    const/16 v16, 0x1

    .line 1814
    :goto_57
    if-eqz v15, :cond_5f

    invoke-virtual {v15}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-nez v0, :cond_7e

    :cond_5f
    if-eqz v12, :cond_68

    .line 1815
    invoke-virtual {v12}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_68

    goto :goto_7e

    .line 1818
    :cond_68
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v4, 0x0

    move-object v0, v7

    move-object v2, v9

    move-object/from16 v5, p5

    move v6, v11

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1820
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1822
    const/16 v17, 0x1

    .line 1824
    :cond_7e
    :goto_7e
    if-eqz v16, :cond_93

    if-eqz v17, :cond_93

    .line 1825
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1826
    .local v0, "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1827
    .end local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_b8

    :cond_93
    if-eqz v16, :cond_a6

    .line 1828
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1829
    .restart local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1830
    .end local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_b8

    :cond_a6
    const/4 v2, 0x0

    if-eqz v17, :cond_b8

    .line 1831
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1832
    .restart local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1834
    .end local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v12    # "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v13    # "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v14    # "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v15    # "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v16    # "centerX":Z
    .end local v17    # "centerY":Z
    :cond_b8
    :goto_b8
    goto :goto_10a

    :cond_b9
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v10, v0, :cond_ea

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_c2

    goto :goto_ea

    .line 1842
    :cond_c2
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v10, v0, :cond_ca

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_10a

    .line 1844
    :cond_ca
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v4, 0x0

    move-object v0, v7

    move-object v2, v9

    move-object v3, v10

    move-object/from16 v5, p5

    move v6, v11

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1846
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1848
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1849
    .restart local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1850
    .end local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_10a

    .line 1836
    :cond_ea
    :goto_ea
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v4, 0x0

    move-object v0, v7

    move-object v2, v9

    move-object v3, v10

    move-object/from16 v5, p5

    move v6, v11

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1838
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1840
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1841
    .restart local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1842
    .end local v0    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    nop

    .line 1963
    :cond_10a
    :goto_10a
    move-object/from16 v3, p5

    goto/16 :goto_282

    .line 1851
    :cond_10e
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v0, :cond_13b

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v10, v0, :cond_11a

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_13b

    .line 1854
    :cond_11a
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1855
    .local v0, "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 1856
    .local v1, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 1857
    .local v2, "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v3, 0x0

    invoke-virtual {v0, v1, v3, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1858
    invoke-virtual {v2, v1, v3, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1859
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 1860
    .local v4, "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v4, v1, v3, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1861
    .end local v0    # "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v1    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v2    # "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_10a

    :cond_13b
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v0, :cond_168

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v10, v0, :cond_147

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_168

    .line 1864
    :cond_147
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1865
    .local v0, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 1866
    .local v1, "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v2, 0x0

    invoke-virtual {v1, v0, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1867
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 1868
    .local v3, "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3, v0, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1869
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 1870
    .local v4, "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v4, v0, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1871
    .end local v0    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v1    # "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_10a

    :cond_168
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v0, :cond_19e

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_19e

    .line 1874
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1875
    .local v0, "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 1876
    .local v1, "leftTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1877
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 1878
    .local v3, "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 1879
    .local v4, "rightTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3, v4, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1880
    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v5

    .line 1881
    .local v5, "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v5, v6, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1882
    .end local v0    # "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v1    # "leftTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "rightTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v5    # "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto/16 :goto_10a

    :cond_19e
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v0, :cond_1d4

    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v10, v0, :cond_1d4

    .line 1885
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1886
    .local v0, "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 1887
    .local v1, "topTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1888
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 1889
    .local v3, "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v9, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 1890
    .local v4, "bottomTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3, v4, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1891
    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v5

    .line 1892
    .local v5, "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v5, v6, v2, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z

    .line 1893
    .end local v0    # "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v1    # "topTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "bottomTarget":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v5    # "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto/16 :goto_10a

    .line 1894
    :cond_1d4
    invoke-virtual/range {p0 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 1895
    .local v0, "fromAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual/range {p2 .. p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 1896
    .local v1, "toAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v0, v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isValidConnection(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z

    move-result v2

    if-eqz v2, :cond_10a

    .line 1899
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v2, :cond_1ff

    .line 1900
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 1901
    .local v2, "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 1902
    .restart local v3    # "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    if-eqz v2, :cond_1f7

    .line 1903
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1905
    :cond_1f7
    if-eqz v3, :cond_1fc

    .line 1906
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1908
    :cond_1fc
    const/4 v2, 0x0

    .line 1909
    .end local v3    # "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local p4    # "margin":I
    .local v2, "margin":I
    goto/16 :goto_271

    .line 1909
    .end local v2    # "margin":I
    .restart local p4    # "margin":I
    :cond_1ff
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v8, v2, :cond_23a

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v2, :cond_208

    goto :goto_23a

    .line 1935
    :cond_208
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v8, v2, :cond_210

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v8, v2, :cond_26f

    .line 1937
    :cond_210
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 1938
    .local v2, "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    if-eq v3, v1, :cond_21f

    .line 1939
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1941
    :cond_21f
    invoke-virtual/range {p0 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOpposite()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 1942
    .local v3, "opposite":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 1943
    .local v4, "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v5

    if-eqz v5, :cond_26f

    .line 1944
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1945
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1945
    .end local v2    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "opposite":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_26f

    .line 1911
    :cond_23a
    :goto_23a
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 1912
    .local v2, "baseline":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    if-eqz v2, :cond_245

    .line 1913
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1915
    :cond_245
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 1916
    .local v3, "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    if-eq v4, v1, :cond_254

    .line 1917
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1919
    :cond_254
    invoke-virtual/range {p0 .. p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOpposite()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 1920
    .local v4, "opposite":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v7, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v5

    .line 1921
    .restart local v5    # "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v5}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v6

    if-eqz v6, :cond_26e

    .line 1922
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1923
    invoke-virtual {v5}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 1935
    .end local v2    # "baseline":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "opposite":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v5    # "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_26e
    nop

    .line 1959
    :cond_26f
    :goto_26f
    move/from16 v2, p4

    .line 1959
    .end local p4    # "margin":I
    .local v2, "margin":I
    :goto_271
    move-object/from16 v3, p5

    invoke-virtual {v0, v1, v2, v3, v11}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)Z

    .line 1960
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v5

    invoke-virtual {v4, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connectedTo(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V

    .line 1960
    .end local v0    # "fromAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v1    # "toAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    goto :goto_284

    .line 1963
    .end local v2    # "margin":I
    .restart local p4    # "margin":I
    :goto_282
    move/from16 v2, p4

    .line 1963
    .end local p4    # "margin":I
    .restart local v2    # "margin":I
    :goto_284
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)V
    .registers 10
    .param p1, "from"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "to"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p3, "margin"    # I

    .line 1723
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    invoke-virtual/range {v0 .. v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1724
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)V
    .registers 11
    .param p1, "from"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "to"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p3, "margin"    # I
    .param p4, "creator"    # I

    .line 1719
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move v5, p4

    invoke-virtual/range {v0 .. v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1720
    return-void
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;Landroid/support/constraint/solver/widgets/ConstraintAnchor;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V
    .registers 14
    .param p1, "from"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "to"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p3, "margin"    # I
    .param p4, "strength"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    .param p5, "creator"    # I

    .line 1728
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    if-ne v0, p0, :cond_19

    .line 1729
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v2

    invoke-virtual {p2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v3

    invoke-virtual {p2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v4

    move-object v1, p0

    move v5, p3

    move-object v6, p4

    move v7, p5

    invoke-virtual/range {v1 .. v7}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)V

    .line 1731
    :cond_19
    return-void
.end method

.method public connectCircularConstraint(Landroid/support/constraint/solver/widgets/ConstraintWidget;FI)V
    .registers 10
    .param p1, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "angle"    # F
    .param p3, "radius"    # I

    .line 605
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v5, 0x0

    move-object v0, p0

    move-object v2, p1

    move v4, p3

    invoke-virtual/range {v0 .. v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->immediateConnect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;II)V

    .line 607
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCircleConstraintAngle:F

    .line 608
    return-void
.end method

.method public connectedTo(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 2
    .param p1, "source"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 1691
    return-void
.end method

.method public createObjectVariables(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 7
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 700
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 701
    .local v0, "left":Landroid/support/constraint/solver/SolverVariable;
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 702
    .local v1, "top":Landroid/support/constraint/solver/SolverVariable;
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v2

    .line 703
    .local v2, "right":Landroid/support/constraint/solver/SolverVariable;
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v3}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v3

    .line 704
    .local v3, "bottom":Landroid/support/constraint/solver/SolverVariable;
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v4, :cond_21

    .line 705
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    .line 707
    :cond_21
    return-void
.end method

.method public disconnectUnlockedWidget(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 8
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2115
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchors()Ljava/util/ArrayList;

    move-result-object v0

    .line 2116
    .local v0, "anchors":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/ConstraintAnchor;>;"
    const/4 v1, 0x0

    .line 2116
    .local v1, "i":I
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 2116
    .local v2, "anchorsSize":I
    :goto_9
    if-ge v1, v2, :cond_2e

    .line 2117
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 2118
    .local v3, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v4

    if-eqz v4, :cond_2b

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    if-ne v4, p1, :cond_2b

    .line 2119
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getConnectionCreator()I

    move-result v4

    const/4 v5, 0x2

    if-ne v4, v5, :cond_2b

    .line 2120
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2116
    .end local v3    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_2b
    add-int/lit8 v1, v1, 0x1

    goto :goto_9

    .line 2123
    .end local v1    # "i":I
    .end local v2    # "anchorsSize":I
    :cond_2e
    return-void
.end method

.method public disconnectWidget(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 7
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 2100
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchors()Ljava/util/ArrayList;

    move-result-object v0

    .line 2101
    .local v0, "anchors":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/ConstraintAnchor;>;"
    const/4 v1, 0x0

    .line 2101
    .local v1, "i":I
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 2101
    .local v2, "anchorsSize":I
    :goto_9
    if-ge v1, v2, :cond_27

    .line 2102
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 2103
    .local v3, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v4

    if-eqz v4, :cond_24

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    if-ne v4, p1, :cond_24

    .line 2104
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2101
    .end local v3    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_24
    add-int/lit8 v1, v1, 0x1

    goto :goto_9

    .line 2107
    .end local v1    # "i":I
    .end local v2    # "anchorsSize":I
    :cond_27
    return-void
.end method

.method public forceUpdateDrawPosition()V
    .registers 6

    .line 1146
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1147
    .local v0, "left":I
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1148
    .local v1, "top":I
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    iget v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    add-int/2addr v2, v3

    .line 1149
    .local v2, "right":I
    iget v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    add-int/2addr v3, v4

    .line 1150
    .local v3, "bottom":I
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 1151
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 1152
    sub-int v4, v2, v0

    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    .line 1153
    sub-int v4, v3, v1

    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    .line 1154
    return-void
.end method

.method public getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .registers 4
    .param p1, "anchorType"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 2132
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_30

    .line 2160
    new-instance v0, Ljava/lang/AssertionError;

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 2158
    :pswitch_15
    const/4 v0, 0x0

    return-object v0

    .line 2152
    :pswitch_17
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2149
    :pswitch_1a
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2155
    :pswitch_1d
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2146
    :pswitch_20
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2143
    :pswitch_23
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2140
    :pswitch_26
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2137
    :pswitch_29
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 2134
    :pswitch_2c
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    nop

    :pswitch_data_30
    .packed-switch 0x1
        :pswitch_2c
        :pswitch_29
        :pswitch_26
        :pswitch_23
        :pswitch_20
        :pswitch_1d
        :pswitch_1a
        :pswitch_17
        :pswitch_15
    .end packed-switch
.end method

.method public getAnchors()Ljava/util/ArrayList;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Landroid/support/constraint/solver/widgets/ConstraintAnchor;",
            ">;"
        }
    .end annotation

    .line 1050
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getBaselineDistance()I
    .registers 2

    .line 1031
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    return v0
.end method

.method public getBiasPercent(I)F
    .registers 3
    .param p1, "orientation"    # I

    .line 1007
    if-nez p1, :cond_5

    .line 1008
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    return v0

    .line 1009
    :cond_5
    const/4 v0, 0x1

    if-ne p1, v0, :cond_b

    .line 1010
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    return v0

    .line 1012
    :cond_b
    const/high16 v0, -0x40800000    # -1.0f

    return v0
.end method

.method public getBottom()I
    .registers 3

    .line 976
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getY()I

    move-result v0

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getCompanionWidget()Ljava/lang/Object;
    .registers 2

    .line 1041
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCompanionWidget:Ljava/lang/Object;

    return-object v0
.end method

.method public getContainerItemSkip()I
    .registers 2

    .line 1612
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mContainerItemSkip:I

    return v0
.end method

.method public getDebugName()Ljava/lang/String;
    .registers 2

    .line 652
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    return-object v0
.end method

.method public getDimensionBehaviour(I)Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .registers 3
    .param p1, "orientation"    # I

    .line 2188
    if-nez p1, :cond_7

    .line 2189
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v0

    return-object v0

    .line 2190
    :cond_7
    const/4 v0, 0x1

    if-ne p1, v0, :cond_f

    .line 2191
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v0

    return-object v0

    .line 2193
    :cond_f
    const/4 v0, 0x0

    return-object v0
.end method

.method public getDimensionRatio()F
    .registers 2

    .line 1359
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    return v0
.end method

.method public getDimensionRatioSide()I
    .registers 2

    .line 1368
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    return v0
.end method

.method public getDrawBottom()I
    .registers 3

    .line 893
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDrawY()I

    move-result v0

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getDrawHeight()I
    .registers 2

    .line 884
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    return v0
.end method

.method public getDrawRight()I
    .registers 3

    .line 902
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDrawX()I

    move-result v0

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getDrawWidth()I
    .registers 2

    .line 880
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    return v0
.end method

.method public getDrawX()I
    .registers 3

    .line 867
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getDrawY()I
    .registers 3

    .line 876
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getHeight()I
    .registers 3

    .line 830
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    const/16 v1, 0x8

    if-ne v0, v1, :cond_8

    .line 831
    const/4 v0, 0x0

    return v0

    .line 833
    :cond_8
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    return v0
.end method

.method public getHorizontalBiasPercent()F
    .registers 2

    .line 986
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    return v0
.end method

.method public getHorizontalChainControlWidget()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 8

    .line 2240
    const/4 v0, 0x0

    .line 2241
    .local v0, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isInHorizontalChain()Z

    move-result v1

    if-eqz v1, :cond_45

    .line 2242
    move-object v1, v0

    move-object v0, p0

    .line 2244
    .local v0, "tmp":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v1, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_9
    if-nez v1, :cond_46

    if-eqz v0, :cond_46

    .line 2245
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 2246
    .local v2, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v3, 0x0

    if-nez v2, :cond_18

    move-object v4, v3

    goto :goto_1c

    :cond_18
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 2247
    .local v4, "targetOwner":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :goto_1c
    if-nez v4, :cond_20

    move-object v5, v3

    goto :goto_24

    :cond_20
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v5

    .line 2248
    .local v5, "target":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_24
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v6

    if-ne v5, v6, :cond_2c

    .line 2249
    move-object v1, v0

    .line 2250
    goto :goto_46

    .line 2252
    :cond_2c
    if-nez v5, :cond_2f

    goto :goto_39

    :cond_2f
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v5, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 2253
    .local v3, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :goto_39
    if-eqz v3, :cond_43

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v6

    if-eq v6, v0, :cond_43

    .line 2254
    move-object v1, v0

    goto :goto_44

    .line 2256
    :cond_43
    move-object v0, v5

    .line 2258
    .end local v2    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "targetOwner":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v5    # "target":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_44
    goto :goto_9

    .line 2260
    .end local v1    # "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v0, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_45
    move-object v1, v0

    .line 2260
    .end local v0    # "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v1    # "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_46
    :goto_46
    return-object v1
.end method

.method public getHorizontalChainStyle()I
    .registers 2

    .line 1650
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    return v0
.end method

.method public getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .registers 3

    .line 2169
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    return-object v0
.end method

.method public getInternalDrawBottom()I
    .registers 3

    .line 745
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getInternalDrawRight()I
    .registers 3

    .line 741
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    add-int/2addr v0, v1

    return v0
.end method

.method getInternalDrawX()I
    .registers 2

    .line 733
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    return v0
.end method

.method getInternalDrawY()I
    .registers 2

    .line 737
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    return v0
.end method

.method public getLeft()I
    .registers 2

    .line 949
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getX()I

    move-result v0

    return v0
.end method

.method public getLength(I)I
    .registers 3
    .param p1, "orientation"    # I

    .line 852
    if-nez p1, :cond_7

    .line 853
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v0

    return v0

    .line 854
    :cond_7
    const/4 v0, 0x1

    if-ne p1, v0, :cond_f

    .line 855
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v0

    return v0

    .line 857
    :cond_f
    const/4 v0, 0x0

    return v0
.end method

.method public getMaxHeight()I
    .registers 3

    .line 101
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    const/4 v1, 0x1

    aget v0, v0, v1

    return v0
.end method

.method public getMaxWidth()I
    .registers 3

    .line 105
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    const/4 v1, 0x0

    aget v0, v0, v1

    return v0
.end method

.method public getMinHeight()I
    .registers 2

    .line 940
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    return v0
.end method

.method public getMinWidth()I
    .registers 2

    .line 931
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    return v0
.end method

.method public getOptimizerWrapHeight()I
    .registers 5

    .line 798
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 799
    .local v0, "h":I
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v2, 0x1

    aget-object v1, v1, v2

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v1, v3, :cond_2a

    .line 800
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    if-ne v1, v2, :cond_16

    .line 801
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    goto :goto_20

    .line 802
    :cond_16
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    if-lez v1, :cond_1f

    .line 803
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    .line 804
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    goto :goto_20

    .line 806
    :cond_1f
    const/4 v0, 0x0

    .line 808
    :goto_20
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    if-lez v1, :cond_2a

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    if-ge v1, v0, :cond_2a

    .line 809
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    .line 812
    :cond_2a
    return v0
.end method

.method public getOptimizerWrapWidth()I
    .registers 4

    .line 780
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 781
    .local v0, "w":I
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v1, v2, :cond_2b

    .line 782
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    const/4 v2, 0x1

    if-ne v1, v2, :cond_17

    .line 783
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    goto :goto_21

    .line 784
    :cond_17
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    if-lez v1, :cond_20

    .line 785
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    .line 786
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    goto :goto_21

    .line 788
    :cond_20
    const/4 v0, 0x0

    .line 790
    :goto_21
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    if-lez v1, :cond_2b

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    if-ge v1, v0, :cond_2b

    .line 791
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    .line 794
    :cond_2b
    return v0
.end method

.method public getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 555
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method getRelativePositioning(I)I
    .registers 3
    .param p1, "orientation"    # I

    .line 1548
    if-nez p1, :cond_5

    .line 1549
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelX:I

    return v0

    .line 1550
    :cond_5
    const/4 v0, 0x1

    if-ne p1, v0, :cond_b

    .line 1551
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelY:I

    return v0

    .line 1553
    :cond_b
    const/4 v0, 0x0

    return v0
.end method

.method public getResolutionHeight()Landroid/support/constraint/solver/widgets/ResolutionDimension;
    .registers 2

    .line 394
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    if-nez v0, :cond_b

    .line 395
    new-instance v0, Landroid/support/constraint/solver/widgets/ResolutionDimension;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/ResolutionDimension;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    .line 397
    :cond_b
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    return-object v0
.end method

.method public getResolutionWidth()Landroid/support/constraint/solver/widgets/ResolutionDimension;
    .registers 2

    .line 383
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    if-nez v0, :cond_b

    .line 384
    new-instance v0, Landroid/support/constraint/solver/widgets/ResolutionDimension;

    invoke-direct {v0}, Landroid/support/constraint/solver/widgets/ResolutionDimension;-><init>()V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    .line 386
    :cond_b
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    return-object v0
.end method

.method public getRight()I
    .registers 3

    .line 967
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getX()I

    move-result v0

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getRootWidgetContainer()Landroid/support/constraint/solver/widgets/WidgetContainer;
    .registers 3

    .line 539
    move-object v0, p0

    .line 540
    .local v0, "root":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_1
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    if-eqz v1, :cond_c

    .line 541
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    goto :goto_1

    .line 543
    :cond_c
    instance-of v1, v0, Landroid/support/constraint/solver/widgets/WidgetContainer;

    if-eqz v1, :cond_14

    .line 544
    move-object v1, v0

    check-cast v1, Landroid/support/constraint/solver/widgets/WidgetContainer;

    return-object v1

    .line 546
    :cond_14
    const/4 v1, 0x0

    return-object v1
.end method

.method protected getRootX()I
    .registers 3

    .line 912
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    add-int/2addr v0, v1

    return v0
.end method

.method protected getRootY()I
    .registers 3

    .line 922
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    add-int/2addr v0, v1

    return v0
.end method

.method public getTop()I
    .registers 2

    .line 958
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getY()I

    move-result v0

    return v0
.end method

.method public getType()Ljava/lang/String;
    .registers 2

    .line 616
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    return-object v0
.end method

.method public getVerticalBiasPercent()F
    .registers 2

    .line 996
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    return v0
.end method

.method public getVerticalChainControlWidget()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 8

    .line 2283
    const/4 v0, 0x0

    .line 2284
    .local v0, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->isInVerticalChain()Z

    move-result v1

    if-eqz v1, :cond_45

    .line 2285
    move-object v1, v0

    move-object v0, p0

    .line 2286
    .local v0, "tmp":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v1, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_9
    if-nez v1, :cond_46

    if-eqz v0, :cond_46

    .line 2287
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v0, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 2288
    .local v2, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/4 v3, 0x0

    if-nez v2, :cond_18

    move-object v4, v3

    goto :goto_1c

    :cond_18
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 2289
    .local v4, "targetOwner":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :goto_1c
    if-nez v4, :cond_20

    move-object v5, v3

    goto :goto_24

    :cond_20
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v5

    .line 2290
    .local v5, "target":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_24
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v6

    if-ne v5, v6, :cond_2c

    .line 2291
    move-object v1, v0

    .line 2292
    goto :goto_46

    .line 2294
    :cond_2c
    if-nez v5, :cond_2f

    goto :goto_39

    :cond_2f
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v5, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 2295
    .local v3, "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :goto_39
    if-eqz v3, :cond_43

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v6

    if-eq v6, v0, :cond_43

    .line 2296
    move-object v1, v0

    goto :goto_44

    .line 2298
    :cond_43
    move-object v0, v5

    .line 2300
    .end local v2    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v3    # "targetAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v4    # "targetOwner":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .end local v5    # "target":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :goto_44
    goto :goto_9

    .line 2303
    .end local v1    # "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .local v0, "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_45
    move-object v1, v0

    .line 2303
    .end local v0    # "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .restart local v1    # "found":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    :cond_46
    :goto_46
    return-object v1
.end method

.method public getVerticalChainStyle()I
    .registers 2

    .line 1670
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    return v0
.end method

.method public getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;
    .registers 3

    .line 2178
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    return-object v0
.end method

.method public getVisibility()I
    .registers 2

    .line 643
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    return v0
.end method

.method public getWidth()I
    .registers 3

    .line 773
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    const/16 v1, 0x8

    if-ne v0, v1, :cond_8

    .line 774
    const/4 v0, 0x0

    return v0

    .line 776
    :cond_8
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    return v0
.end method

.method public getWrapHeight()I
    .registers 2

    .line 842
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapHeight:I

    return v0
.end method

.method public getWrapWidth()I
    .registers 2

    .line 821
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapWidth:I

    return v0
.end method

.method public getX()I
    .registers 2

    .line 755
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    return v0
.end method

.method public getY()I
    .registers 2

    .line 764
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    return v0
.end method

.method public hasAncestor(Landroid/support/constraint/solver/widgets/ConstraintWidget;)Z
    .registers 6
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 512
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    .line 513
    .local v0, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v1, 0x1

    if-ne v0, p1, :cond_8

    .line 514
    return v1

    .line 516
    :cond_8
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    const/4 v3, 0x0

    if-ne v0, v2, :cond_10

    .line 517
    return v3

    .line 519
    :cond_10
    :goto_10
    if-eqz v0, :cond_21

    .line 520
    if-ne v0, p1, :cond_15

    .line 521
    return v1

    .line 523
    :cond_15
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    if-ne v0, v2, :cond_1c

    .line 525
    return v1

    .line 527
    :cond_1c
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    goto :goto_10

    .line 529
    :cond_21
    return v3
.end method

.method public hasBaseline()Z
    .registers 2

    .line 1022
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v0, :cond_6

    const/4 v0, 0x1

    goto :goto_7

    :cond_6
    const/4 v0, 0x0

    :goto_7
    return v0
.end method

.method public immediateConnect(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;II)V
    .registers 15
    .param p1, "startType"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p2, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p3, "endType"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p4, "margin"    # I
    .param p5, "goneMargin"    # I

    .line 1704
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v7

    .line 1705
    .local v7, "startAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {p2, p3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    .line 1706
    .local v8, "endAnchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    const/4 v5, 0x0

    const/4 v6, 0x1

    move-object v0, v7

    move-object v1, v8

    move v2, p4

    move v3, p5

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;IILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;IZ)Z

    .line 1708
    return-void
.end method

.method public isFullyResolved()Z
    .registers 3

    .line 369
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    iget v0, v0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_2a

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 370
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    iget v0, v0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-ne v0, v1, :cond_2a

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 371
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    iget v0, v0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-ne v0, v1, :cond_2a

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 372
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v0

    iget v0, v0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->state:I

    if-ne v0, v1, :cond_2a

    .line 373
    return v1

    .line 375
    :cond_2a
    const/4 v0, 0x0

    return v0
.end method

.method public isHeightWrapContent()Z
    .registers 2

    .line 595
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mIsHeightWrapContent:Z

    return v0
.end method

.method public isInHorizontalChain()Z
    .registers 3

    .line 2227
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_10

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eq v0, v1, :cond_20

    :cond_10
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_22

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-ne v0, v1, :cond_22

    .line 2229
    :cond_20
    const/4 v0, 0x1

    return v0

    .line 2231
    :cond_22
    const/4 v0, 0x0

    return v0
.end method

.method public isInVerticalChain()Z
    .registers 3

    .line 2270
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_10

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eq v0, v1, :cond_20

    :cond_10
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_22

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-ne v0, v1, :cond_22

    .line 2272
    :cond_20
    const/4 v0, 0x1

    return v0

    .line 2274
    :cond_22
    const/4 v0, 0x0

    return v0
.end method

.method public isInsideConstraintLayout()Z
    .registers 4

    .line 492
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    .line 493
    .local v0, "widget":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v1, 0x0

    if-nez v0, :cond_8

    .line 494
    return v1

    .line 496
    :cond_8
    :goto_8
    if-eqz v0, :cond_15

    .line 497
    instance-of v2, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v2, :cond_10

    .line 498
    const/4 v1, 0x1

    return v1

    .line 500
    :cond_10
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    goto :goto_8

    .line 502
    :cond_15
    return v1
.end method

.method public isRoot()Z
    .registers 2

    .line 472
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-nez v0, :cond_6

    const/4 v0, 0x1

    goto :goto_7

    :cond_6
    const/4 v0, 0x0

    :goto_7
    return v0
.end method

.method public isRootContainer()Z
    .registers 2

    .line 482
    instance-of v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v0, :cond_10

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    if-eqz v0, :cond_e

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    instance-of v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-nez v0, :cond_10

    :cond_e
    const/4 v0, 0x1

    goto :goto_11

    :cond_10
    const/4 v0, 0x0

    :goto_11
    return v0
.end method

.method public isSpreadHeight()Z
    .registers 4

    .line 125
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    const/4 v1, 0x1

    if-nez v0, :cond_1d

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    const/4 v2, 0x0

    cmpl-float v0, v0, v2

    if-nez v0, :cond_1d

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    if-nez v0, :cond_1d

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    if-nez v0, :cond_1d

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v0, v0, v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v2, :cond_1d

    goto :goto_1e

    :cond_1d
    const/4 v1, 0x0

    :goto_1e
    return v1
.end method

.method public isSpreadWidth()Z
    .registers 4

    .line 117
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    const/4 v1, 0x0

    if-nez v0, :cond_1e

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    const/4 v2, 0x0

    cmpl-float v0, v0, v2

    if-nez v0, :cond_1e

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    if-nez v0, :cond_1e

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    if-nez v0, :cond_1e

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v0, v0, v1

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v2, :cond_1e

    const/4 v1, 0x1

    nop

    :cond_1e
    return v1
.end method

.method public isWidthWrapContent()Z
    .registers 2

    .line 580
    iget-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mIsWidthWrapContent:Z

    return v0
.end method

.method public reset()V
    .registers 7

    .line 257
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 258
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 259
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 260
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 261
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 262
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 263
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 264
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 265
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 266
    const/4 v1, 0x0

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCircleConstraintAngle:F

    .line 267
    const/4 v2, 0x0

    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 268
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 269
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    .line 270
    const/4 v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    .line 271
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 272
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 273
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 274
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 275
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    .line 276
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    .line 277
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    .line 278
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    .line 279
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    .line 280
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    .line 281
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    .line 282
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapWidth:I

    .line 283
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapHeight:I

    .line 284
    sget v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    .line 285
    sget v3, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    .line 286
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aput-object v4, v3, v2

    .line 287
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v5, 0x1

    aput-object v4, v3, v5

    .line 288
    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCompanionWidget:Ljava/lang/Object;

    .line 289
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mContainerItemSkip:I

    .line 290
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    .line 291
    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    .line 292
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalWrapVisited:Z

    .line 293
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalWrapVisited:Z

    .line 294
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    .line 295
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    .line 296
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainFixedPosition:Z

    .line 297
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainFixedPosition:Z

    .line 298
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    const/high16 v4, -0x40800000    # -1.0f

    aput v4, v3, v2

    .line 299
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    aput v4, v3, v5

    .line 300
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalResolution:I

    .line 301
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalResolution:I

    .line 302
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    const v4, 0x7fffffff

    aput v4, v3, v2

    .line 303
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    aput v4, v3, v5

    .line 304
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    .line 305
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    .line 306
    const/high16 v3, 0x3f800000    # 1.0f

    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentWidth:F

    .line 307
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentHeight:F

    .line 308
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    .line 309
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    .line 310
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    .line 311
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    .line 312
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 313
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 314
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    if-eqz v1, :cond_b3

    .line 315
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionWidth:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->reset()V

    .line 317
    :cond_b3
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    if-eqz v1, :cond_bc

    .line 318
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolutionHeight:Landroid/support/constraint/solver/widgets/ResolutionDimension;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionDimension;->reset()V

    .line 320
    :cond_bc
    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBelongingGroup:Landroid/support/constraint/solver/widgets/ConstraintWidgetGroup;

    .line 321
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasurable:Z

    .line 322
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 323
    iput-boolean v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mGroupsToSolver:Z

    .line 324
    return-void
.end method

.method public resetAllConstraints()V
    .registers 3

    .line 1969
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->resetAnchors()V

    .line 1970
    sget v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalBiasPercent(F)V

    .line 1971
    sget v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalBiasPercent(F)V

    .line 1972
    instance-of v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v0, :cond_12

    .line 1973
    return-void

    .line 1975
    :cond_12
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHorizontalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v0

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v1, :cond_39

    .line 1976
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWrapWidth()I

    move-result v1

    if-ne v0, v1, :cond_2a

    .line 1977
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    goto :goto_39

    .line 1978
    :cond_2a
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWidth()I

    move-result v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getMinWidth()I

    move-result v1

    if-le v0, v1, :cond_39

    .line 1979
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 1982
    :cond_39
    :goto_39
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVerticalDimensionBehaviour()Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    move-result-object v0

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->MATCH_CONSTRAINT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v0, v1, :cond_60

    .line 1983
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getWrapHeight()I

    move-result v1

    if-ne v0, v1, :cond_51

    .line 1984
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    goto :goto_60

    .line 1985
    :cond_51
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getHeight()I

    move-result v0

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getMinHeight()I

    move-result v1

    if-le v0, v1, :cond_60

    .line 1986
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V

    .line 1989
    :cond_60
    :goto_60
    return-void
.end method

.method public resetAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)V
    .registers 12
    .param p1, "anchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 1998
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    if-eqz v0, :cond_1b

    .line 1999
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    instance-of v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v0, :cond_1b

    .line 2000
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    check-cast v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    .line 2001
    .local v0, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->handlesInternalConstraints()Z

    move-result v1

    if-eqz v1, :cond_1b

    .line 2002
    return-void

    .line 2006
    .end local v0    # "parent":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    :cond_1b
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v0

    .line 2007
    .local v0, "left":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v1

    .line 2008
    .local v1, "right":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v2

    .line 2009
    .local v2, "top":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v3

    .line 2010
    .local v3, "bottom":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v4

    .line 2011
    .local v4, "center":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v5}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v5

    .line 2012
    .local v5, "centerX":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    sget-object v6, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p0, v6}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchor(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    .line 2014
    .local v6, "centerY":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    const/high16 v7, 0x3f000000    # 0.5f

    if-ne p1, v4, :cond_87

    .line 2015
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_65

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_65

    .line 2016
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v9

    if-ne v8, v9, :cond_65

    .line 2017
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2018
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2020
    :cond_65
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_81

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_81

    .line 2021
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v9

    if-ne v8, v9, :cond_81

    .line 2022
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2023
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2025
    :cond_81
    iput v7, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    .line 2026
    iput v7, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    goto/16 :goto_109

    .line 2027
    :cond_87
    if-ne p1, v5, :cond_b0

    .line 2028
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_ad

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_ad

    .line 2029
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    invoke-virtual {v8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v8

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v9

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v9

    if-ne v8, v9, :cond_ad

    .line 2030
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2031
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2033
    :cond_ad
    iput v7, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    goto :goto_109

    .line 2034
    :cond_b0
    if-ne p1, v6, :cond_d9

    .line 2035
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_d6

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v8

    if-eqz v8, :cond_d6

    .line 2036
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    invoke-virtual {v8}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v8

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v9

    invoke-virtual {v9}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v9

    if-ne v8, v9, :cond_d6

    .line 2037
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2038
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2040
    :cond_d6
    iput v7, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    goto :goto_109

    .line 2041
    :cond_d9
    if-eq p1, v0, :cond_f6

    if-ne p1, v1, :cond_de

    goto :goto_f6

    .line 2045
    :cond_de
    if-eq p1, v2, :cond_e2

    if-ne p1, v3, :cond_109

    .line 2046
    :cond_e2
    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v7

    if-eqz v7, :cond_109

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v7

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    if-ne v7, v8, :cond_109

    .line 2047
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    goto :goto_109

    .line 2042
    :cond_f6
    :goto_f6
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v7

    if-eqz v7, :cond_109

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v7

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v8

    if-ne v7, v8, :cond_109

    .line 2043
    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2050
    :cond_109
    :goto_109
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2051
    return-void
.end method

.method public resetAnchors()V
    .registers 5

    .line 2057
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    .line 2058
    .local v0, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-eqz v0, :cond_17

    instance-of v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v1, :cond_17

    .line 2059
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    check-cast v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    .line 2060
    .local v1, "parentContainer":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->handlesInternalConstraints()Z

    move-result v2

    if-eqz v2, :cond_17

    .line 2061
    return-void

    .line 2064
    .end local v1    # "parentContainer":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    :cond_17
    const/4 v1, 0x0

    .line 2064
    .local v1, "i":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 2064
    .local v2, "mAnchorsSize":I
    :goto_1e
    if-ge v1, v2, :cond_2e

    .line 2065
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 2066
    .local v3, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2064
    .end local v3    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    add-int/lit8 v1, v1, 0x1

    goto :goto_1e

    .line 2068
    .end local v1    # "i":I
    .end local v2    # "mAnchorsSize":I
    :cond_2e
    return-void
.end method

.method public resetAnchors(I)V
    .registers 7
    .param p1, "connectionCreator"    # I

    .line 2074
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    .line 2075
    .local v0, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    if-eqz v0, :cond_17

    instance-of v1, v0, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    if-eqz v1, :cond_17

    .line 2076
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    check-cast v1, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;

    .line 2077
    .local v1, "parentContainer":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;->handlesInternalConstraints()Z

    move-result v2

    if-eqz v2, :cond_17

    .line 2078
    return-void

    .line 2081
    .end local v1    # "parentContainer":Landroid/support/constraint/solver/widgets/ConstraintWidgetContainer;
    :cond_17
    const/4 v1, 0x0

    .line 2081
    .local v1, "i":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v2

    .line 2081
    .local v2, "mAnchorsSize":I
    :goto_1e
    if-ge v1, v2, :cond_45

    .line 2082
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mAnchors:Ljava/util/ArrayList;

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 2083
    .local v3, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getConnectionCreator()I

    move-result v4

    if-ne p1, v4, :cond_42

    .line 2084
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isVerticalAnchor()Z

    move-result v4

    if-eqz v4, :cond_3a

    .line 2085
    sget v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    invoke-virtual {p0, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalBiasPercent(F)V

    goto :goto_3f

    .line 2087
    :cond_3a
    sget v4, Landroid/support/constraint/solver/widgets/ConstraintWidget;->DEFAULT_BIAS:F

    invoke-virtual {p0, v4}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalBiasPercent(F)V

    .line 2089
    :goto_3f
    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->reset()V

    .line 2081
    .end local v3    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_42
    add-int/lit8 v1, v1, 0x1

    goto :goto_1e

    .line 2092
    .end local v1    # "i":I
    .end local v2    # "mAnchorsSize":I
    :cond_45
    return-void
.end method

.method public resetResolutionNodes()V
    .registers 3

    .line 334
    const/4 v0, 0x0

    .line 334
    .local v0, "i":I
    :goto_1
    const/4 v1, 0x6

    if-ge v0, v1, :cond_12

    .line 335
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v1, v1, v0

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->reset()V

    .line 334
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 337
    .end local v0    # "i":I
    :cond_12
    return-void
.end method

.method public resetSolverVariables(Landroid/support/constraint/solver/Cache;)V
    .registers 3
    .param p1, "cache"    # Landroid/support/constraint/solver/Cache;

    .line 442
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 443
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 444
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 445
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 446
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 447
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenter:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 448
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterX:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 449
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCenterY:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->resetSolverVariable(Landroid/support/constraint/solver/Cache;)V

    .line 450
    return-void
.end method

.method public resolve()V
    .registers 1

    .line 361
    return-void
.end method

.method public setBaselineDistance(I)V
    .registers 2
    .param p1, "baseline"    # I

    .line 1577
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    .line 1578
    return-void
.end method

.method public setCompanionWidget(Ljava/lang/Object;)V
    .registers 2
    .param p1, "companion"    # Ljava/lang/Object;

    .line 1587
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mCompanionWidget:Ljava/lang/Object;

    .line 1588
    return-void
.end method

.method public setContainerItemSkip(I)V
    .registers 3
    .param p1, "skip"    # I

    .line 1599
    if-ltz p1, :cond_5

    .line 1600
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mContainerItemSkip:I

    goto :goto_8

    .line 1602
    :cond_5
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mContainerItemSkip:I

    .line 1604
    :goto_8
    return-void
.end method

.method public setDebugName(Ljava/lang/String;)V
    .registers 2
    .param p1, "name"    # Ljava/lang/String;

    .line 659
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    .line 660
    return-void
.end method

.method public setDebugSolverName(Landroid/support/constraint/solver/LinearSystem;Ljava/lang/String;)V
    .registers 10
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;
    .param p2, "name"    # Ljava/lang/String;

    .line 679
    iput-object p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    .line 680
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v0

    .line 681
    .local v0, "left":Landroid/support/constraint/solver/SolverVariable;
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v1

    .line 682
    .local v1, "top":Landroid/support/constraint/solver/SolverVariable;
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v2

    .line 683
    .local v2, "right":Landroid/support/constraint/solver/SolverVariable;
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v3}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v3

    .line 684
    .local v3, "bottom":Landroid/support/constraint/solver/SolverVariable;
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ".left"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, v4}, Landroid/support/constraint/solver/SolverVariable;->setName(Ljava/lang/String;)V

    .line 685
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ".top"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v1, v4}, Landroid/support/constraint/solver/SolverVariable;->setName(Ljava/lang/String;)V

    .line 686
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ".right"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Landroid/support/constraint/solver/SolverVariable;->setName(Ljava/lang/String;)V

    .line 687
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ".bottom"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Landroid/support/constraint/solver/SolverVariable;->setName(Ljava/lang/String;)V

    .line 688
    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaselineDistance:I

    if-lez v4, :cond_88

    .line 689
    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBaseline:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v4}, Landroid/support/constraint/solver/LinearSystem;->createObjectVariable(Ljava/lang/Object;)Landroid/support/constraint/solver/SolverVariable;

    move-result-object v4

    .line 690
    .local v4, "baseline":Landroid/support/constraint/solver/SolverVariable;
    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v5, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v6, ".baseline"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Landroid/support/constraint/solver/SolverVariable;->setName(Ljava/lang/String;)V

    .line 692
    .end local v4    # "baseline":Landroid/support/constraint/solver/SolverVariable;
    :cond_88
    return-void
.end method

.method public setDimension(II)V
    .registers 5
    .param p1, "w"    # I
    .param p2, "h"    # I

    .line 1442
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1443
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    if-ge v0, v1, :cond_c

    .line 1444
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1446
    :cond_c
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1447
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    if-ge v0, v1, :cond_18

    .line 1448
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1450
    :cond_18
    return-void
.end method

.method public setDimensionRatio(FI)V
    .registers 3
    .param p1, "ratio"    # F
    .param p2, "dimensionRatioSide"    # I

    .line 1349
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    .line 1350
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    .line 1351
    return-void
.end method

.method public setDimensionRatio(Ljava/lang/String;)V
    .registers 14
    .param p1, "ratio"    # Ljava/lang/String;

    .line 1287
    const/4 v0, 0x0

    if-eqz p1, :cond_99

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v1

    if-nez v1, :cond_b

    goto/16 :goto_99

    .line 1291
    :cond_b
    const/4 v1, -0x1

    .line 1292
    .local v1, "dimensionRatioSide":I
    const/4 v2, 0x0

    .line 1293
    .local v2, "dimensionRatio":F
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v3

    .line 1294
    .local v3, "len":I
    const/16 v4, 0x2c

    invoke-virtual {p1, v4}, Ljava/lang/String;->indexOf(I)I

    move-result v4

    .line 1295
    .local v4, "commaIndex":I
    const/4 v5, 0x1

    if-lez v4, :cond_38

    add-int/lit8 v6, v3, -0x1

    if-ge v4, v6, :cond_38

    .line 1296
    const/4 v6, 0x0

    invoke-virtual {p1, v6, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v6

    .line 1297
    .local v6, "dimension":Ljava/lang/String;
    const-string v7, "W"

    invoke-virtual {v6, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v7

    if-eqz v7, :cond_2d

    .line 1298
    const/4 v1, 0x0

    goto :goto_36

    .line 1299
    :cond_2d
    const-string v7, "H"

    invoke-virtual {v6, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v7

    if-eqz v7, :cond_36

    .line 1300
    const/4 v1, 0x1

    .line 1302
    :cond_36
    :goto_36
    add-int/2addr v4, v5

    .line 1303
    .end local v6    # "dimension":Ljava/lang/String;
    goto :goto_39

    .line 1304
    :cond_38
    const/4 v4, 0x0

    .line 1306
    :goto_39
    const/16 v6, 0x3a

    invoke-virtual {p1, v6}, Ljava/lang/String;->indexOf(I)I

    move-result v6

    .line 1308
    .local v6, "colonIndex":I
    if-ltz v6, :cond_7f

    add-int/lit8 v7, v3, -0x1

    if-ge v6, v7, :cond_7f

    .line 1309
    invoke-virtual {p1, v4, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v7

    .line 1310
    .local v7, "nominator":Ljava/lang/String;
    add-int/lit8 v8, v6, 0x1

    invoke-virtual {p1, v8}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v8

    .line 1311
    .local v8, "denominator":Ljava/lang/String;
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v9

    if-lez v9, :cond_7e

    invoke-virtual {v8}, Ljava/lang/String;->length()I

    move-result v9

    if-lez v9, :cond_7e

    .line 1313
    :try_start_5b
    invoke-static {v7}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v9

    .line 1314
    .local v9, "nominatorValue":F
    invoke-static {v8}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v10

    .line 1315
    .local v10, "denominatorValue":F
    cmpl-float v11, v9, v0

    if-lez v11, :cond_7c

    cmpl-float v11, v10, v0

    if-lez v11, :cond_7c

    .line 1316
    if-ne v1, v5, :cond_75

    .line 1317
    div-float v5, v10, v9

    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    move v2, v5

    goto :goto_7c

    .line 1319
    :cond_75
    div-float v5, v9, v10

    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5
    :try_end_7b
    .catch Ljava/lang/NumberFormatException; {:try_start_5b .. :try_end_7b} :catch_7d

    move v2, v5

    .line 1324
    .end local v9    # "nominatorValue":F
    .end local v10    # "denominatorValue":F
    :cond_7c
    :goto_7c
    goto :goto_7e

    .line 1322
    :catch_7d
    move-exception v5

    .line 1326
    .end local v7    # "nominator":Ljava/lang/String;
    .end local v8    # "denominator":Ljava/lang/String;
    :cond_7e
    :goto_7e
    goto :goto_90

    .line 1327
    :cond_7f
    invoke-virtual {p1, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v5

    .line 1328
    .local v5, "r":Ljava/lang/String;
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    move-result v7

    if-lez v7, :cond_90

    .line 1330
    :try_start_89
    invoke-static {v5}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v7
    :try_end_8d
    .catch Ljava/lang/NumberFormatException; {:try_start_89 .. :try_end_8d} :catch_8f

    move v2, v7

    .line 1333
    goto :goto_90

    .line 1331
    :catch_8f
    move-exception v7

    .line 1337
    .end local v5    # "r":Ljava/lang/String;
    :cond_90
    :goto_90
    cmpl-float v0, v2, v0

    if-lez v0, :cond_98

    .line 1338
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    .line 1339
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    .line 1341
    :cond_98
    return-void

    .line 1288
    .end local v1    # "dimensionRatioSide":I
    .end local v2    # "dimensionRatio":F
    .end local v3    # "len":I
    .end local v4    # "commaIndex":I
    .end local v6    # "colonIndex":I
    :cond_99
    :goto_99
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatio:F

    .line 1289
    return-void
.end method

.method public setDrawHeight(I)V
    .registers 2
    .param p1, "drawHeight"    # I

    .line 1204
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    .line 1205
    return-void
.end method

.method public setDrawOrigin(II)V
    .registers 4
    .param p1, "x"    # I
    .param p2, "y"    # I

    .line 1163
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    sub-int v0, p1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 1164
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    sub-int v0, p2, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 1165
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1166
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1167
    return-void
.end method

.method public setDrawWidth(I)V
    .registers 2
    .param p1, "drawWidth"    # I

    .line 1195
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    .line 1196
    return-void
.end method

.method public setDrawX(I)V
    .registers 3
    .param p1, "x"    # I

    .line 1175
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    sub-int v0, p1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 1176
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1177
    return-void
.end method

.method public setDrawY(I)V
    .registers 3
    .param p1, "y"    # I

    .line 1185
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    sub-int v0, p1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 1186
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1187
    return-void
.end method

.method public setFrame(III)V
    .registers 5
    .param p1, "start"    # I
    .param p2, "end"    # I
    .param p3, "orientation"    # I

    .line 1505
    const/4 v0, 0x1

    if-nez p3, :cond_7

    .line 1506
    invoke-virtual {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHorizontalDimension(II)V

    goto :goto_c

    .line 1507
    :cond_7
    if-ne p3, v0, :cond_c

    .line 1508
    invoke-virtual {p0, p1, p2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setVerticalDimension(II)V

    .line 1510
    :cond_c
    :goto_c
    iput-boolean v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 1511
    return-void
.end method

.method public setFrame(IIII)V
    .registers 10
    .param p1, "left"    # I
    .param p2, "top"    # I
    .param p3, "right"    # I
    .param p4, "bottom"    # I

    .line 1461
    sub-int v0, p3, p1

    .line 1462
    .local v0, "w":I
    sub-int v1, p4, p2

    .line 1464
    .local v1, "h":I
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1465
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1467
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    const/4 v3, 0x0

    const/16 v4, 0x8

    if-ne v2, v4, :cond_14

    .line 1468
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1469
    iput v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1470
    return-void

    .line 1474
    :cond_14
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    aget-object v2, v2, v3

    sget-object v3, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v2, v3, :cond_22

    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    if-ge v0, v2, :cond_22

    .line 1475
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1477
    :cond_22
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v3, 0x1

    aget-object v2, v2, v3

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->FIXED:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne v2, v4, :cond_31

    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    if-ge v1, v2, :cond_31

    .line 1478
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1481
    :cond_31
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1482
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1484
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    if-ge v2, v4, :cond_3f

    .line 1485
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1487
    :cond_3f
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    if-ge v2, v4, :cond_49

    .line 1488
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1494
    :cond_49
    iput-boolean v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOptimizerMeasured:Z

    .line 1495
    return-void
.end method

.method public setGoneMargin(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;I)V
    .registers 5
    .param p1, "type"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .param p2, "goneMargin"    # I

    .line 1100
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_22

    goto :goto_20

    .line 1114
    :pswitch_c
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput p2, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 1116
    goto :goto_20

    .line 1110
    :pswitch_11
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput p2, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 1112
    goto :goto_20

    .line 1106
    :pswitch_16
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput p2, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 1108
    goto :goto_20

    .line 1102
    :pswitch_1b
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iput p2, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 1104
    nop

    .line 1124
    :goto_20
    return-void

    nop

    :pswitch_data_22
    .packed-switch 0x1
        :pswitch_1b
        :pswitch_16
        :pswitch_11
        :pswitch_c
    .end packed-switch
.end method

.method public setHeight(I)V
    .registers 4
    .param p1, "h"    # I

    .line 1225
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1226
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    if-ge v0, v1, :cond_c

    .line 1227
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1229
    :cond_c
    return-void
.end method

.method public setHeightWrapContent(Z)V
    .registers 2
    .param p1, "heightWrapContent"    # Z

    .line 588
    iput-boolean p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mIsHeightWrapContent:Z

    .line 589
    return-void
.end method

.method public setHorizontalBiasPercent(F)V
    .registers 2
    .param p1, "horizontalBiasPercent"    # F

    .line 1378
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalBiasPercent:F

    .line 1379
    return-void
.end method

.method public setHorizontalChainStyle(I)V
    .registers 2
    .param p1, "horizontalChainStyle"    # I

    .line 1640
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHorizontalChainStyle:I

    .line 1641
    return-void
.end method

.method public setHorizontalDimension(II)V
    .registers 5
    .param p1, "left"    # I
    .param p2, "right"    # I

    .line 1520
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1521
    sub-int v0, p2, p1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1522
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    if-ge v0, v1, :cond_10

    .line 1523
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1525
    :cond_10
    return-void
.end method

.method public setHorizontalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V
    .registers 4
    .param p1, "behaviour"    # Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 2203
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x0

    aput-object p1, v0, v1

    .line 2204
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne p1, v0, :cond_e

    .line 2205
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapWidth:I

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setWidth(I)V

    .line 2207
    :cond_e
    return-void
.end method

.method public setHorizontalMatchStyle(IIIF)V
    .registers 6
    .param p1, "horizontalMatchStyle"    # I
    .param p2, "min"    # I
    .param p3, "max"    # I
    .param p4, "percent"    # F

    .line 1254
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    .line 1255
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    .line 1256
    iput p3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxWidth:I

    .line 1257
    iput p4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentWidth:F

    .line 1258
    const/high16 v0, 0x3f800000    # 1.0f

    cmpg-float v0, p4, v0

    if-gez v0, :cond_15

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    if-nez v0, :cond_15

    .line 1259
    const/4 v0, 0x2

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultWidth:I

    .line 1261
    :cond_15
    return-void
.end method

.method public setHorizontalWeight(F)V
    .registers 4
    .param p1, "horizontalWeight"    # F

    .line 1621
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    const/4 v1, 0x0

    aput p1, v0, v1

    .line 1622
    return-void
.end method

.method public setLength(II)V
    .registers 4
    .param p1, "length"    # I
    .param p2, "orientation"    # I

    .line 1238
    if-nez p2, :cond_6

    .line 1239
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setWidth(I)V

    goto :goto_c

    .line 1240
    :cond_6
    const/4 v0, 0x1

    if-ne p2, v0, :cond_c

    .line 1241
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHeight(I)V

    .line 1243
    :cond_c
    :goto_c
    return-void
.end method

.method public setMaxHeight(I)V
    .registers 4
    .param p1, "maxHeight"    # I

    .line 113
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    const/4 v1, 0x1

    aput p1, v0, v1

    .line 114
    return-void
.end method

.method public setMaxWidth(I)V
    .registers 4
    .param p1, "maxWidth"    # I

    .line 109
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMaxDimension:[I

    const/4 v1, 0x0

    aput p1, v0, v1

    .line 110
    return-void
.end method

.method public setMinHeight(I)V
    .registers 3
    .param p1, "h"    # I

    .line 1410
    if-gez p1, :cond_6

    .line 1411
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    goto :goto_8

    .line 1413
    :cond_6
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    .line 1415
    :goto_8
    return-void
.end method

.method public setMinWidth(I)V
    .registers 3
    .param p1, "w"    # I

    .line 1397
    if-gez p1, :cond_6

    .line 1398
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    goto :goto_8

    .line 1400
    :cond_6
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    .line 1402
    :goto_8
    return-void
.end method

.method public setOffset(II)V
    .registers 3
    .param p1, "x"    # I
    .param p2, "y"    # I

    .line 1089
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetX:I

    .line 1090
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mOffsetY:I

    .line 1091
    return-void
.end method

.method public setOrigin(II)V
    .registers 3
    .param p1, "x"    # I
    .param p2, "y"    # I

    .line 1078
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1079
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1080
    return-void
.end method

.method public setParent(Landroid/support/constraint/solver/widgets/ConstraintWidget;)V
    .registers 2
    .param p1, "widget"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 564
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mParent:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 565
    return-void
.end method

.method setRelativePositioning(II)V
    .registers 4
    .param p1, "offset"    # I
    .param p2, "orientation"    # I

    .line 1564
    if-nez p2, :cond_5

    .line 1565
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelX:I

    goto :goto_a

    .line 1566
    :cond_5
    const/4 v0, 0x1

    if-ne p2, v0, :cond_a

    .line 1567
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRelY:I

    .line 1569
    :cond_a
    :goto_a
    return-void
.end method

.method public setType(Ljava/lang/String;)V
    .registers 2
    .param p1, "type"    # Ljava/lang/String;

    .line 625
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    .line 626
    return-void
.end method

.method public setVerticalBiasPercent(F)V
    .registers 2
    .param p1, "verticalBiasPercent"    # F

    .line 1388
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalBiasPercent:F

    .line 1389
    return-void
.end method

.method public setVerticalChainStyle(I)V
    .registers 2
    .param p1, "verticalChainStyle"    # I

    .line 1660
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVerticalChainStyle:I

    .line 1661
    return-void
.end method

.method public setVerticalDimension(II)V
    .registers 5
    .param p1, "top"    # I
    .param p2, "bottom"    # I

    .line 1534
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1535
    sub-int v0, p2, p1

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1536
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    if-ge v0, v1, :cond_10

    .line 1537
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinHeight:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    .line 1539
    :cond_10
    return-void
.end method

.method public setVerticalDimensionBehaviour(Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;)V
    .registers 4
    .param p1, "behaviour"    # Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    .line 2215
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListDimensionBehaviors:[Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    const/4 v1, 0x1

    aput-object p1, v0, v1

    .line 2216
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;->WRAP_CONTENT:Landroid/support/constraint/solver/widgets/ConstraintWidget$DimensionBehaviour;

    if-ne p1, v0, :cond_e

    .line 2217
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapHeight:I

    invoke-virtual {p0, v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setHeight(I)V

    .line 2219
    :cond_e
    return-void
.end method

.method public setVerticalMatchStyle(IIIF)V
    .registers 6
    .param p1, "verticalMatchStyle"    # I
    .param p2, "min"    # I
    .param p3, "max"    # I
    .param p4, "percent"    # F

    .line 1272
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    .line 1273
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    .line 1274
    iput p3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMaxHeight:I

    .line 1275
    iput p4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintPercentHeight:F

    .line 1276
    const/high16 v0, 0x3f800000    # 1.0f

    cmpg-float v0, p4, v0

    if-gez v0, :cond_15

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    if-nez v0, :cond_15

    .line 1277
    const/4 v0, 0x2

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintDefaultHeight:I

    .line 1279
    :cond_15
    return-void
.end method

.method public setVerticalWeight(F)V
    .registers 4
    .param p1, "verticalWeight"    # F

    .line 1630
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWeight:[F

    const/4 v1, 0x1

    aput p1, v0, v1

    .line 1631
    return-void
.end method

.method public setVisibility(I)V
    .registers 2
    .param p1, "visibility"    # I

    .line 634
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mVisibility:I

    .line 635
    return-void
.end method

.method public setWidth(I)V
    .registers 4
    .param p1, "w"    # I

    .line 1213
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1214
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    if-ge v0, v1, :cond_c

    .line 1215
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMinWidth:I

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    .line 1217
    :cond_c
    return-void
.end method

.method public setWidthWrapContent(Z)V
    .registers 2
    .param p1, "widthWrapContent"    # Z

    .line 572
    iput-boolean p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mIsWidthWrapContent:Z

    .line 573
    return-void
.end method

.method public setWrapHeight(I)V
    .registers 2
    .param p1, "h"    # I

    .line 1432
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapHeight:I

    .line 1433
    return-void
.end method

.method public setWrapWidth(I)V
    .registers 2
    .param p1, "w"    # I

    .line 1423
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapWidth:I

    .line 1424
    return-void
.end method

.method public setX(I)V
    .registers 2
    .param p1, "x"    # I

    .line 1059
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1060
    return-void
.end method

.method public setY(I)V
    .registers 2
    .param p1, "y"    # I

    .line 1068
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1069
    return-void
.end method

.method public setupDimensionRatio(ZZZZ)V
    .registers 10
    .param p1, "hparentWrapContent"    # Z
    .param p2, "vparentWrapContent"    # Z
    .param p3, "horizontalDimensionFixed"    # Z
    .param p4, "verticalDimensionFixed"    # Z

    .line 2534
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    const/high16 v1, 0x3f800000    # 1.0f

    const/4 v2, 0x0

    const/4 v3, -0x1

    const/4 v4, 0x1

    if-ne v0, v3, :cond_20

    .line 2535
    if-eqz p3, :cond_10

    if-nez p4, :cond_10

    .line 2536
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    goto :goto_20

    .line 2537
    :cond_10
    if-nez p3, :cond_20

    if-eqz p4, :cond_20

    .line 2538
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2539
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDimensionRatioSide:I

    if-ne v0, v3, :cond_20

    .line 2541
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    div-float v0, v1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2546
    :cond_20
    :goto_20
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-nez v0, :cond_37

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_34

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-nez v0, :cond_37

    .line 2547
    :cond_34
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    goto :goto_4d

    .line 2548
    :cond_37
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-ne v0, v4, :cond_4d

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_4b

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-nez v0, :cond_4d

    .line 2549
    :cond_4b
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2553
    :cond_4d
    :goto_4d
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-ne v0, v3, :cond_9c

    .line 2554
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_71

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_71

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 2555
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_71

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-nez v0, :cond_9c

    .line 2557
    :cond_71
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_84

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_84

    .line 2558
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    goto :goto_9c

    .line 2559
    :cond_84
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_9c

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_9c

    .line 2560
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    div-float v0, v1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2561
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2566
    :cond_9c
    :goto_9c
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-ne v0, v3, :cond_b3

    .line 2567
    if-eqz p1, :cond_a7

    if-nez p2, :cond_a7

    .line 2568
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    goto :goto_b3

    .line 2569
    :cond_a7
    if-nez p1, :cond_b3

    if-eqz p2, :cond_b3

    .line 2570
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    div-float v0, v1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2571
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2575
    :cond_b3
    :goto_b3
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-ne v0, v3, :cond_d2

    .line 2576
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    if-lez v0, :cond_c2

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    if-nez v0, :cond_c2

    .line 2577
    iput v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    goto :goto_d2

    .line 2578
    :cond_c2
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinWidth:I

    if-nez v0, :cond_d2

    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mMatchConstraintMinHeight:I

    if-lez v0, :cond_d2

    .line 2579
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    div-float v0, v1, v0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2580
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2584
    :cond_d2
    :goto_d2
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    if-ne v0, v3, :cond_e1

    if-eqz p1, :cond_e1

    if-eqz p2, :cond_e1

    .line 2585
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    div-float/2addr v1, v0

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatio:F

    .line 2586
    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mResolvedDimensionRatioSide:I

    .line 2588
    :cond_e1
    return-void
.end method

.method public toString()Ljava/lang/String;
    .registers 4

    .line 716
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    if-eqz v1, :cond_22

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "type: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mType:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_24

    :cond_22
    const-string v1, ""

    :goto_24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    if-eqz v1, :cond_44

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "id: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDebugName:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_46

    :cond_44
    const-string v1, ""

    :goto_46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") - ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " x "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") wrap: ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapWidth:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " x "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWrapHeight:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public updateDrawPosition()V
    .registers 6

    .line 1132
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    .line 1133
    .local v0, "left":I
    iget v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    .line 1134
    .local v1, "top":I
    iget v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mX:I

    iget v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mWidth:I

    add-int/2addr v2, v3

    .line 1135
    .local v2, "right":I
    iget v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mY:I

    iget v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mHeight:I

    add-int/2addr v3, v4

    .line 1136
    .local v3, "bottom":I
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawX:I

    .line 1137
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawY:I

    .line 1138
    sub-int v4, v2, v0

    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawWidth:I

    .line 1139
    sub-int v4, v3, v1

    iput v4, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mDrawHeight:I

    .line 1140
    return-void
.end method

.method public updateFromSolver(Landroid/support/constraint/solver/LinearSystem;)V
    .registers 10
    .param p1, "system"    # Landroid/support/constraint/solver/LinearSystem;

    .line 2865
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v0}, Landroid/support/constraint/solver/LinearSystem;->getObjectVariableValue(Ljava/lang/Object;)I

    move-result v0

    .line 2866
    .local v0, "left":I
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v1}, Landroid/support/constraint/solver/LinearSystem;->getObjectVariableValue(Ljava/lang/Object;)I

    move-result v1

    .line 2867
    .local v1, "top":I
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v2}, Landroid/support/constraint/solver/LinearSystem;->getObjectVariableValue(Ljava/lang/Object;)I

    move-result v2

    .line 2868
    .local v2, "right":I
    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    invoke-virtual {p1, v3}, Landroid/support/constraint/solver/LinearSystem;->getObjectVariableValue(Ljava/lang/Object;)I

    move-result v3

    .line 2869
    .local v3, "bottom":I
    sub-int v4, v2, v0

    .line 2870
    .local v4, "w":I
    sub-int v5, v3, v1

    .line 2871
    .local v5, "h":I
    if-ltz v4, :cond_35

    if-ltz v5, :cond_35

    const/high16 v6, -0x80000000

    if-eq v0, v6, :cond_35

    const v7, 0x7fffffff

    if-eq v0, v7, :cond_35

    if-eq v1, v6, :cond_35

    if-eq v1, v7, :cond_35

    if-eq v2, v6, :cond_35

    if-eq v2, v7, :cond_35

    if-eq v3, v6, :cond_35

    if-ne v3, v7, :cond_39

    .line 2876
    :cond_35
    const/4 v0, 0x0

    .line 2877
    const/4 v1, 0x0

    .line 2878
    const/4 v2, 0x0

    .line 2879
    const/4 v3, 0x0

    .line 2881
    :cond_39
    invoke-virtual {p0, v0, v1, v2, v3}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->setFrame(IIII)V

    .line 2882
    return-void
.end method

.method public updateResolutionNodes()V
    .registers 3

    .line 343
    const/4 v0, 0x0

    .line 343
    .local v0, "i":I
    :goto_1
    const/4 v1, 0x6

    if-ge v0, v1, :cond_12

    .line 344
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mListAnchors:[Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    aget-object v1, v1, v0

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->update()V

    .line 343
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 346
    .end local v0    # "i":I
    :cond_12
    return-void
.end method
