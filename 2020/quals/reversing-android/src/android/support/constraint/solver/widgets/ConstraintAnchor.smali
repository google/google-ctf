.class public Landroid/support/constraint/solver/widgets/ConstraintAnchor;
.super Ljava/lang/Object;
.source "ConstraintAnchor.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;,
        Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;,
        Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    }
.end annotation


# static fields
.field private static final ALLOW_BINARY:Z = false

.field public static final AUTO_CONSTRAINT_CREATOR:I = 0x2

.field public static final SCOUT_CREATOR:I = 0x1

.field private static final UNSET_GONE_MARGIN:I = -0x1

.field public static final USER_CREATOR:I


# instance fields
.field private mConnectionCreator:I

.field private mConnectionType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

.field mGoneMargin:I

.field public mMargin:I

.field final mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

.field private mResolutionAnchor:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

.field mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

.field private mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

.field mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

.field final mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;


# direct methods
.method public constructor <init>(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;)V
    .registers 5
    .param p1, "owner"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "type"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 86
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    new-instance v0, Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    invoke-direct {v0, p0}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;-><init>(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mResolutionAnchor:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    .line 73
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 74
    const/4 v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 76
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->NONE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 77
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;->RELAXED:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    .line 78
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionCreator:I

    .line 87
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 88
    iput-object p2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    .line 89
    return-void
.end method

.method private isConnectionToMe(Landroid/support/constraint/solver/widgets/ConstraintWidget;Ljava/util/HashSet;)Z
    .registers 10
    .param p1, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            "Ljava/util/HashSet<",
            "Landroid/support/constraint/solver/widgets/ConstraintWidget;",
            ">;)Z"
        }
    .end annotation

    .line 588
    .local p2, "checked":Ljava/util/HashSet;, "Ljava/util/HashSet<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_8

    .line 589
    return v1

    .line 591
    :cond_8
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 593
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v0

    const/4 v2, 0x1

    if-ne p1, v0, :cond_13

    .line 594
    return v2

    .line 596
    :cond_13
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getAnchors()Ljava/util/ArrayList;

    move-result-object v0

    .line 597
    .local v0, "targetAnchors":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroid/support/constraint/solver/widgets/ConstraintAnchor;>;"
    const/4 v3, 0x0

    .line 597
    .local v3, "i":I
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v4

    .line 597
    .local v4, "targetAnchorsSize":I
    :goto_1c
    if-ge v3, v4, :cond_42

    .line 598
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 599
    .local v5, "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    invoke-virtual {v5, p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isSimilarDimensionConnection(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z

    move-result v6

    if-eqz v6, :cond_3f

    invoke-virtual {v5}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v6

    if-eqz v6, :cond_3f

    .line 600
    invoke-virtual {v5}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    move-result-object v6

    invoke-virtual {v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v6

    invoke-direct {p0, v6, p2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnectionToMe(Landroid/support/constraint/solver/widgets/ConstraintWidget;Ljava/util/HashSet;)Z

    move-result v6

    if-eqz v6, :cond_3f

    .line 601
    return v2

    .line 597
    .end local v5    # "anchor":Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    :cond_3f
    add-int/lit8 v3, v3, 0x1

    goto :goto_1c

    .line 605
    .end local v3    # "i":I
    .end local v4    # "targetAnchorsSize":I
    :cond_42
    return v1
.end method


# virtual methods
.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;I)Z
    .registers 10
    .param p1, "toAnchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "margin"    # I

    .line 251
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    const/4 v3, -0x1

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;IILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;IZ)Z

    move-result v0

    return v0
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;II)Z
    .registers 11
    .param p1, "toAnchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "margin"    # I
    .param p3, "creator"    # I

    .line 241
    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    const/4 v3, -0x1

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move v5, p3

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;IILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;IZ)Z

    move-result v0

    return v0
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;IILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;IZ)Z
    .registers 10
    .param p1, "toAnchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "margin"    # I
    .param p3, "goneMargin"    # I
    .param p4, "strength"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    .param p5, "creator"    # I
    .param p6, "forceConnection"    # Z

    .line 210
    const/4 v0, 0x1

    const/4 v1, 0x0

    if-nez p1, :cond_14

    .line 211
    const/4 v2, 0x0

    iput-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 212
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 213
    const/4 v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 214
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->NONE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 215
    const/4 v1, 0x2

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionCreator:I

    .line 216
    return v0

    .line 218
    :cond_14
    if-nez p6, :cond_1d

    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isValidConnection(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z

    move-result v2

    if-nez v2, :cond_1d

    .line 219
    return v1

    .line 221
    :cond_1d
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 222
    if-lez p2, :cond_24

    .line 223
    iput p2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    goto :goto_26

    .line 225
    :cond_24
    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 227
    :goto_26
    iput p3, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 228
    iput-object p4, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 229
    iput p5, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionCreator:I

    .line 230
    return v0
.end method

.method public connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;ILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;I)Z
    .registers 12
    .param p1, "toAnchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .param p2, "margin"    # I
    .param p3, "strength"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    .param p4, "creator"    # I

    .line 194
    const/4 v3, -0x1

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v4, p3

    move v5, p4

    invoke-virtual/range {v0 .. v6}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->connect(Landroid/support/constraint/solver/widgets/ConstraintAnchor;IILandroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;IZ)Z

    move-result v0

    return v0
.end method

.method public getConnectionCreator()I
    .registers 2

    .line 163
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionCreator:I

    return v0
.end method

.method public getConnectionType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;
    .registers 2

    .line 150
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    return-object v0
.end method

.method public getMargin()I
    .registers 4

    .line 125
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v0

    const/16 v1, 0x8

    if-ne v0, v1, :cond_c

    .line 126
    const/4 v0, 0x0

    return v0

    .line 128
    :cond_c
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    const/4 v2, -0x1

    if-le v0, v2, :cond_22

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_22

    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 129
    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getVisibility()I

    move-result v0

    if-ne v0, v1, :cond_22

    .line 130
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    return v0

    .line 132
    :cond_22
    iget v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    return v0
.end method

.method public final getOpposite()Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .registers 3

    .line 613
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_30

    .line 633
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 624
    :pswitch_19
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mTop:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 621
    :pswitch_1e
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mBottom:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 618
    :pswitch_23
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mLeft:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 615
    :pswitch_28
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    iget-object v0, v0, Landroid/support/constraint/solver/widgets/ConstraintWidget;->mRight:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0

    .line 631
    :pswitch_2d
    const/4 v0, 0x0

    return-object v0

    nop

    :pswitch_data_30
    .packed-switch 0x1
        :pswitch_2d
        :pswitch_28
        :pswitch_23
        :pswitch_1e
        :pswitch_19
        :pswitch_2d
        :pswitch_2d
        :pswitch_2d
        :pswitch_2d
    .end packed-switch
.end method

.method public getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .registers 2

    .line 112
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    return-object v0
.end method

.method public getPriorityLevel()I
    .registers 4

    .line 457
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x0

    const/4 v2, 0x2

    packed-switch v0, :pswitch_data_26

    .line 468
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 466
    :pswitch_1b
    return v1

    .line 459
    :pswitch_1c
    return v1

    .line 458
    :pswitch_1d
    return v1

    .line 460
    :pswitch_1e
    const/4 v0, 0x1

    return v0

    .line 464
    :pswitch_20
    return v2

    .line 463
    :pswitch_21
    return v2

    .line 462
    :pswitch_22
    return v2

    .line 461
    :pswitch_23
    return v2

    .line 465
    :pswitch_24
    return v2

    nop

    :pswitch_data_26
    .packed-switch 0x1
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
    .end packed-switch
.end method

.method public getResolutionNode()Landroid/support/constraint/solver/widgets/ResolutionAnchor;
    .registers 2

    .line 58
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mResolutionAnchor:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    return-object v0
.end method

.method public getSnapPriorityLevel()I
    .registers 4

    .line 435
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x1

    const/4 v2, 0x0

    packed-switch v0, :pswitch_data_26

    .line 446
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 444
    :pswitch_1b
    return v2

    .line 441
    :pswitch_1c
    return v1

    .line 438
    :pswitch_1d
    return v2

    .line 442
    :pswitch_1e
    const/4 v0, 0x2

    return v0

    .line 440
    :pswitch_20
    return v2

    .line 439
    :pswitch_21
    return v2

    .line 437
    :pswitch_22
    return v1

    .line 436
    :pswitch_23
    return v1

    .line 443
    :pswitch_24
    const/4 v0, 0x3

    return v0

    :pswitch_data_26
    .packed-switch 0x1
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
    .end packed-switch
.end method

.method public getSolverVariable()Landroid/support/constraint/solver/SolverVariable;
    .registers 2

    .line 95
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    return-object v0
.end method

.method public getStrength()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;
    .registers 2

    .line 138
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    return-object v0
.end method

.method public getTarget()Landroid/support/constraint/solver/widgets/ConstraintAnchor;
    .registers 2

    .line 144
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    return-object v0
.end method

.method public getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    .registers 2

    .line 118
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    return-object v0
.end method

.method public isConnected()Z
    .registers 2

    .line 259
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    if-eqz v0, :cond_6

    const/4 v0, 0x1

    goto :goto_7

    :cond_6
    const/4 v0, 0x0

    :goto_7
    return v0
.end method

.method public isConnectionAllowed(Landroid/support/constraint/solver/widgets/ConstraintWidget;)Z
    .registers 7
    .param p1, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;

    .line 566
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 567
    .local v0, "checked":Ljava/util/HashSet;, "Ljava/util/HashSet<Landroid/support/constraint/solver/widgets/ConstraintWidget;>;"
    invoke-direct {p0, p1, v0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnectionToMe(Landroid/support/constraint/solver/widgets/ConstraintWidget;Ljava/util/HashSet;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_d

    .line 568
    return v2

    .line 570
    :cond_d
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v1

    .line 571
    .local v1, "parent":Landroid/support/constraint/solver/widgets/ConstraintWidget;
    const/4 v3, 0x1

    if-ne v1, p1, :cond_19

    .line 572
    return v3

    .line 574
    :cond_19
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getParent()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    if-ne v4, v1, :cond_20

    .line 575
    return v3

    .line 577
    :cond_20
    return v2
.end method

.method public isConnectionAllowed(Landroid/support/constraint/solver/widgets/ConstraintWidget;Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z
    .registers 4
    .param p1, "target"    # Landroid/support/constraint/solver/widgets/ConstraintWidget;
    .param p2, "anchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 553
    invoke-virtual {p0, p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnectionAllowed(Landroid/support/constraint/solver/widgets/ConstraintWidget;)Z

    move-result v0

    return v0
.end method

.method public isSideAnchor()Z
    .registers 3

    .line 316
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_1e

    .line 329
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 321
    :pswitch_19
    const/4 v0, 0x1

    return v0

    .line 327
    :pswitch_1b
    const/4 v0, 0x0

    return v0

    nop

    :pswitch_data_1e
    .packed-switch 0x1
        :pswitch_1b
        :pswitch_19
        :pswitch_19
        :pswitch_19
        :pswitch_19
        :pswitch_1b
        :pswitch_1b
        :pswitch_1b
        :pswitch_1b
    .end packed-switch
.end method

.method public isSimilarDimensionConnection(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z
    .registers 6
    .param p1, "anchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 340
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v0

    .line 341
    .local v0, "target":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v2, 0x1

    if-ne v0, v1, :cond_a

    .line 342
    return v2

    .line 344
    :cond_a
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v3, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v3}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v3

    aget v1, v1, v3

    const/4 v3, 0x0

    packed-switch v1, :pswitch_data_50

    .line 362
    new-instance v1, Ljava/lang/AssertionError;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1

    .line 360
    :pswitch_24
    return v3

    .line 357
    :pswitch_25
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v0, v1, :cond_38

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v0, v1, :cond_38

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v0, v1, :cond_38

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v0, v1, :cond_36

    goto :goto_38

    :cond_36
    move v2, v3

    nop

    :cond_38
    :goto_38
    return v2

    .line 351
    :pswitch_39
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v0, v1, :cond_48

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v0, v1, :cond_48

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v0, v1, :cond_46

    goto :goto_48

    :cond_46
    move v2, v3

    nop

    :cond_48
    :goto_48
    return v2

    .line 346
    :pswitch_49
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v0, v1, :cond_4e

    goto :goto_4f

    :cond_4e
    move v2, v3

    :goto_4f
    return v2

    :pswitch_data_50
    .packed-switch 0x1
        :pswitch_49
        :pswitch_39
        :pswitch_39
        :pswitch_25
        :pswitch_25
        :pswitch_25
        :pswitch_39
        :pswitch_25
        :pswitch_24
    .end packed-switch
.end method

.method public isSnapCompatibleWith(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z
    .registers 7
    .param p1, "anchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 479
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_8

    .line 480
    return v2

    .line 482
    :cond_8
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    const/4 v3, 0x1

    if-ne v0, v1, :cond_12

    .line 483
    return v3

    .line 485
    :cond_12
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x7

    const/16 v4, 0x8

    packed-switch v0, :pswitch_data_a4

    .line 533
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 522
    :pswitch_2e
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_ba

    .line 525
    return v2

    .line 524
    :pswitch_3e
    return v3

    .line 523
    :pswitch_3f
    return v3

    .line 501
    :pswitch_40
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_c2

    .line 504
    return v2

    .line 503
    :pswitch_50
    return v3

    .line 502
    :pswitch_51
    return v3

    .line 515
    :pswitch_52
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x4

    if-eq v0, v1, :cond_65

    if-eq v0, v4, :cond_64

    .line 518
    return v2

    .line 517
    :cond_64
    return v3

    .line 516
    :cond_65
    return v3

    .line 508
    :pswitch_66
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x5

    if-eq v0, v1, :cond_79

    if-eq v0, v4, :cond_78

    .line 511
    return v2

    .line 510
    :cond_78
    return v3

    .line 509
    :cond_79
    return v3

    .line 494
    :pswitch_7a
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v4

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v4

    aget v0, v0, v4

    const/4 v4, 0x2

    if-eq v0, v4, :cond_8d

    if-eq v0, v1, :cond_8c

    .line 497
    return v2

    .line 496
    :cond_8c
    return v3

    .line 495
    :cond_8d
    return v3

    .line 487
    :pswitch_8e
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v4

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v4

    aget v0, v0, v4

    const/4 v4, 0x3

    if-eq v0, v4, :cond_a1

    if-eq v0, v1, :cond_a0

    .line 490
    return v2

    .line 489
    :cond_a0
    return v3

    .line 488
    :cond_a1
    return v3

    .line 531
    :pswitch_a2
    return v2

    nop

    :pswitch_data_a4
    .packed-switch 0x1
        :pswitch_a2
        :pswitch_8e
        :pswitch_7a
        :pswitch_66
        :pswitch_52
        :pswitch_a2
        :pswitch_40
        :pswitch_2e
        :pswitch_a2
    .end packed-switch

    :pswitch_data_ba
    .packed-switch 0x4
        :pswitch_3f
        :pswitch_3e
    .end packed-switch

    :pswitch_data_c2
    .packed-switch 0x2
        :pswitch_51
        :pswitch_50
    .end packed-switch
.end method

.method public isValidConnection(Landroid/support/constraint/solver/widgets/ConstraintAnchor;)Z
    .registers 7
    .param p1, "anchor"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 268
    const/4 v0, 0x0

    if-nez p1, :cond_4

    .line 269
    return v0

    .line 271
    :cond_4
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getType()Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    move-result-object v1

    .line 272
    .local v1, "target":Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    const/4 v3, 0x1

    if-ne v1, v2, :cond_29

    .line 273
    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v2, v4, :cond_28

    .line 274
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->hasBaseline()Z

    move-result v2

    if-eqz v2, :cond_27

    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v2

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->hasBaseline()Z

    move-result v2

    if-nez v2, :cond_28

    .line 275
    :cond_27
    return v0

    .line 277
    :cond_28
    return v3

    .line 279
    :cond_29
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v4, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v4}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v4

    aget v2, v2, v4

    packed-switch v2, :pswitch_data_90

    .line 307
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v2, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v2}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 305
    :pswitch_42
    return v0

    .line 295
    :pswitch_43
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->TOP:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v1, v2, :cond_4e

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BOTTOM:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v1, v2, :cond_4c

    goto :goto_4e

    :cond_4c
    move v2, v0

    goto :goto_4f

    :cond_4e
    :goto_4e
    move v2, v3

    .line 296
    .local v2, "isCompatible":Z
    :goto_4f
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    instance-of v4, v4, Landroid/support/constraint/solver/widgets/Guideline;

    if-eqz v4, :cond_61

    .line 297
    if-nez v2, :cond_5f

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v1, v4, :cond_5e

    goto :goto_5f

    :cond_5e
    goto :goto_60

    :cond_5f
    :goto_5f
    move v0, v3

    :goto_60
    move v2, v0

    .line 299
    :cond_61
    return v2

    .line 287
    .end local v2    # "isCompatible":Z
    :pswitch_62
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->LEFT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v1, v2, :cond_6d

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->RIGHT:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v1, v2, :cond_6b

    goto :goto_6d

    :cond_6b
    move v2, v0

    goto :goto_6e

    :cond_6d
    :goto_6d
    move v2, v3

    .line 288
    .restart local v2    # "isCompatible":Z
    :goto_6e
    invoke-virtual {p1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->getOwner()Landroid/support/constraint/solver/widgets/ConstraintWidget;

    move-result-object v4

    instance-of v4, v4, Landroid/support/constraint/solver/widgets/Guideline;

    if-eqz v4, :cond_80

    .line 289
    if-nez v2, :cond_7e

    sget-object v4, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-ne v1, v4, :cond_7d

    goto :goto_7e

    :cond_7d
    goto :goto_7f

    :cond_7e
    :goto_7e
    move v0, v3

    :goto_7f
    move v2, v0

    .line 291
    :cond_80
    return v2

    .line 282
    .end local v2    # "isCompatible":Z
    :pswitch_81
    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->BASELINE:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v1, v2, :cond_8f

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_X:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v1, v2, :cond_8f

    sget-object v2, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->CENTER_Y:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    if-eq v1, v2, :cond_8f

    move v0, v3

    nop

    :cond_8f
    return v0

    :pswitch_data_90
    .packed-switch 0x1
        :pswitch_81
        :pswitch_62
        :pswitch_62
        :pswitch_43
        :pswitch_43
        :pswitch_42
        :pswitch_42
        :pswitch_42
        :pswitch_42
    .end packed-switch
.end method

.method public isVerticalAnchor()Z
    .registers 3

    .line 401
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$1;->$SwitchMap$android$support$constraint$solver$widgets$ConstraintAnchor$Type:[I

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_1e

    .line 414
    new-instance v0, Ljava/lang/AssertionError;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 412
    :pswitch_19
    const/4 v0, 0x1

    return v0

    .line 406
    :pswitch_1b
    const/4 v0, 0x0

    return v0

    nop

    :pswitch_data_1e
    .packed-switch 0x1
        :pswitch_1b
        :pswitch_1b
        :pswitch_1b
        :pswitch_19
        :pswitch_19
        :pswitch_19
        :pswitch_1b
        :pswitch_19
        :pswitch_19
    .end packed-switch
.end method

.method public reset()V
    .registers 3

    .line 175
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mTarget:Landroid/support/constraint/solver/widgets/ConstraintAnchor;

    .line 176
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 177
    const/4 v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 178
    sget-object v1, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;->STRONG:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    iput-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 179
    iput v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionCreator:I

    .line 180
    sget-object v0, Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;->RELAXED:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    .line 181
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mResolutionAnchor:Landroid/support/constraint/solver/widgets/ResolutionAnchor;

    invoke-virtual {v0}, Landroid/support/constraint/solver/widgets/ResolutionAnchor;->reset()V

    .line 182
    return-void
.end method

.method public resetSolverVariable(Landroid/support/constraint/solver/Cache;)V
    .registers 5
    .param p1, "cache"    # Landroid/support/constraint/solver/Cache;

    .line 101
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    if-nez v0, :cond_f

    .line 102
    new-instance v0, Landroid/support/constraint/solver/SolverVariable;

    sget-object v1, Landroid/support/constraint/solver/SolverVariable$Type;->UNRESTRICTED:Landroid/support/constraint/solver/SolverVariable$Type;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroid/support/constraint/solver/SolverVariable;-><init>(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)V

    iput-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    goto :goto_14

    .line 104
    :cond_f
    iget-object v0, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mSolverVariable:Landroid/support/constraint/solver/SolverVariable;

    invoke-virtual {v0}, Landroid/support/constraint/solver/SolverVariable;->reset()V

    .line 106
    :goto_14
    return-void
.end method

.method public setConnectionCreator(I)V
    .registers 2
    .param p1, "creator"    # I

    .line 169
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionCreator:I

    return-void
.end method

.method public setConnectionType(Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;)V
    .registers 2
    .param p1, "type"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    .line 157
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mConnectionType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$ConnectionType;

    .line 158
    return-void
.end method

.method public setGoneMargin(I)V
    .registers 3
    .param p1, "margin"    # I

    .line 390
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_8

    .line 391
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mGoneMargin:I

    .line 393
    :cond_8
    return-void
.end method

.method public setMargin(I)V
    .registers 3
    .param p1, "margin"    # I

    .line 380
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_8

    .line 381
    iput p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mMargin:I

    .line 383
    :cond_8
    return-void
.end method

.method public setStrength(Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;)V
    .registers 3
    .param p1, "strength"    # Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 370
    invoke-virtual {p0}, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_8

    .line 371
    iput-object p1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mStrength:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Strength;

    .line 373
    :cond_8
    return-void
.end method

.method public toString()Ljava/lang/String;
    .registers 3

    .line 424
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mOwner:Landroid/support/constraint/solver/widgets/ConstraintWidget;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintWidget;->getDebugName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ":"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroid/support/constraint/solver/widgets/ConstraintAnchor;->mType:Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;

    invoke-virtual {v1}, Landroid/support/constraint/solver/widgets/ConstraintAnchor$Type;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
