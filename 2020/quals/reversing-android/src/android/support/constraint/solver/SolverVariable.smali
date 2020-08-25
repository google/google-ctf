.class public Landroid/support/constraint/solver/SolverVariable;
.super Ljava/lang/Object;
.source "SolverVariable.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroid/support/constraint/solver/SolverVariable$Type;
    }
.end annotation


# static fields
.field private static final INTERNAL_DEBUG:Z = false

.field static final MAX_STRENGTH:I = 0x7

.field public static final STRENGTH_BARRIER:I = 0x7

.field public static final STRENGTH_EQUALITY:I = 0x5

.field public static final STRENGTH_FIXED:I = 0x6

.field public static final STRENGTH_HIGH:I = 0x3

.field public static final STRENGTH_HIGHEST:I = 0x4

.field public static final STRENGTH_LOW:I = 0x1

.field public static final STRENGTH_MEDIUM:I = 0x2

.field public static final STRENGTH_NONE:I

.field private static uniqueConstantId:I

.field private static uniqueErrorId:I

.field private static uniqueId:I

.field private static uniqueSlackId:I

.field private static uniqueUnrestrictedId:I


# instance fields
.field public computedValue:F

.field definitionId:I

.field public id:I

.field mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

.field mClientEquationsCount:I

.field private mName:Ljava/lang/String;

.field mType:Landroid/support/constraint/solver/SolverVariable$Type;

.field public strength:I

.field strengthVector:[F

.field public usageInRowCount:I


# direct methods
.method static constructor <clinit>()V
    .registers 1

    .line 41
    const/4 v0, 0x1

    sput v0, Landroid/support/constraint/solver/SolverVariable;->uniqueSlackId:I

    .line 42
    sput v0, Landroid/support/constraint/solver/SolverVariable;->uniqueErrorId:I

    .line 43
    sput v0, Landroid/support/constraint/solver/SolverVariable;->uniqueUnrestrictedId:I

    .line 44
    sput v0, Landroid/support/constraint/solver/SolverVariable;->uniqueConstantId:I

    .line 45
    sput v0, Landroid/support/constraint/solver/SolverVariable;->uniqueId:I

    return-void
.end method

.method public constructor <init>(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)V
    .registers 5
    .param p1, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;
    .param p2, "prefix"    # Ljava/lang/String;

    .line 119
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 49
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 50
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 51
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 55
    const/4 v1, 0x7

    new-array v1, v1, [F

    iput-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    .line 58
    const/16 v1, 0x8

    new-array v1, v1, [Landroid/support/constraint/solver/ArrayRow;

    iput-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    .line 59
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 60
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 120
    iput-object p1, p0, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    .line 124
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Landroid/support/constraint/solver/SolverVariable$Type;)V
    .registers 5
    .param p1, "name"    # Ljava/lang/String;
    .param p2, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;

    .line 114
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 49
    const/4 v0, -0x1

    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 50
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 51
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 55
    const/4 v1, 0x7

    new-array v1, v1, [F

    iput-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    .line 58
    const/16 v1, 0x8

    new-array v1, v1, [Landroid/support/constraint/solver/ArrayRow;

    iput-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    .line 59
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 60
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 115
    iput-object p1, p0, Landroid/support/constraint/solver/SolverVariable;->mName:Ljava/lang/String;

    .line 116
    iput-object p2, p0, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    .line 117
    return-void
.end method

.method private static getUniqueName(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)Ljava/lang/String;
    .registers 4
    .param p0, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;
    .param p1, "prefix"    # Ljava/lang/String;

    .line 93
    if-eqz p1, :cond_14

    .line 94
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Landroid/support/constraint/solver/SolverVariable;->uniqueErrorId:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    .line 96
    :cond_14
    sget-object v0, Landroid/support/constraint/solver/SolverVariable$1;->$SwitchMap$android$support$constraint$solver$SolverVariable$Type:[I

    invoke-virtual {p0}, Landroid/support/constraint/solver/SolverVariable$Type;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_a2

    .line 106
    new-instance v0, Ljava/lang/AssertionError;

    invoke-virtual {p0}, Landroid/support/constraint/solver/SolverVariable$Type;->name()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    .line 104
    :pswitch_29
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "V"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Landroid/support/constraint/solver/SolverVariable;->uniqueId:I

    add-int/lit8 v1, v1, 0x1

    sput v1, Landroid/support/constraint/solver/SolverVariable;->uniqueId:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    .line 101
    :pswitch_41
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "e"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Landroid/support/constraint/solver/SolverVariable;->uniqueErrorId:I

    add-int/lit8 v1, v1, 0x1

    sput v1, Landroid/support/constraint/solver/SolverVariable;->uniqueErrorId:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    .line 99
    :pswitch_59
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "S"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Landroid/support/constraint/solver/SolverVariable;->uniqueSlackId:I

    add-int/lit8 v1, v1, 0x1

    sput v1, Landroid/support/constraint/solver/SolverVariable;->uniqueSlackId:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    .line 98
    :pswitch_71
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "C"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Landroid/support/constraint/solver/SolverVariable;->uniqueConstantId:I

    add-int/lit8 v1, v1, 0x1

    sput v1, Landroid/support/constraint/solver/SolverVariable;->uniqueConstantId:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    .line 97
    :pswitch_89
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "U"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Landroid/support/constraint/solver/SolverVariable;->uniqueUnrestrictedId:I

    add-int/lit8 v1, v1, 0x1

    sput v1, Landroid/support/constraint/solver/SolverVariable;->uniqueUnrestrictedId:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_a2
    .packed-switch 0x1
        :pswitch_89
        :pswitch_71
        :pswitch_59
        :pswitch_41
        :pswitch_29
    .end packed-switch
.end method

.method static increaseErrorId()V
    .registers 1

    .line 89
    sget v0, Landroid/support/constraint/solver/SolverVariable;->uniqueErrorId:I

    add-int/lit8 v0, v0, 0x1

    sput v0, Landroid/support/constraint/solver/SolverVariable;->uniqueErrorId:I

    .line 90
    return-void
.end method


# virtual methods
.method public final addToRow(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 4
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;

    .line 163
    const/4 v0, 0x0

    .line 163
    .local v0, "i":I
    :goto_1
    iget v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    if-ge v0, v1, :cond_f

    .line 164
    iget-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v1, v1, v0

    if-ne v1, p1, :cond_c

    .line 165
    return-void

    .line 163
    :cond_c
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 168
    .end local v0    # "i":I
    :cond_f
    iget v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    iget-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    array-length v1, v1

    if-lt v0, v1, :cond_25

    .line 169
    iget-object v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    iget-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    array-length v1, v1

    mul-int/lit8 v1, v1, 0x2

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroid/support/constraint/solver/ArrayRow;

    iput-object v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    .line 171
    :cond_25
    iget-object v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    iget v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    aput-object p1, v0, v1

    .line 172
    iget v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 173
    return-void
.end method

.method clearStrengths()V
    .registers 4

    .line 127
    const/4 v0, 0x0

    .line 127
    .local v0, "i":I
    :goto_1
    const/4 v1, 0x7

    if-ge v0, v1, :cond_c

    .line 128
    iget-object v1, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    const/4 v2, 0x0

    aput v2, v1, v0

    .line 127
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 130
    .end local v0    # "i":I
    :cond_c
    return-void
.end method

.method public getName()Ljava/lang/String;
    .registers 2

    .line 213
    iget-object v0, p0, Landroid/support/constraint/solver/SolverVariable;->mName:Ljava/lang/String;

    return-object v0
.end method

.method public final removeFromRow(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 9
    .param p1, "row"    # Landroid/support/constraint/solver/ArrayRow;

    .line 176
    iget v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 177
    .local v0, "count":I
    const/4 v1, 0x0

    move v2, v1

    .line 177
    .local v2, "i":I
    :goto_4
    if-ge v2, v0, :cond_2e

    .line 178
    iget-object v3, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v3, v3, v2

    if-ne v3, p1, :cond_2b

    .line 179
    nop

    .line 179
    .local v1, "j":I
    :goto_d
    sub-int v3, v0, v2

    add-int/lit8 v3, v3, -0x1

    if-ge v1, v3, :cond_24

    .line 180
    iget-object v3, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    add-int v4, v2, v1

    iget-object v5, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    add-int v6, v2, v1

    add-int/lit8 v6, v6, 0x1

    aget-object v5, v5, v6

    aput-object v5, v3, v4

    .line 179
    add-int/lit8 v1, v1, 0x1

    goto :goto_d

    .line 182
    .end local v1    # "j":I
    :cond_24
    iget v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    add-int/lit8 v1, v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 183
    return-void

    .line 177
    :cond_2b
    add-int/lit8 v2, v2, 0x1

    goto :goto_4

    .line 186
    .end local v2    # "i":I
    :cond_2e
    return-void
.end method

.method public reset()V
    .registers 3

    .line 197
    const/4 v0, 0x0

    iput-object v0, p0, Landroid/support/constraint/solver/SolverVariable;->mName:Ljava/lang/String;

    .line 198
    sget-object v0, Landroid/support/constraint/solver/SolverVariable$Type;->UNKNOWN:Landroid/support/constraint/solver/SolverVariable$Type;

    iput-object v0, p0, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    .line 199
    const/4 v0, 0x0

    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->strength:I

    .line 200
    const/4 v1, -0x1

    iput v1, p0, Landroid/support/constraint/solver/SolverVariable;->id:I

    .line 201
    iput v1, p0, Landroid/support/constraint/solver/SolverVariable;->definitionId:I

    .line 202
    const/4 v1, 0x0

    iput v1, p0, Landroid/support/constraint/solver/SolverVariable;->computedValue:F

    .line 203
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 204
    iput v0, p0, Landroid/support/constraint/solver/SolverVariable;->usageInRowCount:I

    .line 205
    return-void
.end method

.method public setName(Ljava/lang/String;)V
    .registers 2
    .param p1, "name"    # Ljava/lang/String;

    .line 216
    iput-object p1, p0, Landroid/support/constraint/solver/SolverVariable;->mName:Ljava/lang/String;

    return-void
.end method

.method public setType(Landroid/support/constraint/solver/SolverVariable$Type;Ljava/lang/String;)V
    .registers 3
    .param p1, "type"    # Landroid/support/constraint/solver/SolverVariable$Type;
    .param p2, "prefix"    # Ljava/lang/String;

    .line 218
    iput-object p1, p0, Landroid/support/constraint/solver/SolverVariable;->mType:Landroid/support/constraint/solver/SolverVariable$Type;

    .line 222
    return-void
.end method

.method strengthsToString()Ljava/lang/String;
    .registers 7

    .line 133
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "["

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 134
    .local v0, "representation":Ljava/lang/String;
    const/4 v1, 0x0

    .line 135
    .local v1, "negative":Z
    const/4 v2, 0x1

    .line 136
    .local v2, "empty":Z
    const/4 v3, 0x0

    .line 136
    .local v3, "j":I
    :goto_14
    iget-object v4, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    array-length v4, v4

    if-ge v3, v4, :cond_76

    .line 137
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v5, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    aget v5, v5, v3

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 138
    iget-object v4, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    aget v4, v4, v3

    const/4 v5, 0x0

    cmpl-float v4, v4, v5

    if-lez v4, :cond_37

    .line 139
    const/4 v1, 0x0

    goto :goto_40

    .line 140
    :cond_37
    iget-object v4, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    aget v4, v4, v3

    cmpg-float v4, v4, v5

    if-gez v4, :cond_40

    .line 141
    const/4 v1, 0x1

    .line 143
    :cond_40
    :goto_40
    iget-object v4, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    aget v4, v4, v3

    cmpl-float v4, v4, v5

    if-eqz v4, :cond_49

    .line 144
    const/4 v2, 0x0

    .line 146
    :cond_49
    iget-object v4, p0, Landroid/support/constraint/solver/SolverVariable;->strengthVector:[F

    array-length v4, v4

    add-int/lit8 v4, v4, -0x1

    if-ge v3, v4, :cond_62

    .line 147
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ", "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    goto :goto_73

    .line 149
    :cond_62
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "] "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 136
    :goto_73
    add-int/lit8 v3, v3, 0x1

    goto :goto_14

    .line 152
    .end local v3    # "j":I
    :cond_76
    if-eqz v1, :cond_89

    .line 153
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " (-)"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 155
    :cond_89
    if-eqz v2, :cond_9c

    .line 156
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " (*)"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 159
    :cond_9c
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .registers 4

    .line 229
    const-string v0, ""

    .line 233
    .local v0, "result":Ljava/lang/String;
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Landroid/support/constraint/solver/SolverVariable;->mName:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 235
    return-object v0
.end method

.method public final updateReferencesWithNewDefinition(Landroid/support/constraint/solver/ArrayRow;)V
    .registers 7
    .param p1, "definition"    # Landroid/support/constraint/solver/ArrayRow;

    .line 189
    iget v0, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 190
    .local v0, "count":I
    const/4 v1, 0x0

    move v2, v1

    .line 190
    .local v2, "i":I
    :goto_4
    if-ge v2, v0, :cond_16

    .line 191
    iget-object v3, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v3, v3, v2

    iget-object v3, v3, Landroid/support/constraint/solver/ArrayRow;->variables:Landroid/support/constraint/solver/ArrayLinkedVariables;

    iget-object v4, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquations:[Landroid/support/constraint/solver/ArrayRow;

    aget-object v4, v4, v2

    invoke-virtual {v3, v4, p1, v1}, Landroid/support/constraint/solver/ArrayLinkedVariables;->updateFromRow(Landroid/support/constraint/solver/ArrayRow;Landroid/support/constraint/solver/ArrayRow;Z)V

    .line 190
    add-int/lit8 v2, v2, 0x1

    goto :goto_4

    .line 193
    .end local v2    # "i":I
    :cond_16
    iput v1, p0, Landroid/support/constraint/solver/SolverVariable;->mClientEquationsCount:I

    .line 194
    return-void
.end method
