# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.class Lcom/google/ctf/sandbox/ő$1;
.super Ljava/lang/Object;
.source "\u0151.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/google/ctf/sandbox/ő;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/google/ctf/sandbox/ő;

.field final synthetic val$editText:Landroid/widget/EditText;

.field final synthetic val$textView:Landroid/widget/TextView;


# direct methods
.method constructor <init>(Lcom/google/ctf/sandbox/ő;Landroid/widget/EditText;Landroid/widget/TextView;)V
    .registers 4
    .param p1, "this$0"    # Lcom/google/ctf/sandbox/ő;

    .line 39
    iput-object p1, p0, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iput-object p2, p0, Lcom/google/ctf/sandbox/ő$1;->val$editText:Landroid/widget/EditText;

    iput-object p3, p0, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .registers 20
    .param p1, "v"    # Landroid/view/View;

    move-object/from16 v1, p0

    .line 42
    iget-object v2, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    const/4 v3, 0x0

    iput v3, v2, Lcom/google/ctf/sandbox/ő;->ő:I

    const/16 v2, 0x31

    const/4 v3, 0x0

    const/4 v4, 0x3

    const/4 v5, 0x2

    const/4 v6, 0x1

    const/4 v7, 0x4

    goto :try_start_d2

    :handler_22

    const/16 v2, 0x31

    :handler_2

    const/16 v2, 0x31

    const/4 v3, 0x0

    const/4 v4, 0x3

    const/4 v5, 0x2

    const/4 v6, 0x1

    const/4 v7, 0x4

    goto :catch_1f1

    :try_start_d

    .line 44
    const/16 v2, 0x31

    const/4 v3, 0x0

    const/4 v4, 0x3

    const/4 v5, 0x2

    const/4 v6, 0x1

    const/4 v7, 0x4

    :try_start_d2

    new-array v2, v2, [Ljava/lang/Object;

    const/16 v8, 0x41

    .line 45
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    aput-object v8, v2, v3

    const/16 v8, 0x70

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v6

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    aput-object v8, v2, v5

    const/16 v8, 0x61

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v4

    const/16 v9, 0x72

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v7

    const/4 v9, 0x5

    const/16 v10, 0x65

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    aput-object v10, v2, v9

    const/4 v9, 0x6

    const/16 v10, 0x6e

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    aput-object v11, v2, v9

    const/4 v9, 0x7

    const/16 v11, 0x74

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    aput-object v12, v2, v9

    const/16 v9, 0x8

    const/16 v12, 0x6c

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    aput-object v12, v2, v9

    const/16 v9, 0x9

    const/16 v12, 0x79

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    aput-object v12, v2, v9

    const/16 v9, 0xa

    const/16 v12, 0x20

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    aput-object v13, v2, v9

    const/16 v9, 0xb

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    aput-object v13, v2, v9

    const/16 v9, 0xc

    const/16 v13, 0x68

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    aput-object v14, v2, v9

    const/16 v9, 0xd

    const/16 v14, 0x69

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    aput-object v15, v2, v9

    const/16 v9, 0xe

    .line 46
    const/16 v15, 0x73

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0xf

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x10

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x11

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x12

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x13

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x14

    const/16 v3, 0x6f

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x15

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x16

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x17

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x18

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v9

    const/16 v9, 0x19

    const/16 v6, 0x65

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v9

    const/16 v6, 0x1a

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v6

    const/16 v6, 0x1b

    const/16 v9, 0x66

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v6

    const/16 v6, 0x1c

    const/16 v9, 0x6c

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v6

    const/16 v6, 0x1d

    .line 47
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v6

    const/16 v6, 0x1e

    const/16 v9, 0x67

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v16

    aput-object v16, v2, v6

    const/16 v6, 0x1f

    const/16 v5, 0x2e

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    aput-object v5, v2, v6

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    aput-object v5, v2, v12

    const/16 v5, 0x21

    const/16 v6, 0x57

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x22

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x23

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x24

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x25

    const/16 v6, 0x27

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x26

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x27

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x28

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x29

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x2a

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x2b

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x2c

    .line 48
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x2d

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    aput-object v6, v2, v5

    const/16 v5, 0x2e

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    aput-object v3, v2, v5

    const/16 v3, 0x2f

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    aput-object v5, v2, v3

    const/16 v3, 0x30

    const/16 v5, 0x3f

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    aput-object v5, v2, v3

    .line 49
    .local v2, "key":[Ljava/lang/Object;
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 50
    .local v3, "keyString":Ljava/lang/StringBuilder;
    array-length v5, v2

    const/4 v6, 0x0

    :goto_1bb
    if-ge v6, v5, :cond_1cc

    aget-object v8, v2, v6

    .line 51
    .local v8, "chr":Ljava/lang/Object;
    move-object v9, v8

    check-cast v9, Ljava/lang/Character;

    invoke-virtual {v9}, Ljava/lang/Character;->charValue()C

    move-result v9

    invoke-virtual {v3, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 50
    .end local v8    # "chr":Ljava/lang/Object;
    add-int/lit8 v6, v6, 0x1

    goto :goto_1bb

    .line 53
    :cond_1cc
    iget-object v5, v1, Lcom/google/ctf/sandbox/ő$1;->val$editText:Landroid/widget/EditText;

    invoke-virtual {v5}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1e8

    .line 54
    iget-object v5, v1, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    const-string v6, "\ud83d\udea9"

    invoke-virtual {v5, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    goto :goto_1ef

    .line 56
    :cond_1e8
    iget-object v5, v1, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    const-string v6, "\u274c"

    invoke-virtual {v5, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    :try_end_1ef
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_1ef} :handler_2
    .catch Ljava/lang/Error; {:try_start_d .. :try_end_1ef} :handler_2
    .catch J {:try_start_d .. :try_end_1ef} :handler_2

    .line 85
    .end local v2    # "key":[Ljava/lang/Object;
    .end local v3    # "keyString":Ljava/lang/StringBuilder;
    :goto_1ef
    goto/16 :goto_2ac

    .line 58
    :catch_1f1
    :try_start_2

    # move-exception v0
    # move-object v2, v0

    .line 60
    .local v2, "e":Ljava/lang/Exception;
    iget-object v3, v1, Lcom/google/ctf/sandbox/ő$1;->val$editText:Landroid/widget/EditText;

    invoke-virtual {v3}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v3

    .line 61
    .local v3, "flagString":Ljava/lang/String;
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v5

    const/16 v6, 0x30

    if-eq v5, v6, :cond_20d

    .line 62
    iget-object v4, v1, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    const-string v5, "\u274c"

    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 63
    return-void

    .line 65
    :cond_20d
    const/4 v5, 0x0

    .line 65
    .local v5, "i":I
    :goto_20e
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v6

    div-int/2addr v6, v7

    if-ge v5, v6, :cond_260

    .line 66
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v6, v6, Lcom/google/ctf/sandbox/ő;->ő:[J

    mul-int/lit8 v8, v5, 0x4

    add-int/2addr v8, v4

    invoke-virtual {v3, v8}, Ljava/lang/String;->charAt(I)C

    move-result v8

    shl-int/lit8 v8, v8, 0x18

    int-to-long v8, v8

    aput-wide v8, v6, v5

    .line 67
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v6, v6, Lcom/google/ctf/sandbox/ő;->ő:[J

    aget-wide v8, v6, v5

    mul-int/lit8 v10, v5, 0x4

    const/4 v11, 0x2

    add-int/2addr v10, v11

    invoke-virtual {v3, v10}, Ljava/lang/String;->charAt(I)C

    move-result v10

    shl-int/lit8 v10, v10, 0x10

    int-to-long v12, v10

    or-long/2addr v8, v12

    aput-wide v8, v6, v5

    .line 68
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v6, v6, Lcom/google/ctf/sandbox/ő;->ő:[J

    aget-wide v8, v6, v5

    mul-int/lit8 v10, v5, 0x4

    const/4 v12, 0x1

    add-int/2addr v10, v12

    invoke-virtual {v3, v10}, Ljava/lang/String;->charAt(I)C

    move-result v10

    shl-int/lit8 v10, v10, 0x8

    int-to-long v12, v10

    or-long/2addr v8, v12

    aput-wide v8, v6, v5

    .line 69
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v6, v6, Lcom/google/ctf/sandbox/ő;->ő:[J

    aget-wide v8, v6, v5

    mul-int/lit8 v10, v5, 0x4

    invoke-virtual {v3, v10}, Ljava/lang/String;->charAt(I)C

    move-result v10

    int-to-long v12, v10

    or-long/2addr v8, v12

    aput-wide v8, v6, v5

    .line 65
    add-int/lit8 v5, v5, 0x1

    goto :goto_20e

    .line 72
    .end local v5    # "i":I
    :cond_260
    const-wide v4, 0x100000000L

    .line 73
    .local v4, "m":J
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v7, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v7, v7, Lcom/google/ctf/sandbox/ő;->ő:[J

    iget-object v8, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v8, v8, Lcom/google/ctf/sandbox/ő;->ő:I

    aget-wide v8, v7, v8

    invoke-static {v8, v9, v4, v5}, Lcom/google/ctf/sandbox/R;->ő(JJ)[J

    move-result-object v6

    .line 74
    .local v6, "g":[J
    const/4 v7, 0x0

    aget-wide v7, v6, v7

    rem-long/2addr v7, v4

    add-long/2addr v7, v4

    rem-long/2addr v7, v4

    .line 75
    .local v7, "inv":J
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v9, v9, Lcom/google/ctf/sandbox/ő;->class:[J

    iget-object v10, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v10, v10, Lcom/google/ctf/sandbox/ő;->ő:I

    aget-wide v10, v9, v10

    cmp-long v9, v7, v10

    if-eqz v9, :cond_291

    .line 76
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    const-string v10, "\u274c"

    invoke-virtual {v9, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 77
    return-void

    .line 79
    :cond_291
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v10, v9, Lcom/google/ctf/sandbox/ő;->ő:I

    const/4 v11, 0x1

    add-int/2addr v10, v11

    iput v10, v9, Lcom/google/ctf/sandbox/ő;->ő:I

    .line 81
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v9, v9, Lcom/google/ctf/sandbox/ő;->ő:I

    iget-object v10, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v10, v10, Lcom/google/ctf/sandbox/ő;->ő:[J

    array-length v10, v10

    if-lt v9, v10, :cond_2ac

    .line 82
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    const-string v10, "\ud83d\udea9"

    invoke-virtual {v9, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 83
    return-void

    .line 86
    .end local v2    # "e":Ljava/lang/Exception;
    .end local v3    # "flagString":Ljava/lang/String;
    .end local v4    # "m":J
    .end local v6    # "g":[J
    .end local v7    # "inv":J
    :cond_2ac

    new-instance v8, Ljava/lang/RuntimeException;
    invoke-direct {v8}, Ljava/lang/RuntimeException;-><init>()V
    throw v8

    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :foofoo} :handler_2

    :goto_2ac
    return-void

    :array_14
    .array-data 8
        0x1
    .end array-data

    :foofoo
.end method
