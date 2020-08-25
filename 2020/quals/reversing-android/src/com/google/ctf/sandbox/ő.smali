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

.class public Lcom/google/ctf/sandbox/ő;
.super Landroid/app/Activity;
.source "\u0151.java"

# instance fields
.field class:[J

.field ő:[J

.field ő:I

# direct methods
.method public constructor <init>()V
    .registers 15

    .line 11
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    :handler_1
    :try_start_1

    const/16 v0, 0xc
    new-array v1, v0, [J

    fill-array-data v1, :array_14

    iput-object v1, p0, Lcom/google/ctf/sandbox/ő;->class:[J

    .line 16
    new-array v0, v0, [J

    iput-object v0, p0, Lcom/google/ctf/sandbox/ő;->ő:[J

    .line 17
    const/4 v0, 0x0

    iput v0, p0, Lcom/google/ctf/sandbox/ő;->ő:I

    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :handler_1
    .catch Ljava/lang/Error; {:try_start_1 .. :try_end_1} :handler_1
    .catch I {:try_start_1 .. :try_end_1} :end

    goto/16 :end

    :try_start_2

    const/16 v0, 0xc

    :end
    return-void

    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :foofoo} :handler_1

    :array_14
    .array-data 8
        0x271986b
        0xa64239c9L
        0x271ded4b
        0x1186143
        0xc0fa229fL
        0x690e10bf
        0x28dca257
        0x16c699d1
        0x55a56ffd
        0x7eb870a1
        0xc5c9799fL
        0x2f838e65
    .end array-data

    :foofoo

.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 6
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 33
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 34
    const/high16 v0, 0x7f050000

    invoke-virtual {p0, v0}, Lcom/google/ctf/sandbox/ő;->setContentView(I)V

    .line 36
    const v0, 0x7f040006

    invoke-virtual {p0, v0}, Lcom/google/ctf/sandbox/ő;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/EditText;

    .line 37
    .local v0, "editText":Landroid/widget/EditText;
    const v1, 0x7f040015

    invoke-virtual {p0, v1}, Lcom/google/ctf/sandbox/ő;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    .line 38
    .local v1, "textView":Landroid/widget/TextView;
    const v2, 0x7f040002

    invoke-virtual {p0, v2}, Lcom/google/ctf/sandbox/ő;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroid/widget/Button;

    .line 39
    .local v2, "button":Landroid/widget/Button;
    new-instance v3, Lcom/google/ctf/sandbox/ő$1;

    invoke-direct {v3, p0, v0, v1}, Lcom/google/ctf/sandbox/ő$1;-><init>(Lcom/google/ctf/sandbox/ő;Landroid/widget/EditText;Landroid/widget/TextView;)V

    invoke-virtual {v2, v3}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 88
    return-void
.end method
