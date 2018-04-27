/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <openssl/sha.h>

typedef unsigned __int128 uint128_t;

#define TREE_DEPTH 15u
//#define TREE_DEPTH 5u
#define NUM_LISTS (1u << TREE_DEPTH)
#define TWEAKS_PER_BLOCK 100000u  // Big enough to keep lists maxed out
#define BLOCK_LEN 28
// The l value from David Wagner's generalized birthday attack.    It is the
// number of new 0's we need to see at each level.
#define LEN 16u
#define DIGEST_SIZE 32

struct Bignum_st {
    uint128_t L;  // Stores lower 80 bits
    uint128_t M;  // Stores middle 80 bits
    uint128_t H;  // Stores upper 96 bits
};

typedef struct Bignum_st Bignum;

uint8_t P[DIGEST_SIZE] = {
    0xc3, 0xb2, 0xdd, 0xb1, 0x74, 0x24, 0x0e, 0xa2,
    0x7e, 0x6a, 0xb7, 0xaf, 0xa7, 0xe0, 0x42, 0x4d,
    0x5f, 0x54, 0x68, 0x10, 0xf3, 0x6d, 0x52, 0xc6,
    0x35, 0x89, 0xb0, 0x1c, 0xab, 0xbb, 0xf5, 0xb4
};
Bignum bnP, bnHalfP;
Bignum bnTargetHash;  // Target hash we need to match.
Bignum bnTemp;  // Used in debugging
uint32_t startIndex;

typedef uint8_t Digest[DIGEST_SIZE];
struct List_st;
typedef struct List_st *List;
struct Entry_st;
typedef struct Entry_st *Entry;

struct List_st {
    uint32_t pos;
    uint32_t size;
    List parent;
    List left;
    List right;
    Bignum *data;
};

struct Entry_st {
    Bignum *bn;
    uint32_t nextEntryIndex;
};

static struct Entry_st *entries;
static uint32_t usedEntries, allocatedEntries;

// Hash tables are just an array of Entry.  We have two of them statically allocated.
static uint32_t *positiveTable;
static uint32_t *negativeTable;

static inline uint32_t entry2Index(Entry entry) {
    if (entry == NULL) {
        return 0;
    }
    return entry - entries;
}

static inline Entry index2Entry(uint32_t index) {
    if (index == 0) {
        return NULL;
    }
    return entries + index;
}

static inline void bignumZero(Bignum *A) {
    memset(A, 0, sizeof(Bignum));
}

static inline void bignumInit(Bignum *A, Digest digest) {
    bignumZero(A);
    memcpy(&(A->L), digest, 10);
    memcpy(&(A->M), digest + 10, 10);
    memcpy(&(A->H), digest + 20, 12);
}

static bool bignumGE(const Bignum *A, const Bignum *B) {
    if (A->H > B->H) {
        return true;
    } else if (A->H < B->H) {
        return false;
    }
    if (A->M > B->M) {
        return true;
    } else if (A->M < B->M) {
        return false;
    }
    if (A->L > B->L) {
        return true;
    } else if (A->L < B->L) {
        return false;
    }
    return true;
}

static bool bignumEQ(Bignum *A, Bignum *B) {
    return A->H == B->H && A->M == B->M && A->L == B->L;
}

// Compute A - B.  This assumes A >= B.
static void bignumSubtract(Bignum A, Bignum B, Bignum *R) {
    uint128_t one = 1;
    if (A.L < B.L) {
        A.L += one << 80;
        if (A.M == 0) {
            A.H--;
            A.M += one << 80;
        }
        A.M--;
    }
    if (A.M < B.M) {
        A.M += one << 80;
        A.H--;
    }
    R->L = A.L - B.L;
    R->M = A.M - B.M;
    R->H = A.H - B.H;
}

// Compute A + B.
static void bignumAdd(Bignum A, Bignum B, Bignum *R) {
    uint128_t one = 1;
    uint128_t mask = (one << 80) - 1;
    uint128_t val = A.L + B.L;
    uint128_t carry = val >> 80;
    R->L = val & mask;
    val = A.M + B.M + carry;
    carry = val >> 80;
    R->M = val & mask;
    R->H = A.H + B.H + carry;
}

// Compute A + B mod P.
static void bignumAddModP(Bignum A, Bignum B, Bignum *R) {
    bignumAdd(A, B, R);
    while (bignumGE(R, &bnP)) {
        bignumSubtract(*R, bnP, R);
    }
}

// Compute A - B mod P.
static void bignumSubtractModP(Bignum A, Bignum B, Bignum *R) {
    bignumAdd(A, bnP, &A);
    bignumSubtract(A, B, R);
    while (bignumGE(R, &bnP)) {
        bignumSubtract(*R, bnP, R);
    }
}

// Get a uint16_t value from a 256-bit Bignum.  Index can be 0 to 15.
static inline uint16_t bignumGetUint16(const Bignum *bn, uint32_t index) {
    if (index < 5) {
        return bn->L >> (index << 4);
    }
    if (index < 10) {
        return bn->M >> ((index - 5) << 4);
    }
    return bn->H >> ((index - 10) << 4);
}

static uint8_t hexCharToInt(char c) {
    if (c >= 'a') {
        return 10 + c - 'a';
    }
    return c - '0';
}

static char intToHexChar(uint8_t i) {
    if (i < 10) {
        return '0' + i;
    }
    return 'a' + i - 10;
}

// Write out a uint128_t in hex, with leading 0's if needed to fill the space.
static void dumpUint128(uint128_t val, uint32_t space) {
    int32_t i;
    for (i = (space - 1) * 4; i >= 0; i -= 4) {
        putchar(intToHexChar(((uint8_t)(val >> i)) & 0xf));
    }
}

// Print the bignum.
static void dumpBignum(const char *label, Bignum val) {
    if (label != NULL) {
        printf("%s: ", label);
    }
    dumpUint128(val.H, 24);
    dumpUint128(val.M, 20);
    dumpUint128(val.L, 20);
    printf("\n");
}

// Write the list to stdout.
static void dumpList(List list) {
    printf("Pos = %u, size = %u\n", list->pos, list->size);
    uint32_t i;
    for (i = 0; i < list->pos; i++) {
        printf("    ");
        dumpBignum(NULL, list->data[i]);
    }
}

// Set bnP and bnHalfP.
static void initP() {
    uint8_t halfP[DIGEST_SIZE];
    uint32_t i;
    for (i = 0; i < DIGEST_SIZE - 1; i++) {
        halfP[i] = (P[i] >> 1);
        if (P[i + 1] & 1) {
            halfP[i] |= 0x80;
        }
    }
    halfP[DIGEST_SIZE - 1] = P[DIGEST_SIZE - 1] >> 1;
    bignumInit(&bnP, P);
    bignumInit(&bnHalfP, halfP);
}

static void init(void) {
    usedEntries = 1;
    allocatedEntries = 1u << 17u;
    entries = calloc(allocatedEntries, sizeof(struct Entry_st));
    positiveTable = calloc(1u << LEN, sizeof(uint32_t));
    negativeTable = calloc(1u << LEN, sizeof(uint32_t));
    initP();
}

static Bignum hashBlock(uint8_t *data, uint32_t blockNum) {
    uint8_t block[DIGEST_SIZE];
    memcpy(block, data, BLOCK_LEN);
    uint32_t index = blockNum;
    memcpy(block + BLOCK_LEN, &index, sizeof(uint32_t));
    uint8_t digest[DIGEST_SIZE];
    SHA256(block, DIGEST_SIZE, digest);
    Bignum val;
    bignumInit(&val, digest);
    while (bignumGE(&val, &bnP)) {
        bignumSubtract(val, bnP, &val);
    }
    return val;
}

// Compute the hash of the file.
static Bignum computeHash(uint8_t *data, uint32_t blockOffset, uint32_t numBlocks, uint32_t fileLen) {
    Bignum sum;
    bignumZero(&sum);
    sum.L = fileLen;
    uint32_t i;
    for (i = blockOffset; i < numBlocks + blockOffset; i++) {
        Bignum hash = hashBlock(data + i*BLOCK_LEN, i);
        bignumAddModP(sum, hash, &sum);
    }
    return sum;
}

// Create a list.
static inline List listCreate(List left, List right) {
    List list = calloc(1, sizeof(struct List_st));
    list->size = TWEAKS_PER_BLOCK + 1000;
    list->data = calloc(list->size, sizeof(Bignum));
    list->left = left;
    list->right = right;
    if (left != NULL) {
        assert(right != NULL);
        assert(left != right);
        left->parent = list;
    }
    if (right != NULL) {
        right->parent = list;
        assert(left != NULL);
    }
    return list;
}

// Recursively destroy a list.
static inline void listDestroy(List list) {
    List parent = list->parent;
    if (list->left != NULL) {
        listDestroy(list->left);
    }
    if (list->right != NULL) {
        listDestroy(list->right);
    }
    if (parent != NULL) {
        if (parent->left == list) {
            parent->left = NULL;
        } else {
            assert(parent->right == list);
            parent->right = NULL;
        }
    }
    free(list->data);
    free(list);
}

// Append a Bignum to a list.
static inline void listAppendBignum(List list, Bignum *bn) {
    if (list->pos == list->size) {
        list->size <<= 1;
        list->data = realloc(list->data, list->size * sizeof(Bignum));
    }
    memcpy(list->data + list->pos++, bn, sizeof(Bignum));
}

// Create an Entry in a hash table.
static inline Entry entryCreate(uint32_t *table, uint32_t index, Bignum *bn, Entry next) {
    if (usedEntries == allocatedEntries) {
        allocatedEntries <<= 1;
        entries = realloc(entries, allocatedEntries*sizeof(struct Entry_st));
    }
    Entry entry = entries + usedEntries++;
    entry->bn = bn;
    entry->nextEntryIndex = table[index];
    table[index] = entry2Index(entry);
    return entry;
}

static void entryFreeAll(void) {
    usedEntries = 1;
}

static void clearTables(void) {
    memset(positiveTable, 0, (1u << LEN) * sizeof(uint32_t));
    memset(negativeTable, 0, (1u << LEN) * sizeof(uint32_t));
}

// Lookup an entry in the table.  Just get the index used at this depth, and return table[index].
static inline Entry lookupEntry(uint32_t *table, Bignum *bn, uint32_t depth) {
    // Only works for L == 16.
    uint16_t index = bignumGetUint16(bn, 16 - depth);
    return index2Entry(table[index]);
}

// Tweak a block in a deterministic way that still looks like hexidecimal.
static void tweakBlock(const uint8_t *data, uint32_t blockNum, uint32_t tweak, uint8_t *tweakedBlock) {
    memcpy(tweakedBlock, data + BLOCK_LEN*blockNum, BLOCK_LEN);
    memcpy(tweakedBlock + BLOCK_LEN, &blockNum, sizeof(uint32_t));
    uint32_t pos = 0;
    while (tweak != 0) {
        while (!isxdigit(tweakedBlock[pos])) {
            pos++;
        }
        uint8_t digitTweak = tweak & 0xf;
        tweak >>= 4;
        uint8_t digit = hexCharToInt(tweakedBlock[pos]);
        tweakedBlock[pos] = intToHexChar((digit + digitTweak) % 16);
        pos++;
    }
}

// Read the file into a buffer.
static uint8_t *readFile(const char *fileName, uint32_t *fileLen) {
    FILE *file = fopen(fileName, "r");
    if (file == NULL) {
        printf("Unable to open file %s\n", fileName);
        exit(1);
    }
    fseek(file, 0L, SEEK_END);
    *fileLen = ftell(file);
    rewind(file);
    // Pad the file with 0's to BLOCK_LEN.
    uint32_t roundedFileLen = ((*fileLen + BLOCK_LEN - 1) / BLOCK_LEN) * BLOCK_LEN;
    uint8_t *data = calloc(roundedFileLen, sizeof(uint8_t));
    assert(fread(data, 1, *fileLen, file) == *fileLen);
    fclose(file);
    return data;
}

// Write the file data.
static void writeFile(const char *fileName, const uint8_t *data, uint32_t fileLen) {
    FILE *file = fopen(fileName, "w");
    assert(fwrite(data, 1, fileLen, file) == fileLen);
    fclose(file);
}

static bool bignumIsPositive(const Bignum *val) {
    return bignumGE(&bnHalfP, val);
}

static inline void bignumAbs(const Bignum *val, Bignum *absVal) {
    if (bignumIsPositive(val)) {
        *absVal = *val;
    } else {
        bignumSubtract(bnP, *val, absVal);
    }
}

// Fill the positive and negative tables with digests from the list.
static void fillTables(List list, uint32_t depth) {
    entryFreeAll();
    clearTables();
    uint32_t i;
    for (i = 0; i < list->pos; i++) {
        Bignum *val = list->data + i;
        if (bignumIsPositive(val)) {
            // It is positive mod P.  Put it in positiveTable.
            uint16_t index = bignumGetUint16(val, 16 - depth);
            Entry next = index2Entry(positiveTable[index]);
            entryCreate(positiveTable, index, val, next);
        } else {
            // It is negative mod P.  Put it in negativeTable.
            // Compute the absolute value to find the index.
            Bignum absVal;
            bignumAbs(val, &absVal);
            uint16_t index = bignumGetUint16(&absVal, 16 - depth);
            Entry next = index2Entry(negativeTable[index]);
            entryCreate(negativeTable, index, val, next);
        }
    }
}

// This is a modification of regular GBA list union.  We wish for the new list
// to contain values that have (depth+1)*L 0's in their MSBs, when we take the
// absolute value, except at the root, where we want all 0's.
//
// To find pairs of hashes that when added mod P are close enough to 0, create
// two arrays of lists of hahes.  The first array lists positive sums by the
// next L bits to be zeroed.  The second array lists negations of negative sums
// by the next L bits to be zeroed.  After computing these arrays, for each sum
// in the second list, we add the elements in the appropriate array entry and
// add the results to the output list.
//
// prevZeros is the number of leading zeros in the absolute value of digests in
// both input lists.  newZeros is how many more zeros are required in the
// result list.
static List listUnion(List leftList, List rightList, uint32_t depth) {
    List l = listCreate(leftList, rightList);
    fillTables(leftList, depth);
    uint32_t i;
    for (i = 0; i < rightList->pos && (depth >= TREE_DEPTH - 1 || l->pos < TWEAKS_PER_BLOCK); i++) {
        Bignum *val = rightList->data + i;
        Entry entry;
        if (bignumIsPositive(val)) {
            entry = lookupEntry(negativeTable, val, depth);
        } else {
            Bignum absVal;
            bignumAbs(val, &absVal);
            entry = lookupEntry(positiveTable, &absVal, depth);
        }
        while (entry != NULL) {
            Bignum sum;
            bignumAddModP(*val, *(entry->bn), &sum);
            listAppendBignum(l, &sum);
            entry = index2Entry(entry->nextEntryIndex);
        }
    }
    return l;
}

// Find values in the left and right list that add to the collision.
static void findCollisionInLists(List leftList, List rightList, uint32_t depth, Bignum target,
        Bignum *leftVal, Bignum *rightVal) {
    fillTables(leftList, depth);
    uint32_t i;
    for (i = 0; i < rightList->pos; i++) {
        Bignum *val = rightList->data + i;
        Entry entry;
        if (bignumIsPositive(val)) {
            entry = lookupEntry(negativeTable, val, depth);
        } else {
            Bignum absVal;
            bignumAbs(val, &absVal);
            entry = lookupEntry(positiveTable, &absVal, depth);
        }
        while (entry != NULL) {
            Bignum sum;
            bignumAddModP(*val, *(entry->bn), &sum);
            if (bignumEQ(&sum, &target)) {
                *leftVal = *entry->bn;
                *rightVal = *val;
                return;
            }
            entry = index2Entry(entry->nextEntryIndex);
        }
    }
    assert(false);  // Should have found it!
}

// Compute the list union for 2^depth blocks.
static List computeTreeList(uint8_t *data, uint32_t blockNum, uint32_t depth, bool preserveLists) {
    List newList;
    if (depth > 0) {
        uint32_t numBlocks = 1 << depth;
        List leftList = computeTreeList(data, blockNum, depth - 1, preserveLists);
        List rightList = computeTreeList(data, blockNum + (numBlocks >> 1), depth - 1, preserveLists);
        newList = listUnion(leftList, rightList, depth);
        // To save memory, we collapse lists below TREE_DEPTH/2.
        if (!preserveLists && depth <= TREE_DEPTH/2) {
            listDestroy(leftList);
            listDestroy(rightList);
        }
    } else {
        static uint32_t count = 0;
        printf("block %u\n", count++);
        fflush(stdout);
        newList = listCreate(NULL, NULL);
        uint8_t tweakedBlock[32];
        uint32_t i;
        for (i = 0; i < TWEAKS_PER_BLOCK; i++) {
            tweakBlock(data, blockNum, i, tweakedBlock);
            Bignum val = hashBlock(tweakedBlock, blockNum);
            // We subtract the target value from the first block values.  When
            // we then find a total adding to 0, it actually adds to the target
            // value.
            if (blockNum == startIndex) {
                bignumSubtractModP(val, bnTargetHash, &val);
            }
            listAppendBignum(newList, &val);
        }
    }
    return newList;
}

// Rebuild the sub-tree.
static void rebuildSubTree(List list, uint8_t *data, uint32_t blockNum, uint32_t depth) {
    uint32_t numBlocks = 1 << depth;
    assert(list->right == NULL);
    list->left = computeTreeList(data, blockNum, depth - 1, true);
    list->left->parent = list;
    list->right = computeTreeList(data, blockNum + (numBlocks >> 1), depth - 1, true);
    list->right->parent = list;
}

// Print out the blocks below this list that caused the collision.
static void extractCollision(List list, uint8_t *data, uint32_t blockNum, uint32_t depth, Bignum target) {
    if (depth > 0) {
        bool rebuiltTree = false;
        if (list->left == NULL) {
            rebuildSubTree(list, data, blockNum, depth);
            rebuiltTree = true;
        }
        Bignum leftVal, rightVal;
        uint32_t numBlocks = 1 << depth;
        findCollisionInLists(list->left, list->right, depth, target, &leftVal, &rightVal);
        extractCollision(list->left, data, blockNum, depth - 1, leftVal);
        extractCollision(list->right, data, blockNum + (numBlocks >> 1), depth - 1, rightVal);
        if (rebuiltTree) {
            listDestroy(list->left);
            listDestroy(list->right);
        }
    } else {
        uint8_t tweakedBlock[DIGEST_SIZE];
        uint32_t i;
        for (i = 0; i < TWEAKS_PER_BLOCK; i++) {
            tweakBlock(data, blockNum, i, tweakedBlock);
            Bignum val = hashBlock(tweakedBlock, blockNum);
            // We subtract the target value from the first block values.  When
            // we then find a total adding to 0, it actually adds to the target
            // value.
            if (blockNum == startIndex) {
                bignumSubtractModP(val, bnTargetHash, &val);
            }
            if (bignumEQ(&val, &target)) {
                memcpy(data + BLOCK_LEN*blockNum, tweakedBlock, BLOCK_LEN);
                return;
            }
        }
        assert(false);
    }
}

// Find the smallest value in the list.
static Bignum findSmallestValueInList(List list) {
    Bignum smallestValue = bnP;
    uint32_t i;
    for (i = 0; i < list->pos; i++) {
        if (bignumGE(&smallestValue, list->data + i)) {
            smallestValue = list->data[i];
        }
    }
    return smallestValue;
}

int main() {
    init();
    uint32_t fileLen, newFileLen;
    uint8_t *data = readFile("../checker/farnsworth_fry_will", &fileLen);
    uint32_t numBlocks = (fileLen + BLOCK_LEN - 1) / BLOCK_LEN;
    Bignum originalHash = computeHash(data, 0, numBlocks, fileLen);
    dumpBignum("P", bnP);
    dumpBignum("originalHash", originalHash);
    data = readFile("solution_template", &newFileLen);
    if (fileLen != newFileLen) {
        fprintf(stderr, "Size of new and old wills differ!\n");
        return 1;
    }
    Bignum newHash = computeHash(data, 0, numBlocks, fileLen);
    dumpBignum("changedHash", newHash);
    Bignum delta;
    // We need to increase the hash value of the hashed range by delta.
    uint32_t start = (uint8_t*)strchr((char*)data, '1') - data;
    // Round up to first block in hex data.
    startIndex = (start + BLOCK_LEN - 1) / BLOCK_LEN;
    bignumSubtractModP(originalHash, newHash, &delta);
    Bignum rangeHash = computeHash(data, startIndex, 1 << TREE_DEPTH, 0);
    bignumAddModP(rangeHash, delta, &bnTargetHash);
    dumpBignum("The target hash in the range", bnTargetHash);
    List list = computeTreeList(data, startIndex, TREE_DEPTH, false);
    Bignum smallestValue = findSmallestValueInList(list);
    Bignum zero;
    bignumZero(&zero);
    if (bignumEQ(&smallestValue, &zero)) {
        printf("Found collision!\n");
    } else {
        printf("No collision found.  ");
        dumpBignum("Smallest value", smallestValue);
    }
    // Just in case this is a small test run, print the collision for the first
    // value in the list.
    extractCollision(list, data, startIndex, TREE_DEPTH, smallestValue);
    newHash = computeHash(data, 0, numBlocks, fileLen);
    dumpBignum("After extractCollision", newHash);
    Bignum hashCheck = computeHash(data, startIndex, 1 << TREE_DEPTH, 0);
    dumpBignum("hashCheck", hashCheck);
    bignumSubtractModP(hashCheck, bnTargetHash, &hashCheck);
    bignumAbs(&hashCheck, &hashCheck);
    dumpBignum("Final absolute value of hash of range - bnTarget", hashCheck);
    newHash = computeHash(data, 0, numBlocks, fileLen);
    dumpBignum("New hash of file", newHash);
    if (!bignumEQ(&newHash, &originalHash)) {
        printf("Hashes do not match!\n");
    }
    writeFile("farnsworth_bender_will", data, fileLen);
    (void)dumpList;  // Suppress unused function warning
    return 0;
}
