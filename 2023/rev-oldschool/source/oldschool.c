// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ---------------------------------------------------------------------------------------
// ~ = ~ = ~ = Google CTF 2023 = ~ = ~ = ~
//
// Challenge Name: Old School
// Category      : Reversing
// Difficulty    : Medium
// Author        : ispo@
//
//
// NOTE: The code is intentionally not "clean" to make reversing harder.
// ---------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <form.h>
#include <assert.h>
#include <asm/unistd.h>
#include "strobf.h"


// Uncomment me to go into debug mode.
//#define __DEBUG__

#ifdef __DEBUG__
    int d_line = 0;
    #define LOG(...) mvprintw(nrows - ++d_line, 0, __VA_ARGS__)
#else
    #define LOG(...)
#endif

#define FATAL(msg)                                    \
    endwin();                                         \
    fprintf(stderr, OBF("[!] Error. %s\n"), OBF(msg));\
    /*fprintf(stderr, OBF("[!] Error. %s, %d\n"), OBF(msg), __LINE__);*/\
    exit(-1)

// Assertion macros. We use them to add annoying branches to the code.
#define ASSERT_EQ(expr, expected_val)                   \
    if ((expr) != (expected_val)) {                     \
        FATAL("ASSERT_EQ failed!");                     \
    }

#define ASSERT_NE(expr, expected_val)                   \
    if ((expr) == (expected_val)) {                     \
        FATAL("ASSERT_NE failed!");                     \
    }

/* Checks if debugger is present using ptrace (we can `ptrace` only once). */
#define CHECK_DEBUGGER                                                           \
    __asm__(                                                                     \
        ".intel_syntax noprefix;\n"                                              \
        "push ebx               \n" /* backup ebx */                             \
        "xor  ecx, ecx          \n"                                              \
        "movd eax, 0x22bc       \n" /* obfuscate syscall to confuse decompiler */\
        "cwd                    \n"                                              \
        "movd ebx, 0x156        \n" /* eax = 0x1a = ptrace */                    \
        "idiv bx                \n"                                              \
        "xor  ebx, ebx          \n" /* PTRACE_TRACEME */                         \
        "xor  edx, edx          \n"                                              \
        "or   dl, 1             \n"                                              \
        "xor  esi, esi          \n"                                              \
        "int  0x80              \n" /* do syscall */                             \
        "nop                    \n"                                              \
        /* eax is 0 or -1 (-1 mean debugger precense) */                         \
        "neg  eax               \n" /* -1 ~> 0, 0 ~> 1 */                        \
        "movd %0, eax           \n" /* store result */                           \
        "pop  ebx               \n"                                              \
        ".att_syntax noprefix;  \n"                                              \
        : "=r" (is_debugged)                                                     \
    )

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define SKULL_MAX_LEN 41
#define SKULL_HEIGHT 26
#define GAP 5
#define BANNER_LEN 65
#define BANNER_HEIGHT 18
#define PWD_BUFLEN 64

int is_debugged = 0;

char *skull[] = {
        strdup(OBF("                uuuuuuu")),
        strdup(OBF("             uu$$$$$$$$$$$uu")),
        strdup(OBF("          uu$$$$$$$$$$$$$$$$$uu")),
        strdup(OBF("         u$$$$$$$$$$$$$$$$$$$$$u")),
        strdup(OBF("        u$$$$$$$$$$$$$$$$$$$$$$$u")),
        strdup(OBF("       u$$$$$$$$$$$$$$$$$$$$$$$$$u")),
        strdup(OBF("       u$$$$$$$$$$$$$$$$$$$$$$$$$u")),
        strdup(OBF("       u$$$$$$'   '$$$'   '$$$$$$u")),
        strdup(OBF("       '$$$$'      u$u       $$$$'")),
        strdup(OBF("        $$$u       u$u       u$$$")),
        strdup(OBF("        $$$u      u$$$u      u$$$")),
        strdup(OBF("         '$$$$uu$$$   $$$uu$$$$'")),
        strdup(OBF("          '$$$$$$$'   '$$$$$$$'")),
        strdup(OBF("            u$$$$$$$u$$$$$$$u")),
        strdup(OBF("             u$'$'$'$'$'$'$u")),
        strdup(OBF("  uuu        $$u$ $ $ $ $u$$       uuu")),
        strdup(OBF(" u$$$$        $$$$$u$u$u$$$       u$$$$")),
        strdup(OBF("  $$$$$uu      '$$$$$$$$$'     uu$$$$$$")),
        strdup(OBF("u$$$$$$$$$$$uu    '''''    uuuu$$$$$$$$$$")),
        strdup(OBF("$$$$'''$$$$$$$$$$uuu   uu$$$$$$$$$'''$$$'")),
        strdup(OBF(" '''      ''$$$$$$$$$$$uu ''$'''")),
        strdup(OBF("           uuuu ''$$$$$$$$$$uuu")),
        strdup(OBF("  u$$$uuu$$$$$$$$$uu ''$$$$$$$$$$$uuu$$$")),
        strdup(OBF("  $$$$$$$$$$''''           ''$$$$$$$$$$$'")),
        strdup(OBF("   '$$$$$'                      ''$$$$''")),
        strdup(OBF("     $$$'                         $$$$'"))
};

const char *banner[] = {
       strdup(OBF(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::")),
       strdup(OBF("::'######::::'#######:::'#######:::'######:::'##:::::::'########:")),
       strdup(OBF(":'##... ##::'##.... ##:'##.... ##:'##... ##:: ##::::::: ##.....::")),
       strdup(OBF(": ##:::..::: ##:::: ##: ##:::: ##: ##:::..::: ##::::::: ##:::::::")),
       strdup(OBF(": ##::'####: ##:::: ##: ##:::: ##: ##::'####: ##::::::: ######:::")),
       strdup(OBF(": ##::: ##:: ##:::: ##: ##:::: ##: ##::: ##:: ##::::::: ##...::::")),
       strdup(OBF(": ##::: ##:: ##:::: ##: ##:::: ##: ##::: ##:: ##::::::: ##:::::::")),
       strdup(OBF(":. ######:::. #######::. #######::. ######::: ########: ########:")),
       strdup(OBF("::......:::::.......::::.......::::......::::........::........::")),
       strdup(OBF("::::::'######::'########:'########:::::'#######:::'#######:::::::")),
       strdup(OBF(":::::'##... ##:... ##..:: ##.....:::::'##.... ##:'##.... ##::::::")),
       strdup(OBF("::::: ##:::..::::: ##:::: ##::::::::::..::::: ##:..::::: ##::::::")),
       strdup(OBF("::::: ##:::::::::: ##:::: ######:::::::'#######:::'#######:::::::")),
       strdup(OBF("::::: ##:::::::::: ##:::: ##...:::::::'##:::::::::...... ##::::::")),
       strdup(OBF("::::: ##::: ##:::: ##:::: ##:::::::::: ##::::::::'##:::: ##::::::")),
       strdup(OBF(":::::. ######::::: ##:::: ##:::::::::: #########:. #######:::::::")),
       strdup(OBF("::::::......::::::..:::::..:::::::::::.........:::.......::::::::")),
       strdup(OBF(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"))
};

/** 5-bit sbox from Shamash algorithm. */
// https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/round-1/spec-doc/ShamashAndShamashash-spec.pdf
const int sbox[32] = {
    16, 14, 13, 2,  11, 17, 21, 30,
    7,  24, 18, 28, 26, 1,  12,  6, 
    31, 25, 0,  23, 20, 22, 8,  27,
    4,  3,  19, 5,  9,  10, 29, 15
};

/* 5-bit (almost) constant array for XOR. */
// Generated using: numpy.random.permutation(32)
// Based on debugger presence, the values get slightly modified.
int xor_array[32] = {
    25,  2,  8, 15, 10, 26, 13, 30,
     4,  5, 16,  7, 14,  0,  6, 31,
    29, 11, 17,  3, 28, 19,  9, 20,
    27, 21,  1, 12, 24, 22, 23, 18
};

/* 3 element bit indices to construct Feistel key.*/
// Generated using: random.sample(range(0, 27), 3))
// Based on debugger presence, we select different triples as indices. 
int feistel_key_triplets[32][3] = {
    { 3, 10, 22},
    { 4, 12, 16},
    {20, 13, 22},
    {13, 22, 19},
    {14, 13, 12},
    {23,  7, 19},
    {14, 20,  1},
    {11,  7, 24},
    {25, 11, 13},
    { 8, 9,   1},
    {12, 7,  20},
    {21, 19, 16},
    { 6, 23,  7},
    {10, 18, 17},
    { 2, 11,  4},
    { 3, 10, 12},
    { 5, 26,  8},
    { 6, 15,  4},
    {10,  0, 15},
    { 1, 14,  9},
    {11,  7,  1},
    {25,  1, 23},
    { 1,  9, 24},
    {15, 23, 19},
    {16, 22, 15},
    {12,  4, 23},
    {19, 24,  5},
    {19,  8, 13},
    {18,  1, 21},
    { 7,  4, 19},
    {25,  8, 17},
    {14,  6, 23}
};

int lcg_seed = 31337;

/** Prints skull and banner in the center of the screen. */
int print_skull_n_banner(int nrows, int ncols) {
/* Quick implementation of string.replace(). */
#define REPLACE(str, chr, rep) {        \
    for (int _=0; str[_]!=0; ++_) {     \
        if (str[_] == chr) str[_] = rep;\
    }                                   \
}
    ASSERT_EQ(attron(A_BOLD), OK);

    // Sanity check. Ensure that skull & banner fit in the screen.
    if ((ncols < SKULL_MAX_LEN + BANNER_LEN + 5) ||
         nrows < SKULL_HEIGHT + 2) {
        return -1;  // Error.
    }
        
    int x_s = (ncols - SKULL_MAX_LEN - BANNER_LEN - 5) / 2;
    int y_s = (nrows - SKULL_HEIGHT) / 2 - 15;
    int x_b = x_s + SKULL_MAX_LEN + GAP;
    int y_b = (nrows - BANNER_HEIGHT) / 2 - 15;

    if (x_s < 0 || y_s < 0 || x_b < 0 || y_b < 0) {
        return -1;  // Error.
    }
    /* Print skull line by line. Substitute single quotes with double ones. */
    for (int i=0; i<sizeof(skull) / sizeof(const char *); ++i) {
        REPLACE(skull[i], '\'','"');
        ASSERT_EQ(mvprintw(y_s++, x_s, OBF("%s"), skull[i]), OK);
    }

    // Debugger Check #1.
    // CHECK_DEBUGGER;
    if (is_debugged) {
        // Debugger detected. Modify LCG seed.
        lcg_seed += 7;
    }

    /* Now print banner line by line, next to skull. */
    for (int i=0; i<sizeof(banner) / sizeof(const char *); ++i) {
        ASSERT_EQ(mvprintw(y_b++, x_b, OBF("%s"), banner[i]), OK);
    }

    ASSERT_EQ(attroff(A_BOLD), OK);
    return MAX(y_s, y_b);
#undef REPLACE
}


/** Validates a username/password combination. */
int authenticate(char *usr, char *pwd, int nrows, int ncols) {
#define PRINT_ARR(a)                                        \
    for (int _=4; _>=0; --_) {                              \
        LOG("%d ~> %2d %2d %2d %2d %2d",                    \
            _, a[_][0], a[_][1], a[_][2], a[_][3], a[_][4]);\
    }
            
    int i, j, k, l;  // Iterators.

    /* ~ = ~ = ~ = Step #1: Password Sanity Checks & Matrix Transformation = ~ = ~ = ~ */

    // Check password format: Must be in the 5x5 serial key format:
    // XXXXX-YYYYY-ZZZZZ-WWWWW-KKKKK.
    //
    // Allowed charset (5-bit): 23456789ABCDEFGHJKLMNPQRSTUVWXYZ
    //
    // Then transform password onto a 5x5 5-bit matrix `pwmat`.

    // Testing only.
    /*
    strcpy(usr, "ispoleetmoreyeah1338");
    strcpy(pwd, "D78UE-UJF6Y-VLYWY-X2F8J-STPA3");

    strcpy(usr, "AUeAFPvcVgsKEwigvYCV");
    strcpy(pwd, "8UTWY-ZF6B9-HXSDD-ZFSSD-TNAA5");
    
    strcpy(usr, "HBBRIZfprBYDWLZOIaAd");
    strcpy(pwd, "NLGEL-NF9ZR-PFBFY-2QQP9-U88ZB");
    */

    if (strlen(pwd) != 29) {
        return 0;  // A value of 0 indicates failure.
    }

    int pwmat[5][5] = {0};

    for (i=0, j=0; pwd[i]; ++i) {
        if (i == 5 || i == 11 || i == 17 || i == 23) {
            if (pwd[i] == '-') {
                continue;  // Skip dashes.
            } else {
                return 0;  // Password is malformed.
            }
        }

        // We start with matrix conversion to obscure algorithm.
        // Use the index of the allowed charset as the initial matrix value.
        bool found = false;
        for (k=0; k<32; ++k) {        
            if (OBF("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")[k] == pwd[i]) {
                pwmat[j / 5][j++ % 5] = k;
                found = true;
                break;
            }
        }

        if (!found) {
            return 0;  // We hit an invalid character.
        }
    }
   
    LOG("Password sanity check passed successfully");

    /* ~ = ~ = ~ = Step #2: Process username = ~ = ~ = ~ */

    // Split username into groups of 4 characters. Each character is 7-bits
    // so we get a 28-bit number. We use 25-bits to get 3 numbers in the matrix
    // and the remaining 3-bits as a key for the Fiestel network.
    int feistel_key = 0;
    int p = lcg_seed;
    int usrmat[5][16] = {0};
    int usrcols = 0;
    int keylen = 0;

    for (i=0; i<strlen(usr); i+=4) {
        int b = 0;
        for (j=0; j<4; ++j) {
            if (i + j == strlen(usr)) {
                break;  // We reached the end of the username.
            }

            b = (b << 7) | (usr[i + j] & 0x7f);
        }
    
        // Select 3 bits to serve as a key for the Feistel Network.        
        for (k=0; k<3; ++k) {
            int q = feistel_key_triplets[p % 32][k];
            feistel_key = (feistel_key << 1) | ((b & (1 << q)) >> q);
        }
        // Delete q-th bits from `b`.
        for (k=0; k<3; ++k) {
            int q = feistel_key_triplets[p % 32][k];
            b = ((b >> (q + 1)) << q) | (b & ((1 << q) - 1));            
        }

        keylen += 3;

        // At this point b should be 25-bits.
        
        // Update triplet index using an LCG.
        //
        // The next triplet that we will select depends on the current value.
        // That is, to reverse this you have to work backwards.        
        for (k=0; k<1 + (feistel_key & 7); ++k) {
            p = (8121 * p + 28411) % 134456;
        }

        // Use the remaining bits as the next column in the user matrix.
        for (k=0; k<5; ++k, b>>=5) {
            usrmat[usrcols][k] = ~b & 0x1F; 
        }

        ++usrcols;
    }

    if (keylen > 32 || usrcols < 5) {
        return 0;  // We have an overflow.
    }

    LOG("Transformed username matrix:");
    PRINT_ARR(usrmat);

    LOG("Feistel Key: 0x%X", feistel_key);

// Helper functions for Feistel's Round function.
#define ROL(n, c, b) (((n) << (c)) | ((n) >> ((b) - (c)))) & ((1 << (b)) - 1)
// Round function for Feistel.
#define F(r, k) ROL(r, 3, 15) ^ ~ROL(k, 1, keylen)

    // Part 2.2: Apply 13 rounds of a Feistel network in each column.
    for (i=0; i<usrcols; ++i) {
        // Use the first 12-bits in L and the last 13-bits in R.        
        int L = usrmat[0][i] | (usrmat[1][i] << 5) | ((usrmat[2][i] & 3) << 10);
        int R = ((usrmat[2][i] & 0x1C) >> 2) | (usrmat[3][i] << 3) | (usrmat[4][i] << 8);

        for (j=0; j<13; ++j) {
            int t = L ^ F(R, feistel_key);        
            L = R & 0x7FFF;
            R = t & 0x7FFF;
        }

        usrmat[0][i] = L & 0x1F;
        usrmat[1][i] =  (L >>  5) & 0x1F;
        usrmat[2][i] = ((L >> 10) & 0x3) | (R & 0x1C);
        usrmat[3][i] = (R >>   5) & 0x1F;
        usrmat[4][i] = (R >>  10) & 0x1F;
    }
#undef F
#undef ROL

    LOG("Username matrix after Feistel Network:");
    PRINT_ARR(usrmat);

    /* ~ = ~ = ~ = Step #3: Process password = ~ = ~ = ~ */
    
    // Part 3.1: Apply S-Box.
    for (i=0; i<5; ++i) {
        for (j=0; j<5; ++j) {
            pwmat[i][j] = sbox[pwmat[i][j]];
        }
    }

    // Part 3.2: XOR.
    for (i=0; i<5; ++i) {
        // Optional: Add bogus code to confuse the reverser.
        for (j=0; j<5; ++j) {
            pwmat[i][j] ^= xor_array[i*5 + j];
        }
    }

    // Part 3.3: Shift rows by 0, 1, 2, 3 and 4 slots respectively.
    for (i=1; i<5; ++i) {
        int tmp[i] = {0};

        for (j=0; j<i; ++j) {
            tmp[j] = pwmat[i][j];
        }

        for (j=i; j<5; ++j) {
            pwmat[i][j - i] = pwmat[i][j];
        }
        
        for (j=5-i; j<5; ++j) {
            pwmat[i][j] = tmp[j - 5 + i];
        }
    }

    LOG("Transformed password matrix:");
    PRINT_ARR(pwmat);

    /* ~ = ~ = ~ = Step #4: Multiply matrices = ~ = ~ = ~ */
    for (i=0; i<5; ++i) {
        for (j=0; j<usrcols; ++j) {
            int d = 0;
      
            for (k=0; k<5; ++k) {
                d = (d + usrmat[i][k] * pwmat[k][j]) & 0x1F;
            }
            // LOG("Matrix Mult at: (%d, %d) ~> %d", i, j, d);
            if (i == j && d != 1 || i != j && d) {
                return 0;  // Not the identity matrix.
            }
        }
    }

    return 1;  // Product is I. Verification successful.

#undef PRINT_ARR
}


int main(int argc, char **argv) {
    /* Do the required initializations. */
    ASSERT_NE(initscr(), NULL);

    /* Initialize curses. */
    ASSERT_EQ(cbreak(), OK);
    ASSERT_NE(curs_set(0), ERR);
    ASSERT_EQ(noecho(), OK);
    ASSERT_EQ(keypad(stdscr,TRUE), OK);

    if(has_colors() == FALSE) {
        FATAL("Terminal does not support color");
    }

    /* Initialize colors. */     
    ASSERT_EQ(start_color(), OK);
    ASSERT_EQ(init_pair(1, COLOR_YELLOW | 8, COLOR_BLUE), OK);
    ASSERT_EQ(init_pair(2, COLOR_RED, COLOR_BLACK | 8), OK);
    ASSERT_EQ(init_pair(3, COLOR_BLACK, COLOR_BLACK | 8), OK);
    ASSERT_EQ(init_pair(4, COLOR_WHITE, COLOR_BLACK | 8), OK);
    ASSERT_EQ(init_pair(5, COLOR_WHITE, COLOR_BLACK), OK);
    ASSERT_EQ(init_pair(6, COLOR_YELLOW, COLOR_BLUE), OK);
    ASSERT_EQ(init_pair(7, COLOR_BLUE, COLOR_YELLOW), OK);
    ASSERT_EQ(init_pair(8, COLOR_WHITE, COLOR_RED), OK);
    ASSERT_EQ(init_pair(9, COLOR_BLACK, COLOR_GREEN), OK);
    ASSERT_EQ(bkgd(COLOR_PAIR(1)), OK);

    /* Get the number of rows and columns on the screen. */
    int nrows, ncols;

    getmaxyx(stdscr, nrows, ncols);

    LOG("Screen has %d rows and %d columns", nrows, ncols);

    int r = print_skull_n_banner(nrows, ncols);      
    if (r < 0) {
        FATAL("Terminal is too small");
    }

    /* Draw the login window and its shadow. */
    const int w = 60, h = 17;
    int y = r + 2, x = (ncols - w) / 2;
    WINDOW* win;

    if ((win = newwin(h, w, y, x)) == NULL) {
        FATAL("Cannot create login window");
    }

/* We now have a new variable that needs to be dtor'ed upon FATAL. Redefine it using pragma. */
#pragma push_macro("FATAL") 
#undef FATAL
#define FATAL(msg)                             \
    delwin(win);                               \
    _Pragma("pop_macro(\"FATAL\")") FATAL(msg)

    ASSERT_EQ(wbkgd(win, A_NORMAL | COLOR_PAIR(4) | ' '), OK);

    // Draw the shadow (the stackoverflow way).
    ASSERT_EQ(attron(COLOR_PAIR(5)), OK);
    for(int i=x + 2; i<x + w + 1; ++i) {
        ASSERT_EQ(move(y + h, i), OK);
        ASSERT_EQ(addch(' '), OK);
    }

    // Check for debugger and set `is_debugged` global.
    CHECK_DEBUGGER;

    for(int i=y + 1; i<y + h + 1; ++i) {
        ASSERT_EQ(move(i, x + w), OK);
        ASSERT_EQ(addch(' '), OK);
        ASSERT_EQ(move(i, x + w + 1), OK);
        ASSERT_EQ(addch(' '), OK);

        // Debugger Check #2.
        if (is_debugged) {
            // Debugger detected. Flip the wrong bit.
            for (int q=0; q<32; ++q) {
                xor_array[q] ^= 0x4;
            }            
        } else {
            for (int q=0; q<32; ++q) {
                xor_array[q] ^= 0x2;  // Flip the correct bit.
            }
        }
    }

    ASSERT_EQ(attroff(COLOR_PAIR(5)), OK);

    /* Draw the forms in inside the window. */
    WINDOW *win_body, *win_form;

    if ((win_body = newwin(h, w, r + 2, (ncols - w) / 2)) == NULL ||
        (win_form = derwin(win_body, 7, w - 2, 3, 1)) == NULL) {
        FATAL("Cannot create internal window");
    }

#pragma push_macro("FATAL")  // Extend FATAL
#undef FATAL
#define FATAL(msg)                             \
    delwin(win_body);                          \
    delwin(win_form);                          \
    _Pragma("pop_macro(\"FATAL\")") FATAL(msg)

    ASSERT_EQ(box(win_body, 0, 0), OK);
    ASSERT_EQ(box(win_form, 0, 0), OK);
    ASSERT_EQ(wbkgd(win_body, A_NORMAL | COLOR_PAIR(4) | ' '), OK);
    ASSERT_EQ(wbkgd(win_form, A_NORMAL | COLOR_PAIR(4) | ' '), OK);
    ASSERT_EQ(mvwprintw(win_body, 2, 2, OBF("Welcome to our Old School System. Authenticate yourself:")), OK);
    ASSERT_EQ(mvwprintw(win_body, 0, (w - 24) / 2, OBF(" Authorization Required ")), OK);

    // Create the form fields.
    FIELD *fields[7];
    FORM  *my_form;
    int ch;

    if ((fields[0] = new_field(1, 10, 1, 1,  0, 0)) == NULL ||
        (fields[1] = new_field(1, 44, 1, 11, 0, 0)) == NULL ||
        (fields[2] = new_field(1, 10, 3, 1,  0, 0)) == NULL ||
        (fields[3] = new_field(1, 44, 3, 11, 0, 0)) == NULL ||
        /**
         *  Create 2 tiny invisible fields of size 1x1 to be in sync with the buttons.
         */
        (fields[4] = new_field(1, 1,  2, 11, 0, 0)) == NULL ||
        (fields[5] = new_field(1, 1,  2, 13, 0, 0)) == NULL) {
        FATAL("Cannot create form fields");
    }
    
    fields[6] = NULL;

#pragma push_macro("FATAL")
#undef FATAL
#define FATAL(msg)                             \
    free_field(fields[0]);                     \
    free_field(fields[1]);                     \
    free_field(fields[2]);                     \
    free_field(fields[3]);                     \
    free_field(fields[4]);                     \
    free_field(fields[5]);                     \
    _Pragma("pop_macro(\"FATAL\")") FATAL(msg)

    ASSERT_EQ(set_field_buffer(fields[0], 0, OBF("Username:")), OK);
    ASSERT_EQ(set_field_buffer(fields[2], 0, OBF("Password:")), OK);

    ASSERT_EQ(set_field_opts(fields[0], O_VISIBLE | O_PUBLIC | O_AUTOSKIP), OK);
    ASSERT_EQ(set_field_opts(fields[1], O_VISIBLE | O_PUBLIC | O_EDIT | O_ACTIVE), OK);
    ASSERT_EQ(set_field_opts(fields[2], O_VISIBLE | O_PUBLIC | O_AUTOSKIP), OK);
    ASSERT_EQ(set_field_opts(fields[3], O_VISIBLE | O_PUBLIC | O_EDIT | O_ACTIVE), OK);
    ASSERT_EQ(set_field_opts(fields[4], O_VISIBLE | O_PUBLIC | O_ACTIVE), OK);
    ASSERT_EQ(set_field_opts(fields[5], O_VISIBLE | O_PUBLIC | O_ACTIVE), OK);

    ASSERT_EQ(set_field_back(fields[1], COLOR_PAIR(5)), OK);
    ASSERT_EQ(set_field_back(fields[3], COLOR_PAIR(5)), OK);
    ASSERT_EQ(set_field_back(fields[0], COLOR_PAIR(4)), OK);
    ASSERT_EQ(set_field_back(fields[2], COLOR_PAIR(4)), OK);
    ASSERT_EQ(set_field_back(fields[4], COLOR_PAIR(3)), OK); // Make it invisible.
    ASSERT_EQ(set_field_back(fields[5], COLOR_PAIR(3)), OK); // Make it invisible.

    FORM *form;
    if ((form = new_form(fields)) == NULL) {
        FATAL("Cannot create form");
    }

    ASSERT_EQ(set_form_win(form, win_form), OK);
    ASSERT_EQ(set_form_sub(form, derwin(win_form, 5, w - 4, 1, 1)), OK);
    ASSERT_EQ(post_form(form), OK);

#pragma push_macro("FATAL")
#undef FATAL
#define FATAL(msg)                             \
    unpost_form(form);                         \
    free_form(form);                           \
    _Pragma("pop_macro(\"FATAL\")") FATAL(msg)

    /* Create the login button. */
    WINDOW *win_button_login, *win_shadow_login;

    if ((win_button_login = derwin(win_body, 3, 13, 11, 15)) == NULL ||
        (win_shadow_login = derwin(win_body, 3, 13, 11 + 1, 15 + 1)) == NULL) {
        FATAL("Cannot create login button");
    }

#pragma push_macro("FATAL")
#undef FATAL
#define FATAL(msg)                             \
    delwin(win_button_login);                  \
    delwin(win_shadow_login);                  \
    _Pragma("pop_macro(\"FATAL\")") FATAL(msg)

    ASSERT_EQ(wbkgd(win_button_login, A_BOLD | COLOR_PAIR(6) | ' '), OK);
    ASSERT_EQ(wbkgd(win_shadow_login, COLOR_PAIR(5) | ' '), OK);
    ASSERT_EQ(mvwprintw(win_button_login, 1, 4, OBF("Login")), OK);

    /* Create exit buttons. */
    WINDOW *win_button_exit, *win_shadow_exit;

    if ((win_button_exit = derwin(win_body, 3, 12, 11, 32)) == NULL ||
        (win_shadow_exit = derwin(win_body, 3, 12, 11 + 1, 32 + 1)) == NULL) {
        FATAL("Cannot create exit button");
    }

#pragma push_macro("FATAL")
#undef FATAL
#define FATAL(msg)                             \
    delwin(win_button_exit);                   \
    delwin(win_shadow_exit);                   \
    _Pragma("pop_macro(\"FATAL\")") FATAL(msg)

    ASSERT_EQ(wbkgd(win_button_exit, A_BOLD | COLOR_PAIR(6) | ' '), OK);
    ASSERT_EQ(wbkgd(win_shadow_exit, COLOR_PAIR(5) | ' '), OK);
    ASSERT_EQ(mvwprintw(win_button_exit, 1, 4, OBF("Exit")), OK);

    // Refresh everything to appear on the screen.
    ASSERT_EQ(refresh(), OK);
    ASSERT_EQ(wrefresh(win_body), OK);
    ASSERT_EQ(wrefresh(win_form), OK);
    ASSERT_EQ(wrefresh(win_button_login), OK);
    ASSERT_EQ(wrefresh(win_shadow_login), OK);
    ASSERT_EQ(wrefresh(win_button_exit), OK);
    ASSERT_EQ(wrefresh(win_shadow_exit), OK);


    // TODO(ispo): Inject some flag-related computations here, so if reversers bypass this,
    // it will fail to analyze. Use a precomputed table and  add an anti-re check here to
    // modify this table.

    // Enable key pad inside the login window.
    ASSERT_EQ(keypad(win_form, TRUE), OK);
    ASSERT_NE(curs_set(2), ERR)
    ASSERT_EQ(move(r + 2 + 5, (ncols - w) / 2 + 11 + 2), OK);
    
    /* Loop that implements form and buttons logic. */
    int usr_cnt = 0, pwd_cnt = 0;
    char password[PWD_BUFLEN + 1] = {0};
    bool halt = false;

    while(!halt && (ch = getch()) != KEY_F(9)) {  // Exit with F9 and activate backdoor.
        switch(ch) {
            /* Up and down arrows move you to the previous and next fields */
            case KEY_UP:
                ASSERT_NE(form_driver(form, REQ_PREV_FIELD), ERR);
                // Go to the end of the previous buffer.
                ASSERT_NE(form_driver(form, REQ_END_LINE), ERR);
                break;
            case KEY_DOWN:
            case KEY_STAB:  // Tab is an alias for down.
            case '\t':
                ASSERT_NE(form_driver(form, REQ_NEXT_FIELD), ERR);
                ASSERT_NE(form_driver(form, REQ_END_LINE), ERR);
                break;
            /* Left and right arrows move you inside the buffer, as long as there is space. */
            case KEY_LEFT:
                ASSERT_NE(form_driver(form, REQ_PREV_CHAR), ERR);
                break;
            case KEY_RIGHT:
                ASSERT_NE(form_driver(form, REQ_NEXT_CHAR), ERR);
                break;
            /* Enter key used to click the buttons or act as a down arrow. */
            case KEY_ENTER:
            case 10:
                if (form->current == fields[1] || form->current == fields[3]) {
                    ASSERT_NE(form_driver(form, REQ_NEXT_FIELD), ERR);
                    ASSERT_NE(form_driver(form, REQ_END_LINE), ERR);
                } else if (form->current == fields[4]) {
                    /* Login button clicked. */

                    // Debugger Check #3.
                    // CHECK_DEBUGGER;
                    if (is_debugged) {
                        // Debugger detected. Destroy the triplet order.
                        for (int q=0; q<32; ++q) {
                            feistel_key_triplets[q][1] ^= feistel_key_triplets[q][2];
                            feistel_key_triplets[q][2] ^= feistel_key_triplets[q][1];
                            feistel_key_triplets[q][1] ^= feistel_key_triplets[q][2];
                        }
                    } else {
                        for (int q=0; q<32; ++q) {
                            feistel_key_triplets[q][0] ^= feistel_key_triplets[q][1];
                            feistel_key_triplets[q][1] ^= feistel_key_triplets[q][0];
                            feistel_key_triplets[q][0] ^= feistel_key_triplets[q][1];
                        }
                    }

                    // Erase the login window and replace it with the goodboy/badboy window.
                    ASSERT_EQ(werase(win_body), OK);
                    ASSERT_EQ(wrefresh(win_body), OK);
                    ASSERT_EQ(clear(), OK);
                    r = print_skull_n_banner(nrows, ncols);
                    if (r < 0) {
                        FATAL("Terminal is too small");
                    }
                    ASSERT_EQ(refresh(), OK);
                    ASSERT_NE(form_driver(form, REQ_VALIDATION), ERR);
                    char *username = field_buffer(fields[1], 0);
                    // fields[3] contains only '*' characters.

                    /* Drop trailing whitespaces. */
                    int j;
                    for (j=strlen(username) - 1; j>=0 && username[j]==' '; --j)
                        ;

                    if (j) username[j + 1] = '\0';

                    LOG("Username: '%s'", username);
                    LOG("Password: '%s'", password);

                    /* Prepare result window. */
                    WINDOW *win_res, *win_res_shadow;

                    if ((win_res = newwin(7, 50, r + 5, (ncols - 50)/2)) == NULL ||
                        (win_res_shadow = newwin(7, 50, r + 5 + 1, (ncols - 50)/2 + 1)) == NULL) {
                        FATAL("Cannot create result window");
                    }

                    ASSERT_EQ(box(win_res, 0, 0), OK);
                    ASSERT_EQ(wbkgd(win_shadow_exit, COLOR_PAIR(5) | ' '), OK);

                    /* Do the actual password verification. */
                    if (authenticate(username, password, nrows, ncols) == 1) {
                        ASSERT_EQ(wbkgd(win_res, A_BOLD | COLOR_PAIR(9) | ' '), OK);
                        ASSERT_EQ(mvwprintw(win_res, 3, 7, OBF("Authentication successful. Welcome :)")), OK);
                    } else {
                        ASSERT_EQ(wbkgd(win_res, A_BOLD | COLOR_PAIR(8) | ' '), OK);
                        ASSERT_EQ(mvwprintw(win_res, 3, 6, OBF("Login Failed. Press any key to exit ...")), OK);
                    }

                    ASSERT_EQ(wrefresh(win_shadow_exit), OK);
                    ASSERT_EQ(wrefresh(win_res), OK);

                    getch();  // Wait ...

                    ASSERT_EQ(delwin(win_res), OK);
                    ASSERT_EQ(delwin(win_res_shadow), OK);
                    halt = true;
                } else if (form->current == fields[5]) {
                    /* Exit button clicked. */
                    halt = true;                    
                }
                break;
            /* Backspace to delete character from the username/password edits. */
            case KEY_BACKSPACE:
            case KEY_DC:
            case 127:
                if (form->current == fields[1] && usr_cnt > 0) {
                    if (--usr_cnt >= 0) {
                        ASSERT_NE(form_driver(form, REQ_DEL_PREV), ERR);
                    }
                } else if (form->current == fields[3] && pwd_cnt > 0) {
                    if (--pwd_cnt >= 0) {
                        password[pwd_cnt] = 0;
                        ASSERT_NE(form_driver(form, REQ_DEL_PREV), ERR);
                    }
                }
                break;
            /* For every other key, simply append it to the form. */    
            default:
                if (form->current == fields[1]){
                    usr_cnt++;
                    ASSERT_NE(form_driver(form, ch), ERR);
                } else if (form->current == fields[3]) {
                    ASSERT_NE(form_driver(form, '*'), ERR);
                    if (pwd_cnt < PWD_BUFLEN) {
                        password[pwd_cnt++] = ch;
                    }
                }
                break;
        }

        /* Implement button logic. Sync buttons with hidden form fields. */
        if (form->current == fields[4]) {  // Activate login button.
            ASSERT_NE(curs_set(0), ERR);  // Hide cursor.
            ASSERT_EQ(wbkgd(win_button_login, A_BOLD | COLOR_PAIR(7) | ' '), OK);
            ASSERT_EQ(wbkgd(win_button_exit, A_BOLD | COLOR_PAIR(6) | ' '), OK);
        } else if (form->current == fields[5]) {  // Activate exit button.
            ASSERT_NE(curs_set(0), ERR);  // Hide cursor.
            ASSERT_EQ(wbkgd(win_button_exit, A_BOLD | COLOR_PAIR(7) | ' '), OK);
            ASSERT_EQ(wbkgd(win_button_login, A_BOLD | COLOR_PAIR(6) | ' '), OK);
        } else {  // Deactivate both buttons.
            ASSERT_NE(curs_set(2), ERR);  // Make cursor visible again.         
            ASSERT_EQ(wbkgd(win_button_login, A_BOLD | COLOR_PAIR(6) | ' '), OK);
            ASSERT_EQ(wbkgd(win_button_exit, A_BOLD | COLOR_PAIR(6) | ' '), OK);
        }

        ASSERT_EQ(wrefresh(win_button_login), OK);
        ASSERT_EQ(wrefresh(win_button_exit), OK);
        ASSERT_EQ(wrefresh(win_form), OK);
    }

    /* Teardown. */
    ASSERT_EQ(delwin(win_button_exit), OK);
    ASSERT_EQ(delwin(win_shadow_exit), OK);
    ASSERT_EQ(delwin(win_button_login), OK);
    ASSERT_EQ(delwin(win_shadow_login), OK);
    ASSERT_EQ(unpost_form(form), OK);
    ASSERT_EQ(free_form(form), OK);
    ASSERT_EQ(free_field(fields[0]), OK);
    ASSERT_EQ(free_field(fields[1]), OK);
    ASSERT_EQ(free_field(fields[2]), OK);
    ASSERT_EQ(free_field(fields[3]), OK);
    ASSERT_EQ(free_field(fields[4]), OK);
    ASSERT_EQ(free_field(fields[5]), OK);
    // These 2 MACROs below return an error. Not sure why. Just uncomment for now.
    //ASSERT_EQ(delwin(win_form), OK);
    //ASSERT_EQ(delwin(win_body), OK);
    ASSERT_EQ(delwin(win), OK);
    ASSERT_EQ(endwin(), OK);

    return 0;
}

