# Google CTF 2023 - pwn: gradebook writeup

In the challenge we get a server host and port, as well as binary running on the server and some "gradebook" file. Running the binary, we see:

```
WELCOME TO THE GOOGLE PUBLIC SCHOOL DISTRICT DATANET

PLEASE LOGON WITH USER PASSWORD:
> pencil

PASSWORD VERIFIED

MENU:
1. OPEN STUDENT FILE
2. UPLOAD STUDENT FILE
3. QUIT

> 2
ENTER FILENAME:
> x
FILE NOT FOUND. GENERATING RANDOM NAME.
GENERATED FILENAME: /tmp/grades_873d2ce28460aa70baea4fd120875041

ENTER FILE SIZE:
> 800

SEND BINARY FILE DATA: [the gradebook file bytes]
MENU:
1. OPEN STUDENT FILE
2. UPLOAD STUDENT FILE
3. QUIT

> 1
ENTER FILENAME:
> /tmp/grades_873d2ce28460aa70baea4fd120875041


  2023, STUDENT NAME: Lightman, David L.



  CLASS #   COURSE TITLE         GRADE    TEACHER    PERIOD    ROOM
—————————————————————————————————————————————————————————————————————
   S-202    BIOLOGY 2              A+     LIGGET       3       214
   E-314    ENGLISH 11B            D      TURMAN       5       172
   H-221    WORLD HISTORY 11B      C      DWYER        2       108
   M-106    TRIG 2                 B      DICKERSON    4       315
   PE-02    PHYSICAL EDUCATION     C      COMSTOCK     1       GYM
   M-122    CALCULUS 1             B      LOGAN        6       240



MENU:
1. ADD GRADE
2. UPDATE GRADE
3. REMOVE GRADE
4. DOWNLOAD GRADEBOOK
5. CLOSE GRADEBOOK
6. QUIT
```

It's a tribute to the Wargames movie! We could guess the pencil password from the movie (where the main character uses it), or it's very visible in the binary itself. When we log in, we can upload or open a gradebook file, and while we have it open, we can modify it (add, update or remove grades).

Reverse engineering the binary, we also find a secret option 1337:

```
WELCOME TO THE GOOGLE PUBLIC SCHOOL DISTRICT DATANET

PLEASE LOGON WITH USER PASSWORD:
pencil

PASSWORD VERIFIED

MENU:
1. OPEN STUDENT FILE
2. UPLOAD STUDENT FILE
3. QUIT

1337
WELCOME PROFESSOR FALKEN. LET'S PLAY A GAME OF RUSSIAN ROULETTE.

... *click*
... *click*
... *click*
... *click*
... *click*
... *BAM!*
-- CONNECTION TERMINATED --
```

If we pass the probability 5/6 check a thousand times, we get the flag! However (5/6)^1000 is about 6.5^10^-80, so it is astronomically unlikely to happen by chance.

Instead we reverse engineer the main part of the server. We find the gradebook structure consists of a file header, followed by a list of grade records.
The file header is a bunch of metadata like year, or student name, but also file size, and grade offsets: initial, and last one's.
The grade record is a simple structure of metadata like fixed-width teacher or class name strings, followed by a 64-bit offset to the next grade. So the grades form a linked list, with head written in the file header.

We reverse engineered the binary and found a few almost-bugs; but all of them were thwarted in some way. For example you could supply an invalid gradebook file and remove a grade. If the linked list pointers were engineered to point outside the file, you could overwrite arbitrary memory. However the function looping over the linked list had an important check, that the current grade location was smaller than the gradebook size written in the file header. We could forge that field as well, but that in turn is checked against the actual file size on disk while opening the gradebook, before any grade parsing is performed.

We do find a stack pointer leak though: the grade listing code silently assumes room string is only three characters long, whereas the space provided is actually 4 bytes. If we supply a four byte room, the internal buffer will not be zero-terminated and we get sent garbage after the buffer - that happens to be a stack pointer.

We notice that the file parsing is done in an interesting, uncommon way: by mapping the file and casting it as a structure. This is important, since gradebook files we supply persist and can be referenced between server connections (i.e. you can upload a file, close a connection, open a new connection and open the file you just uploaded).
This gives us the idea to perform a TOCTOU attack. First we upload a well-formed gradebook in session 1 and open it. Then we open a second session where we upload a malformed gradebook with gradebook_size field being near max uint64, with the same name as the one in session 1. Opening it would of course fail due to the field being invalid. However, we already have the first session with the file already open. The checks have already passed, and the mmap now sees a different file!

Using this idea, and the stack pointer we leaked, we craft a gradebook with its pointers actually pointing into the stack area (calculated from difference between leaked stack pointer and the constant address where our gradebook is mmapped). Listing grades will then provide us with more stack leaks - we arrange it so that the leak is of a return address, so we can break ASLR for code as well.
Finally, we repeat the TOCTOU trick with a new gradebook, this time engineered so that the grade records point into the stack at the position of the return address. The pointers are arranged so that removing a grade will overwrite the return address into a value we provide; and we calculate it (from the code pointer we leaked earlier) to be the win function (called if we were to survive the russian roulette). When we run the exploit, we get the flag: `CTF{mm4p_p4rs1ng_c0nsid3red_h4rmfu1}`
