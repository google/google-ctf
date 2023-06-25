# Mine the gap writeup

In the task we are given a Python script minesweeper.py along with 
some text file it processes. When we run it, we see it is a huge 
board from the Minesweeper game. We are told that if we fill the 
whole board correctly, we’ll get the flag.

Instantly we can notice a repeatable structure. There are definitely 
“wires”, that pass a “signal” of two possible options:

```
111
1?1
1?1
111
1?1
1?1
111
1?1
1?1
111
1?1
1?1
111
```

If the topmost question mark is a mine, then the next one cannot be, 
the one after must be, and so on.

After searching on the Internet for a while with queries like 
“minesweeper circuit”, we find a few pages dedicated to proving 
Minesweeper is NP-Complete. For example: 
- http://www.formauri.es/personal/pgimeno/compurec/Minesweeper.php
- http://web.math.ucsb.edu/~padraic/ucsb_2014_15/ccs_problem_solving_w2015/NP3.pdf 

We find that most of the patterns we see in our board are indeed copies 
of the ones written in the paper; and the remaining ones are 
simple enough to deduce quickly (e.g. wire corner). We wrote a script 
to pattern match them and rewrite the board to a nicer form, 
for example this:

```
12321                   12321           
1BBB1                   1BBB1           
13?31                   13?31           
13?2  1221               1?1            
1BB4212BB31             12321           
25BB??2?BB2             1B?B1           
1BB42112?B2             23532           
13?2   1221             1B?B1           
 1?1   1?1              23532           
12321  1?1              1B?B1           
1B?B1 12321             23532           
23532 1B?B1             1B?B1           
1B?B1 12321             12321           
23532  1?1               1?1            
1B?B1  1?1          123211?1 12321      
12321 1221   111    1BBB223211BBB1      
 1?1  2B?21112B2111135?54B?B223?32111111
 1?1  2BB?2??3?3??1??BBB??6??1?2?1??1??1
12321 13BB2112B2111134?BBB?B211?11111111
1B?B1  1221  111    1B4?B5321 1221      
23532               12B5B4?2111?B2      
1B?B1                13B?????2?5B2      
12321                 2B322212BB21      
 1?1                  1111?1 1221       
 1?1                     1?1            
 111                     111            
 1?1                     1?1            
 1?1                     1?1            
```

is replaced with:

```
I                       I    
|                       |    
|                       |    
>-----+                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     |                 |    
|     +-----------------H----
|                       |    
|                       |    
|                       |    
|                       |    
```

We also added a few heuristics, such as the double negation gate 
is reduced to a straight wire.

The board is still a pretty big mishmash of random gates, unfeasible 
to solve by hand (and the number of inputs is over 100, so we 
cannot brute force it either). Instead, I parsed the simplified 
circuit and put it into Z3. The script returned just a single 
solution, which means we can use the logic from the minesweeper.py 
file to calculate the flag: 
`CTF{d8675fca837faa20bc0f3a7ad10e9d2682fa0c35c40872938f1d45e5ed97ab27}.`



