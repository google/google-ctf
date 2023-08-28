


data = open("circuit3-release.txt").readlines()
data = [list(line.strip("\n")) for line in data]

#data = data[:300]
#data = [line[:100] for line in data]

patterns = [
("""
12321
1BBB1
13931
""","""
     
     
INPUT
"""),
("""
191
111
191
""","""
 | 
 | 
 | 
"""),("""
 1221 
12BB31
929BB2
1129B2
  1221
  191 
""","""
      
      
---+  
   |  
   |  
   |  
"""),("""
 191  
1221  
2B9211
2BB929
13BB21
 1221 
""","""
  |   
  |   
  |   
  +---
      
      
"""),("""
 1221 
13BB21
2BB929
2B9211
1221  
 191  
""","""
      
      
  +---
  |   
  |   
  |   
"""),("""
  191 
  1221
1129B2
929BB2
12BB31
 1221 
""","""
   |  
   |  
   |  
---+  
      
      
"""),("""
 191 
12321
1B9B1
12321
 191 
""","""
  |  
  |  
  N  
  |  
  |  
"""),("""
 191 
12321
1B9B1
23532
1B9B1
23532
1B9B1
12321
 191 
""","""
  |  
  |  
  |  
  |  
  N  
  |  
  |  
  |  
  |  
"""),("""
 191 
12321
1B9B1
23532
1B9B1
12321
 191 
""","""
  |  
  |  
  |  
  |  
  |  
  |  
  |  
"""),("""
 191 
12321
1B9B1
23532
1B9B1
23532
1B9B1
23532
1B9B1
12321
 191 
""","""
  |  
  |  
  |  
  |  
  |  
  |  
  |  
  |  
  |  
  |  
  |  
"""),("""
 111 
12B21
93939
12B21
 111 
""","""
     
     
--N--
     
     
"""),("""
12321191 12321 
1BBB223211BBB1 
35954B9B2239321
9BBB99699192919
349BBB9B2119111
1B49B5321 1221 
12B5B4921119B2 
 13B99999295B2 
  2B322212BB21 
  111191 1221  
""","""
      |        
      |        
      |        
------H--------
      |        
      |        
      |        
      |        
      |        
      |        
"""),("""
111
919
111
""","""
   
---
   
"""),("""
 2931
24BB1
9BB52
24BB1
 2931
""","""
  N  
  |  
--<  
  |  
  |  
"""),("""
1392 
1BB42
25BB9
1BB42
1392 
""","""
  |  
  |  
  >--
  |  
  N  
"""),
("""
 11211 
12B3B21
9395939
12B3B21
 11211 
""","""
       
       
-------
       
       
"""),("""
 1121211 
12B3B3B21
939595939
12B3B3B21
 1121211 
""","""
         
         
----N----
         
         
"""),("""
111
3B2
BB3
3B2
111
""","""
   
   
==1
   
   
"""),
("""
13931
1BBB1
12321
""","""
  =  
  =  
  I? 
"""),
("""
  191 12321 
 123211BBB1 
12B9B2239321
939699192919
12B9B5439221
 24BBBBB4B1 
 2B99999B31 
 2BB323BB2  
 1221 1221  
""","""
   |        
   |        
   |        
---OR-------
            
            
            
            
            
"""),("""
  1222221  
 12BB3BB21 
 2B59495B1 
 2B912B921 
 23422291  
 1B9B1111  
 235332921 
23B9B3B9B2 
9B969596B2 
3B99B3BB21 
1233222321 
12992112B21
93BB3993939
2B33B212B21
111111 111 
""","""
           
           
           
           
           
           
           
           
----+      
    |      
    |      
    |      
----XOR----
           
           
"""),






        ]

second_patterns = [
("""
  |   1221 111 111  
  |   2BB323B212B321
 191124B999993993BB2
12211BB4B323B21129B2
2B92249311 111  1221
2BB39992         9  
245B4B49---------2--
2BB39992         9  
2B92249311 111  1221
12211BB4B323B21129B2
 191124B999993993BB2
  |   2BB323B212B321
  |   1221 111 111  
""","""
  |                 
  |                 
  |                 
  |                 
  |                 
  |                 
  AND---------------
  |                 
  |                 
  |                 
  |                 
  |                 
  |                 
"""),("""
N
|
|
|
|
N
""","""
|
|
|
|
|
|
"""),("""
N      
|      
|      
|      
|      
|      
+-----N
""","""
|      
|      
|      
|      
|      
|      
+------
"""),("""
N
|
|
N
""","""
|
|
|
|
"""),



]
# https://web.mat.bham.ac.uk/R.W.Kaye/minesw/minesw.pdf

for i in range(len(patterns)):
    x,y, = patterns[i]
    patterns[i] = (x.strip("\n").splitlines(), y.strip("\n").splitlines())
for i in range(len(second_patterns)):
    x,y, = second_patterns[i]
    second_patterns[i] = (x.strip("\n").splitlines(), y.strip("\n").splitlines())

def matches(data, y, x, pattern):
    for i in range(len(pattern)):
        yy = y+i
        if yy >= len(data): return False
        for j in range(len(pattern[i])):
            xx = x+j
            if xx >= len(data[yy]): return False
            if data[yy][xx] != pattern[i][j]: return False
    return True
    
def replace(data, y, x, replacement):
    for i in range(len(pattern)):
        yy = y+i
        for j in range(len(pattern[i])):
            xx = x+j
            data[yy][xx] = replacement[i][j]


for y in range(len(data)):
    for x in range(len(data[y])):
        for pattern, replacement in patterns:
            if matches(data, y, x, pattern):
                replace(data, y, x, replacement)
for y in range(len(data)):
    for x in range(len(data[y])):
        for pattern, replacement in second_patterns:
            if matches(data, y, x, pattern):
                replace(data, y, x, replacement)

open("result", "w").write("\n".join("".join(line) for line in data))
