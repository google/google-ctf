import math
import sys
import numpy as np
#from fastcache import lru_cache

#sum for 0 to 10,000 is 849666

#9009131337
"""
1% subtotal = 16048870167
2% subtotal = 33399517565
3% subtotal = 51241228480
4% subtotal = 69403305656
5% subtotal = 87801582085
6% subtotal = 106388662087
7% subtotal = 125147715698
8% subtotal = 144014637417
9% subtotal = 163009595982
10% subtotal = 182113834041
11% subtotal = 201305705800
12% subtotal = 220590567923
13% subtotal = 239949500242
14% subtotal = 259411104491
15% subtotal = 278881493903
16% subtotal = 298446401543
17% subtotal = 318078390323
18% subtotal = 337739855362
19% subtotal = 357453575536
20% subtotal = 377248608245
21% subtotal = 397114063114
22% subtotal = 416942278078
23% subtotal = 436864589474
24% subtotal = 456807447136
25% subtotal = 476816744744
26% subtotal = 496836484082
27% subtotal = 516891035167
28% subtotal = 537050808237
29% subtotal = 557100103102
30% subtotal = 577293226629
31% subtotal = 597491771738
32% subtotal = 617726397253
33% subtotal = 637986872899
34% subtotal = 658293399131
35% subtotal = 678631162694
36% subtotal = 698918211065
37% subtotal = 719332705122
38% subtotal = 739646321594
39% subtotal = 760118224093
40% subtotal = 780534683932
41% subtotal = 800987646762
42% subtotal = 821566237720
43% subtotal = 841981325300
44% subtotal = 862537211883
45% subtotal = 883070463513
46% subtotal = 903690399695
47% subtotal = 924265272268
48% subtotal = 944864468986
49% subtotal = 965476645520
50% subtotal = 986178016890
51% subtotal = 1006859125098
52% subtotal = 1027538676360
53% subtotal = 1048301947508
54% subtotal = 1068939554574
55% subtotal = 1089651949665
56% subtotal = 1110551958090
57% subtotal = 1131172731315
58% subtotal = 1151973144347
59% subtotal = 1172946964624
60% subtotal = 1193642410396
61% subtotal = 1214416684604
62% subtotal = 1235363999995
63% subtotal = 1256330890250
64% subtotal = 1277117374497
65% subtotal = 1297988835007
66% subtotal = 1318947965890
67% subtotal = 1339850739435
68% subtotal = 1360857036301
69% subtotal = 1381829282463
70% subtotal = 1402839924609
71% subtotal = 1423812512031
72% subtotal = 1444713121577
73% subtotal = 1465762208318
74% subtotal = 1486843413205
75% subtotal = 1507816840535
76% subtotal = 1528773050799
77% subtotal = 1549860036676
78% subtotal = 1571030038674
79% subtotal = 1592101914722
80% subtotal = 1613145324847
81% subtotal = 1634259664020
82% subtotal = 1655373867524
83% subtotal = 1676639550154
84% subtotal = 1697807122309
85% subtotal = 1718839713058
86% subtotal = 1739960480416
87% subtotal = 1761112370814
88% subtotal = 1782375127359
89% subtotal = 1803638881899
90% subtotal = 1824729230857
91% subtotal = 1845950514471
92% subtotal = 1867300768645
93% subtotal = 1888487859790
94% subtotal = 1909728736665
95% subtotal = 1930962496379
96% subtotal = 1952232252753
97% subtotal = 1973512676752
98% subtotal = 1994780527156
99% subtotal = 2016132948982
100% subtotal = 2037448181291
answer = 2037448192360

real	285m50.512s
user	283m37.697s
sys	1m8.617s
"""
#9,009,131,337
#recurvsive (900,000) = 53.0 * 10,000
#recurvsive (900,000) + functools.lru_cache = 9.2 * 10,000
#dictionary with bit wizardry = 1.74 * 10,000
#np.arry with bit wizardry = 1.93 * 10,000
#C (900,000) = 0.058 * 10,000
#C++ (900,000) = 0.61 * 10,000

#8.0 seconds for miss caching
#16.4 seconds for latest cached
#13.6 cache largest steps

sys.setrecursionlimit(1500)

class Counter():
	def start(self, input_val):
		if input_val < 11:
			return 0
			
		total = 2037448192360 #self.collatzSum(input_val)
		print("total=" + str(total))
		fib_value = self.fib(input_val, total)
		return fib_value
		
	
	def collatzSum(self, upperLimit, x):
		totalSteps = 0
		cacheSize = 10000000
		#collatzCache = dict.fromkeys(range(cacheSize))
		collatzCache = np.zeros(cacheSize)

		for num in range(1, upperLimit + 1):
			start_num = num
			steps = 0
			while num != 1:
				#check cache
				if num < start_num:
					steps += collatzCache[num]
					break
				
				#not in cache calculate next collatz
				if num & 0x1: #odd
					num += (num >> 1) + 1
					steps += 2
				
				if num & 0x1 == 0: #even
					num >>= 1
					steps += 1
			
			#write to cache
			collatzCache[start_num] = steps
		
		#sum cache
		totalSteps = np.sum(collatzCache, dtype = 'int')
		#totalSteps = sum(collatzCache)

		return totalSteps

	def collatzSum(self, upperLimit):
		total = 0
		for i in range(upperLimit + 1):
			total +=self.collatz(i)
		return total
	
	def collatz(self, num):
		if num <= 1:
			return 0
		else:
			if num % 2 == 1:
				return self.collatz((3 * num) + 1) + 1
			else:
				return self.collatz(num/2) + 1
	
	
	
	def fib(self, n, modulo): 
	      
	    F = [[1, 1], 
	         [1, 0]] 
	    if (n == 0): 
	        return 0
	    self.power(F, n - 1, modulo) 
	          
	    return F[0][0] % modulo
	
	      
	def multiply(self, F, M, modulo): 
	      
	    x = (F[0][0] * M[0][0] + 
	         F[0][1] * M[1][0]) 
	    y = (F[0][0] * M[0][1] + 
	         F[0][1] * M[1][1]) 
	    z = (F[1][0] * M[0][0] + 
	         F[1][1] * M[1][0]) 
	    w = (F[1][0] * M[0][1] + 
	         F[1][1] * M[1][1]) 
	      
	    F[0][0] = (x % modulo)
	    F[0][1] = (y % modulo) 
	    F[1][0] = (z % modulo)
	    F[1][1] = (w % modulo)
	
	def power(self, F, n, modulo):
		if n == 0 or n == 1:
			return
		
		M = [[1, 1],
			[1, 0]]
		
		self.power(F, math.floor(n/2), modulo)
		self.multiply(F, F, modulo)
		
		if n % 2 != 0:
			self.multiply(F, M, modulo)




counter = Counter()
input_value = sys.argv[1]
print(hex(counter.start(int(input_value))))
