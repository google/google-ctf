#include <stdio.h> //for printf
#include <stdbool.h> //for bool
#include <stdlib.h> //for strtol

/* 
    run comands:
    gcc counter-final.cp
    a.out 9009131337

    takes 5 hours to run on a laptop
 */
#define CS 100000000	/* cache size (~1.5GB) */

typedef unsigned long ulong;
typedef unsigned long long ull;

struct hailstoneEntry
{
    ull key;
    ulong steps;
};

struct hailstoneEntry hailstoneCache[CS] = {0};

void addToCache(ull key, ulong steps)
{
    ulong pos = key % CS;
    hailstoneCache[pos].key = key;
    hailstoneCache[pos].steps = steps;
}

ulong getFromCache(ull key)
{
    ulong pos = key % CS;
    if( hailstoneCache[pos].key != key )
    {
        return 0;
    }
    return hailstoneCache[pos].steps;
}

ull hailstoneSum(ull n)
{
    ull totalSteps = 0;
    ull percent = n / 100;
	for (ull start_num = 1; start_num <= n; ++start_num) 
    {
        ull num = start_num;
		ulong steps = 0;
        ulong deltaSteps = 0;
        ulong missedNum = 0;
		while( num != 1 )
        {
			if( num & 0x1 ) //odd
            {
				num += (num >> 1) + 1; //num = (3 * num + 1) / 2
				steps += 2;
            }
			if( (num & 0x1) == 0 ) //even
            {
                num >>= 1;
				steps += 1;
            }
            
            //check cache
            if( num < start_num )
            {
                //could be in cache
                ulong cacheSteps = getFromCache(num);
                if( cacheSteps > 0 )
                {
                    steps += cacheSteps;
                    num = 1;
                }
                else
                {
                    //cache miss
                    if(missedNum == 0) 
                    {
                        missedNum = num;
                        deltaSteps = steps;
                    }
                }
            }
        }
        
        //write to cache the first cache miss
        if(missedNum != 0 )
        {
            addToCache(missedNum, steps - deltaSteps);
        }
        totalSteps += steps;

        if(start_num % percent == 0)
        {
            printf("%llu%% subtotal = %llu\n", (start_num / percent), totalSteps);
        }
	}
    return totalSteps;
}

ull fib(ull num, ull total)
{
    ull a = 0;
    ull b = 1;
    for(ull i = 1; i < num; ++i)
    {
        ull c = (a + b) % total;
        a = b;
        b = c;
    }
    return b;
}
 
int main(int argc, char *argv[])
{
    ull N = strtol(argv[1], 0, 10);
    ull total = hailstoneSum(N); //2037448192360;
    ull fib_value = fib(N, total);

	printf("result = %llx\n", fib_value);
	return 0;
}