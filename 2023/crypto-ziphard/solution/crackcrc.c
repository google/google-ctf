/*
 * Copyright 2023 Google LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t crc_table[256];

static void make_crc_table(void)
{
   int i, j;
   uint32_t c;
   
   for (i = 0; i < 256; ++i)
   {
      c = i;
      for (j = 0; j < 8; ++j)
      {
	 if (c & 1)
	    c = 0xedb88320U ^ (c >> 1);
	 else
	    c >>= 1;
      }
      crc_table[i] = c;
   }
}

static uint32_t update_crc(uint32_t crc, const uint8_t *buf, int len)
{
   int i;
   crc = ~crc;
   for (i = 0; i < len; ++i)
      crc = crc_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
   return ~crc;
}

int main(int argc, char *argv[])
{
   uint32_t crc, testmin, testmax;
   uint32_t i, candcrc;

   make_crc_table();
		       
   if (argc != 4)
   {
      fputs("usage: crackcrc crc minimum_test_value maximum_test_value\n", stderr);
      return -1;
   }

   crc = (uint32_t) strtoul(argv[1], NULL, 16);
   testmin = (uint32_t) strtoul(argv[2], NULL, 16);
   testmax = (uint32_t) strtoul(argv[3], NULL, 16);

   printf("wanted crc = %x\nstart value = %x\nstop value = %x\n", crc, testmin,
	  testmax);

   for (i = testmin;;)
   {
      candcrc = update_crc(0, (uint8_t *) &i, sizeof i);
      if (candcrc == crc)
      {
	 FILE *fp;
	 printf("plaintext found: %x\n", htonl(i));
	 fp = fopen("second_plaintext", "wb");
	 putc(crc >> 24, fp);
	 fwrite(&i, 1, sizeof i, fp);
	 fclose(fp);
	 return 0;
      }
      if (i == testmax)
	 break;
      ++i;
   }

   return -1;
}
