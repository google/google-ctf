// Windows  : g++ test.cpp NetSock.cpp -lws2_32
// GNU/Linux: g++ test.cpp
#include <stdio.h>
#include "NetSock.h"

int main() {
  NetSock::InitNetworking(); // Initialize WinSock
  
  NetSock s;
  int ret;
  unsigned char buffer[8] = {0};
  
  if (!s.Connect("127.0.0.1", 1333))
    return 1; // Some error handling.
  
  // Write some ASCII string.
  ret = s.Write((unsigned char*)"asdf", 4);
  if (ret != 4)
    return 2; // Some error handling.

  // Read some ASCII string.
  ret = s.Read(buffer, sizeof(buffer) - 1);
  if (ret <= 0)
    return 3; // Some error handling.

  // Write out the string.
  puts((char*)buffer);  
  
  s.Disconnect();
  
  return 0;
}

