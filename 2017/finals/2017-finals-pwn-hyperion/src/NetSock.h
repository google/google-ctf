// NOTE: This NetSock has been modified to allow using both sockets and
// stdin/stdout pair as NetSock objects. The implementation isn't complete,
// so be careful.
//
// NetSock socket helper class
// code by gynvael.coldwind//vx
// http://gynvael.vexillium.org
// http://vexillium.org
//
// additional thx to:
//   Mateusz "j00ru" Jurczyk
//   and others
//
// Version: 2017-07-11
//
// LICENSE
//   Copyright 2017 Gynvael Coldwind
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
#pragma once
#ifdef __unix__
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#else
#  include <winsock2.h>
#  include <windows.h>
#endif
#include <cstdio>

using namespace std;

class NetSock
{
private:
  unsigned int    ip;
  unsigned short  port;

  unsigned int    bindip;
  unsigned int    bindport;

  int   mode;

  // If only fd[0] is set, it's used as a standard full-duplex socket.
  // If both fd[0] and fd[1] are non -1, then fd[0] is used for reading and
  // fd[1] is used for writing.
  int   fd[2];

  char  str_ip[32], str_bindip[16];

  bool  isUDP;
  bool  UDPCanBroadcast;

public:
  // Creates a NetSock object from two low-level descriptors (useful mostly on
  // UNIX-like systems). You can use it to e.g. create a NetSock object backed
  // by stdin/stdout, or a set of pipes.
  static NetSock *FromDescriptors(int read_fd, int write_fd);

  NetSock();
  ~NetSock();

  static const int SYNCHRONIC;
  static const int ASYNCHRONIC;

  bool ListenUDP(unsigned short bindport, const char *bindhost);
  bool ListenAllUDP(unsigned short bindport);

  bool Connect(const char* host, unsigned short port);
  bool Connect(unsigned int ip, unsigned short port);
  bool SetMode(int mode);
  bool Disconnect();
  bool Listen(unsigned short port, const char *bindip);
  bool ListenAll(unsigned short port);
  NetSock *Accept();
  int Read(void *Buffer, int Size);
  int GetDescriptor() const;  // Returns full-duplex descriptor or read descriptor.
  int GetWriteDescriptor() const;

  // Return the low-level socket descriptor and detach it from this NetSock
  // object (this will stop NetSock's destructor from shutting down and
  // closing the socket on delete, but will also make the NetSock object
  // generally not usable for most operations).
  int DetachDescriptor();

  // Reads exactly Size bytes. Does not return until then,
  // unless an error has occured.
  // If it's used on a non-blocking socket, it switches the
  // socket to blocking mode until all the data is read,
  // and switches it back to non-blocking mode after that.
  int ReadAll(void *Buffer, int Size);

  // Write and WriteAll work the same in blocking sockets.
  // In non-blocking, Write writes only so much data that does
  // not cause a block. WriteAll on the other hand makes sure
  // all the data is transmited.
  int Write(const void *Buffer, int Size);
  int WriteAll(const void *Buffer, int Size);

  // Use BroadcastUDP to send packets to broadcast addresses.
  // Due to some change in Windows 7 BroadcastUDP cannot use 255.255.255.255 as source address,
  // currently you need to use an interface specific broadcast address (e.g. 192.168.1.255).
  int WriteUDP(const char* host, unsigned short port, const void *buffer, int size);
  int BroadcastUDP(const char* broadcast, unsigned short port, const void *buffer, int size);
  int ReadUDP(void *buffer, int size, char *srchost, unsigned short *srcport);

  unsigned short GetPort() const;
  unsigned int GetIP() const;
  const char *GetStrIP();

  unsigned short GetBindPort() const;
  unsigned int GetBindIP() const;
  const char *GetStrBindIP();

  // Inits winsock on Windows
  static bool InitNetworking(void);
};

