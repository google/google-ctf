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
#if defined(_WIN32) && !defined(WIN32)
#  define WIN32
#endif

#if defined(WIN32)
#  include <winsock2.h>
#  include <windows.h>
#elif defined(__unix__)
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <resolv.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#  define closesocket(a) close(a)
#endif

#include <cstdlib>
#include <stdint.h>
#include "NetSock.h"

const int NetSock::SYNCHRONIC  = 1;
const int NetSock::ASYNCHRONIC = 2;

NetSock* NetSock::FromDescriptors(int read_fd, int write_fd) {
  NetSock *s = new NetSock;
  s->fd[0] = read_fd;
  s->fd[1] = write_fd;
  snprintf(s->str_ip, sizeof(s->str_ip), "fd(%i,%i)", read_fd, write_fd);
  return s;
}

NetSock::NetSock()
{
  this->fd[0]  = -1;
  this->fd[1]  = -1;
  this->ip     = 0x00000000;
  this->mode   = 0;
  this->port   = 0;
  this->isUDP  = false;
  this->UDPCanBroadcast = false;

  this->bindip   = 0;
  this->bindport = 0;

  this->str_ip[0] = '\0';
  this->str_bindip[0] = '\0';
}

NetSock::~NetSock()
{
  this->Disconnect();
}

int
NetSock::GetWriteDescriptor() const {
  if (this->fd[1] != -1) {
    return this->fd[1];
  }

  return this->fd[0];
}

bool
NetSock::InitNetworking(void)
{
#ifdef _WIN32
  WSADATA wsdat;
  memset(&wsdat, 0, sizeof(wsdat));

  if(WSAStartup(MAKEWORD(2,2), &wsdat))
    return false;
#endif

  return true;
}

bool
NetSock::ListenUDP(unsigned short bindport, const char *bindhost)
{
  int ret;
  sockaddr_in desc;

  desc.sin_family = AF_INET;
  desc.sin_addr.s_addr = inet_addr(bindhost); // TODO: fix this
  desc.sin_port = htons(bindport);
  memset(desc.sin_zero, 0, sizeof(desc.sin_zero));

  ret = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(ret == -1)
    return false;

  this->fd[0] = ret;
  this->bindport = bindport;
  this->bindip = htonl(desc.sin_addr.s_addr);

  this->isUDP = true;

  // bind ip it!
  if(bind(this->fd[0], (sockaddr*)&desc, sizeof(sockaddr)) == -1)
    return false;

  return true;
}

bool
NetSock::ListenAllUDP(unsigned short bindport)
{
  return this->ListenUDP(bindport, "0.0.0.0");
}

bool
NetSock::Listen(unsigned short port, const char *bindip)
{
  sockaddr_in desc;
  int ret;

  desc.sin_family = AF_INET;
  desc.sin_addr.s_addr = inet_addr(bindip);
  desc.sin_port = htons(port);

  ret = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(ret == -1)
    return false;

  this->fd[0] = ret;

  int enable = 1;
  if (setsockopt(this->fd[0], SOL_SOCKET,
                 SO_REUSEADDR, (const char*)&enable, sizeof(int)) < 0) {
    this->fd[0] = -1;
    return false;
  }

  if(bind(this->fd[0], (sockaddr*)&desc, sizeof(sockaddr)) == -1)
    return false;

  if(listen(this->fd[0], SOMAXCONN) == -1)
    return false;

  return true;
}

bool
NetSock::ListenAll(unsigned short port)
{
  return this->Listen(port, "0.0.0.0");
}

NetSock *
NetSock::Accept()
{
 sockaddr_in desc;
  int remote;
#if defined(WIN32)
  int size;
#elif defined(__unix__)
  socklen_t size;
#endif

  size = sizeof(sockaddr);
  remote = accept(this->fd[0], (sockaddr*)&desc, &size);
  if(remote == -1)
    return NULL;

  NetSock *NewSock = new NetSock;

  NewSock->fd[0]  = remote;
  NewSock->port   = htons(desc.sin_port);
  memcpy(&NewSock->ip, &desc.sin_addr.s_addr, 4);

  return NewSock;
}

bool
NetSock::Connect(const char* host, unsigned short port)
{
  unsigned int ip;

  ip = (unsigned int)inet_addr(host);
  if(ip == INADDR_NONE)
  {
    struct hostent *hostip;

    // resolve
    hostip = gethostbyname(host);
    if(!hostip)
      return false;

    memcpy(&ip, hostip->h_addr_list[0], 4);
  }

  return this->Connect(htonl(ip), port);
}

bool
NetSock::Connect(unsigned int ip, unsigned short port)
{
  struct sockaddr_in sock_info;
  int ret, sock = -1;

  if(this->fd[0] != -1)
    throw "Socket already exists";

  ret = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(ret == -1)
    throw "Socket create failed";

  sock = ret;

  // sock info
  sock_info.sin_family = AF_INET;
  sock_info.sin_addr.s_addr = htonl(ip);
  sock_info.sin_port = htons(port);
  memset(sock_info.sin_zero, 0, sizeof(sock_info.sin_zero));

  // conn
  ret = connect(sock, (struct sockaddr*)&sock_info, sizeof( struct sockaddr ));
  if(ret == -1)
  {
    closesocket(sock);
    return false;
  }

  // ok
  this->ip = ip;
  this->port = port;
  this->mode = this->SYNCHRONIC;
  this->fd[0] = sock;
  return true;
}

bool
NetSock::SetMode(int mode)
{
#if defined(WIN32)
  unsigned long mode_temp;
#endif
  if(this->fd[0] == -1)
    return false;

  if(this->mode == mode)
    return true;

  switch(mode)
  {
    case NetSock::SYNCHRONIC:
#if defined(WIN32)
      mode_temp = 0;
      ioctlsocket(this->fd[0], FIONBIO, &mode_temp);
#else
      fcntl(this->fd[0], F_SETFL, 0);
#endif
      break;

    case NetSock::ASYNCHRONIC:
#if defined(WIN32)
      mode_temp = 1;
      ioctlsocket(this->fd[0], FIONBIO, &mode_temp);
#else
      fcntl(this->fd[0], F_SETFL, O_NONBLOCK);
#endif
      break;
  }

  this->mode = mode;
  return true;
}

bool
NetSock::Disconnect()
{
  if(this->fd[0] == -1)
    return false;

#if defined(WIN32)
  shutdown(this->fd[0], SD_BOTH);
#else
  shutdown(this->fd[0], SHUT_RDWR);
#endif
  closesocket(this->fd[0]);
  this->fd[0] = -1;
  this->ip     = 0x00000000;
  this->mode   = 0;
  this->port   = 0;
  return true;
}

int
NetSock::Read(void *Buffer, int Size)
{
  if(this->fd[0] == -1)
    return -1;

#ifdef __unix__
  return read(this->fd[0], Buffer, Size);
#elif _WIN32
  return recv(this->fd[0], (char*)Buffer, Size, 0);
#endif
}

int
NetSock::ReadAll(void *Buffer, int Size)
{
  if(this->fd[0] == -1)
    return -1;

  // If non-blocking, switch to blocking mode to
  // save CPU cycles. This function is always blocking.
  int old_mode = this->mode;
  if(this->mode == ASYNCHRONIC)
    this->SetMode(SYNCHRONIC); // Ignore fail.

  // Read data.
  int received = 0;
  bool error_state = false;

  while(received != Size)
  {
    // Read a portion of data.
    int left = Size - received;

    int ret = this->Read((int8_t*)Buffer + received, left);
    if(ret <= 0)
    {
      error_state = true;
      break;
    }

    received += ret;
  }

  // Switch back mode if needed.
  if(old_mode == ASYNCHRONIC)
    this->SetMode(ASYNCHRONIC);

  // Return.
  if(error_state)
    return -1;

  return received;
}

int
NetSock::Write(const void *Buffer, int Size)
{
  if(this->GetWriteDescriptor() == -1)
    return -1;

#ifdef __unix__
  return write(this->GetWriteDescriptor(), Buffer, Size);
#elif _WIN32
  return send(this->GetWriteDescriptor(), (const char*)Buffer, Size, 0);
#endif
}

int
NetSock::WriteAll(const void *Buffer, int Size)
{
  if(this->GetWriteDescriptor() == -1)
    return -1;

  int ret, ptr = 0;

  while(ptr != Size)
  {
#ifdef __unix__
    ret = write(this->GetWriteDescriptor(), (const char*)((int8_t*)Buffer + ptr),
               Size - ptr);
#elif _WIN32
    ret = send(this->GetWriteDescriptor(), (const char*)((int8_t*)Buffer + ptr),
               Size - ptr, 0);
#endif

    // Thx to the anonymous . for pointing a bug that was previously
    // here.
    if(ret == 0)
    {
      continue; // TODO: Add some sleep here, since obviously
                // it cannot be sent now
    }
    else if(ret == -1)
    {
      // What's the problem?
#ifdef __unix__
      if(errno == EAGAIN || errno == EWOULDBLOCK)
        continue;
#elif _WIN32
      if(WSAGetLastError() == WSAEWOULDBLOCK)
        continue;
#endif

      // Seems it was an error.
      return 0;
    }

    ptr += ret;
  }

  return Size;
}


unsigned short
NetSock::GetPort() const
{
  return this->port;
}

unsigned int
NetSock::GetIP() const
{
  return this->ip;
}

const char *
NetSock::GetStrIP()
{
  // cached ?
  if(this->str_ip[0])
    return this->str_ip;

  strncpy(this->str_ip, inet_ntoa(*(in_addr*)&this->ip), 16);
  this->str_ip[15] = '\0';
  return this->str_ip;
}

unsigned short
NetSock::GetBindPort() const
{
  return this->bindport;
}

unsigned int
NetSock::GetBindIP() const
{
  return this->bindip;
}

const char *
NetSock::GetStrBindIP()
{
  // cached ?
  if(this->str_bindip[0])
    return this->str_bindip;

  strncpy(this->str_bindip, inet_ntoa(*(in_addr*)&this->bindip), 16);
  this->str_bindip[15] = '\0';
  return this->str_bindip;
}

int
NetSock::BroadcastUDP(const char* broadcast, unsigned short port, const void *buffer, int size)
{
  // Sanity check
  if(this->fd[0] == -1)
    return -1;

  // Address
  struct sockaddr_in sock_info;

  memset(&sock_info, 0, sizeof(sock_info));

  sock_info.sin_family = AF_INET;
  sock_info.sin_addr.s_addr = inet_addr(broadcast);
  sock_info.sin_port = htons(port);

  if(!this->UDPCanBroadcast)
  {
#ifdef WIN32
    int OptVal = 1;
    if(setsockopt(this->fd[0], SOL_SOCKET, SO_BROADCAST, (char*)&OptVal, sizeof(BOOL)) ==
        SOCKET_ERROR)
      return -2;

    // Double check if this works.
    int OptValLen = sizeof(OptVal);
    if(getsockopt(this->fd[0], SOL_SOCKET, SO_BROADCAST, (char*)&OptVal, &OptValLen) == SOCKET_ERROR)
      return -3;
#else
    int OptVal = 1;
    if(setsockopt(this->fd[0], SOL_SOCKET, SO_BROADCAST, (char*)&OptVal, sizeof(OptVal)) == -1)
      return -2;
#endif

    UDPCanBroadcast = true;
  }

  memset(sock_info.sin_zero, 0, sizeof(sock_info.sin_zero));

#ifndef WIN32_OLD
  return sendto(this->fd[0], (const char*)buffer, size, 0, (struct sockaddr*)&sock_info, sizeof(struct sockaddr));
#else
  return sendto(this->fd[0], buffer, size, 0, (struct sockaddr*)&sock_info, sizeof(struct sockaddr));
#endif
}

int
NetSock::WriteUDP(const char* host, unsigned short port, const void *buffer, int size)
{
  // Sanity check
  if(this->GetWriteDescriptor() == -1)
    return -1;

  // Address
  struct sockaddr_in sock_info;

  memset(&sock_info, 0, sizeof(sock_info));

  sock_info.sin_family = AF_INET;
  sock_info.sin_addr.s_addr = inet_addr(host); // Change this to 'host' later
  sock_info.sin_port = htons(port);

  memset(sock_info.sin_zero, 0, sizeof(sock_info.sin_zero));

#ifndef WIN32_OLD
  return sendto(this->GetWriteDescriptor(), (const char*)buffer, size, 0, (struct sockaddr*)&sock_info, sizeof(struct sockaddr));
#else
  return sendto(this->GetWriteDescriptor(), buffer, size, 0, (struct sockaddr*)&sock_info, sizeof(struct sockaddr));
#endif
}

int
NetSock::ReadUDP(void *buffer, int size, char *srchost, unsigned short *srcport)
{
  // Sanity check
  if(this->fd[0] == -1)
    return -1;

  // Recieve
  struct sockaddr_in srcaddr;
#if !defined (WIN32_OLD) && !defined (__unix__)
  typedef int socklen_t;
#endif
  socklen_t len = sizeof(srcaddr);
#ifndef WIN32_OLD
  int ret = recvfrom(this->fd[0], (char*)buffer, size, 0, (struct sockaddr*)&srcaddr, &len);
#else
  int ret = recvfrom(this->fd[0], buffer, size, 0, (struct sockaddr*)&srcaddr, &len);
#endif

  // Fill some info ?
  if(ret > 0)
  {
    if(srchost)
    {
      strncpy(srchost, inet_ntoa(srcaddr.sin_addr), 16); // htonl?
      srchost[15] = '\0';
    }

    if(srcport)
    {
      *srcport = htons(srcaddr.sin_port);
    }
  }

  // Done
  return ret;
}

int NetSock::GetDescriptor() const {
  return this->fd[0];
}

int NetSock::DetachDescriptor() {
  int s = this->fd[0];
  this->fd[0] = -1;
  return s;
}

