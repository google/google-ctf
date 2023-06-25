// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _LARGEFILE64_SOURCE
#define VERSION 1
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#ifndef VERSION
    #error "Version undefined!"
#endif
char maps[4096];
/* NOTE: The competitor can make the first byte of the flag anything they want by
 * overwriting just before the flag with the flag so that the desired byte lands
 * at the beginning. Future writes of size 1 will only write the desired flag byte.
 */
char flag[128];

int main()
{
    int mapsfd = open("/proc/self/maps",O_RDONLY);
    read(mapsfd,maps,sizeof(maps));
    close(mapsfd);
    int flagfd = open("./flag.txt",O_RDONLY);
    if(flagfd == -1)
    {
        puts("flag.txt not found");
        return 1;
    }
    if(read(flagfd,flag,128) <= 0)
    {
        puts("flag.txt empty");
        return 1;
    }
    close(flagfd);
    int sockfd = dup2(1,1337);
    int devnullfd = open("/dev/null",O_RDWR);
    dup2(devnullfd,0);
    dup2(devnullfd,1);
    dup2(devnullfd,2);
    close(devnullfd);
    //Timeout control
    alarm(60);
    #if VERSION == 1
    dprintf(sockfd,"This challenge is not a classical pwn\n"
            "In order to solve it will take skills of your own\n"
            "An excellent primitive you get for free\n"
            "Choose an address and I will write what I see\n"
            "But the author is cursed or perhaps it's just out of spite\n"
            "For the flag that you seek is the thing you will write\n"
            "ASLR isn't the challenge so I'll tell you what\n"
            "I'll give you my mappings so that you'll have a shot.\n");
    #endif
    #if VERSION == 2
    dprintf(sockfd,"Was that too easy? Let's make it tough\n"
    "It's the challenge from before, but I've removed all the fluff\n");
    #endif
    #if VERSION == 3
    dprintf(sockfd,"Your skills are considerable, I'm sure you'll agree\n"
    "But this final level's toughness fills me with glee\n"
    "No writes to my binary, this I require\n"
    "For otherwise I will surely expire\n");
    #endif
    dprintf(sockfd,"%s\n\n",maps);
    while (1)
    {
        #if VERSION == 1
        dprintf(sockfd,"Give me an address and a length just so:\n"
           "<address> <length>\n"
           "And I'll write it wherever you want it to go.\n"
           "If an exit is all that you desire\n"
           "Send me nothing and I will happily expire\n");
        #endif
        char buffer[64] = { 0 };
        int ret = read(sockfd,buffer,sizeof(buffer));
        unsigned long address;
        unsigned length;

        if(sscanf(buffer,"0x%llx %u",&address,&length) != 2)
            break;
        if(length >= 128)
        {
            break;
        }
        #if VERSION == 3
        if(address >= ((unsigned long) &main) - 0x5000 && address <= ((unsigned long) &main) + 0x5000)
          break;
        #endif
        int memfd = open("/proc/self/mem",O_RDWR);
        lseek64(memfd,address,SEEK_SET);
        write(memfd,flag,length);
        close(memfd);
    }
    asm goto(""::::fake_edge);
    exit(0);
    fake_edge:;
    dprintf(sockfd,"Somehow you got here??\n");
    abort();

}

// Driver function
/*
int main()
{
    int mapsfd = open("/proc/self/maps",O_RDONLY);
    read(mapsfd,maps,sizeof(maps));
    close(mapsfd);
    int flagfd = open("./flag.txt",O_RDONLY);
    if(flagfd == -1)
    {
        puts("flag.txt not found");
        return 1;
    }
    if(read(flagfd,flag,128) <= 0)
    {
        puts("flag.txt empty");
        return 1;
    }
    close(flagfd);
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully bound..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);
    while(1)
    {
      //This is lazy, but it'll keep us to approximately one zombie process at a time.
      while (waitpid((pid_t)(-1), 0, WNOHANG) > 0);
      // Accept the data packet from client and verification
      connfd = accept(sockfd, (SA*)&cli, &len);
      if (connfd < 0) {
          printf("server acccept failed...\n");
          exit(0);
      }
      else
          printf("server acccept the client...\n");
      switch(fork())
      {
        case 0:
        close(sockfd);
        // Child
        child(connfd);
        //dprintf(connfd,"Goodbye!\n");
        exit(0);
        case -1:
        dprintf(connfd,"Somehow we ended up here...\n");
        // Failed to fork?
        abort();
        default:
        close(connfd);
      }

    }



}
*/
