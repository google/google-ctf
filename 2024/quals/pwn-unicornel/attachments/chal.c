// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "unicorn/unicorn.h"
#include "unicornel.h"
pthread_mutex_t task_lock = PTHREAD_MUTEX_INITIALIZER;
struct pollfd pfds[MAX_PROCESSES + 1];
struct process* processes[MAX_PROCESSES];
unsigned next_pid = 1;
bool arch_used[UC_ARCH_MAX] = { false };
unsigned long ARG_REGR(struct process* current,unsigned reg) {
  unsigned long _ = 0;
  uc_reg_read(current->uc,call_regs[current->arch][reg],&_);
  return _;
}
void ARG_REGW(struct process* current,unsigned reg, unsigned long value)
{
  uc_reg_write(current->uc,call_regs[current->arch][reg],&value);
}
void hook_call(uc_engine* uc, unsigned intno, void* user_data)
{
  struct process* current = user_data;
  unsigned long syscall_no = ARG_REGR(current,0);
  //fprintf(stderr,"pid %d: syscall with value %lu\n",(int)current->pid,syscall_no);
  //fflush(stderr);
  if(syscall_no == 0xff)
  {
    //Loop detected - let me save us all some blushes and just stop
    uc_emu_stop(current->uc);
    return;
  }
  //Check for OOB syscall number?
  if(syscall_no > 10) {
    ARG_REGW(current,0,0xff);
    return;
  }
  unsigned long ret = syscalls[syscall_no](current);
  ARG_REGW(current,0,ret);
}

//Must be holding task lock
int destroy_process(struct process* current)
{
  //If this happens something has gone terribly wrong in our bookkeeping. Panic.
  if(processes[current->pid] != current)
    abort();
  processes[current->pid] = NULL;
  uc_context_free(current->bookmark);
  uc_close(current->uc);
  close(current->outfd);
  arch_used[current->arch] = false;
  if(current->sbr.va)
  {
    shared_buffers[current->sbr.handle].refs--;
    if(shared_buffers[current->sbr.handle].refs == 1)
    {
        //last reference, destroy it
        free(shared_buffers[current->sbr.handle].buffer);
        shared_buffers[current->sbr.handle].refs--;
    }
  }
  free(current);
  return 0;
}

void* process_thread(void* param)
{
  struct process* current = param;
  uc_err e = uc_emu_start(current->uc,current->entrypoint,current->entrypoint + current->code_length,0,0);
  unsigned long ip = 0;
  uc_reg_read(current->uc,ip_reg[current->arch],&ip);
  printf("Process %u finished with status %s at address %lu\n",(unsigned) current->pid,uc_strerror(e),ip);
  fflush(stdout);
  pthread_mutex_lock(&task_lock);
  destroy_process(current);
  pthread_mutex_unlock(&task_lock);
  pthread_exit(NULL);
}

//Must be holding task lock
int find_free_process()
{
  for(unsigned int i = 0; i < MAX_PROCESSES; i++)
  {
    /* We check pfds here to avoid a race between destroy_process ending a task and the
      main poll thread reaping the read end of the pipe
    */
    if(processes[i] == NULL && pfds[i].fd == -1)
      return i;
  }
  return -1;
}
int start_process() 
{
  pthread_mutex_lock(&task_lock);
  int pid = find_free_process();
  if(pid < 0)
  {
    printf("At max processes already\n");
    pthread_mutex_unlock(&task_lock);
    return -1;
  }
  struct unicornelf process_data;
  //Signal to client that we're ready to receive process_data
  printf("DATA_START\n");
  int ret = read(0,&process_data,sizeof(process_data));
  if(ret != sizeof(process_data)) {
    printf("Unexpected read size\n");
    pthread_mutex_unlock(&task_lock);
    return -1;
  }
  if(!process_data.code_length || !process_data.num_maps || process_data.num_maps > 4 || process_data.code_length > process_data.maps[0].length)
  {
    printf("Malformed process data\n");
    pthread_mutex_unlock(&task_lock);
    return -1;
  }
  //Only allow one process per architecture
  if(process_data.arch >= UC_ARCH_MAX || process_data.arch < 1 || arch_used[process_data.arch])
  {
    printf("Invalid arch specified\n");
    pthread_mutex_unlock(&task_lock);
    return -1;
  }
  char* code_recv = calloc(1,process_data.code_length);
  //Signal to client that we're ready to receive process code
  printf("CODE_START\n");
  fflush(stdout);
  read(0,code_recv,process_data.code_length);
  uc_engine *uc;
  uc_err err;
  err = uc_open(process_data.arch,process_data.mode,&uc);
  if(err != UC_ERR_OK) {
    printf("Failed on uc_open() %u %u with error %u\n",process_data.arch,process_data.mode,err);
    pthread_mutex_unlock(&task_lock);
    free(code_recv);
    return -1;
  }
  for(unsigned i = 0; i < process_data.num_maps; i++)
  {
    err = uc_mem_map(uc,process_data.maps[i].va,process_data.maps[i].length,UC_PROT_ALL);
    if(err != UC_ERR_OK)
    {
      printf("Failed on uc_mem_map() with error %u\n",err);
      free(code_recv);
      uc_close(uc);
      pthread_mutex_unlock(&task_lock);
      return -1;
    }
  }
  err = uc_mem_write(uc,process_data.maps[0].va,code_recv,process_data.code_length);
  free(code_recv);
  if(err != UC_ERR_OK)
  {
    printf("failed on uc_mem_write() with error %u\n",err);
    uc_close(uc);
    pthread_mutex_unlock(&task_lock);
    return -1;
  }
  uc_hook trace;
  int pipefds[2];
  pipe(pipefds);

  pfds[pid].fd = pipefds[0];
  pfds[pid].events = POLLIN;
  pfds[pid].revents = 0;
  struct process* new_process = calloc(1,sizeof(struct process));
  new_process->pid = pid;
  new_process->outfd = pipefds[1];
  new_process->uc = uc;
  new_process->arch = process_data.arch;
  new_process->entrypoint = process_data.maps[0].va;
  new_process->code_length = process_data.code_length;
  new_process->bookmark = NULL;
  new_process->sbr.va = 0;
  new_process->sbr.unmap_on_rewind = false;
  new_process->transition = false;
  memcpy(new_process->maps,process_data.maps,sizeof(process_data.maps));
  new_process->num_maps = process_data.num_maps;
  processes[pid] = new_process;
  err = uc_hook_add(uc,&trace,UC_HOOK_INTR,hook_call,new_process,1,0);
  if(err != UC_ERR_OK)
  {
    printf("failed on uc_hook_add() with error %u\n",err);
    destroy_process(new_process);
    pthread_mutex_unlock(&task_lock);
    return -1;
  }
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  int pthread_err = pthread_create(&new_process->thread,&attr,process_thread,new_process);
  if(pthread_err != 0)
  {
    printf("failed to create pthread\n");
    destroy_process(new_process);
  }
  else {
    printf("new process created with pid %d\n",pid);
    arch_used[process_data.arch] = true;
  }
  pthread_mutex_unlock(&task_lock);
  return pthread_err;
}
int main(int argc, char *argv[]) {
  pfds[MAX_PROCESSES].fd = 0 /* stdin */;
  pfds[MAX_PROCESSES].events = POLLIN;
  pfds[MAX_PROCESSES].revents = 0;
  for(unsigned int i = 0; i < MAX_PROCESSES; i++) {
    pfds[i].fd = -1;
    pfds[i].events = POLLIN;
    pfds[i].revents = 0;
  }
  printf("Welcome to the unicornel!\n");
  fflush(stdout);
  pthread_mutex_init(&task_lock,NULL);
  while(1) {
    poll(pfds,MAX_PROCESSES + 1,-1);
    for(unsigned i = 0; i < MAX_PROCESSES; i++) {
      //Data available from emulated process
      if(pfds[i].revents & POLLIN) {
        int nbytes;
        ioctl(pfds[i].fd,FIONREAD,&nbytes);
        splice(pfds[i].fd,0,1 /* stdout */,0,nbytes,0);
      }
      //Process ended, and the write end of the pipe was closed in destroy_process. Finish cleanup
      if(pfds[i].revents & POLLHUP) {
        close(pfds[i].fd);
        pfds[i].fd = -1;
      }
    }
    if(pfds[MAX_PROCESSES].revents & POLLIN) {
      //Received new process data
      start_process();
      fflush(stdout);
    }
  }
  return 0;
}
