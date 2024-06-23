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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>

#include "unicorn/unicorn.h"
#include "unicornel.h"
/* I'm reusing MAX_PROCESSES here, but there's not a 1:1 mapping of shared buffers to processes.
 * a process can create multiple shared mappings */
struct shared_buffer shared_buffers[MAX_PROCESSES] = { 0 };
long create_shared(struct process* current) {
    pthread_mutex_lock(&task_lock);
    unsigned long length = ARG_REGR(current,1);
    if(length > 0x10000 || !length || length & 0xFFF)
    {
        pthread_mutex_unlock(&task_lock);            
        return -1;
    }
    //Find an empty shared buffer handle
    unsigned long handle;
    for(handle = 0; handle < MAX_PROCESSES; handle++) {
        if(!shared_buffers[handle].refs)
            break;
    }
    if(handle == MAX_PROCESSES) {
        pthread_mutex_unlock(&task_lock);
        return -2;
    }
    void* buffer = calloc(1,length);
    if(!buffer) {
        pthread_mutex_unlock(&task_lock);
        return -3;
    }
    shared_buffers[handle].refs = 1; //Set to 1 to give a chance to map it
    shared_buffers[handle].buffer = buffer;
    shared_buffers[handle].length = length;
    pthread_mutex_unlock(&task_lock);
    return handle;
}

long map_shared(struct process* current)
{
    if(current->sbr.va) {
        return -1;
    }
    pthread_mutex_lock(&task_lock);
    unsigned long handle = ARG_REGR(current,3);
    if(handle >= MAX_PROCESSES || !shared_buffers[handle].refs) {
        pthread_mutex_unlock(&task_lock);
        return -2;
    }
    unsigned long length = ARG_REGR(current,2);
    if(!length || length & 0xFFF || length > shared_buffers[handle].length) {
        pthread_mutex_unlock(&task_lock);
        return -3;
    }
    unsigned long addr = ARG_REGR(current,1);
    if(!addr|| addr & 0xFFF)
    {
        pthread_mutex_unlock(&task_lock);
        return -4;
    }
    uc_err e = uc_mem_map_ptr(current->uc,addr, length,UC_PROT_ALL,shared_buffers[handle].buffer);
    if(e == UC_ERR_OK)
    {
        shared_buffers[handle].refs++;
        current->sbr.handle = handle;
        current->sbr.length = length;
        current->sbr.va = addr;
        if(current->bookmark)
        {
            //We need to unmap the shared mapping on rewind if we bookmarked previously
            current->sbr.unmap_on_rewind = true;
        }
    }
    pthread_mutex_unlock(&task_lock);
    return e;
}

//The bottom reference is only ever released by destroy_shared. Any maps will increase refcount to > 1
long unmap_shared(struct process* current) {
    if(!current->sbr.va)
    {
        return -1;
    }
    pthread_mutex_lock(&task_lock);
    uc_err e = uc_mem_unmap(current->uc,current->sbr.va,current->sbr.length);
    if(e == UC_ERR_OK)
    {
        shared_buffers[current->sbr.handle].refs--;
        current->sbr.va = 0;
        current->sbr.unmap_on_rewind = false;
    }
    if(shared_buffers[current->sbr.handle].refs == 1)
    {
        //last reference, destroy it
        free(shared_buffers[current->sbr.handle].buffer);
        shared_buffers[current->sbr.handle].refs--;
    }
    pthread_mutex_unlock(&task_lock);
    return e;
}
long unicornel_write(struct process* current) {
    unsigned long pointer = ARG_REGR(current,1);
    unsigned long length =  ARG_REGR(current,2);
    char* buffer = malloc(length);
    if(!buffer) return -1;
    uc_err err = uc_mem_read(current->uc,pointer,buffer,length);
    if(err != UC_ERR_OK) {
        free(buffer);
        return -1;
    }
    long ret = write(current->outfd,buffer,length);
    free(buffer);
    return ret;
}
//You're welcome
long print_integer(struct process* current) {
    dprintf(current->outfd,"%ld\n",ARG_REGR(current,1));
    return 0;
}
long unicornel_exit(struct process* current) {
    uc_emu_stop(current->uc);
    return 0;
}
long bookmark(struct process* current) {
    if(current->bookmark) {
        return -1;
    }
    uc_err e = uc_context_alloc(current->uc,&current->bookmark);
    if(e == UC_ERR_OK)
        e = uc_context_save(current->uc,current->bookmark);
    return e;
}
long unicornel_rewind(struct process* current) {
    if(current->bookmark == NULL)
    {
        return -1;
    }
    uc_err e = uc_context_restore(current->uc,current->bookmark);
    if(e != UC_ERR_OK)
    {
        //Couldn't rewind so just fail out
        return -2;
    }
    /* If we bookmarked, then mapped a shared buffer, we need to unmap the shared buffer to
     * restore the original state properly.
     * We can skip a full unmap_shared call because we do the checking here directly.
     */
    if(current->sbr.va && current->sbr.unmap_on_rewind)
    {
        uc_err e = uc_mem_unmap(current->uc,current->sbr.va,current->sbr.length);
        if(e == UC_ERR_OK)
        {
            shared_buffers[current->sbr.handle].refs--;
        }
        current->sbr.va = 0;
        current->sbr.unmap_on_rewind = false;
        if(shared_buffers[current->sbr.handle].refs == 1)
        {
            //last reference, destroy it
            free(shared_buffers[current->sbr.handle].buffer);
            shared_buffers[current->sbr.handle].refs--;
        }
    }
    return 0;
}
long switch_arch(struct process* current) {
    //Only allow switching architectures once in order to avoid potential recursion stack overflows
    if(current->transition)
        return -1;
    uc_arch arch = ARG_REGR(current,1);
    uc_mode mode = ARG_REGR(current,2);
    unsigned long new_pc = ARG_REGR(current,3);
    if(!uc_arch_supported(arch) || arch_used[arch]) {
        return -2;
    }
    uc_engine* new_uc;
    uc_engine* og_uc = current->uc;
    uc_arch og_arch = current->arch;
    struct buffer_ref og_sbr = current->sbr;

    uc_err e = uc_open(arch,mode,&new_uc);
    if(e != UC_ERR_OK) {
        return -3;
    }
    //Add in the hook so syscalls are supported
    uc_hook trace;
    e = uc_hook_add(new_uc,&trace,UC_HOOK_INTR,hook_call,current,1,0);
    if(e != UC_ERR_OK)
    {
        uc_close(new_uc);
        return -5;
    }
    //Transition maps
    for(unsigned i = 0; i < current->num_maps; i++)
    {
        e = uc_mem_map(new_uc,current->maps[i].va,current->maps[i].length,UC_PROT_ALL);
        if(e != UC_ERR_OK)
        {
            uc_close(new_uc);
            return -4;
        }
        //Transition the memory across to the new uc
        char* transition_buffer = malloc(current->maps[i].length);
        if(!transition_buffer) {
            uc_close(new_uc);
            return -4;
        }
        uc_mem_read(current->uc,current->maps[i].va,transition_buffer,current->maps[i].length);
        uc_mem_write(new_uc,current->maps[i].va,transition_buffer,current->maps[i].length);
        free(transition_buffer);
    }
    //Including shared regions
    if(og_sbr.va)
    {
        uc_mem_map_ptr(new_uc,og_sbr.va,og_sbr.length,UC_PROT_ALL,shared_buffers[og_sbr.handle].buffer);
        //Transitioning architectures means there's now two references to the shared buffer - the original arch ref and the new arch ref
        shared_buffers[og_sbr.handle].refs++;
        current->sbr.unmap_on_rewind = false;
    }
    //Destroy bookmark, because we can't rewind through architectures anyway
    uc_context_free(current->bookmark);
    current->bookmark = NULL;
    //Complete transition
    current->uc = new_uc;
    current->arch = arch;
    arch_used[arch] = true;
    arch_used[og_arch] = false;
    current->transition = true;
    uc_emu_start(new_uc,new_pc,0,0,0);
    //Detransition, destorying the new state and restoring the old state so destroy_process can clean up
    current->uc = og_uc;
    pthread_mutex_lock(&task_lock);
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
    //Restore sbr, only for it to be freed in destroy_process
    current->sbr = og_sbr;
    arch_used[arch] = false;
    pthread_mutex_unlock(&task_lock);
    uc_close(new_uc);
    uc_emu_stop(og_uc);
    return 0;
}
long unicornel_pause(struct process* current) {
    current->paused = true;
    while(current->paused);
    return 0;
}
long unicornel_resume(struct process* current) {
    unsigned long pid = ARG_REGR(current,1);
    pthread_mutex_lock(&task_lock);
    if(pid > MAX_PROCESSES || !processes[pid] || !processes[pid]->paused)
    {
        pthread_mutex_unlock(&task_lock);
        return -1;
    }
    processes[pid]->paused = false;
    pthread_mutex_unlock(&task_lock);
    return 0;
}

long (*syscalls[])(struct process* current) = {
    unicornel_exit,
    unicornel_write,
    print_integer,
    create_shared,
    map_shared,
    unmap_shared,
    bookmark,
    unicornel_rewind,
    switch_arch,
    unicornel_pause,
    unicornel_resume
};
