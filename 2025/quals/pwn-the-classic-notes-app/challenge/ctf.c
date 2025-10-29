/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int note_size = 0;
char **notes = NULL;

#define SIZE_OF_FUNCTION_FRAME_NAME 0x8
struct function_frame
{
    char name[SIZE_OF_FUNCTION_FRAME_NAME];
    void *function_pointer;
};

#define SIZE_OF_MY_FUNCTION_FRAMES 0x8
struct function_frame *my_function_frames;

void flag(int code)
{
    printf("FLAG\n");
    FILE *file_pointer;
    file_pointer = fopen("/home/user/flag.txt", "r");
    if (file_pointer != NULL)
    {
        int character;
        while ((character = fgetc(file_pointer)) != EOF)
        {
            printf("%c", character);
        }
        fclose(file_pointer);
        printf("\n");
    }
    exit(code);
}

void handler(int sig, siginfo_t *siginfo, void *pointer)
{
    printf("SIGFAULT!\n");
    for (int i = 0; i < SIZE_OF_MY_FUNCTION_FRAMES; i++)
    {
        if (my_function_frames != NULL && strcmp(my_function_frames[i].name, "exit") == 0)
        {
            printf("Calling exit from function frames\n");
            typedef void (*exit_type)(int);
            exit_type function = my_function_frames[i].function_pointer;
            function(-1);
        }
    }
    exit(-1);
}

void create_note(int size)
{
    if (note_size > 1024)
    {
        printf("Too many notes!\n");
        return;
    }
    if (size > 16384)
    {
        printf("Size too large!\n");
        return;
    }
    char *note = (char *)malloc(size * sizeof(char));
    char **new_notes = (char **)malloc((note_size + 1) * sizeof(char *));
    if (notes != NULL)
    {
        for (int i = 0; i < note_size; i++)
        {
            new_notes[i] = notes[i];
        }
        free(notes);
    }
    new_notes[note_size] = note;
    note_size++;
    notes = new_notes;
}

void read_note(int index)
{
    if (index < 0 || index >= note_size)
    {
        printf("Index out of range\n");
        return;
    }
    printf("Note at %d: %s\n", index, notes[index]);
}

void write_note(int index, int offset, const char *buffer, int size)
{
    if (index < 0 || index >= note_size)
    {
        printf("Index out of range\n");
        return;
    }
    if (notes[index] == NULL)
    {
        printf("Create note first\n");
        return;
    }
    if (offset < 0)
    {
        printf("Offset cannot be less than 0\n");
        return;
    }
    memcpy(notes[index] + offset, buffer, size);
}

int handle_command(const char *command)
{
    // The 'command' pointer is advanced as the string is parsed.
    while (1)
    {
        // Skip any leading whitespace before the command character itself.
        // This allows for commands to be separated by spaces, e.g., "C10 R5"
        while (*command != '\0' && isspace((unsigned char)*command))
        {
            command++;
        }

        // If we've reached the end of the string after skipping whitespace, no more commands.
        if (*command == '\0')
        {
            break;
        }

        char command_type = *command; // Get the command type (e.g., 'C', 'R', 'W')
        command++;                    // Advance the pointer PAST the command type character.
                                      // 'command' now points to what should be the arguments or whitespace before them.

        // Skip any whitespace characters immediately following the command type letter
        // and before the actual arguments. E.g., "C   123"
        while (*command != '\0' && isspace((unsigned char)*command))
        {
            command++;
        }

        // If, after skipping spaces, we are at the end of the string,
        // it means a command character was found but no arguments followed (if they were expected).
        // sscanf will handle this by failing to match, leading to the error break.

        int n_consumed = 0; // Variable to store the number of characters consumed by sscanf for a number.

        if (command_type == 'C')
        {
            int size;
            // Read an integer as size. %n stores the number of characters read into n_consumed.
            if (sscanf(command, "%d%n", &size, &n_consumed) == 1)
            {
                command += n_consumed; // Advance the command pointer past the parsed integer.
                create_note(size);
            }
            else
            {
                // Failed to parse size (e.g., "C" followed by non-integer or end-of-string).
                printf("Error: 'C' command expects an integer size.\n");
                break; // Stop processing further commands due to error.
            }
        }
        else if (command_type == 'R')
        {
            int index;
            // Read an integer as index.
            if (sscanf(command, "%d%n", &index, &n_consumed) == 1)
            {
                command += n_consumed; // Advance command pointer.
                read_note(index);
            }
            else
            {
                // Failed to parse index.
                printf("Error: 'R' command expects an integer index.\n");
                break; // Stop processing.
            }
        }
        else if (command_type == 'W')
        {
            int index, offset, content_size;
            int n_idx_consumed, n_offset_consumed, n_size_consumed;

            // Read an integer as index.
            if (sscanf(command, "%d%n", &index, &n_idx_consumed) == 1)
            {
                command += n_idx_consumed; // Advance past index.

                // Skip whitespace after index and before offset.
                while (*command != '\0' && isspace((unsigned char)*command))
                {
                    command++;
                }
                // Check if end of string reached prematurely
                if (*command == '\0')
                {
                    printf("Error: 'W' command missing offset and content after index.\n");
                    break;
                }

                // Read an integer as offset.
                if (sscanf(command, "%d%n", &offset, &n_offset_consumed) == 1)
                {
                    command += n_offset_consumed; // Advance past size.

                    // Skip whitespace after offset and before size.
                    while (*command != '\0' && isspace((unsigned char)*command))
                    {
                        command++;
                    }
                    // Check if end of string reached prematurely
                    if (*command == '\0')
                    {
                        printf("Error: 'W' command missing size and content after offset.\n");
                        break;
                    }

                    // Read an integer as size.
                    if (sscanf(command, "%d%n", &content_size, &n_size_consumed) == 1)
                    {
                        command += n_size_consumed; // Advance past size.

                        // Check if end of string reached prematurely but content was expected
                        if (*command == '\0' && content_size > 0)
                        {
                            printf("Error: 'W' command missing content after size specification (expected %d chars).\n", content_size);
                            break;
                        }
                        
                        // The content characters start at the current 'command' position.
                        // Check if there are enough characters left in the string for the content.
                        const char *content_start = command;
                        int available_chars = 0;
                        const char *temp_scan = command;
                        while (*temp_scan != '\0' && available_chars < content_size)
                        {
                            available_chars++;
                            temp_scan++;
                        }

                        if (available_chars == content_size)
                        {
                            write_note(index, offset, content_start, content_size);
                            command += content_size; // Advance the command pointer past the read content.
                        }
                        else
                        {
                            // Not enough characters available for the specified content size.
                            printf("Error: 'W' command: not enough characters for content. Expected %d, available %d.\n", content_size, available_chars);
                            break; // Stop processing.
                        }
                    }
                    else
                    {
                        // Failed to parse size for 'W'.
                        printf("Error: 'W' command expects an integer size after the offset.\n");
                        break; // Stop processing.
                    }
                }
                else
                {
                    // Failed to parse offset for 'W'.
                    printf("Error: 'W' command expects an integer offset after the index.\n");
                    break; // Stop processing.
                }
            }
            else
            {
                // Failed to parse index for 'W'.
                printf("Error: 'W' command expects an integer index.\n");
                break; // Stop processing.
            }
        }
        else // Unknown command type
        {
            // If command_type is not 'C', 'R', or 'W', or if it was an
            // unhandled case (e.g. '\0' if not caught at the loop start, though it should be).
            printf("Error: Unknown command type '%c'.\n", command_type);
            return -1;
        }
        // The loop continues, and will skip any spaces before the next command character.
    }
    return 0;
}

int main(void)
{
    setbuf(stdout, NULL);

    // Register handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sa.sa_sigaction = handler;
    sigaction(SIGSEGV, &sa, NULL);

    // Prepare frames
    my_function_frames = (struct function_frame *)malloc(SIZE_OF_MY_FUNCTION_FRAMES * sizeof(struct function_frame));
    for (int i = 0; i < SIZE_OF_MY_FUNCTION_FRAMES; i++)
    {
        strcpy(my_function_frames[i].name, "0123456");
        my_function_frames[i].function_pointer = NULL;
    }
    strcpy(my_function_frames[0].name, "flag");
    my_function_frames[0].function_pointer = (void *)flag;
    strcpy(my_function_frames[1].name, "exit");
    my_function_frames[1].function_pointer = (void *)exit;

    create_note(8);
    write_note(0, 0, "Hello!", 7);
    create_note(8);
    write_note(1, 0, "World!", 7);

    char buffer[0x100];
    while (1)
    {
        printf("Give me your command:\n");
        memset(buffer, 0, 0x100);
        if (fgets(buffer, sizeof(buffer), stdin) != NULL)
        {
            if (handle_command(buffer))
            {
                break;
            }
        }
        else
        {
            printf("Error reading input.\n");
        }
    }

    return 0;
}
