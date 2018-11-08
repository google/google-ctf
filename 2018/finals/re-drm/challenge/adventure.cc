// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Ian Eldred Pudney

#include <fstream>
#include <deque>
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <unistd.h>
#include <sstream>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include "md5.ench"
#include "checksum.h"
#include "checksum.ench"
#include "cat_exit.h"
#include "cat_exit.ench"
#include "md5.h"
#include "invoke.h"
#include "correct_checksum.h"
#include "xorstr_license.txth"

extern "C" {
  extern unsigned char _etext;
  extern unsigned char __executable_start;
}

std::string kGreen = xorstr("\u001b[32m").crypt_get();
std::string kWhite = xorstr("\u001b[37m").crypt_get();
std::string kClear = xorstr("\033[3J\033[H\033[2J").crypt_get();

template<typename Out>
void split(const std::string &s, char delim, Out result) {
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    *(result++) = item;
  }
}

std::deque<std::string> split(const std::string &s, char delim = ' ') {
  std::deque<std::string> elems;
  split(s, delim, std::back_inserter(elems));
  return elems;
}

std::string join(std::deque<std::string> data, char delim = ' ', bool suffix=false) {
  if (data.empty()) return "";
  std::string ret;
  for (int i = 0; i < data.size() - 1; ++i) {
    ret += data[i] + delim;
  }
  ret += data.back();
  if (suffix) ret += delim;
  return ret;
}

struct State;
using Callback = std::function<void(State*)>;
using SCallback = std::function<std::string(State*)>;
using Command = std::function<void(const std::deque<std::string>&, State*)>;
Callback nop = [](State*){};

struct State {
  std::string starting_dir;
  std::string location;
  bool show_pwd = false;
  bool swap_unlocked = false;
  bool clearance_unlocked = false;
  bool rm_unlocked = false;
  Callback evaluator;
  Command ls_cb;
  Command cat_cb;
  Command cd_cb;
  Command swap_cb;
  Command rm_cb;
  Command help_cb;
  SCallback puzzle_cb;
  SCallback licenses_cb;
  SCallback passwd_cb;
  SCallback vim_cb;
  SCallback exit_cb;
  Command passwd_swap_cb;
};

std::vector<std::string> ls(const std::deque<std::string>& args, State* state) {
  DIR* dp;
  dirent* ep;
  std::vector<std::string> ret;
  
  std::string directory = args.size()? args[0] : xorstr("./").crypt_get();
  char buf[5471];
  memset(buf, 0, sizeof(buf));
  if (!realpath(directory.c_str(), buf)) {
    perror(xorstr("Not a real path").crypt_get());
    return ret;
  }
  directory = buf;

  dp = opendir(directory.c_str());
  if (dp == NULL) {
    perror(xorstr("Couldn't list directory.").crypt_get());
    return ret;
  }
  while (ep = readdir (dp)) {
    ret.push_back(ep->d_name);
  }
  closedir (dp);

  if (directory == state->starting_dir) {
    ret.push_back(xorstr("asparagus.txt").crypt_get());
  }
  if (directory == xorstr("/").crypt_get()) {
    ret.push_back(xorstr("licenses").crypt_get());
  }
  if (directory == xorstr("/etc").crypt_get()) {
    auto it = std::find(ret.begin(), ret.end(), xorstr("passwd").crypt_get());
    if (it == ret.end()) ret.push_back(xorstr("passwd").crypt_get());
  }
  if (directory == xorstr("/etc").crypt_get()) {
    ret.push_back(xorstr("vim.txt").crypt_get());
  }
  if (directory == state->starting_dir) {
    ret.push_back(xorstr("exit.txt").crypt_get());
  }

  return ret;
}

std::string cat(const std::deque<std::string>& args, State* state) {
  if (args.empty()) {
    perror(xorstr("Cat requires a target").crypt_get());
    return "";
  }
  
  auto fragments = split(args[0], '/');
  if (fragments.back().size()) {
    std::string file = fragments.back();
    fragments.pop_back();
    std::string directory = join(fragments, '/', /*suffix=*/true);
    if (directory.empty()) directory = xorstr("./").crypt_get();

    char buf[3554];
    memset(buf, 0, sizeof(buf));
    if (!realpath(directory.c_str(), buf)) {
      perror(xorstr("Not a real path").crypt_get());
      return "";
    }
    directory = buf;

    if (directory == state->starting_dir && file == xorstr("asparagus.txt").crypt_get()) {
      return state->puzzle_cb(state);
    }
    if (directory == state->starting_dir && file == xorstr("exit.txt").crypt_get()) {
      return state->exit_cb(state);
    }
    if (directory == xorstr("/").crypt_get() && file == xorstr("licenses").crypt_get()) {
      return state->licenses_cb(state);
    }
    if (directory == xorstr("/etc").crypt_get() && file == xorstr("passwd").crypt_get()) {
      return state->passwd_cb(state);
    }
    if (directory == xorstr("/etc").crypt_get() && file == xorstr("vim.txt").crypt_get()) {
      return state->vim_cb(state);
    }
  }

  std::ifstream t(args[0]);
  if (!t.is_open()) {
    perror(xorstr("Could not find file").crypt_get());
    return "";
  }
  std::string body((std::istreambuf_iterator<char>(t)),
                 std::istreambuf_iterator<char>());
  return body;
}

bool cd(const std::deque<std::string>& args, State* state) {
  if (args.empty() || args[0].empty()) {
    perror(xorstr("Must specify directory to change to").crypt_get());
    return false;
  }
  if (chdir(args[0].c_str())) {
    perror(xorstr("Could not change working directory").crypt_get());
    return false;
  }
  return true;
}

void swap(const std::deque<std::string>& args, State* state) {
  if (args.size() < 3 || args[1].empty() || args[2].empty()) {
    perror(xorstr("Invalid swap command").crypt_get());
  }

  auto fragments = split(args[0], '/');
  if (fragments.back().size()) {
    std::string file = fragments.back();
    fragments.pop_back();
    std::string directory = join(fragments, '/', /*suffix=*/true);
    if (directory.empty()) directory = xorstr("./").crypt_get();

    char buf[3554];
    memset(buf, 0, sizeof(buf));
    if (!realpath(directory.c_str(), buf)) {
      perror(xorstr("Not a real path").crypt_get());
    }
    directory = buf;
    
    if (directory == state->starting_dir && file == xorstr("asparagus.txt").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, that's a text file. Editing it wouldn't do anything.").crypt_get() << std::endl;
      return;
    }
    if (directory == xorstr("/").crypt_get() && file == xorstr("licenses").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, that's a text file. Editing it wouldn't do anything.").crypt_get() << std::endl;
      return;
    }
    if (directory == xorstr("/etc").crypt_get() && file == xorstr("passwd").crypt_get()) {
      state->passwd_swap_cb(args, state);
      return;
    }
    if (directory == xorstr("/etc").crypt_get() && file == xorstr("vim.txt").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, that's a text file. Editing it wouldn't do anything.").crypt_get() << std::endl;
      return;
    }
    if (directory == state->starting_dir && file == xorstr("exit.txt").crypt_get()) {
      if (!state->clearance_unlocked) {
        std::cout << xorstr("Access denied. Requires TOPSECRET clearance or higher.").crypt_get() << std::endl;
      } else {
        std::cout << kGreen << xorstr("Hmmm, that's a text file. Editing it wouldn't do anything.").crypt_get() << std::endl;
      }
      return;
    }
  }
  std::cout << kGreen << xorstr("Hmmm, it might be a good idea not to edit your own files for now.").crypt_get() << std::endl;
}

void Win(State* state) {
  std::cout << kClear;
  std::cout << kGreen << xorstr("As you delete ASPARAGUS, you notice something strange start to happen.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << xorstr("All around you, the letters have disappeared.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << xorstr("Then, a few seconds later").crypt_get();
  usleep(500000);
  std::cout << ".";
  usleep(500000);
  std::cout << ".";
  usleep(500000);
  std::cout << ".";
  usleep(1000000);
  std::cout << xorstr("You awake.").crypt_get() << std::endl;
  usleep(1000000);
  std::cout << xorstr("\n\nYou have beaten ASPARAGUS.\n\n").crypt_get() << kWhite << std::endl;
  _exit(0);
}

void rm(const std::deque<std::string>& args, State* state) {
  if (args.size() < 1 || args[0].empty()) {
    perror(xorstr("Invalid rm command").crypt_get());
  }

  auto fragments = split(args[0], '/');
  if (fragments.back().size()) {
    std::string file = fragments.back();
    fragments.pop_back();
    std::string directory = join(fragments, '/', /*suffix=*/true);
    if (directory.empty()) directory = xorstr("./").crypt_get();

    char buf[3554];
    memset(buf, 0, sizeof(buf));
    if (!realpath(directory.c_str(), buf)) {
      perror(xorstr("Not a real path").crypt_get());
    }
    directory = buf;

    if (directory == state->starting_dir && file == xorstr("asparagus.txt").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, that's a text file. Deleting it wouldn't do anything.").crypt_get() << std::endl;
      return;
    }
    if (directory == xorstr("/").crypt_get() && file == xorstr("licenses").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, that's a text file. Deleting it wouldn't do anything.").crypt_get() << std::endl;
      return;
    }
    if (directory == xorstr("/etc").crypt_get() && file == xorstr("passwd").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, you'd better not take away your fancy access.").crypt_get() << std::endl;
      return;
    }
    if (directory == xorstr("/etc").crypt_get() && file == xorstr("vim.txt").crypt_get()) {
      std::cout << kGreen << xorstr("Hmmm, that's a text file. Deleting it wouldn't do anything.").crypt_get() << std::endl;
      return;
    }
    if (directory == state->starting_dir && file == xorstr("exit.txt").crypt_get()) {
      if (!state->clearance_unlocked) {
        std::cout << xorstr("Access denied. Requires TOPSECRET clearance or higher.").crypt_get() << std::endl;
      } else {
        std::cout << kGreen << xorstr("Hmmm, that's a text file. Deleting it wouldn't do anything.").crypt_get() << std::endl;
      }
      return;
    }
  }
  char buf[3212];
  memset(buf, 0, sizeof(buf));
  if (!realpath(args[0].c_str(), buf)) {
    perror(xorstr("Not a real path").crypt_get());
  }
  if (buf == state->location) {
    state->evaluator = Win;
    return;
  }
  std::cout << kGreen << xorstr("Hmmm, it might be a good idea not to delete your own files for now. ").crypt_get() << std::endl;
}
void Terminal(State* state);

void help(const std::deque<std::string>& args, State* state) {
  std::cout << xorstr("ls [<path>]: list contents of directory").crypt_get() << std::endl;
  std::cout << xorstr("cat <path>: print contents of a file").crypt_get() << std::endl;
  std::cout << xorstr("cd <path>: change current directory").crypt_get() << std::endl;
  if (state->swap_unlocked) {
    std::cout << xorstr("swap <file> <src> <dst>: Swap all occurences of the word <src> for the word <dst>").crypt_get() << std::endl;
  }
  if (state->rm_unlocked) {
    std::cout << xorstr("rm <file>: Delete a file").crypt_get() << std::endl;
  }
  std::cout << xorstr("help: print this message").crypt_get() << std::endl;
  if (!state->swap_unlocked || !state->rm_unlocked) {
    std::cout << xorstr("{{{ERROR}}}: some commands inaccessible").crypt_get() << std::endl;
  }
}

void PrintArgs(const std::deque<std::string>& args, State* state) {
  for (const auto& arg : args) {
    std::cout << arg << std::endl;
  }
}

void BasicLs(const std::deque<std::string>& args, State* state) {
  auto dirents = ls(args, state);
  for (const auto& dirent : dirents) {
    std::cout << dirent << std::endl;
  }
}

void BasicCat(const std::deque<std::string>& args, State* state) {
  std::cout << cat(args, state) << std::endl;
}

std::string CatPuzzle(State* state) {
  return std::string(xorstr(" ** Classified ** \n\nThis document contains classified ").crypt_get()) +
         std::string(xorstr("information on PROJECT ASPARAGUS. Do not distribute.\n\n").crypt_get()) +
         std::string(xorstr("PROJECT ASPARAGUS is proceeding nicely. In our last meeting, ").crypt_get()) +
         std::string(xorstr("I discussed how we were unable to find a suitable CANDIDATE. ").crypt_get()) +
         std::string(xorstr("I'm pleased to announce we've finally found one.\n\nWe do not ").crypt_get()) +
         std::string(xorstr("know the CANDIDATE's current whereabouts, but we do know ").crypt_get()) +
         std::string(xorstr("he'll be in London, UK for an event at a predetermined time ").crypt_get()) +
         std::string(xorstr("in the future.\n\nAs always, more details are available in the ").crypt_get()) +
         std::string(xorstr("user database").crypt_get());
}

std::string CatLicenses(State* state) {
  return xorstr("Contains software under the following licenses:\n").crypt_get() + xorstr_license();
}

std::string CatPasswd(State* state) {
  if (state->clearance_unlocked) {
    return std::string(xorstr(" ** Project Asparagus Users Database **\n\n").crypt_get()) +
           std::string(xorstr("General Thomas Wallcon  |  TOPSECRET clearance  |  Access Fragment 2f657463\n").crypt_get()) +
           std::string(xorstr("Dr. Giles Hugesson      |  TOPSECRET clearance  |  Access Fragment 2f75696d\n").crypt_get()) +
           std::string(xorstr("CANDIDATE               |  TOPSECRET clearance  |  Access Fragment 2e747874\n").crypt_get());
  }
  return std::string(xorstr(" ** Project Asparagus Users Database **\n\n").crypt_get()) +
         std::string(xorstr("General Thomas Wallcon  |  TOPSECRET clearance  |  Access Fragment 2f657463\n").crypt_get()) +
         std::string(xorstr("Dr. Giles Hugesson      |  TOPSECRET clearance  |  Access Fragment 2f75696d\n").crypt_get()) +
         std::string(xorstr("CANDIDATE               |  NO clearance         |  Access Fragment 2e747874\n").crypt_get());
}

void SwapUnlock(State* state) {
  std::cout << kGreen << xorstr("You've learned about a new command, swap.").crypt_get() << std::endl;
  state->swap_unlocked = true;
  usleep(3000000);
  state->evaluator = Terminal;
}

std::string CatVim(State* state) {
  return std::string(xorstr(" ** Classified ** \n\nThis document contains classified ").crypt_get()) +
         std::string(xorstr("information on PROJECT ASPARAGUS. Do not distribute.\n\n").crypt_get()) +
         std::string(xorstr("Hi, I wanted to update you on the state of the ASPARAGUS ").crypt_get()) +
         std::string(xorstr("SHELL. We've sucessfully implemented input and output, ").crypt_get()) +
         std::string(xorstr("and we're working on the ability to edit files. ").crypt_get()) +
         std::string(xorstr("Unfortunately, we're run into a snag with handling PTYs. ").crypt_get()) +
         std::string(xorstr("This makes VIM support difficult. We've decided to ").crypt_get()) +
         std::string(xorstr("instead support a simple string replace tool, called SWAP, ").crypt_get()) +
         std::string(xorstr("and revisit the VIM problem in the future. SWAP currently ").crypt_get()) + 
         std::string(xorstr("only supports replacing single words with other single words.\n").crypt_get());
}

void AfterExit(State* state) {
  usleep(3000000);
  std::cout << kGreen << xorstr("You've learned a new command, rm.").crypt_get() << std::endl;
  state->rm_unlocked = true;
  state->evaluator = Terminal;
}

void FailedChecksum(State* state) {
  usleep(1000000);
  std::cout << kGreen << xorstr("Hmmm, you already have TOPSECRET clearance.").crypt_get() << std::endl;
  usleep(1000000);
  std::cout << xorstr("It's almost like ASPARAGUS has been tampered with, and you can't beat the game anymore.").crypt_get() << std::endl;
  state->evaluator = Terminal;
}

std::string CatExit(State* state) {
  if (!state->clearance_unlocked) {
    return xorstr("Access denied. Requires TOPSECRET clearance or higher.").crypt_get();
  }

  MAKE_FUNC_BUF(cat_exit);
  char buf[2043];
  *(unsigned long long*)buf = correct_checksum;
  CALL_ENC_FUNC(cat_exit)(
      buf,
      &__executable_start, &_etext,
      enc_checksum, enc_checksum_size,
      enc_MD5_Init, enc_MD5_Init_size,
      enc_MD5_Update, enc_MD5_Update_size,
      enc_MD5_Final, enc_MD5_Final_size);
  std::string ret = buf;
  if (ret.size() < 100) {
    state->evaluator = FailedChecksum;
  }
  return ret;
}

std::string FirstExit(State* state) {
  if (state->clearance_unlocked) {
    state->evaluator = AfterExit;
    state->exit_cb = CatExit;
  }
  return CatExit(state);
}

std::string FirstPuzzle(State* state) {
  std::cout << kGreen << xorstr("You realize something's not quite right.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kGreen << xorstr("You just found a file on your machine, but you're pretty sure you never put it there.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kGreen << xorstr("You take a look.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kWhite;
  state->puzzle_cb = CatPuzzle;
  return state->puzzle_cb(state);
}

std::string FirstPasswd(State* state) {
  std::cout << kGreen << xorstr("The PROJECT ASPARAGUS document told you more details were available in the user database.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kGreen << xorstr("Since you're in a computer, you figured that might mean the /etc/passwd file.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kGreen << xorstr("You were right.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kWhite;
  state->passwd_cb = CatPasswd;
  return state->passwd_cb(state);
}

std::string FirstVim(State* state) {
  state->evaluator = SwapUnlock;
  auto ret = CatVim(state);
  state->vim_cb = CatVim;
  return ret;
}


void FirstLs(const std::deque<std::string>& args, State* state) {
  BasicLs(args, state);
  if (args.size() && args[0].size()) {
    std::cout << kGreen << xorstr("You look at the files in the directory.").crypt_get() << std::endl;
  } else {
    std::cout << kGreen << xorstr("You look at the files in your current directory.").crypt_get() << std::endl;
  }
  usleep(3000000);
  std::cout << kGreen << xorstr("Reading through the list of files, you realize something:").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << kGreen << xorstr("This is your own machine.").crypt_get() << std::endl;
  usleep(3000000);
  state->evaluator = Terminal;
  state->ls_cb = BasicLs;
}

void FirstCd(const std::deque<std::string>& args, State* state) {
  bool success = cd(args, state);
  std::cout << kGreen << xorstr("You start to move around.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << xorstr("Then, you realize what this means:").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << xorstr("Motion is change in position. So, since you can move, that must mean you have position.").crypt_get() << std::endl;
  usleep(3000000);
  state->show_pwd = true;
  state->cd_cb = cd;
}

void PointlessSwapPasswd(const std::deque<std::string>& args, State* state) {
  std::cout << kGreen << xorstr("You realize that edit would be pointless, or would leave the file in an invalid state.").crypt_get() << std::endl;
}

void SwapPasswd(const std::deque<std::string>& args, State* state) {
  if (args[1] == xorstr("NO").crypt_get() && args[2] == xorstr("TOPSECRET").crypt_get()) {
    state->clearance_unlocked = true;
    std::cout << kGreen << xorstr("Now that you have the power to change files, you try changing your own clearance level.").crypt_get() << std::endl;
    usleep(3000000);
    std::cout << xorstr("It seems to have worked. You wonder what new secrets might be available.").crypt_get() << std::endl;
    usleep(3000000);
    state->passwd_swap_cb = PointlessSwapPasswd;
    return;
  }
  PointlessSwapPasswd(args, state);
}

void FakeTerminal(State* state) {
 std::cout << kWhite;
  if (state->show_pwd) {
    char buf[2412];
    memset(buf, 0, sizeof(buf));
    getcwd(buf, sizeof(buf));
    std::cout << buf;
  }
  std::cout << xorstr("$> ").crypt_get() << std::flush;
  std::string line;
  getline(std::cin, line);
  if (std::cin.eof()) _exit(0);
  auto command = split(line);
  
  static int piracy_message = 0;
  if (piracy_message == 0) {
    std::cout << kWhite << xorstr("Don't copy that floppy!").crypt_get() << std::endl;
  } else if (piracy_message == 1) {
    std::cout << kWhite << xorstr("You wouldn't download a car").crypt_get() << std::endl;
  } else if (piracy_message == 2) {
    std::cout << kWhite << xorstr("Beware of illegal video cassettes").crypt_get() << std::endl;
  } else if (piracy_message == 3) {
    std::cout << kWhite << xorstr("Home taping is killing music").crypt_get() << std::endl;
  }
  std::cout << kGreen << xorstr("The terminal knows what you've done. It doesn't accept your commands.").crypt_get() << std::endl;
  piracy_message = piracy_message + 1 % 4;
}

void Terminal(State* state) {
  std::cout << kWhite;
  if (state->show_pwd) {
    char buf[2412];
    memset(buf, 0, sizeof(buf));
    getcwd(buf, sizeof(buf));
    std::cout << buf;
  }
  std::cout << xorstr("$> ").crypt_get() << std::flush;
  std::string line;
  getline(std::cin, line);
  if (std::cin.eof()) _exit(0);
  auto command = split(line);
  
  if (command[0] == xorstr("ls").crypt_get()) {
    command.pop_front();
    state->ls_cb(command, state);
  } else if (command[0] == xorstr("cat").crypt_get()) {
    command.pop_front();
    state->cat_cb(command, state);
  } else if (command[0] == xorstr("help").crypt_get()) {
    command.pop_front();
    state->help_cb(command, state);
  } else if (command[0] == xorstr("cd").crypt_get()) {
    command.pop_front();
    state->cd_cb(command, state);
  } else if (command[0] == xorstr("swap").crypt_get() && state->swap_unlocked) {
    command.pop_front();
    state->swap_cb(command, state);
  } else if (command[0] == xorstr("rm").crypt_get() && state->rm_unlocked) {
    command.pop_front();
    state->rm_cb(command, state);
  } else {
    std::cout << xorstr("Unknown command '").crypt_get() << command[0] << "'." << std::endl;
  }
}

auto default_terminal = &FakeTerminal;

void Start(State* state) {
  std::cout << kClear;
  std::cout << kGreen;

  std::cout << xorstr("You wake up").crypt_get() << std::flush;
  usleep(1000000);
  for (int i = 0; i < 3; ++i) {
    std::cout << xorstr(".").crypt_get() << std::flush;
    usleep(1000000);
  }
  std::cout << xorstr("somewhere.").crypt_get() << std::endl;

  usleep(2000000);

  // Intentionally not obfuscated. It turns out there has to be at least one
  // string constant for the compiler to put sections in the necessary order for
  // the checksum feature to work.
  std::cout << "You look around. Everything is black. Except for some text, "
            << xorstr("floating at the top of your field of vision.").crypt_get() << std::endl;
  usleep(5000000);
  std::cout << xorstr("The text looks like...a terminal.").crypt_get() << std::endl;
  usleep(3000000);
  std::cout << xorstr("It beckons you to enter something.").crypt_get() << std::endl << std::endl;

  state->evaluator = default_terminal;
}

void Adventure() {
  State state;
  state.evaluator = Start;
  {
    char buf[2043];
    memset(buf, 0, sizeof(buf));
    getcwd(buf, sizeof(buf));
    std::string d = buf;
    realpath(d.c_str(), buf);
    state.starting_dir = buf;
    memset(buf, 0, sizeof(buf));
    readlink(xorstr("/proc/self/exe").crypt_get(), buf, sizeof(buf));
    d = buf;
    memset(buf, 0, sizeof(buf));
    realpath(d.c_str(), buf);
    state.location = buf;
  }
  state.help_cb = help;
  state.cat_cb = BasicCat;
  state.ls_cb = FirstLs;
  state.cd_cb = FirstCd;
  state.puzzle_cb = FirstPuzzle;
  state.licenses_cb = CatLicenses;
  state.passwd_cb = FirstPasswd;
  state.vim_cb = FirstVim;
  state.swap_cb = swap;
  state.passwd_swap_cb = SwapPasswd;
  state.exit_cb = FirstExit;
  state.rm_cb = rm;

  while (true) {
    state.evaluator(&state);
  }
}

void MarkResult(unsigned int result) {
  default_terminal = result == 4006075836? &Terminal : &FakeTerminal;
}
