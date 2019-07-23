// Copyright 2019 Google LLC
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

// Handles one client connection over over stdin/stdout. Multiple instances of
// this binary can be running - the executor binary will provide atomicity.

#include <iostream>
#include <functional>
#include <set>
#include <map>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <sstream>

#include "third_party/subprocess.h"

using namespace std;
namespace sp = subprocess;
mutex m;

string ReadFile(ifstream& file) {
  return string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

string BinDir() {
  string buf;
  buf.resize(4096);
  int read_size = buf.size();
  while (read_size == buf.size()) {
    read_size = readlink("/proc/self/exe", &buf[0], buf.size());
    if (read_size < 0) {
      std::cerr << "Error reading /proc/self/exe: " << strerror(errno) << std::endl;
      exit(-1);
    }
  }
  buf.resize(read_size);
  while (buf.back() != '/') {
    buf.pop_back();
  }
  return buf;
}

void WriteIntDirectly(int val) {
  cout.write((char*)(&val), 4);
}
void WriteStringDirectly(const string& val) {
  cout.write(val.c_str(), val.size());
}

void WriteInt(ostream& os, int val) {
  os.write((char*)(&val), 4);
}

void WriteString(ostream& os, const string& val) {
  os.write(val.c_str(), val.size());
}

int ReadInt(istream& is) {
  int ret;
  is.read((char*)&ret, 4);
  if (!cin) {
    std::cerr << "Failed to read 4 bytes from istream." << std::endl;
    exit(1);
  }
  return ret;
}
string ReadString(istream& is) {
  size_t size = ReadInt(is);
  string ret;
  ret.resize(size);

  is.read(&ret[0], size);
  if (!cin) exit(1);
  return ret;
}

void SendCommand(int opcode, const string& message) {
  lock_guard<mutex> locker(m);
  WriteIntDirectly(opcode);
  WriteIntDirectly(message.size());
  WriteStringDirectly(message);
  std::cout << std::flush;
}

void SendStdout(const string& buf, int ref_id) {
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteInt(tmp, buf.size());
  WriteString(tmp, buf);
  SendCommand(1, tmp.str());
}

void SendStderr(const string& buf, int ref_id) {
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteInt(tmp, buf.size());
  WriteString(tmp, buf);
  SendCommand(2, tmp.str());
}

void SendExited(int ref_id, int code) {
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteInt(tmp, code);
  SendCommand(5, tmp.str());
}

void SendServerError(const string& error, int ref_id=0) {
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteInt(tmp, error.size());
  WriteString(tmp, error);
  SendCommand(9, tmp.str());
}

std::map<int, std::shared_ptr<sp::Popen>> procs;
std::map<int, string> tmpdirs;
std::set<int> input_closed;

void BuildImpl(istream& in, int ref_id, const vector<string>& args) {
  auto proc = std::shared_ptr<sp::Popen>(
      new sp::Popen(args, sp::input{sp::PIPE}, sp::output{sp::PIPE}, sp::error{sp::PIPE})
  );
  procs[ref_id] = proc;

  thread t([proc, ref_id](){
    while (true) {
      std::cout << flush;
      char c;
      if (fread(&c, 1, 1, proc->output()) != 1) break;
      SendStdout(string(&c, 1), ref_id);
    };
    SendStdout(string(), ref_id);
  });
  t.detach();

  thread u([proc, ref_id](){
    while (true) {
      std::cerr << flush;
      char c;
      if (fread(&c, 1, 1, proc->error()) != 1) break;
      SendStderr(string(&c, 1), ref_id);
    };
    SendStderr(string(), ref_id);
  });
  u.detach();

  thread waiter([proc, ref_id]() {
    int waitval = proc->wait();
    SendExited(ref_id, waitval);
  });
  waiter.detach();
}

void Build(istream& in) {
  /*
   * opcode: `int` _(must be `3`)_
   * command-size: `int`
   * ref-id: `int`
   * array-of-args size: `int`
   * `array` of args, where each arg is:
     * argument size: `int`
     * argument: `string`
   * command to run: `string`
   * array-of-files size: `int`
   * `array` of files, where each file is:
     * filepath size: `int`
     * filepath: `string`
     * file size: `int`
     * file contents: `string`
  */
  stringstream& in_str = static_cast<stringstream&>(in);

  int ref_id = ReadInt(in);
  if (procs.count(ref_id)) {
    SendServerError("ref-id " + to_string(ref_id) + " already exists", ref_id);
    return;
  }

  std::vector<string> args;
  args.resize(ReadInt(in));
  if (args.empty()) {
    SendServerError("Missing command!", ref_id);
    return;
  }
  for (string& arg : args) {
    arg = ReadString(in);
  }

  string dir = "/home/user/builds/build-workdir-XXXXXX";
  if (!mkdtemp(&dir[0])) {
    std::cerr << "mkdtemp(" << &dir[0] << " failed: " << strerror(errno) << std::endl;
    exit(-3);
  }
  tmpdirs[ref_id] = dir;

  std::vector<std::pair<string, string>> files;
  files.resize(ReadInt(in));
  for(auto& file : files) {
    file.first = ReadString(in);
    if (file.first[0] == '/') {
      SendServerError("Filenames must not start with /", ref_id);
      return;
    }
    if (file.first.back() == '/') {
      SendServerError("Filenames must not end with /", ref_id);
      return;
    }
    if (file.first.find("..") != string::npos) {
      SendServerError("Filenames must not contain ..", ref_id);
      return;
    }
    file.second = ReadString(in);
  }

  for (const auto& file : files) {
    ofstream outfile(dir + "/" + file.first);
    if (!outfile.is_open()) {
      std::cerr << "Unable to create file" << std::endl;
      exit (-4);
    }
    outfile << file.second;
  }

  std::vector<string> executor_args;
  executor_args.push_back("./executor");
  executor_args.push_back(dir);
  executor_args.insert(executor_args.end(), args.begin(), args.end());

  BuildImpl(in, ref_id, executor_args);
}

void Stdin(istream& in) {
  int ref_id = ReadInt(in);
  if (!procs.count(ref_id)) {
    SendServerError("ref-id " + to_string(ref_id) + " does not exist", ref_id);
    return;
  }
  string buf = ReadString(in);
  if (buf.empty()) {
    procs[ref_id]->close_input();
    input_closed.insert(ref_id);
  } else if (input_closed.count(ref_id)) {
    SendServerError("Stdin has already been closed.", ref_id);
  } else {
    procs[ref_id]->send(&buf[0], buf.size());
  }
}

void SendFetched(int ref_id, const string& file, const string& body) {
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteInt(tmp, file.size());
  WriteString(tmp, file);
  WriteInt(tmp, body.size());
  WriteString(tmp, body);
  SendCommand(8, tmp.str());
}

void Fetch(istream& in) {
  int ref_id = ReadInt(in);
  if (!tmpdirs.count(ref_id)) {
    SendServerError("ref-id " + to_string(ref_id) + " does not exist", ref_id);
    return;
  }

  string dir = tmpdirs[ref_id];
  if (dir == "<admin>") {
    SendServerError("ref-id " + to_string(ref_id) + " is an administrator console", ref_id);
    return;
  }
  if (dir.back() != '/') dir.push_back('/');
  string file = ReadString(in);

  std::unique_ptr<char> real_path(realpath((dir + file).c_str(), nullptr));
  if (string(real_path.get()).substr(0, dir.size()) != dir) {
    SendServerError(string("Filenames must point to within the working directory, ") + dir +
                    string(". Attempted to fetch file with absolute path ") + real_path.get());
    return;
  }

  ifstream infile(real_path.get());
  if (!infile.is_open()) {
    SendServerError(string("Failed to open file  ") + real_path.get() +
                    string(": ") + strerror(errno));
  }
  string body = ReadFile(infile);

  SendFetched(ref_id, file, body);
}

void Admin(istream& in) {
  int ref_id = ReadInt(in);
  if (procs.count(ref_id)) {
    SendServerError("ref-id " + to_string(ref_id) + " already exists", ref_id);
    return;
  }
  tmpdirs[ref_id] = "<admin>";

  std::vector<string> args;
  args.push_back("./drop_privs");
  args.push_back("admin");  // admin user
  args.push_back("admin");  // admin group
  args.push_back("./admin");

  BuildImpl(in, ref_id, args);
}

function<void(istream& in)> ReverseError(string op) {
  return [op](istream& in) {
    SendServerError("Operation \"" + op + "\" is reserved for server->client communication only.");
  };
}

map<int, function<void(istream& in)>> ops = {
  {3, Build},
  {0, Stdin},
  {1, ReverseError("stdout")},
  {2, ReverseError("stderr")},
  {5, ReverseError("exited")},
  {7, Fetch},
  {8, ReverseError("fetched")},
  {9, ReverseError("server-error")},
  {10, Admin}
};

int main(int argc, char** argv) {
  while(true) {
    int opcode;
    cin.read((char*)&opcode, 4);
    if (!cin) break;

    stringstream tmp;
    tmp << ReadString(cin);

    if (!ops.count(opcode)) {
      SendServerError("Unknown opcode " + to_string(opcode));
      continue;
    }
    ops[opcode](tmp);
  }
  exit(0);
}
