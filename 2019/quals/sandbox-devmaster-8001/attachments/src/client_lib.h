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

// A library that supports the development of clients to the DevMaster 8000.

#ifndef CLIENT_LIB_H
#define CLIENT_LIB_H

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <streambuf>

#include "third_party/subprocess.h"
using namespace std;
namespace sp = subprocess;

void WriteInt(ostream& os, int val) {
  os.write((char*)&val, 4);
}
void WriteString(ostream& os, const string& val) {
  WriteInt(os, val.size());
  os.write(val.c_str(), val.size());
}

int ReadIntDirectly(sp::Popen& proc) {
  int ret;
  int read_bytes = fread(&ret, 1, 4, proc.output());
  if (read_bytes != 4) {
    std::cerr << "Read only " << read_bytes << " bytes when attempting to fread an int" << std::endl;
    exit(2);
  }
  return ret;
}
string ReadStringDirectly(sp::Popen& proc) {
  size_t size = ReadIntDirectly(proc);
  string ret;
  ret.resize(size);
  if (fread(&ret[0], 1, size, proc.output()) != size) {
    std::cerr << "Failed to read all " << size << " bytes when reading from string" << std::endl;
    exit(3);
  }
  return ret;
}

int ReadInt(istream& is) {
  int ret;
  is.read((char*)&ret, 4);
  if (!is) {
    std::cerr << "Could not read 4 bytes when attempting to read an int" << std::endl;
    exit(100);
  }
  return ret;
}
string ReadString(istream& is) {
  int size = ReadInt(is);
  string ret;
  ret.resize(size);
  is.read((char*)&ret[0], size);
  if (!is) {
    std::cerr << "Could not read all " << size << " bytes of string from message" << std::endl;
    exit(101);
  }
  return ret;
}

void SendCommand(sp::Popen& proc, int opcode, const string& body) {
  int size = body.size();
  proc.send((char*)&opcode, sizeof(opcode));
  proc.send((char*)&size, sizeof(size));
  proc.send(body.c_str(), body.size());
}

void SendBuild(sp::Popen& proc, int ref_id, const vector<string>& args, const std::vector<std::pair<string, string>>& files) {
  /*
   * opcode: `int` _(must be `3`)_
   * command-size: `int`
   * ref-id: `int`
   * command size: `int`
   * command to run: `string`
   * array-of-files size: `int`
   * `array` of files, where each file is:
     * filepath size: `int`
     * filepath: `string`
     * file size: `int`
     * file contents: `string`
  */
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteInt(tmp, args.size());
  for (const string& arg : args) {
    WriteString(tmp, arg);
  }
  WriteInt(tmp, files.size());
  for (const auto& p : files) {
    WriteString(tmp, p.first);
    WriteString(tmp, p.second);
  }

  SendCommand(proc, 3, tmp.str());
}

void SendStdin(sp::Popen& proc, int ref_id, const std::string& buf) {
  /*
   * opcode: `int` _(must be `0`)_
   * command-size: `int`
   * ref-id: `int`
   * input size: `int`
   * input: `string`
  */
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteString(tmp, buf);

  SendCommand(proc, 0, tmp.str());
}

void SendFetch(sp::Popen& proc, int ref_id, const string& file) {
  /*
   * opcode: `int` _(must be `7`)_
   * command-size: `int`
   * ref-id: `int`
   * filepath size: `int`
   * filepath: `string`
  */
  stringstream tmp;
  WriteInt(tmp, ref_id);
  WriteString(tmp, file);

  SendCommand(proc, 7, tmp.str());
}

void SendAdmin(sp::Popen& proc, int ref_id) {
  stringstream tmp;
  WriteInt(tmp, ref_id);

  SendCommand(proc, 10, tmp.str());
}

void Stdout(istream& in) {
  ReadInt(in);  // ref-id
  string debug_buf = static_cast<stringstream&>(in).str();
  string debug_believed_size = debug_buf.substr(0, 4);

  std::cout << ReadString(in) << std::flush;
}
void Stderr(istream& in) {
  ReadInt(in);  // ref-id
  std::cerr << ReadString(in) << std::flush;
}
int Exited(istream& in) {
  return ReadInt(in);  // Exit code
}
void Fetched(istream& in) {
  /*
   * opcode: `int` _(must be `8`)_
   * command-size: `int`
   * ref-id: `int`
   * filepath size: `int`
   * filepath: `string`
   * file size: `int`
   * contents: `string`
  */
  ReadInt(in); // ref-id
  string file = ReadString(in);
  string contents = ReadString(in);

  ofstream outfile(file);
  if (!outfile.is_open()) {
    exit(-5);
  }
  outfile << contents;
}
void ServerError(istream& in) {
  int ref_id = ReadInt(in);
  string error = ReadString(in);
  std::cerr << "Server error on ref_id=" << ref_id << ": " << error << std::endl;
}

function<void(istream& is)> ReverseError(string op) {
  return [op](istream& is) {
    std::cerr << "Operation \"" + op + "\" is reserved for client->server communication only." << std::endl;
  };
}

string ReadFile(const string& filename) {
  std::ifstream t(filename);
  if (!t.is_open()) {
    std::cerr << "Failed to open file " << filename << std::endl;
    exit(-2);
  }
  auto ret = string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
  return ret;
}

map<int, function<void(istream&)>> ops = {
  {3, ReverseError("build")},
  {0, ReverseError("stdin")},
  {1, Stdout},
  {2, Stderr},
  {5, Exited},
  {7, ReverseError("fetch")},
  {8, Fetched},
  {9, ServerError},
  {10, ReverseError("admin")},
  {11, ReverseError("exit")}
};

#endif  // CLIENT_LIB_H
