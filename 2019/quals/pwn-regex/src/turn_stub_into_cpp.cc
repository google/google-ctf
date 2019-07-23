/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cstdlib>
#include <string>
char *readFile(std::string filename, int *size) {
  FILE *f = fopen(filename.c_str(), "rb");
  fseek(f, 0, SEEK_END);
  *size = ftell(f);
  rewind(f);
  char *buf = (char*) malloc(sizeof(char) * *size);
  fread(buf, 1, *size, f);
  fclose(f);
  return buf;
}
void writeOutStubData(FILE *f, const char *name, char *buf, int size) {
  fprintf(f, "int stub%sLen = %d;\n", name, size);
  fprintf(f, "const char *stub%s = \"", name);
  for (int i = 0; i < size; i++) {
    fprintf(f, "\\x%02x", (unsigned char) buf[i]);
  }
  fprintf(f, "\";\n");
}
void handleStub(FILE *f, const char *name) {
  int size;
  char realName[100];
  sprintf(realName, "stub%s.o", name);
  char *b = readFile(realName, &size);
  writeOutStubData(f, name, b, size);
}
int main() {
  FILE *f = fopen("stubs.h", "w");
  handleStub(f, "1");
  handleStub(f, "2");
  handleStub(f, "3");
  handleStub(f, "4");
  fclose(f);
  return 0;
}
