// Copyright 2020 Google LLC
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

// Author: Ian Eldred Pudney
#ifndef RUNTIME_H
#define RUNTIME_H

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <unistd.h>

#include "../../threading/thread.h"
#include "../../threading/semaphore.h"

void __attribute__ ((noinline)) exit_fail(const std::string& error) {
  std::cerr << error << std::endl;
  _exit(1);
}

template <typename Type>
struct atomic_wrapper : std::atomic<Type> {
  using BaseType = std::atomic<Type>;

  constexpr atomic_wrapper() : BaseType() {}
  constexpr atomic_wrapper(const Type& other) : BaseType(other) {}
  constexpr atomic_wrapper(const std::atomic<Type>& other) : BaseType(other.load()) {}
  constexpr atomic_wrapper(const atomic_wrapper<Type>& other) : BaseType(other.load()) {}

  void operator=(const Type& other) { BaseType::operator=(other); }
  void operator=(const std::atomic<Type>& other) {
    BaseType::operator=(other.load());
  }
  void operator=(const atomic_wrapper<Type>& other) {
    BaseType::operator=(other.load());
  }
  template<typename T>
  constexpr operator atomic_wrapper<T>() {
    return atomic_wrapper<T>(this->load());
  }
};

using achar = atomic_wrapper<unsigned char>;
using int32 = atomic_wrapper<int32_t>;
using int64 = atomic_wrapper<int64_t>;
using uint32 = atomic_wrapper<uint32_t>;
using uint64 = atomic_wrapper<uint64_t>;
using thread = uthread;

constexpr uint64_t convertible_int(uint64_t arg) {
  return arg;
}

template <typename T>
struct ref {
  std::shared_ptr<T> impl;

  ref() {}
  ref(const std::shared_ptr<T>& ptr) : impl(ptr) {}
  ref(const ref& other) : impl(std::atomic_load(&other.impl)) {}

  T& operator*() { return *std::atomic_load(&impl); }

  T* operator->() { return std::atomic_load(&impl).get(); }

  operator std::shared_ptr<T>() { return std::atomic_load(&impl); }

  operator bool() { return impl.get(); }
};

template <typename T, size_t sz>
struct fixed_array {
  std::array<T, sz> impl;
  void setitem(size_t idx, T new_value) {
    if (idx >= sz) {
      exit_fail("Attempt to set field in fixed array of size " +
                std::to_string(sz) + " with past-the-end index " +
                std::to_string(idx));
    }
    impl[idx] = new_value;
  }
  T getitem(size_t idx) {
    if (idx >= sz) {
      exit_fail("Attempt to get field in fixed array of size " +
                std::to_string(sz) + " with past-the-end index " +
                std::to_string(idx));
    }
    return impl[idx];
  }
  size_t size() { return sz; }
};

template <typename T>
struct dynamic_array {
  ref<std::vector<T>> impl;

  dynamic_array(size_t size = 0) : impl(std::make_shared<std::vector<T>>(size)) {}

  dynamic_array(const dynamic_array& other) {
    *this = const_cast<dynamic_array&>(other);
  }

  void setitem(size_t idx, T new_value) {
    ref<std::vector<T>> buf = impl;
    if (idx >= buf->size()) {
      exit_fail("Attempt to set field in dynamic array of size " +
                std::to_string(buf->size()) + " with past-the-end index " +
                std::to_string(idx));
    }
    (*buf)[idx] = new_value;
  }
  T getitem(size_t idx) {
    ref<std::vector<T>> buf = impl;
    if (idx >= buf->size()) {
      exit_fail("Attempt to get field in dynamic array of size " +
                std::to_string(buf->size()) + " with past-the-end index " +
                std::to_string(idx));
    }
    return (*buf)[idx];
  }
  size_t size() const {
    ref<std::vector<T>> buf = impl;
    return buf->size();
  }

  void resize(size_t new_size) {
    ref<std::vector<T>> buf = impl;
    ref<std::vector<T>> new_buf = std::make_shared<std::vector<T>>(new_size);
    for (int i = 0; i < std::min(buf->size(), new_size); ++i) {
     (*new_buf)[i] = (*buf)[i];
    }
    impl = new_buf;
  }

  dynamic_array& operator=(dynamic_array& other) {
    ref<std::vector<T>> other_buf = other.impl;
    ref<std::vector<T>> new_buf = std::make_shared<std::vector<T>>(*other_buf);
    impl = new_buf;
    return *this;
  }

  dynamic_array& operator=(dynamic_array&& other) {
    ref<std::vector<T>> other_buf = other.impl;
    ref<std::vector<T>> new_buf = std::make_shared<std::vector<T>>(*other_buf);
    impl = new_buf;
    return *this;
  }
};

template<typename T>
void sbt_resize(dynamic_array<T>& arr, size_t size) {
  arr.resize(size);
}

template<typename T>
void sbt_resize(dynamic_array<T>&& arr, size_t size) {
  arr.resize(size);
}

template<typename T>
void sbt_resize(ref<dynamic_array<T>>& arr, size_t size) {
  if (!arr) exit_fail("Attempt to resize null ref<dynamic_array>.");
  arr->resize(size);
}

template<typename T>
void sbt_resize(ref<dynamic_array<T>>&& arr, size_t size) {
  if (!arr) exit_fail("Attempt to resize null ref<dynamic_array>.");
  arr->resize(size);
}

dynamic_array<achar> make_string(const char* arg) {
  dynamic_array<achar> ret(strlen(arg));
  int i = 0;
  while (*arg != '\0') {
    ret.setitem(i, *arg);
    ++arg;
    ++i;
  }
  return ret;
}

dynamic_array<achar> make_string(std::string& arg) {
  dynamic_array<achar> ret(arg.size());
  for (int i = 0; i < arg.size(); ++i) {
    ret.setitem(i, arg[i]);
  }
  return ret;
}

dynamic_array<achar> make_string(std::string&& arg) {
  dynamic_array<achar> ret(arg.size());
  for (int i = 0; i < arg.size(); ++i) {
    ret.setitem(i, arg[i]);
  }
  return ret;
}

template <typename Return, typename... Args>
using func = typename std::add_pointer<Return(Args...)>::type;

template <typename T>
dynamic_array<T> __attribute__ ((noinline)) sbt_make_array(size_t integral) {
  return dynamic_array<T>(integral);
}

template <typename T, typename IntegralType>
dynamic_array<T> __attribute__ ((noinline)) sbt_make_array(atomic_wrapper<IntegralType> integral) {
  return dynamic_array<T>(integral);
}

template <typename T, typename IntegralType>
dynamic_array<T> __attribute__ ((noinline)) sbt_make_array(ref<atomic_wrapper<IntegralType>> integral) {
  return dynamic_array<T>(*integral);
}

dynamic_array<achar> __attribute__ ((noinline)) sbt_make_string(size_t integral) {
  return sbt_make_array<achar>(integral);
}

template <typename IntegralType>
dynamic_array<achar> __attribute__ ((noinline)) sbt_make_string(atomic_wrapper<IntegralType> integral) {
  return sbt_make_array<achar>(integral);
}

template <typename IntegralType>
dynamic_array<achar> __attribute__ ((noinline)) sbt_make_string(ref<atomic_wrapper<IntegralType>> integral) {
  return sbt_make_array<achar>(*integral);
}

template <typename T>
uint64 __attribute__ ((noinline))  sbt_size(dynamic_array<T>& arr) {
  return arr.size();
}

template <typename T>
uint64 __attribute__ ((noinline))  sbt_size(dynamic_array<T>&& arr) {
  return arr.size();
}

template <typename T, size_t size>
constexpr int64 sbt_size(fixed_array<T, size>& arr) {
  return size;
}

template <typename T, size_t size>
constexpr int64 sbt_size(fixed_array<T, size>&& arr) {
  return size;
}

template <typename T>
ref<T> __attribute__ ((noinline)) sbt_new() {
  return ref<T>(std::make_shared<T>());
}

template <typename T, typename A>
ref<T> __attribute__ ((noinline)) sbt_new(A& arg) {
  return ref<T>(std::make_shared<T>(arg));
}

template <typename T, typename A>
ref<T> __attribute__ ((noinline)) sbt_new(A&& arg) {
  return ref<T>(std::make_shared<T>(arg));
}

template <typename T>
T& sbt_deref(ref<T>& arg) {
  if (!arg) {
    exit_fail("Attempt to dereference null ref.");
  }
  return *arg;
}

template <typename T>
T& sbt_deref(ref<T>&& arg) {
  if (!arg) {
    exit_fail("Attempt to dereference null ref.");
  }
  return *arg;
}

template <typename T>
void sbt_print(ref<T> arg);

void __attribute__ ((noinline)) sbt_print(achar arg) { std::cout << arg << std::flush; }
void __attribute__ ((noinline)) sbt_print(int32 arg) { std::cout << arg << std::flush; }
void __attribute__ ((noinline)) sbt_print(int64 arg) { std::cout << arg << std::flush; }
void __attribute__ ((noinline)) sbt_print(uint32 arg) { std::cout << arg << std::flush; }
void __attribute__ ((noinline)) sbt_print(uint64 arg) { std::cout << arg << std::flush; }
void __attribute__ ((noinline)) sbt_print(uint64_t arg) { std::cout << arg << std::flush; }

template <typename T, size_t sz>
void __attribute__ ((noinline)) sbt_print(fixed_array<T, sz>& arg) {
  std::cout << "[";
  for (int i = 0; i < sz; ++i) {
    sbt_print(arg.getitem(i));
    if (i != sz - 1) std::cout << ", ";
  }
  std::cout << "]" << std::flush;
}

template <typename T, size_t sz>
void __attribute__ ((noinline)) sbt_print(fixed_array<T, sz>&& arg) {
  std::cout << "[";
  for (int i = 0; i < sz; ++i) {
    sbt_print(arg.getitem(i));
    if (i != sz - 1) std::cout << ", ";
  }
  std::cout << "]" << std::flush;
}


template <typename T>
void __attribute__ ((noinline)) sbt_print(dynamic_array<T>& arg) {
  std::cout << "[";
  for (int i = 0; i < arg.size(); ++i) {
    sbt_print(arg.getitem(i));
    if (i != arg.size() - 1) std::cout << ", ";
  }
  std::cout << "]" << std::flush;
}

template <typename T>
void __attribute__ ((noinline)) sbt_print(dynamic_array<T>&& arg) {
  std::cout << "[";
  for (int i = 0; i < arg.size(); ++i) {
    sbt_print(arg.getitem(i));
    if (i != arg.size() - 1) std::cout << ", ";
  }
  std::cout << "]" << std::flush;
}


template <>
void __attribute__ ((noinline)) sbt_print<achar>(dynamic_array<achar>& arg) {
  for (int i = 0; i < arg.size(); ++i) {
    std::cout << (char)arg.getitem(i);
  }
  std::cout << std::flush;
}

template <>
void __attribute__ ((noinline)) sbt_print<achar>(dynamic_array<achar>&& arg) {
  for (int i = 0; i < arg.size(); ++i) {
    std::cout << (char)arg.getitem(i);
  }
  std::cout << std::flush;
}

template <typename T>
void __attribute__ ((noinline)) sbt_print(ref<T> arg) {
  if (!arg) {
    std::cout << "ref<null>";
    return;
  }
  std::cout << "ref<";
  std::cout << (arg.operator->());
  std::cout << ">(";
  sbt_print(*arg);
  std::cout << ")";
  std::cout << std::flush;
}

template<typename RetType, typename... ArgType>
void __attribute__ ((noinline)) sbt_print(RetType(*func)(ArgType...)) {
  std::cout << "func<" << reinterpret_cast<void*>(func) << ">" << std::flush;
}

achar sbt_hex_to_byte(achar major, achar minor) {
  char ret = 0;
  if (minor >= '0' && minor <= '9') {
    ret += (minor - '0');
  } else if (minor >= 'a' && minor <= 'f') {
    ret += (minor - 'a' + 10);
  } else if (minor >= 'A' && minor <= 'F') {
    ret += (minor - 'A' + 10);
  } else {
    exit_fail(std::string("Character ") + std::string(minor, 1) + " is not a valid hex char.");
  }

  if (major >= '0' && major <= '9') {
    ret += 16 * (major - '0');
  } else if (major >= 'a' && major <= 'f') {
    ret += 16 * (major - 'a' + 10);
  } else if (major >= 'A' && major <= 'F') {
    ret += 16 * (major - 'A' + 10);
  } else {
    exit_fail(std::string("Character ") + std::string(major, 1) + " is not a valid hex char.");
  }

  return ret;
}

dynamic_array<achar> sbt_hex_to_bytes(dynamic_array<achar>&& arg) {
  if (arg.size() % 2 != 0) {
    exit_fail("hex_to_bytes called on odd-length string.");
  }
  dynamic_array<achar> ret;
  ret.resize(arg.size() / 2);
  for(int i = 0; i < arg.size(); i += 2) {
    ret.setitem(i/2, sbt_hex_to_byte(arg.getitem(i), arg.getitem(i+1)));
  }
  return ret;
}

dynamic_array<achar> sbt_hex_to_bytes(dynamic_array<achar>& arg) {
  if (arg.size() % 2 != 0) {
    exit_fail("hex_to_bytes called on odd-length string.");
  }
  dynamic_array<achar> ret;
  ret.resize(arg.size() / 2);
  for(int i = 0; i < arg.size(); i += 2) {
    ret.setitem(i/2, sbt_hex_to_byte(arg.getitem(i), arg.getitem(i+1)));
  }
  return ret;
}

dynamic_array<achar> sbt_bytes_to_hex(dynamic_array<achar>&& arg) {
  std::stringstream ss;
  for (int i = 0; i < arg.size(); ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)arg.getitem(i);
  }
  return make_string(ss.str());
}

dynamic_array<achar> sbt_bytes_to_hex(dynamic_array<achar>& arg) {
  std::stringstream ss;
  for (int i = 0; i < arg.size(); ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)arg.getitem(i);
  }
  return make_string(ss.str());
}

achar sbt_hex8(dynamic_array<achar>&& arg) {
  if (arg.size() != 2) exit_fail("hex8 called with string not 2 chars long.");
  return sbt_hex_to_byte(arg.getitem(0), arg.getitem(1));
}

achar sbt_hex8(dynamic_array<achar>& arg) {
  if (arg.size() != 2) exit_fail("hex8 called with string not 2 chars long.");
  return sbt_hex_to_byte(arg.getitem(0), arg.getitem(1));
}

uint32 sbt_hex32(dynamic_array<achar>&& arg) {
  if (arg.size() != 8) exit_fail("hex32 called with string not 8 chars long.");
  return
      (sbt_hex_to_byte(arg.getitem(0), arg.getitem(1)) << 24) +
      (sbt_hex_to_byte(arg.getitem(2), arg.getitem(3)) << 16) +
      (sbt_hex_to_byte(arg.getitem(4), arg.getitem(5)) << 8) +
      (sbt_hex_to_byte(arg.getitem(6), arg.getitem(7)));
}

uint32 sbt_hex32(dynamic_array<achar>& arg) {
  if (arg.size() != 8) exit_fail("hex32 called with string not 8 chars long.");
  return
      (sbt_hex_to_byte(arg.getitem(0), arg.getitem(1)) << 24) +
      (sbt_hex_to_byte(arg.getitem(2), arg.getitem(3)) << 16) +
      (sbt_hex_to_byte(arg.getitem(4), arg.getitem(5)) << 8) +
      (sbt_hex_to_byte(arg.getitem(6), arg.getitem(7)));
}

uint64 sbt_hex64(dynamic_array<achar>&& arg) {
  if (arg.size() != 16) exit_fail("hex64 called with string not 16 chars long.");
    uint64 major =
      (sbt_hex_to_byte(arg.getitem(0), arg.getitem(1)) << 24) +
      (sbt_hex_to_byte(arg.getitem(2), arg.getitem(3)) << 16) +
      (sbt_hex_to_byte(arg.getitem(4), arg.getitem(5)) << 8) +
      (sbt_hex_to_byte(arg.getitem(6), arg.getitem(7)));
    uint32 minor =
      (sbt_hex_to_byte(arg.getitem(8), arg.getitem(9)) << 24) +
      (sbt_hex_to_byte(arg.getitem(10), arg.getitem(11)) << 16) +
      (sbt_hex_to_byte(arg.getitem(12), arg.getitem(13)) << 8) +
      (sbt_hex_to_byte(arg.getitem(14), arg.getitem(15)));
  major = major << 32;
  major += minor;
  return major;
}

uint64 sbt_hex64(dynamic_array<achar>& arg) {
  if (arg.size() != 16) exit_fail("hex64 called with string not 16 chars long.");
    uint64 major =
      (sbt_hex_to_byte(arg.getitem(0), arg.getitem(1)) << 24) +
      (sbt_hex_to_byte(arg.getitem(2), arg.getitem(3)) << 16) +
      (sbt_hex_to_byte(arg.getitem(4), arg.getitem(5)) << 8) +
      (sbt_hex_to_byte(arg.getitem(6), arg.getitem(7)));
    uint32 minor =
      (sbt_hex_to_byte(arg.getitem(8), arg.getitem(9)) << 24) +
      (sbt_hex_to_byte(arg.getitem(10), arg.getitem(11)) << 16) +
      (sbt_hex_to_byte(arg.getitem(12), arg.getitem(13)) << 8) +
      (sbt_hex_to_byte(arg.getitem(14), arg.getitem(15)));
  major = major << 32;
  major += minor;
  return major;
}

dynamic_array<achar> sbt_to_hex(achar val) {
  std::stringstream ss;
  ss << std::hex << std::setw(2) << std::setfill('0') << (int)val;
  return make_string(ss.str());
}

dynamic_array<achar> sbt_to_hex(uint32 val) {
  std::stringstream ss;
  ss << std::hex << std::setw(8) << std::setfill('0') << val;
  return make_string(ss.str());
}

dynamic_array<achar> sbt_to_hex(int32 val) {
  std::stringstream ss;
  ss << std::hex << std::setw(8) << std::setfill('0') << val;
  return make_string(ss.str());
}

dynamic_array<achar> sbt_to_hex(uint64 val) {
  std::stringstream ss;
  ss << std::hex << std::setw(16) << std::setfill('0') << val;
  return make_string(ss.str());
}

dynamic_array<achar> sbt_to_hex(int64 val) {
  std::stringstream ss;
  ss << std::hex << std::setw(16) << std::setfill('0') << val;
  return make_string(ss.str());
}

achar sbt_bytes8(dynamic_array<achar>&& arg) {
  if (arg.size() != 1) exit_fail("bytes8 called with string not 1 char long.");
  return arg.getitem(0);
}

achar sbt_bytes8(dynamic_array<achar>& arg) {
  if (arg.size() != 1) exit_fail("bytes8 called with string not 1 char long.");
  return arg.getitem(0);
}

uint32 sbt_bytes32(dynamic_array<achar>&& arg) {
  if (arg.size() != 4) exit_fail("bytes32 called with string not 4 chars long.");
  return
      (arg.getitem(0)) +
      (arg.getitem(1) << 8) +
      (arg.getitem(2) << 16) +
      (arg.getitem(3) << 24);
}

uint32 sbt_bytes32(dynamic_array<achar>& arg) {
  if (arg.size() != 4) exit_fail("bytes32 called with string not 4 chars long.");
  return
      (arg.getitem(0)) +
      (arg.getitem(1) << 8) +
      (arg.getitem(2) << 16) +
      (arg.getitem(3) << 24);
}

uint64 sbt_bytes64(dynamic_array<achar>&& arg) {
  if (arg.size() != 8) exit_fail("bytes64 called with string not 8 chars long.");
  uint64 minor =
      (arg.getitem(0)) +
      (arg.getitem(1) << 8) +
      (arg.getitem(2) << 16) +
      (arg.getitem(3) << 24);
  uint64 major =
      (arg.getitem(4)) +
      (arg.getitem(5) << 8) +
      (arg.getitem(6) << 16) +
      (arg.getitem(7) << 24);
  major = major << 32;
  major = major + minor;
  return major;
  return major;
}

uint64 sbt_bytes64(dynamic_array<achar>& arg) {
  if (arg.size() != 8) exit_fail("bytes64 called with string not 8 chars long.");
  uint64 minor =
      (arg.getitem(0)) +
      (arg.getitem(1) << 8) +
      (arg.getitem(2) << 16) +
      (arg.getitem(3) << 24);
  uint64 major =
      (arg.getitem(4)) +
      (arg.getitem(5) << 8) +
      (arg.getitem(6) << 16) +
      (arg.getitem(7) << 24);
  major = major << 32;
  major = major + minor;
  return major;
}

dynamic_array<achar> sbt_to_bytes(achar val) {
  return make_string(std::string((const char*)&val, 1));
}

dynamic_array<achar> sbt_to_bytes(uint32 val) {
  return make_string(std::string((const char*)&val, 4));
}

dynamic_array<achar> sbt_to_bytes(int32 val) {
  return make_string(std::string((const char*)&val, 4));
}

dynamic_array<achar> sbt_to_bytes(uint64 val) {
  return make_string(std::string((const char*)&val, 8));
}

dynamic_array<achar> sbt_to_bytes(int64 val) {
  return make_string(std::string((const char*)&val, 8));
}

dynamic_array<achar> __attribute__ ((noinline)) sbt_read(size_t integral) {
  dynamic_array<achar> ret(integral);
  for (int i = 0; i < integral; ++i) {
    char c = std::cin.get();
    if (std::cin.eof()) {
      ret.impl->resize(i);
      return ret;
    }
    ret.setitem(i, c);
  }
  return ret;
}

// Threading wrappers
void sbt_up(semaphore& sem) { sem.up(); }
void sbt_up(ref<semaphore> sem) {
  if (!sem) {
    exit_fail("Attempt to dereference null ref<semaphore>.");
  }
  sem->up();
}

void sbt_down(semaphore& sem) { sem.down(); }

void sbt_down(ref<semaphore> sem) {
  if (!sem) {
    exit_fail("Attempt to down null ref<semaphore>.");
  }
  sem->down();
}

void sbt_join(uthread& t) { t.join(); }
void sbt_join(uthread&& t) { t.join(); }


void sbt_join(ref<thread> t) {
  if (!t) {
    exit_fail("Attempt to join null ref<thread>.");
  }
  t->join();
}

template <typename FuncPtr, typename... Args>
uthread __attribute__ ((noinline)) sbt_make_thread(FuncPtr func, Args... args) {
  return uthread{[func, args...]() { func(args...); }};
}

void __attribute__ ((noinline)) sbt_set_max_native_threads(int threads) {
  set_max_native_threads(threads);
}

void __attribute__ ((noinline)) sbt_usleep(int64_t duration) {
  uthread_safe_sleep(duration);
}

#endif
