/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>
#include <unordered_map>

extern "C" __attribute__((weak)) void __scudo_print_stats(void);
extern "C" const char* __scudo_default_options(void) {
  // Small Quarantine so that recycling kicks in sooner rather than later.
  return "QuarantineSizeKb=24:ThreadLocalQuarantineSizeKb=12";
}

enum Status : uint64_t {
  Valid = 0,
  Processed = 1,
  Cancelled = 2,
};

// C++ class with some virtual methods so that a vtable will be used.
class Transaction {
 public:
  Transaction(std::string symbol, uint64_t quantity, uint64_t price)
      : id_(rand()),
        status_(Valid),
        time_(std::time(nullptr)),
        symbol_(std::move(symbol)),
        quantity_(quantity),
        price_(price) {}
  uint64_t getId() { return id_; }
  void setStatus(Status status) { status_ = status; }
  Status getStatus(void) { return status_; }
  std::time_t getTime() { return time_; }
  const std::string& getSymbol() { return symbol_; }
  uint64_t getQuantity() { return quantity_; }
  uint64_t getPrice() { return price_; }
  virtual void dump(){};
  virtual ~Transaction() {}

 private:
  uint64_t id_;
  Status status_;
  std::time_t time_;
  std::string symbol_;
  uint64_t quantity_;
  uint64_t price_;
};

class BuyTransaction : public Transaction {
 public:
  BuyTransaction(std::string symbol, uint64_t quantity, uint64_t price)
      : Transaction(std::move(symbol), quantity, price) {}
  void dump() {
    std::cout << "[" << getId() << "] BUY " << getQuantity() << " "
              << getSymbol() << " @ $" << getPrice() << std::endl;
  }
  ~BuyTransaction() {}
};

class SellTransaction : public Transaction {
 public:
  SellTransaction(std::string symbol, uint64_t quantity, uint64_t price)
      : Transaction(symbol, quantity, price) {}
  void dump() {
    std::cout << "[" << getId() << "] SELL " << getQuantity() << " "
              << getSymbol() << " @ $" << getPrice() << std::endl;
  }
  ~SellTransaction() {}
};

std::atomic_bool finished;
std::mutex m;
std::vector<Transaction*> v;
// BUGBUG: the map is not protected by the mutex in some cases!
std::unordered_map<uint64_t, Transaction*> map;  // Indexed by Transaction's id.
std::condition_variable c;

void transactionsProcessingThread() {
  while (!finished.load()) {
    std::unique_lock<std::mutex> l(m);
    c.wait(l);
    while (!v.empty()) {
      Transaction* t = v.back();
      std::cout << "Processing transaction " << t->getId() << "." << std::endl;
      v.pop_back();
      map.erase(t->getId());
      t->dump();
      t->setStatus(Processed);
      delete t;
    }
    l.unlock();
  }
}

/*
 * The application accepts the following commands:
 * - QUIT: terminates the process
 * - BUY [stock] [quantity] [price]: queues a buy transaction, returns an id
 * - SELL [stock] [quantity] [price]: queues a sell transaction, returns an id
 * - STATUS [id]: gets the status of a transaction
 * - CANCEL [id]: marks a transaction as cancelled, remove it from the map (but
 *                not the vector), deletes it
 * - PROCESS: triggers the processing thread that dequeues and deletes all
 *            transactions
 *
 * The idea is that one can free a transaction by calling CANCEL on it, and then
 * causing the other thread to reference it and delete it again.  The processing
 * thread offers a strong deallocation primitive (std::string & Transaction),
 * but being separated from the main thread, it has its own Quarantine & cache.
 * The main thread has most of the allocations primitives, the spurious
 * deallocation, and a potential memory disclosure via STATUS.
 */
int main() {
  std::thread th(transactionsProcessingThread);
  std::string input;
  while (!finished.load()) {
    std::getline(std::cin, input);
    std::transform(input.begin(), input.end(), input.begin(),
                   [](unsigned char c) { return std::toupper(c); });

    std::istringstream iss(input);
    std::string action;
    iss >> action;
    if (action.size() == 0) {
      std::cout << "Invalid input." << std::endl;
      continue;
    }

    if (action == "QUIT" || action == "PROCESS") {
      if (action == "QUIT") finished.store(true);
      c.notify_all();
    } else if (action == "STATUS") {
      uint64_t id;
      iss >> id;
      auto it = map.find(id);
      if (it != map.end()) {
          std::cout << "[" << id << "] " << it->second->getSymbol()
                    << " FILED @ " << it->second->getTime()
                    << " STATUS " << it->second->getStatus() << std::endl;
      } else {
        std::cout << "not found" << std::endl;
      }
    } else if (action == "CANCEL") {
      uint64_t id;
      iss >> id;
      auto search = map.find(id);
      if (search == map.end()) {
        std::cout << "Transaction not found." << std::endl;
        continue;
      }
      Transaction* t = search->second;
      t->setStatus(Cancelled);
      v.erase(std::remove(v.begin(), v.end(), t), v.end());
      delete t;
      std::cout << "Transaction cancelled." << std::endl;
    } else if (action == "BUY" || action == "SELL") {
      std::string stock;
      uint64_t quantity;
      uint64_t price;
      std::vector<uint64_t> numbers;
      iss >> stock;
      iss >> quantity;
      iss >> price;
      Transaction* t;
      if (action == "BUY")
        t = new BuyTransaction(std::move(stock), quantity, price);
      else
        t = new SellTransaction(stock, quantity, price);
      t->dump();
      {
        std::lock_guard<std::mutex> l(m);
        v.push_back(t);
        map[t->getId()] = t;
      }
    } else {
      std::cout << "Invalid command." << std::endl;
    }
  }
  th.join();
  if (&__scudo_print_stats) __scudo_print_stats();  // DEBUG
  std::cout << "Done!" << std::endl;
  return 0;
}
