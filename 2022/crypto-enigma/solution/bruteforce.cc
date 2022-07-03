// Copyright 2022 Google LLC
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

#include "enigma/enigma.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <thread>
#include <unordered_set>
#include <utility>

#include "bigrams.h"

std::string read_is(std::istream& is) {
  std::istreambuf_iterator<char> begin(is), end;
  std::string s(begin, end);
  return s;
}

std::string clean(const std::string& str) {
  std::string ret;
  for (char c : str) {
    if (c < 'A' || c > 'Z') continue;
    ret.push_back(c);
  }
  return ret;
}

std::array<int, 26> count_occurences(const std::string& buf) {
  std::array<int, 26> ret;
  memset(ret.data(), 0, ret.size() * sizeof(int));

  for (char c : buf) {
    ret[c - 65]++;
  }

  return ret;
}

constexpr int bigram_size = 26*26;

std::array<int, bigram_size> bi_count_occurences(const std::string& buf) {
  std::array<int, bigram_size> ret;
  memset(ret.data(), 0, ret.size() * sizeof(int));

  for (int i = 0; i < buf.size() - 1; ++i) {
    char c1 = buf[i] - 65;
    char c2 = buf[i+1] - 65;
    ret[((int)c1) * 26 + c2]++;
  }

  return ret;
}

const std::array<unsigned long long, bigram_size> bigram_scores = [](){
  std::array<unsigned long long, bigram_size> ret;
  memset(ret.data(), 0, ret.size() * sizeof(unsigned long long));

  for(const auto& p : bigrams) {
    ret[(p.first[0] - 65) * 26 + (p.first[1] - 65)] = p.second;
  }

  return ret;
}();

const unsigned long long total_bigram_count = [](){
  unsigned long long ret = 0;
  for(const auto& p : bigrams) {
    ret += p.second;
  }
  return ret;
}();

double bigram_score(const std::array<int, bigram_size>& occurences) {
  unsigned long long score = 0;
  unsigned long long total_occurences = 0;
  for (int i = 0; i < occurences.size(); ++i) {
    score += occurences[i] * bigram_scores[i];
    total_occurences += occurences[i];
  }

  return (((double)score) / (double)total_bigram_count);
}

constexpr int trigram_size = 26*26*26;

std::array<int, trigram_size> tri_count_occurences(const std::string& buf) {
  std::array<int, trigram_size> ret;
  memset(ret.data(), 0, ret.size() * sizeof(int));

  for (int i = 0; i < buf.size() - 2; ++i) {
    char c1 = buf[i] - 65;
    char c2 = buf[i+1] - 65;
    char c3 = buf[i+2] - 65;
    ret[((int)c1) * 26 * 26 + ((int)c2) * 26 + c3]++;
  }

  return ret;
}

template<unsigned long size>
double index_of_coincidence(const std::array<int, size>& occurences) {
  int64_t total = 0;
  int64_t sum = 0;
  for(int i = 0; i < occurences.size(); ++i) {
    total += occurences[i];
    sum += occurences[i] * (occurences[i] - 1);
  }

  double denominator = total * (total - 1)/occurences.size();
  double ic = sum / denominator;

  return ic;
}

struct RotorSetting {
  std::string rotor;
  int start_pos;
  int ring_setting;


  Rotor gen() const {
    Rotor ret = rotors.at(rotor);
    ret.rotor_position = start_pos;
    ret.ring_setting = ring_setting;
    return ret;
  }

  bool operator==(const RotorSetting& other) const {
    return rotor == other.rotor && start_pos == other.start_pos && ring_setting == other.ring_setting;
  }

  bool operator<(const RotorSetting& other) const {
    if (rotor < other.rotor) return true;
    if (rotor > other.rotor) return false;
    if (start_pos < other.start_pos) return true;
    if (start_pos > other.start_pos) return false;
    if (ring_setting < other.ring_setting) return true;
    if (ring_setting > other.ring_setting) return false;
    return false;
  }
};

std::ostream& operator<<(std::ostream& os, const RotorSetting& rs) {
  os << rs.rotor << "[" << rs.start_pos << "/" << rs.ring_setting << "]";
  return os;
}

template<>
struct std::hash<RotorSetting>
{
    std::size_t operator()(RotorSetting const& s) const noexcept
    {
        return std::hash<std::string>()(s.rotor) ^ (std::hash<int>()(s.start_pos) << 32) ^ std::hash<int>()(s.ring_setting);
    }
};

template<>
struct std::hash<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>>
{
    std::size_t operator()(std::tuple<RotorSetting, RotorSetting, RotorSetting, double> const& s) const noexcept
    {
        const auto& arg0 = std::get<0>(s);
        const auto& arg1 = std::get<1>(s);
        const auto& arg2 = std::get<2>(s);
        const auto& arg3 = std::get<3>(s);
        return
            std::hash<RotorSetting>()(arg0) ^
            std::hash<RotorSetting>()(arg1) ^
            std::hash<RotorSetting>()(arg2) ^
            std::hash<double>()(arg3);
    }
};

template<>
struct std::hash<std::tuple<RotorSetting, RotorSetting, RotorSetting>>
{
    std::size_t operator()(std::tuple<RotorSetting, RotorSetting, RotorSetting> const& s) const noexcept
    {
        const auto& arg0 = std::get<0>(s);
        const auto& arg1 = std::get<1>(s);
        const auto& arg2 = std::get<2>(s);
        return
            std::hash<RotorSetting>()(arg0) ^
            std::hash<RotorSetting>()(arg1) ^
            std::hash<RotorSetting>()(arg2);
    }
};

std::mutex scores_lock;
std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>> scores;
std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>> ring_scores;
uint64_t expected_scores;
uint64_t expected_ring_scores;

std::string ciphertext;
Plugboard best_plugboard({});

void bruteforce_start_positions(const Rotor& left, const Rotor& center, const Rotor& right) {
  Enigma enigma({left, center, right}, B, best_plugboard);

  for (int l = 0; l < 26; ++l) {
    for (int c = 0; c < 26; ++c) {
      for (int r = 0; r < 26; ++r) {
        enigma.left_rotor.rotor_position = l;
        enigma.center_rotor.rotor_position = c;
        enigma.right_rotor.rotor_position = r;
        std::string plaintext = enigma.encrypt(ciphertext);
        double index = index_of_coincidence(count_occurences(plaintext));
        auto bi_occurences = bi_count_occurences(plaintext);
        double index2 = index_of_coincidence(bi_occurences);
        double bigram = bigram_score(bi_occurences);
        //double index3 = index_of_coincidence(tri_count_occurences(plaintext));

        RotorSetting lrs{left.name, l, left.ring_setting};
        RotorSetting crs{center.name, c, center.ring_setting};
        RotorSetting rrs{right.name, r, right.ring_setting};

        std::lock_guard<std::mutex> guard(scores_lock);
        size_t last_val = (scores.size() * 100) / expected_scores;
        scores.emplace_back(lrs, crs, rrs, index + index2 + bigram);
        size_t new_val = (scores.size() * 100) / expected_scores;
        if (last_val != new_val) {
          std::cerr << "Progress: " << scores.size() << "/" << expected_scores << " " << (scores.size() * 100 / (double)expected_scores) << "%" << std::endl;
        }
      }
    }
  }
}

int num_unique_ring_settings(const std::string& name) {
  if (name == "VI" || name == "VII" || name == "VIII") {
    return 13;
  }
  return 26;
}

void bruteforce_ring_settings(const Rotor& left, const Rotor& center, const Rotor& right) {

  int ls = left.rotor_position;
  int cs = center.rotor_position;
  int rs = right.rotor_position;

  int cr = center.ring_setting;
  int rr = right.ring_setting;
  Enigma enigma({left, center, right}, B, best_plugboard);

  int c_max = num_unique_ring_settings(center.name);
  int r_max = num_unique_ring_settings(right.name);


  for (int c = 0; c < c_max; ++c) {
    int local_ring_c = (cr + c) % 26;
    for (int r = 0; r < r_max; ++r) {
      int local_ring_r = (rr + r) % 26;
      enigma.left_rotor.rotor_position = ls;
      enigma.center_rotor.rotor_position = (cs + c) % 26;
      enigma.right_rotor.rotor_position = (rs + r) % 26;

      enigma.center_rotor.ring_setting = local_ring_c;
      enigma.right_rotor.ring_setting = local_ring_r;

      std::string plaintext = enigma.encrypt(ciphertext);
      double index = index_of_coincidence(count_occurences(plaintext));
      auto bi_occurences = bi_count_occurences(plaintext);
      double index2 = index_of_coincidence(bi_occurences);
      double bigram = bigram_score(bi_occurences);
      //double index3 = index_of_coincidence(tri_count_occurences(plaintext));

      RotorSetting lrs{left.name, ls, 0};
      RotorSetting crs{center.name, (cs + c) % 26, local_ring_c};
      RotorSetting rrs{right.name, (rs + r) % 26, local_ring_r};

      std::lock_guard<std::mutex> guard(scores_lock);
        size_t last_val = (ring_scores.size() * 100) / expected_ring_scores;
      ring_scores.emplace_back(lrs, crs, rrs, index + index2 + bigram);
        size_t new_val = (ring_scores.size() * 100) / expected_ring_scores;
      if (last_val != new_val) {
        std::cerr << "Progress: " << ring_scores.size() << "/" << expected_ring_scores << " " << (ring_scores.size() * 100 / (double)expected_ring_scores) << "%" << std::endl;
      }
    }
  }
}

void run_bruteforce_start_positions() {
  std::vector<std::thread> threads;
  scores.clear();
  expected_scores = 26 * 26 * 26 * ring_scores.size();

  threads.reserve(ring_scores.size());
for (const auto& score : ring_scores) {
    threads.emplace_back(&bruteforce_start_positions,
                         std::get<0>(score).gen(),
                         std::get<1>(score).gen(),
                         std::get<2>(score).gen());
  }

  for (auto& thread : threads) {
    thread.join();
  }

  std::sort(scores.begin(), scores.end(), [](const auto& left, const auto& right) {
    return std::get<3>(left) > std::get<3>(right);
  });
}

void run_bruteforce_ring_settings() {
  std::vector<std::thread> threads;
  threads.reserve(scores.size());
  ring_scores.clear();
  expected_ring_scores = 26 * 26 * scores.size();

for (const auto& score : scores) {
    threads.emplace_back(&bruteforce_ring_settings,
                         std::get<0>(score).gen(),
                         std::get<1>(score).gen(),
                         std::get<2>(score).gen());
  }


  for (auto& thread : threads) {
    thread.join();
  }

  std::sort(ring_scores.begin(), ring_scores.end(), [](const auto& left, const auto& right) {
    return std::get<3>(left) > std::get<3>(right);
  });
}

void print_correctish_positions(const std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>>& scores) {
  std::cerr << "Positioning of the correct choices: " << std::endl;
  for (int i = 0; i < scores.size(); ++i) {
    const auto& score = scores[i];
    int correct = 0;
    if (std::get<0>(score).rotor == "I") ++correct;
    if (std::get<0>(score).start_pos == 6) ++correct;
    if (std::get<1>(score).rotor == "II") ++correct;
    if (std::get<1>(score).start_pos - std::get<1>(score).ring_setting == 3) ++correct;
    if (std::get<2>(score).rotor == "III") ++correct;
    if (std::get<2>(score).start_pos - std::get<2>(score).ring_setting == 3) ++correct;

    if (correct > 5) {
      std::cerr << i << ": (" << correct << ") " << std::get<3>(score) << " " << std::get<0>(score) << " " << std::get<1>(score) << " " << std::get<2>(score) << std::endl;
    }
  }
}

void init_ring_settings() {
  for (const auto& [name1, rotor1] : rotors) {
    if (name1 == "N") continue;
    for (const auto& [name2, rotor2] : rotors) {
      if (name1 == name2) continue;
      if (name2 == "N") continue;
      for (const auto& [name3, rotor3] : rotors) {
        if (name1 == name3) continue;
        if (name2 == name3) continue;
        if (name3 == "N") continue;
        RotorSetting lrs{name1, 0, 0};
        RotorSetting crs{name2, 0, 0};
        RotorSetting rrs{name3, 0, 0};

        ring_scores.emplace_back(lrs, crs, rrs, 0.0);
      }
    }
  }
}

void deduplicate(std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>>& scores) {
  std::set<std::tuple<RotorSetting, RotorSetting, RotorSetting>> best;
  std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>> out;

  for (const auto& entry : scores) {
    auto [left, center, right, score] = entry;

    if (!best.count(std::tuple<RotorSetting, RotorSetting, RotorSetting>{left, center, right})) {
      best.insert(std::tuple<RotorSetting, RotorSetting, RotorSetting>{left, center, right});
      out.push_back(entry);
    }
  }

  scores = out;
}

void deduplicate_ignore_start_pos(std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>>& scores) {
  std::set<std::tuple<RotorSetting, RotorSetting, RotorSetting>> best;
  std::vector<std::tuple<RotorSetting, RotorSetting, RotorSetting, double>> out;

  for (const auto& entry : scores) {
    auto [left, center, right, score] = entry;
    left.start_pos = 0;
    center.start_pos = 0;
    right.start_pos = 0;

    if (!best.count(std::tuple<RotorSetting, RotorSetting, RotorSetting>{left, center, right})) {
      best.insert(std::tuple<RotorSetting, RotorSetting, RotorSetting>{left, center, right});
      out.push_back(entry);
    }
  }

  scores = out;
}

void do_rotors() {
  init_ring_settings();
  run_bruteforce_start_positions();
  //print_correctish_positions(scores);

  scores.resize(std::min<size_t>(scores.size(), 1024 * 32));

  std::cerr << "Best rotor positions: " << std::endl;
  for (int i = 0; i < 64 && i < scores.size(); ++i) {
    const auto& score = scores[i];
    std::cerr << std::get<3>(score) << " " << std::get<0>(score) << " " << std::get<1>(score) << " " << std::get<2>(score) << std::endl;
  }

  run_bruteforce_ring_settings();

  //print_correctish_positions(ring_scores);
  ring_scores.resize(std::min<size_t>(ring_scores.size(), 1024));

  std::cerr << "Best ring positions: " << std::endl;
  for (int i = 0; i < std::min<size_t>(64, ring_scores.size()); ++i) {
    const auto& score = ring_scores[i];
    std::cerr << std::get<3>(score) << " " << std::get<0>(score) << " " << std::get<1>(score) << " " << std::get<2>(score) << std::endl;
  }

  std::cerr << "Completed pass 1" << std::endl;

  deduplicate_ignore_start_pos(ring_scores);
  run_bruteforce_start_positions();

  scores.resize(std::min<size_t>(scores.size(), 1024));

  std::cerr << "Best rotor positions: " << std::endl;
  for (int i = 0; i < 64 && i < scores.size(); ++i) {
    const auto& score = scores[i];
    std::cerr << std::get<3>(score) << " " << std::get<0>(score) << " " << std::get<1>(score) << " " << std::get<2>(score) << std::endl;
  }

  run_bruteforce_ring_settings();
  deduplicate(ring_scores);

  //print_correctish_positions(ring_scores);
  ring_scores.resize(std::min<size_t>(ring_scores.size(), 1024));

  std::cerr << "Best ring positions: " << std::endl;
  for (int i = 0; i < 64 && i < ring_scores.size(); ++i) {
    const auto& score = ring_scores[i];
    std::cerr << std::get<3>(score) << " " << std::get<0>(score) << " " << std::get<1>(score) << " " << std::get<2>(score) << std::endl;
  }

  std::cerr << "Completed pass 2" << std::endl;
}

struct PlugboardSetting {
  std::vector<std::string> plugs;

  bool operator==(const PlugboardSetting& other) const {
    return plugs == other.plugs;
  }
  bool operator<(const PlugboardSetting& other) const {
    if (plugs.size() < other.plugs.size()) return true;
    if (plugs.size() > other.plugs.size()) return false;
    for (int i = 0; i < plugs.size(); ++i) {
      if (plugs[i] < other.plugs[i]) return true;
      if (plugs[i] > other.plugs[i]) return false;
    }
    return false;
  }
};

std::ostream& operator<<(std::ostream& os, const PlugboardSetting& rs) {
  os << "{";
  if (rs.plugs.size() > 0) os << rs.plugs[0];
  for (int i = 1; i < rs.plugs.size(); ++i) {
    os << " " << rs.plugs[i];
  }
  //os.seekp(-1, std::ios_base::end);
  os << "}";
  return os;
}

std::vector<std::tuple<PlugboardSetting, double, RotorSetting, RotorSetting, RotorSetting>> prev_plugboard_scores;
std::vector<std::tuple<PlugboardSetting, double, RotorSetting, RotorSetting, RotorSetting>> plugboard_scores;
size_t expected_plugboard_scores;

void bruteforce_one_plug(PlugboardSetting setting) {
  std::array<bool, 256> presence_array;
  for (const auto& p : setting.plugs) {
    presence_array[p[0]] = true;
    presence_array[p[1]] = true;
  }

  for (const auto& [left, center, right, _] : ring_scores) {
    for (char c = 'A'; c < 'Z'; ++c) {
      if (presence_array[c]) continue;
      for (char d = c + 1; d <= 'Z'; ++d) {
        if (presence_array[d]) continue;
        setting.plugs.push_back({c, d});
        Enigma enigma(
            {left.gen(), center.gen(), right.gen()},
            B,
            Plugboard(setting.plugs)
        );

        std::string plaintext = enigma.encrypt(ciphertext);
        double index = index_of_coincidence(count_occurences(plaintext));
        auto bi_occurences = bi_count_occurences(plaintext);
        double index2 = index_of_coincidence(bi_occurences);
        double bigram = bigram_score(bi_occurences);
        //double index3 = index_of_coincidence(tri_count_occurences(plaintext));

        PlugboardSetting setting_copy = setting;
        std::sort(setting_copy.plugs.begin(), setting_copy.plugs.end());

        std::lock_guard<std::mutex> guard(scores_lock);
        size_t last_val = (plugboard_scores.size() * 100) / expected_plugboard_scores;
        plugboard_scores.emplace_back(std::move(setting_copy), index + index2 + bigram, left, center, right);
        size_t new_val = (plugboard_scores.size() * 100) / expected_plugboard_scores;
        if (last_val != new_val) {
          std::cerr << "Progress: " << plugboard_scores.size() << "/" << expected_plugboard_scores << " " << (plugboard_scores.size() * 100 / (double)expected_plugboard_scores) << "%" << std::endl;
        }

        setting.plugs.pop_back();
      }
    }
  }
}

void deduplicate(std::vector<std::tuple<PlugboardSetting, double, RotorSetting, RotorSetting, RotorSetting>>& scores) {
  std::vector<std::tuple<PlugboardSetting, double, RotorSetting, RotorSetting, RotorSetting>> result;
  std::set<PlugboardSetting> seen_settings;
  for (const auto& p : scores) {
    if (seen_settings.count(std::get<0>(p))) continue;
    seen_settings.insert(std::get<0>(p));
    result.push_back(p);
  }
  scores = result;
}

void run_bruteforce_one_plug() {
  std::vector<std::thread> threads;
  plugboard_scores.clear();

  int preexisting_plugs = std::get<0>(prev_plugboard_scores[0]).plugs.size();
  expected_plugboard_scores = ring_scores.size() * (26 - 2 * preexisting_plugs) * (25 - 2 * preexisting_plugs) * prev_plugboard_scores.size() / 2;

  for (const auto& [plugboard_setting, rotor1, rotor2, rotor3, score] : prev_plugboard_scores) {
    (void)score;
    threads.emplace_back(&bruteforce_one_plug, plugboard_setting);
  }

  for (auto& thread : threads) {
    thread.join();
  }

  std::sort(plugboard_scores.begin(), plugboard_scores.end(), [](const auto& left, const auto& right) {
    return std::get<1>(left) > std::get<1>(right);
  });

  deduplicate(plugboard_scores);

  plugboard_scores.resize(std::min<size_t>(plugboard_scores.size(), 64));
  std::cerr << "Best plugboard scores: " << std::endl;

  for (int i = 0; i < std::min<size_t>(64, plugboard_scores.size()); ++i) {
    std::cerr << std::get<1>(plugboard_scores[i]) << " " << std::get<0>(plugboard_scores[i]) << " " << std::get<2>(plugboard_scores[i]) << " " << std::get<3>(plugboard_scores[i]) << " " << std::get<4>(plugboard_scores[i]) << std::endl;
  }
}

void do_plugboard() {
  prev_plugboard_scores.resize(1);
  for (int i = 0; i < 10; ++i) {
    run_bruteforce_one_plug();
    prev_plugboard_scores = plugboard_scores;
    plugboard_scores.clear();
  }
  plugboard_scores = prev_plugboard_scores;
}

std::string Chunk(const std::string& text) {
  int chunk_ctr = 0;
  int line_ctr = 0;
  std::string ret;
  for (char c : text) {
    ret.push_back(c);
    ++chunk_ctr;
    if (chunk_ctr == 5) {
      chunk_ctr = 0;
      ret.push_back(' ');
      line_ctr++;
    }
    if (line_ctr == 8) {
      ret.back() = '\n';
      line_ctr = 0;
    }
  }
  return ret;
}

int main(int argc, char** argv) {
  ciphertext = read_is(std::cin);
  ciphertext = clean(ciphertext);

  //ring_scores.push_back({RotorSetting{"III", 22, 0}, RotorSetting{"IV", 13, 15}, RotorSetting{"I", 4, 22}, 1.2358});
  do_rotors();
  const auto& [left, center, right, score] = ring_scores[0];
  std::cerr << "Best rotor scores: " << left << " " << center << " " << right << std::endl;
  //ring_scores.resize(1);


  do_plugboard();
  std::cerr << "Best rotor scores: " << left << " " << center << " " << right << std::endl;
  std::cerr << "Best plugboard scores: " << std::get<0>(plugboard_scores[0]) << std::endl;

  // Do the bruteforce again
  best_plugboard = Plugboard(std::get<0>(plugboard_scores[0]).plugs);
  do_rotors();
  std::cerr << "Best rotor scores: " << left << " " << center << " " << right << std::endl;

  prev_plugboard_scores.clear();
  plugboard_scores.clear();

  do_plugboard();

  std::cerr << "Best ring scores: " << left << " " << center << " " << right << std::endl;
  std::cerr << "Best plugboard scores: " << std::get<0>(plugboard_scores[0]) << std::endl;

  std::cerr << "Generating best solution" << std::endl;
  Enigma best_enigma({
    left.gen(),
    center.gen(),
    right.gen()
  }, B, Plugboard(std::get<0>(plugboard_scores[0]).plugs));
  std::string plaintext = best_enigma.encrypt(ciphertext);
  std::cout << Chunk(plaintext) << std::endl;


  return 0;
}






























































