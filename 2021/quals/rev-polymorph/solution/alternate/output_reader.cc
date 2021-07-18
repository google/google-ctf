#include <iostream>
#include <map>
#include <string>

int main(int argc, char** argv) {
  std::string bit_name = argv[1];

  std::string line;
  while(getline(std::cin, line)) {
    std::cerr << line << std::endl;
    if (line.find("private") != std::string::npos) break;
  }

  std::cerr << "Starting data collection" << std::endl;

  std::map<std::string, int> bits;

  while(getline(std::cin, line)) {
    std::cerr << line << std::endl;
    if (line.find("Total time:") != std::string::npos) break;
    if (line.find("  /home/user/test_cases/") == std::string::npos) continue;

    std::string challenge_name = line.substr(24, std::string::npos);
    challenge_name = challenge_name.substr(0, challenge_name.find(":"));

    int expected;
    int actual;
    if (challenge_name.find("polymorph") != std::string::npos) {
      expected = 1;
    } else if (challenge_name.find("safe") != std::string::npos) {
      expected = 0;
    } else {
      std::cerr << "Failed to find polymorph or safe" << std::endl;
      exit(1);
    }

    if (line.find("✅") != std::string::npos) {
      actual = expected;
    } else if (line.find("❌") != std::string::npos) {
      actual = 1 - expected;
    } else {
      std::cerr << "Failed to find unicode marker" << std::endl;
    }

    bits[challenge_name] = actual;
  }

  std::cout << "std::map<std::string, int> bit_" << bit_name << " ={\n";
  for (const auto& [name, bit] : bits) {
    std::cout << "  {\"" << name << "\", " << bit << "},\n";
  }
  std::cout << "{\"\", -1}};\n" << std::endl;
}
