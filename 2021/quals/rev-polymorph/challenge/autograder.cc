#include <cerrno>
#include <iostream>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/times.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <random>

std::string recv_file() {
  unsigned int size = 0;
  std::cin.read((char*)&size, 4);
  std::string ret;
  ret.resize(size);
  std::cin.read(&ret[0], size);
  std::cerr << std::endl;
  return ret;
}

std::string read_file(const char* path) {
  std::ifstream t(path);
  if (!t.is_open()) {
    std::cerr << "Failed to open " << path << std::endl;
    exit(1);
  }
  std::string str((std::istreambuf_iterator<char>(t)),
                   std::istreambuf_iterator<char>());
  return str;
}

std::map<std::string, bool> load_results(const char* path) {
  std::map<std::string, bool> ret;

  std::ifstream infile(path);
  std::string line;
  while(std::getline(infile, line)) {
    while(line.back() == '\n') line.pop_back();
    if (line.empty()) continue;

    int space = line.find(' ');
    if (space == std::string::npos) {
      std::cerr << "Failed to find space delimiter in results line " << line << std::endl;
      exit(3);
    }
    std::string filename = line.substr(0, space);
    std::string retcode = line.substr(space + 1, std::string::npos);

    ret[filename] = (retcode != "0");
  }

  return ret;
}

void make_nsjail_cfg(std::istream& infile, std::ostream& outfile, const char* tmpdir) {
  std::string line;
  while(std::getline(infile, line)) {
    if(line.back() == '\n') line.pop_back();
    if(line.empty()) continue;

    if(line == "# INSERT BIND HERE") {
      std::stringstream buf;
      buf
          << "{\n"
          << "src: \"" << tmpdir << "\"\n"
          << "dst: \"/home/user/\"\n"
          << "is_bind: true\n"
          << "},\n";
      outfile << buf.str();
    } else {
      outfile << line << "\n";
    }
  }
}

long double clocks_per_sec = sysconf(_SC_CLK_TCK);

// Used to subtract out the time it takes to spawn a simple nsjail.
long double time_normalization_factor(const std::string& tmpdir) {
  static long double ret = [&](){
    struct tms old_times;
    if (times(&old_times) == -1) {
      std::cerr << "times(): " << strerror(errno) << std::endl;
    }

    for (int i = 0; i < 10; ++i) {
      pid_t pid = fork();
      if (pid == 0) {
        std::string nsjail_cfg = tmpdir + "/nsjail.cfg";

        std::vector<const char*> subprocess;
        subprocess.push_back("/usr/bin/nsjail");
        subprocess.push_back("-q");
        subprocess.push_back("--config");
        subprocess.push_back(nsjail_cfg.c_str());
        subprocess.push_back("/bin/true");
        subprocess.push_back(nullptr);

        execv(subprocess[0], (char**)&subprocess[0]);

        std::cerr << "Failed to execv: " << subprocess[0] << "\n" << strerror(errno) << std::endl;
        exit(1);
      } else if (pid < 0) {
        std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
        exit(2);
      }

      int status;
      waitpid(pid, &status, 0);
    }

    struct tms new_times;
    if (times(&new_times) == -1) {
      std::cerr << "times(): " << strerror(errno) << std::endl;
    }

    return (new_times.tms_cutime - old_times.tms_cutime + new_times.tms_cstime - old_times.tms_cstime) / clocks_per_sec / 10;
  }();
  return ret;
}

bool run_test_case(const std::string& tmpdir, const std::string& testcase, bool silence, long double* time) {
  std::string tmp_testcase = tmpdir + "/test_case";
  int removeret = remove(tmp_testcase.c_str());
  if (removeret) {
    int x = errno;
    if (x != ENOENT) {
      std::cerr << "remove(" << tmp_testcase.c_str() << "): " << strerror(x) << std::endl;
      exit(1);
    }
  }
  std::filesystem::copy(testcase, tmp_testcase, std::filesystem::copy_options::overwrite_existing);
  chmod(tmp_testcase.c_str(), 0777);

  struct tms old_times;
  if (times(&old_times) == -1) {
    std::cerr << "times(): " << strerror(errno) << std::endl;
  }
  pid_t pid = ::fork();
  if (pid == 0) {
    dup2(STDERR_FILENO, STDOUT_FILENO);
    if (silence) {
      int devnull = open("/dev/null", O_RDONLY);
      if (devnull < 0) {
        std::cerr << "Failed to open /dev/null: " << strerror(errno) << std::endl;
        exit(1);
      }
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }

    std::string nsjail_cfg = tmpdir + "/nsjail.cfg";

    std::vector<const char*> subprocess;
    subprocess.push_back("/usr/bin/nsjail");
    subprocess.push_back("-q");
    subprocess.push_back("--config");
    subprocess.push_back(nsjail_cfg.c_str());
    subprocess.push_back("/home/user/antivirus");
    subprocess.push_back("/home/user/test_case");
    subprocess.push_back(nullptr);

    execv(subprocess[0], (char**)&subprocess[0]);

    std::cerr << "Failed to execv: " << subprocess[0] << "\n" << strerror(errno) << std::endl;
    exit(1);
  } else if (pid < 0) {
    std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
    exit(2);
  }

  int status;
  waitpid(pid, &status, 0);

  struct tms new_times;
  if (times(&new_times) == -1) {
    std::cerr << "times(): " << strerror(errno) << std::endl;
  }

  // This time-measuring mechanism is probably bypassable - nsjail needs to be a
  // subreaper, or a subreaper needs to be run inside nsjail, to fix that.
  *time += (new_times.tms_cutime - old_times.tms_cutime + new_times.tms_cstime - old_times.tms_cstime) / clocks_per_sec - time_normalization_factor(tmpdir);

  return status;
}

void run_test_cases(int* passed, int* failed, const std::string& tmpdir, const std::string& mapping_file, bool silence, bool super_silence=false) {
  std::map<std::string, bool> ordered_mapping = load_results(mapping_file.c_str());
  std::vector<std::pair<std::string, bool>> mapping(ordered_mapping.begin(), ordered_mapping.end());
  if (silence) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::shuffle(mapping.begin(), mapping.end(), mt);
  }
  long double time = 0;
  for (const auto& [s, b] : mapping) {
    if (!super_silence) std::cout << "  Running test " << s << "... " << std::endl;
    bool result = run_test_case(tmpdir, s, silence, &time);
    bool matches = (result == b);
    if (!super_silence) std::cout <<"  " << s << ": " << (matches? "✅ " : "❌ ");
    if (!matches) {
      (*failed)++;
      if (!super_silence) std::cout << "Expected " << b << ", got " << result;
    } else {
      (*passed)++;
    }
    if (!super_silence) std::cout << std::endl;

    if (time > mapping.size() * 4.04) {
      if (!super_silence) std::cerr << "❌❌ Exceeded maximum time! Your program has consumed " << time << " seconds, but must take (on average) no more than 4 cpu-seconds per test case. " << std::endl;
      *failed += mapping.size() - (*passed + *failed);
      break;
    }
  }
  if (!super_silence) std::cerr << "Total time: " << time << std::endl;
}

char tmpdirname_for_cleanup[256] = "\0";
void cleanup() {
  system((std::string("rm -rf ") + tmpdirname_for_cleanup + std::string(" > /dev/null 2>&1")).c_str());
}


int main(int argc, char** argv) {
  dup2(STDOUT_FILENO, STDERR_FILENO);

  std::cout <<
R"(Malware Autograder
==================
Please upload a 4-byte little-endian integer specifying the size of your binary,
followed by your binary.
)" << std::flush;

  // Load antivirus
  std::string antivirus = recv_file();

  close(STDIN_FILENO);

  std::string tmpdirname("/tmp/autograder.XXXXXX");
  char* tmperror = mkdtemp(&tmpdirname[0]);
  if (!tmperror) {
    std::cerr << "Failed to create tmpdir: " << strerror(errno) << std::endl;
    exit(1);
  }
  strcpy(tmpdirname_for_cleanup, tmpdirname.c_str());
  atexit(cleanup);

  std::string filename = tmpdirname + "/antivirus";
  {
    std::ofstream av_outfile(filename.c_str());
    av_outfile << antivirus;
  }

  chmod(tmpdirname.c_str(), 0777);
  chmod(filename.c_str(), 0777);

  std::string built_nsjail_cfg = tmpdirname + "/nsjail.cfg";
  {
    std::ifstream nsjail_cfg_in("/home/user/nsjail.cfg");
    std::ofstream nsjail_cfg_out(built_nsjail_cfg.c_str());
    make_nsjail_cfg(nsjail_cfg_in, nsjail_cfg_out, tmpdirname.c_str());
  }

  int passed = 0;
  int failed = 0;
  
  std::cout <<
R"(
Running public test cases
-------------------------
)";
  
  run_test_cases(&passed, &failed, tmpdirname, "/home/user/expected_public_map", false);
  std::cout << "-------------------------" << std::endl;
  std::cout << "Score: " << passed << "/" << (passed + failed) << std::endl;

  if (failed > 0) {
    std::cout << "You must pass all public test cases to continue. These test cases are available in your downloaded package." << std::endl;
    return 1;
  }
  
  passed = 0;
  failed = 0;

  std::cout <<
R"(
Running private test cases
--------------------------
)";

  run_test_cases(&passed, &failed, tmpdirname, "/home/user/expected_map", true);
  std::cout << "-------------------------" << std::endl;
  std::cout << "Score: " << passed << "/" << (passed + failed) << std::endl;

  if (failed >= 3) {
    std::cout << "You are permitted to fail up to 3 private test cases. You failed too many." << std::endl;
    return 1;
  }

  std::string flag = read_file("/home/user/flag");

  std::cout << "Your flag is:\x1b[38;5;198m\n" << flag << "\n\x1b[39;49m" << std::flush;
  
  passed = 0;
  failed = 0;
  run_test_cases(&passed, &failed, tmpdirname, "/home/user/expected_super_secret_map", true, true);
  if (passed <= 10) {
    std::cout << "\x1b[38;5;198m\n\nCongrats on finding the 'unintended' solution ;)\n\x1b[39;49m" << std::endl;
  }
}
