#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/procfs.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <linux/elf.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "json.hpp"

#define MIN(x,y) ((x) < (y) ? (x) : (y))

static FILE *logfp = NULL;

void clog(char *fmt, ...) {
  if (!logfp) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(logfp, fmt, ap);
  va_end(ap);
}

struct X86_64_REGS {  // Normal (non-FPU) CPU registers
  uint64_t R15, R14, R13, R12, RBP, RBX, R11, R10;
  uint64_t R9, R8, RAX, RCX, RDX, RSI, RDI, ORIG_RAX;
  uint64_t RIP, CS, EFLAGS;
  uint64_t RSP, SS;
};

class Binary {
 protected:
  uint8_t *core_view_;
  size_t core_size_;
  char file_[64];
  uint64_t vaddr_;
  uint64_t prot_;
 public:
  Binary(uint8_t *core, size_t size) : core_view_(core), core_size_(size) { }
  uint8_t *GetCore() { return core_view_; }
  uint64_t GetSize() { return core_size_; }
  uint64_t GetVirtualAddress() { return vaddr_; }
  void SetFileName(const char *file);
  const char *GetFileName() { return file_; }
  void SetVirtualAddress(uint64_t vaddr) { vaddr_ = vaddr; }
  void SetMemoryProtections(uint64_t prot) { prot_ = prot; }
  bool ContainsVirtualAddress(uint64_t vaddr) {
    return vaddr >= vaddr_ && vaddr < (vaddr_ + core_size_);
  }
  bool IsExecutable() { return prot_ & PF_X; }
};

void Binary::SetFileName(const char *file) {
  struct stat sb;
  ::stat(file, &sb);
  if (sb.st_mode & S_IXUSR)
    memcpy(file_, file, MIN(strlen(file), sizeof(file_)));
}

// using CallFrame = std::tuple<uint64_t, uint64_t, Binary *>;
class CallFrame {
  uint64_t sp_;
  uint64_t mapped_address_;
  Binary *binary_;
 public:
  CallFrame() { }
  CallFrame(uint64_t a, uint64_t b, Binary *c) : sp_(a), mapped_address_(b), binary_(c) { }
  uint64_t GetSP() { return sp_; }
  uint64_t GetMappedAddress() { return mapped_address_; }
  Binary *GetBinary() { return binary_; }
};

class Backtrace {
  uint64_t sp_;
  uint64_t rel;
  std::optional<uint32_t> frame_count;

 public:
  CallFrame frames[7];
  Backtrace(uint64_t SP) : frame_count(std::nullopt), sp_(SP) { memset(&frames, '\0', sizeof(frames)); /* frames.reserve(4); printf("vector.__data() + %p\n", frames.data()); memset(frames.data(), '\0', frames.capacity() * sizeof(CallFrame)); */ }

  void PushModule(Binary *binary, uint64_t address, uint64_t sp_rel) {
    if (!frame_count.has_value()) frame_count = 1;
    if (frame_count > 6) return;
    frame_count = frame_count.value() + 1;
    frames[*frame_count - 1] = CallFrame(sp_rel, address - binary->GetVirtualAddress(), binary); // std::make_tuple(sp_rel, address - binary->GetVirtualAddress(), binary);
  }

  uint32_t GetFrameCount() { return *frame_count; }
};

class RegisterSet : public Binary { protected: uint64_t sp_; public: RegisterSet(uint8_t *core, size_t size) : Binary(core, size) { } virtual uint64_t GetSP() { return 0; } };

class X86RegisterSet  : public RegisterSet {
 protected:
  X86_64_REGS regs_;

 public:
  X86RegisterSet (uint8_t *core, size_t size) : RegisterSet(core, size) {
    elf_prstatus *status = (elf_prstatus *)core_view_;
    memcpy(&regs_, &status->pr_reg, sizeof(regs_));
  }

  virtual uint64_t GetSP() { return GetRSP(); }
  X86_64_REGS *GetRegisters() { return &regs_; }
#define REG_ACCESS(x) uint64_t &Get##x() { return GetRegisters()->x; }
  REG_ACCESS(RAX)
  REG_ACCESS(RBX)
  REG_ACCESS(RCX)
  REG_ACCESS(RDX)
  REG_ACCESS(RDI)
  REG_ACCESS(RSI)
  REG_ACCESS(R8)
  REG_ACCESS(R9)
  REG_ACCESS(R10)
  REG_ACCESS(R11)
  REG_ACCESS(R12)
  REG_ACCESS(R13)
  REG_ACCESS(R14)
  REG_ACCESS(R15)
  REG_ACCESS(RSP)
  REG_ACCESS(RBP)
};

class MappedRegisterSet : public X86RegisterSet {
  public:
   MappedRegisterSet(uint8_t *core, size_t size) : X86RegisterSet(core, size) { }
};

class ELFBinary : public Binary {
 protected:
  std::vector<elf64_phdr *> phdrs_;

 public:
  ELFBinary(uint8_t *core, size_t size) : Binary(core, size) { }
  static ELFBinary *Create(uint8_t *core, size_t size);
  virtual void Process() { /* print_elf((elf64_hdr *)core_view_); */ this->ProcessPHeaders(); }

 private:
  virtual void ProcessPHeaders() {
    elf64_hdr *hdr64 = (elf64_hdr *)core_view_;
    // Gotta go fast, jk this is for the heap groom.
    phdrs_.reserve(hdr64->e_phnum);
    for (int i = 0; i < hdr64->e_phnum; i++) {
      elf64_phdr *phdr = (elf64_phdr *)(hdr64->e_phoff + core_view_ + i * hdr64->e_phentsize);
      phdrs_.push_back(phdr);
    }
  }
};

class Corefile : ELFBinary {
  std::map<uint64_t, ELFBinary *> modules_;
  std::vector<Binary *> vmmap_;
  std::vector<RegisterSet *> threads_;
  siginfo_t signal_;
  uint8_t *auxv_;
 public:
  Corefile(uint8_t *core, size_t size);
  virtual void Process() { threads_.reserve(128); vmmap_.reserve(128); ELFBinary::Process(); for (auto pair : modules_) { pair.second->Process(); } this->ProcessLOADs(); }

  virtual void GetRegisters();
  virtual Backtrace *GetBacktrace(uint64_t tid);
  virtual std::vector<Binary *> GetModuleList() { return vmmap_;  }
  virtual size_t GetNumberOfThreads() { return threads_.size(); }
  MappedRegisterSet *GetMappedRegisterSet(uint64_t tid);
  Binary *GetBinaryContainingAddress(uint64_t addr);

 private:
  void ParseNtFile(elf64_note *note);
  void ParseAUXV(elf64_note *note);
  void ProcessNotes(elf64_phdr *phdr_note);
  void ProcessLOADs();
  void ProcessSIGINFO(elf64_note *note) {
    uint8_t *sigbase = (uint8_t *)note + sizeof(*note) + (((note->n_namesz + 3) / 4) * 4);
    memcpy(&signal_, sigbase, sizeof(signal_));
  }
};

Binary *Corefile::GetBinaryContainingAddress(uint64_t addr) {
  for (auto bin : vmmap_) {
    if (bin->ContainsVirtualAddress(addr)) return bin;
  }
  return nullptr;
}

class StackWalker {
  Corefile &f_;
 public:
  StackWalker(Corefile &f) : f_(f) { }
  Backtrace *GetBacktrace(uint64_t sp) {
    Backtrace *bt = new Backtrace(sp);
    // Stack should always be contiguous, I hope
    uint64_t sp_iter = sp;
    Binary *stack = f_.GetBinaryContainingAddress(sp_iter);
    // If there's no stack, we can't do anything. Return empty backtrace
    if (!stack) return bt;

    while (true) {
      if (!stack->ContainsVirtualAddress(sp_iter)) break;

      uint64_t rel = sp_iter - stack->GetVirtualAddress();
      uint64_t *core = (uint64_t *)stack->GetCore();
      uint64_t memory = core[rel / 8];

      Binary *mod = f_.GetBinaryContainingAddress(memory);
      if (mod && mod->IsExecutable()) bt->PushModule(mod, memory, sp_iter - sp);

      sp_iter += 8;
    }

    return bt;
  }
};

MappedRegisterSet *Corefile::GetMappedRegisterSet(uint64_t tid) {
  RegisterSet *original = threads_[tid];

  MappedRegisterSet *mapped = new MappedRegisterSet(original->GetCore(), original->GetSize());
  #define TRANSLATE_REGISTER(x) do { \
    Binary *b = this->GetBinaryContainingAddress(mapped->Get##x()); \
    if (!b) break; \
    uint64_t orig = mapped->Get##x(); \
    mapped->Get##x() = (uint64_t)(mapped->Get##x() - b->GetVirtualAddress() + b->GetCore()); \
    clog("TRANSLATED REGISTER (%s) %p (%p) -> %p\n", #x, orig, b->GetVirtualAddress(), mapped->Get##x()); \
  } while (0);

  TRANSLATE_REGISTER(RAX);
  TRANSLATE_REGISTER(RAX)
  TRANSLATE_REGISTER(RBX)
  TRANSLATE_REGISTER(RCX)
  TRANSLATE_REGISTER(RDX)
  TRANSLATE_REGISTER(RDI)
  TRANSLATE_REGISTER(RSI)
  TRANSLATE_REGISTER(R8)
  TRANSLATE_REGISTER(R9)
  TRANSLATE_REGISTER(R10)
  TRANSLATE_REGISTER(R11)
  TRANSLATE_REGISTER(R12)
  TRANSLATE_REGISTER(R13)
  TRANSLATE_REGISTER(R14)
  TRANSLATE_REGISTER(R15)
  TRANSLATE_REGISTER(RSP)
  TRANSLATE_REGISTER(RBP)

  return mapped;
}

Backtrace *Corefile::GetBacktrace(uint64_t tid) {
  RegisterSet *reg_set = threads_[tid];
  uint64_t sp = reg_set->GetSP();
  StackWalker walker(*this);
  Backtrace *bt = walker.GetBacktrace(sp);
  clog("[%d] Backtrace frames: %p\n", tid, bt->GetFrameCount());
  return bt;
}

void Corefile::GetRegisters() {
  for (elf64_phdr *phdr : phdrs_) {
    if (phdr->p_type == PT_NOTE) this->ProcessNotes(phdr);
  }
}

void Corefile::ParseAUXV(elf64_note *note) {
  uint8_t *names = (uint8_t *)note + sizeof(*note);
  uint8_t *descs = (uint8_t *)names + ((note->n_namesz + 3) / 4) * 4;

  uint8_t *auxv = (uint8_t *)malloc(note->n_descsz);

  memcpy(auxv, descs, note->n_descsz);

  if (note->n_descsz % 8) free(auxv);
  else auxv_ = auxv;
}

void Corefile::ParseNtFile(elf64_note *note) {
  uint8_t *names = (uint8_t *)note + sizeof(*note);
  uint8_t *descs = (uint8_t *)names + ((note->n_namesz + 3) / 4) * 4;
  size_t descsz = note->n_descsz;

  uint8_t *note_end = (uint8_t *)descs + ((descsz + 3) / 4) * 4;

  uint64_t entries = *(uint64_t *)descs;
  descs += 8;
  descsz -= 8;

  uint64_t page_size = *(uint64_t *)descs;
  descs += 8;
  descsz -= 8;

  struct nt_file_range {
    uint64_t start, end;
    uint64_t file_offset;
  } __attribute__((packed));

  uint64_t *starts = (uint64_t *)malloc(sizeof(uint64_t) * entries);

  struct nt_file_range *iter = (nt_file_range *)descs;
  for (int i = 0; i < entries; i++) {
    if ((uint8_t *)iter + sizeof(*iter) >= note_end) return;
    starts[i] = iter->start;
    iter += 1;
  }

  descsz -= (sizeof(struct nt_file_range) * entries);
  descs += sizeof(struct nt_file_range) * entries;

  for (int i = 0; i < entries; i++) {
    char *name = strndup((const char *)descs, descsz);
    size_t len = strlen(name);
    descs += len + 1;
    descsz -= (len + 1);
    Binary *bin = GetBinaryContainingAddress(starts[i]);
    if (bin) bin->SetFileName(name);
  }
}

void Corefile::ProcessLOADs() {
  for (elf64_phdr *phdr : phdrs_) {
    if (phdr->p_type != PT_LOAD) continue;

    size_t region_size = phdr->p_filesz;
    if (region_size == 0) region_size = phdr->p_memsz;

    Binary *p = new Binary(core_view_ + phdr->p_offset, (size_t)region_size);

    p->SetVirtualAddress(phdr->p_vaddr);
    p->SetMemoryProtections(phdr->p_flags);

    vmmap_.push_back(p);
  }
}

void Corefile::ProcessNotes(elf64_phdr *phdr_note) {
  uint8_t *note_index = core_view_ + phdr_note->p_offset;
  uint8_t *note_end = note_index + phdr_note->p_filesz;
  while (note_index < note_end) {
    elf64_note *note = (elf64_note *)(note_index);

    size_t namesz_ru = ((note->n_namesz + 3) / 4) * 4;
    size_t descsz_ru = ((note->n_descsz + 3) / 4) * 4;

    switch (note->n_type) {
      case NT_PRSTATUS: {
        X86RegisterSet *reg_set = new X86RegisterSet((uint8_t *)note + sizeof(*note) + namesz_ru, note->n_descsz);
        threads_.push_back(reg_set);
        break;
      }
      case NT_SIGINFO:
        this->ProcessSIGINFO(note);
        break;
      case NT_FILE:
        this->ParseNtFile(note);
        break;
      case NT_AUXV:
        this->ParseAUXV(note);
        break;
      case NT_PRFPREG:
      case NT_PRPSINFO:
      case NT_TASKSTRUCT:
      case NT_PRXFPREG:
      case NT_PPC_VMX:
      case NT_X86_XSTATE:
        break;
    }

    size_t align = sizeof(elf64_note) + namesz_ru + descsz_ru;

    note_index += align;
  }
}

class X86ELF  : public ELFBinary { public: X86ELF (uint8_t *core, size_t size) : ELFBinary(core, size) { } };

ELFBinary *ELFBinary::Create(uint8_t *core_view, size_t size) {
  elf64_hdr *hdr = (elf64_hdr *)core_view;
  switch (hdr->e_machine) {
    case EM_386:
    case EM_486:
    case EM_X86_64:
      return new X86ELF(core_view, size);
    default:
      clog("Unknown e_machine type %d\n", hdr->e_machine);
      return nullptr;
  }
}

Corefile::Corefile(uint8_t *core, size_t size) : ELFBinary(core, size) {
  core_view_ = core;
  core_size_ = size;

  core += 4;
  size -= 4;

  int i = 0;
  for (i = 0; i < size; i++) {
    if (*(uint32_t *)(core + i) == *(uint32_t *)"\x7f""ELF") {
      ELFBinary *elf = ELFBinary::Create(core + i, size - i);
      if (elf) modules_.insert({ (uint64_t)(core + i), elf} );
    }
  }
}

class Symbolizer {
  const char *symbolizer_;
  uint64_t address_;
  Binary *binary_;
 public:
  Symbolizer(Binary *b, uint64_t address) : address_(address), binary_(b) { symbolizer_ = "llvm-symbolizer"; }
  std::string Symbolicate() {
    if (!binary_ || !binary_->GetFileName()) return std::string("<unknown>");

    int size = snprintf(NULL, 0, "%s --obj=%s %p", symbolizer_, binary_->GetFileName(), address_);
    char *cmd_buf = (char *)malloc(size + 1);
    snprintf(cmd_buf, size + 1, "%s --obj=%s %p", symbolizer_, binary_->GetFileName(), address_);

    FILE *pfp = popen(cmd_buf, "r");
    if (!pfp) return std::string("<unknown>");

    char info[128] = { 0 };
    fread(info, 1, 128, pfp);
    pclose(pfp);
    free(cmd_buf);
    return std::string(info);
  }
};

class Reporter {
  Corefile &f_;
 public:
  Reporter(Corefile &f): f_(f) { }
  std::string GenerateReport(std::vector<std::pair<uint64_t, std::string>> &frames) {
    nlohmann::json report = {
      { "modules", nlohmann::json::array() },
      { "backtrace", nlohmann::json::array() },
    };

    std::set<std::string> dedup;
    for (auto b : f_.GetModuleList()) {
      dedup.insert(std::string(b->GetFileName()));
    }

    for (auto s : dedup) {
      if (s != "")
        report["modules"].push_back(s);
    }

    for (auto f : frames) {
      report["backtrace"].push_back(f);
    }

    return report.dump();
  }
};

int main(int argc, char **argv) {
  // logfp = fopen("/tmp/cdump_log.txt", "wb+");
  // setvbuf(logfp, NULL, _IONBF, 0);

  setvbuf(stdout, NULL, _IONBF, 0);

  size_t buffer_size = 1024 * 1024 * 16;
  uint8_t *core_view = (uint8_t *)malloc(buffer_size); // 16MB is enough for anybody

  memset(core_view, '\0', buffer_size);
  uint8_t *core_alias = core_view;
  size_t core_size = 0;

  // Read CORE from stdin
  int sz = 0;
  while (buffer_size) {
    sz = read(0, core_alias, buffer_size);
    if (sz <= 0) break;
    buffer_size -= sz;
    core_alias += sz;
    printf("Read %d\n", sz);
  }
  printf("FINISHED READING.\n");

  Corefile f(core_view, (size_t)(core_alias - core_view));
  f.Process();
  f.GetRegisters();

  std::vector<std::pair<uint64_t, std::string>> symbolicated_bt;

  for (size_t i = 0; i < f.GetNumberOfThreads(); i++) {
    Backtrace *bt = f.GetBacktrace(i);
    MappedRegisterSet *mapped_regs = f.GetMappedRegisterSet(i);
    size_t frames = bt->GetFrameCount();
    for (size_t i = 0; i < frames; i++) {
      CallFrame frame = bt->frames[i];
      Symbolizer s(frame.GetBinary(), frame.GetSP());
      auto str = s.Symbolicate();
      symbolicated_bt.push_back(std::make_pair(frame.GetMappedAddress(), str));
    }
  }

  Reporter reporter(f);
  std::string js_report = reporter.GenerateReport(symbolicated_bt);
  write(1, js_report.data(), js_report.length());

  // fclose(logfp);
  return 0;
}

