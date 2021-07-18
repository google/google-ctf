with import <nixpkgs> {
  crossSystem = {
    config = "riscv64-none-elf";
    libc = "newlib";
  };
};

mkShell {
  buildInputs = [ ];
}

