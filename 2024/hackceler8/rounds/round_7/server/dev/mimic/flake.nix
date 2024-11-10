{
  description = "VARAFM clone";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-formatter-pack = {
      url = "github:Gerschtli/nix-formatter-pack";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        libPath = with pkgs;
          lib.makeLibraryPath (with pkgs; [
            z3
          ]);
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            z3
            libclang
          ];
          LD_LIBRARY_PATH = libPath;
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          Z3_SYS_Z3_HEADER = "/nix/store/3dbac6vhhr8v64fjrz0f7ika805hnpfs-z3-4.8.17-dev/include/z3.h";
        };

        # Formatting
        formatter = inputs.nix-formatter-pack.lib.mkFormatter {
          inherit nixpkgs system;
          config = {
            tools = {
              deadnix = {
                enable = true;
                noLambdaPatternNames = true;
                noLambdaArg = true;
              };
              statix.enable = true;
              nixfmt.enable = true;
              nixpkgs-fmt.enable = true;
            };
          };
        };
      });
}
