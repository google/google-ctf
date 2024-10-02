{
  description = "Hackceler8";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    nix-formatter-pack = {
      url = "github:Gerschtli/nix-formatter-pack";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in rec {
        packages.default = pkgs.callPackage ./game.nix { };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs;
            [ tiled xorg.libX11 qt5.qtwayland ] ++ packages.default.buildInputs;
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

