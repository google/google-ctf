{
  description = "Hackceler8";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    nixgl = {
      url = "github:nix-community/nixGL";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix-formatter-pack = {
      url = "github:Gerschtli/nix-formatter-pack";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ inputs.nixgl.overlay ];
        pkgs = import nixpkgs { inherit system overlays; };
        libPath = pkgs.lib.makeLibraryPath (with pkgs; [
          libGL
          libGLU
          freetype
          fontconfig
          pkgs.stdenv.cc.cc.lib
          zlib
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            ffmpeg-full
            freetype
            fontconfig
            libGL
            libGLU
            python3
            python3Packages.virtualenv
            tiled
            xorg.libX11
            qt5.qtwayland
          ];

          shellHook = ''
            # Create virtualenv
            if [[ ! -d .venv ]]; then
              virtualenv .venv
            fi;

            # Activate virtualenv and install requirements
            source .venv/bin/activate
            pip install -r requirements.txt
          '';

          LD_LIBRARY_PATH = libPath;
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

