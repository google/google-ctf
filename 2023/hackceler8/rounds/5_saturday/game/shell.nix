{ pkgs ? import <nixpkgs> {} }:

(pkgs.buildFHSUserEnv {
  name = "gctf-2023-devenv";
  targetPkgs = pkgs: with pkgs; [
    ffmpeg-full
    fontconfig
    freetype
    libGL
    libGLU
    openal
    python3
    python3Packages.virtualenv
    tiled
    xorg.libX11
  ];
  runScript = ./.venv-shell.sh;
}).env
