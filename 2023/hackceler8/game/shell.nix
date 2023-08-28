{ pkgs ? import <nixpkgs> {} }:

(pkgs.buildFHSUserEnv {
  name = "gctf-2023-devenv";
  targetPkgs = pkgs: with pkgs; [
    ffmpeg-full
    freetype
    fontconfig
    libGL
    libGLU
    python3
    python3Packages.virtualenv
    xorg.libX11
  ];
}).env
