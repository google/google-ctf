{
  description = "bpfbox";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      lib = pkgs.lib;
      init = pkgs.buildGoModule {
        name = "init";

        vendorHash = null;

        src = ./init;
      };
      initrdEnv = pkgs.buildEnv {
        name = "initrd-env";
        paths = with pkgs; [
          pkgsStatic.busybox
          bpftrace
          init
        ];
        pathsToLink = [
          "/bin"
        ];
      };
      kernel = pkgs.linuxPackages.kernel;
      initrd = pkgs.makeInitrdNG {
        name = "initramfs";
        contents = [
          { source = "${initrdEnv}/bin"; target = "/bin"; }
          { source = ./flag.txt; target = "/flag.txt"; }
          { source = "${initrdEnv}/bin/init"; target = "/init"; }
        ];
      };
    in
    {
      packages.x86_64-linux.default = pkgs.stdenvNoCC.mkDerivation {
        name = "bpfbox";
        phases = [ "installPhase" ];
        installPhase = ''
          mkdir -p $out
          cp ${initrd}/initrd.gz $out/
          cp ${kernel}/bzImage $out/
        '';
      };
    };
}
