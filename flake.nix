{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      ...
    }:
    let
      systems = [
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
      perSystem = forEachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
          # Keep the locked nixpkgs tree while applying the required Go security patch.
          secureGo = pkgs.go_1_26.overrideAttrs (_: {
            version = "1.26.9";
            src = pkgs.fetchurl {
              url = "https://go.dev/dl/go1.26.9.src.tar.gz";
              hash = "sha256-lzXX3Ntls10/pXfwQGRzfAO4nPGitx5uaf4vPG+f1Mo=";
            };
          });
          package = (pkgs.buildGo126Module.override { go = secureGo; }) {
            pname = "agevault";
            version = "1.2.0-fork.1";
            src = ./.;
            vendorHash = "sha256-yt4K+EcoZMJ36E5qolZdbDoeWp1WhVzppVx6nDrFq2s=";
          };
        in
        {
          inherit package;
          devShell = pkgs.mkShell {
            inputsFrom = [ package ];
            packages = with pkgs; [
              gotools
              ronn
            ];
          };
          fmt = treefmtEval.config.build.check self;
          formatter = treefmtEval.config.build.wrapper;
        }
      );
    in
    {
      packages = forEachSystem (system: {
        default = perSystem.${system}.package;
      });
      devShells = forEachSystem (system: {
        default = perSystem.${system}.devShell;
      });
      checks = forEachSystem (system: {
        inherit (perSystem.${system}) package fmt;
      });
      formatter = forEachSystem (system: perSystem.${system}.formatter);
    };
}
