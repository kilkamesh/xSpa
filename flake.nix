{
  description = "xSpa eBPF port knocking";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "xSpa";
          version = "0.1.0";
          src = ./.;

          vendorHash = null;

          nativeBuildInputs = with pkgs; [ 
            clang_16 
            llvm 
            libbpf 
            pkg-config 
            bpftool
            kernel
          ];
          
          preBuild = ''
            go generate ./internal/infra/ebpf/gen.go
          '';

          ldflags = [ "-s" "-w" ];
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ go clang_16 libbpf bpftool ];
        };
      }) // {
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.xspa;
          pkg = self.packages.${pkgs.system}.default;
            configFile = pkgs.writeText "xspa-config.json" (builtins.toJSON {
            server = {
              iface = cfg.server.interface;
              port = cfg.server.port;
              sign_key = cfg.server.signKey;
              cipher_key = cfg.server.cipherKey;
              sign_key_file = cfg.server.signSecret;
              cipher_key_file = cfg.server.cipherSecret;
            };
            profiles = lib.mapAttrs (name: p: {
              ipv4 = p.ipv4;
              spa_port = p.spa_port;
              sign_key = p.signKey;
              cipher_key = p.cipherKey;
              sign_key_file = p.signSecret;
              cipher_key_file = p.cipherSecret;
            }) cfg.profiles;
            });
        in {
          options.services.xspa = {
            server = lib.mkOption {
              enable = lib.mkEnableOption "xknock service";
              interface = lib.mkOption {
                type = lib.types.str;
                default = "eth0";
                description = "Interface to attach XDP program";
              };
              port = lib.mkOption {
                type = lib.types.int;
                default = 55555;
                description = "UDP port for SPA packets";
              };
              signKey = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Key for sing";
              };
              signSecret = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to file with key for sing";
              };
              cipherKey = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Key for cipher";
              };
              cipherSecret = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to file with key for cipher";
              };
            };
            profiles = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options = {
                  ipv4 = lib.mkOption { type = lib.types.str; };
                  spa_port = lib.mkOption { type = lib.types.port; };
                                signKey = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Key for sing";
              };
              signSecret = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to file with key for sing";
              };
              cipherKey = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Key for cipher";
              };
              cipherSecret = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to file with key for cipher";
              };
                };
              });
              default = {};
              description = "Profiles for send SPA";
            };
          };

          config = lib.mkIf cfg.server.enable {
            systemd.services.xspa = {
              description = "xSpa eBPF SPA Server";
              after = [ "network.target" ];
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart = "${pkg}/bin/xspa --config ${configFile}";
                DynamicUser = true; 
                CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_BPF" "CAP_SYS_ADMIN" ];
                AmbientCapabilities =[ "CAP_NET_ADMIN" "CAP_BPF" "CAP_SYS_ADMIN" ];
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictNamespaces = true;
                MemoryDenyWriteExecute = false;
                LockPersonality = true;
                Restart = "on-failure";
                RestartSec = "5s";
              };
            };
          };
        };
    };
}
