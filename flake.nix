{
  description = "Packet Diff TUI - Terminal-based packet comparison tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      uv2nix,
      pyproject-nix,
      pyproject-build-systems,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      # Load a uv workspace from a workspace root.
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

      # Create package overlay from workspace.
      overlay = workspace.mkPyprojectOverlay {
        # Prefer prebuilt binary wheels as a package source.
        sourcePreference = "wheel";
      };

      # Extend generated overlay with build fixups
      pyprojectOverrides = _final: _prev: {
        # Build fixups for pyshark and other packages that may need special handling
      };

      # This example is only using x86_64-linux
      pkgs = nixpkgs.legacyPackages.x86_64-linux;

      # Use Python 3.12 from nixpkgs
      python = pkgs.python312;

      # Construct package set
      pythonSet =
        # Use base package set from pyproject.nix builders
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.default
              overlay
              pyprojectOverrides
            ]
          );

    in
    {
      # Package a virtual environment as our main application.
      packages.x86_64-linux.default = pythonSet.mkVirtualEnv "pcap-diff-env" workspace.deps.default;

      # Make pcap-diff runnable with `nix run`
      apps.x86_64-linux = {
        default = {
          type = "app";
          program = "${self.packages.x86_64-linux.default}/bin/pcap-diff";
        };
      };

      # Development shells
      devShells.x86_64-linux = {
        # Impure development shell using uv
        impure = pkgs.mkShell {
          packages = [
            python
            pkgs.uv
            pkgs.wireshark-cli  # For tshark/dumpcap tools
            pkgs.tcpdump        # For additional packet capture tools
          ];
          env =
            {
              # Prevent uv from managing Python downloads
              UV_PYTHON_DOWNLOADS = "never";
              # Force uv to use nixpkgs Python interpreter
              UV_PYTHON = python.interpreter;
            }
            // lib.optionalAttrs pkgs.stdenv.isLinux {
              # Python libraries often load native shared objects using dlopen(3).
              LD_LIBRARY_PATH = lib.makeLibraryPath pkgs.pythonManylinuxPackages.manylinux1;
            };
          shellHook = ''
            unset PYTHONPATH
            echo "🔧 Packet Diff TUI Development Environment"
            echo "Python: ${python.interpreter}"
            echo "Run 'uv sync' to install dependencies"
          '';
        };

        # Pure development using uv2nix
        uv2nix =
          let
            # Create an overlay enabling editable mode for all local dependencies.
            editableOverlay = workspace.mkEditablePyprojectOverlay {
              # Use environment variable
              root = "$REPO_ROOT";
            };

            # Override previous set with our overrideable overlay.
            editablePythonSet = pythonSet.overrideScope (
              lib.composeManyExtensions [
                editableOverlay

                # Apply fixups for building an editable package
                (final: prev: {
                  pcap-diff = prev.pcap-diff.overrideAttrs (old: {
                    # Filter sources for editable build
                    src = lib.fileset.toSource {
                      root = old.src;
                      fileset = lib.fileset.unions [
                        (old.src + "/pyproject.toml")
                        (old.src + "/README.md")
                        (old.src + "/src")
                      ];
                    };

                    # Add editables dependency for hatchling
                    nativeBuildInputs =
                      old.nativeBuildInputs
                      ++ final.resolveBuildSystem {
                        editables = [ ];
                      };
                  });
                })
              ]
            );

            # Build virtual environment, with local packages being editable.
            virtualenv = editablePythonSet.mkVirtualEnv "pcap-diff-dev-env" workspace.deps.all;

          in
          pkgs.mkShell {
            packages = [
              virtualenv
              pkgs.uv
              pkgs.wireshark-cli
              pkgs.tcpdump
            ];

            env = {
              # Don't create venv using uv
              UV_NO_SYNC = "1";
              # Force uv to use nixpkgs Python interpreter
              UV_PYTHON = python.interpreter;
              # Prevent uv from downloading managed Python's
              UV_PYTHON_DOWNLOADS = "never";
            };

            shellHook = ''
              # Undo dependency propagation by nixpkgs.
              unset PYTHONPATH

              # Get repository root using git.
              export REPO_ROOT=$(git rev-parse --show-toplevel)
              
              echo "🔧 Packet Diff TUI Pure Development Environment"
              echo "All dependencies managed by Nix"
            '';
          };
      };
    };
}