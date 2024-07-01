{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    nil_crypto3 = {
      url = "github:NilFoundation/crypto3";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, nil_crypto3, flake-utils }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.llvmPackages_16.stdenv;
        crypto3 = nil_crypto3.packages.${system}.default;
      in rec {
        packages = rec {
          zkllvm-blueprint = stdenv.mkDerivation {
            name = "zkllvm-blueprint";

            src = self;

            buildInputs = with pkgs; [
              cmake
              pkg-config
              clang_16
            ];

            propagatedBuildInputs = [ crypto3 pkgs.boost183 ];

            cmakeBuildType = "Release";

            cmakeFlags = [
              "-DCMAKE_CXX_STANDARD=17"
            ];

            doCheck = false;
          };
          default = zkllvm-blueprint;
        };

        testList = [
            "blueprint_algebra_curves_plonk_unified_addition_test"
            "blueprint_algebra_curves_plonk_variable_base_scalar_mul_test"
            "blueprint_non_native_plonk_bool_scalar_multiplication_test"
            "blueprint_non_native_plonk_add_mul_zkllvm_compatible_test"
        ];

        checks = {
          default = stdenv.mkDerivation {
            name = "zkllvm-blueprint-tests";

            src = self;

            buildInputs = with pkgs; [
              cmake
              ninja
              pkg-config
              clang_16
              boost183
              crypto3
            ];

            cmakeBuildType = "Debug";

            cmakeFlags = [
              "-DCMAKE_CXX_STANDARD=17"
              "-DCMAKE_ENABLE_TESTS=TRUE"
              "-DCMAKE_C_COMPILER=clang"
              "-DCMAKE_CXX_COMPILER=clang++"
              "-DSTANDARD_EC_INF_POINTS_ENABLED=TRUE"
            ];

            ninjaFlags = pkgs.lib.strings.concatStringsSep " " (["-k 0"] ++ testList);

            doCheck = true;

            checkPhase = ''
              # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR` (/build/source)
              export BOOST_TEST_LOGGER=JUNIT:HRF
              ctest --verbose -j $NIX_BUILD_CORES --output-on-failure -R "${nixpkgs.lib.concatStringsSep "|" testList}" || true

              mkdir -p ${placeholder "out"}/test-logs
              find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
            '';

            dontInstall = true;
          };
        };

        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              cmake
              pkg-config
              boost183
              clang_16
              clang-tools_16
              crypto3
            ];

            shellHook = ''
              export NO_AT_BRIDGE="1"
              function nil_test_runner() {
                clear
                filename=$(cat Makefile | grep "$2" | awk 'NR==1{print $NF}')
                make -j$(nproc) "$filename" && ./test/$filename
              }
              function ctcmp() {
                nil_test_runner blueprint $1
              }
              echo "zkllvm-blueprint dev environment activated"
            '';
          };
        };
      }));
}

# 1 build crypto 3 locally with the command 'nix build -L .?submodules=1#'
# 2 use the local source of crypto3: 'nix develop --override-input nil_crypto3 /your/path/to/crypto3 .?submodules=1#'
# 3a to build all in blueprint: 'nix flake -L check .?submodules=1#' or build all and run tests: nix build -L .?submodules=1#checks.x86_64-linux.default
# 3b to build individual targets:
# nix develop . -c cmake -B build -DCMAKE_CXX_STANDARD=17 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_ENABLE_TESTS=TRUE -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
# cd build
# nix develop ../ -c cmake --build . -t blueprint_verifiers_flexible_constant_pow_test
