{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    nil_crypto3 = {
      url = "https://github.com/NilFoundation/crypto3";
      type = "git";
      submodules = true;
      rev = "3de0775395bf06c0e4969ff7f921cc7523904269";
    };
  };

  outputs = { self, nixpkgs, nil_crypto3 }:
    let
      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });

      # This library is header-only, so we don't need to provide debug and
      # release versions of package.
      makePackage = { pkgs }:
        let
          stdenv = pkgs.llvmPackages_16.stdenv;
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
        in
        stdenv.mkDerivation {
          name = "zkllvm-blueprint";

          src = self;

          env.CXXFLAGS = toString ([
            "-fPIC"
          ]);

          env.NIX_CFLAGS_COMPILE = toString ([
            "-Wno-unused-but-set-variable"
          ]);

          buildInputs = with pkgs; [
            cmake
            pkg-config
            clang_16
            boost
          ];

          # Because crypto3 is header-only, we must propagate it so users
          # of this flake must not specify crypto3 in their derivations manually
          propagatedBuildInputs = [
            crypto3
          ];

          cmakeFlags = [
            "-DCMAKE_BUILD_TYPE=Release"
            "-DCMAKE_CXX_STANDARD=17"
          ];

          doCheck = false;
        };

      testList = [
        "blueprint_algebra_fields_plonk_field_operations_test"
        "blueprint_algebra_fields_plonk_exponentiation_test"
        "blueprint_algebra_curves_plonk_unified_addition_test"
        "blueprint_algebra_curves_plonk_variable_base_scalar_mul_test"
        "blueprint_verifiers_kimchi_sponge_oracles_test"
        "blueprint_hashes_plonk_poseidon_test"
        "blueprint_algebra_curves_plonk_endo_scalar_test"
        "blueprint_algebra_fields_plonk_range_check_test"
        "blueprint_algebra_fields_plonk_logic_and_flag_test"
        "blueprint_algebra_fields_plonk_logic_or_flag_test"
        "blueprint_algebra_fields_plonk_interpolation_test"
        "blueprint_algebra_fields_plonk_non_native_addition_test"
        "blueprint_algebra_fields_plonk_non_native_subtraction_test"
        "blueprint_algebra_fields_plonk_non_native_multiplication_test"
        "blueprint_algebra_fields_plonk_non_native_range_test"
        "blueprint_algebra_fields_plonk_non_native_reduction_test"
        "blueprint_algebra_fields_plonk_non_native_bit_decomposition_test"
        "blueprint_algebra_fields_plonk_non_native_bit_composition_test"
        "blueprint_algebra_fields_plonk_non_native_bit_shift_constant_test"
        "blueprint_algebra_fields_plonk_non_native_logic_ops_test"
        "blueprint_algebra_fields_plonk_non_native_lookup_logic_ops_test"
        "blueprint_algebra_fields_plonk_non_native_comparison_checked_test"
        "blueprint_algebra_fields_plonk_non_native_comparison_unchecked_test"
        "blueprint_algebra_fields_plonk_non_native_comparison_flag_test"
        "blueprint_algebra_fields_plonk_non_native_equality_flag_test"
        "blueprint_algebra_fields_plonk_non_native_division_remainder_test"
        "blueprint_non_native_plonk_scalar_non_native_range_test"
        "blueprint_non_native_plonk_bool_scalar_multiplication_test"
        "blueprint_non_native_plonk_add_mul_zkllvm_compatible_test"
        "blueprint_hashes_plonk_decomposition_test"
        "blueprint_verifiers_placeholder_fri_cosets_test"
        "blueprint_hashes_plonk_sha256_process_test"
        "blueprint_hashes_plonk_sha512_process_test"
        "blueprint_hashes_plonk_sha256_test"
        "blueprint_hashes_plonk_sha512_test"
        "blueprint_algebra_fields_plonk_sqrt_test"
        "blueprint_verifiers_placeholder_fri_lin_inter_test"
        "blueprint_verifiers_placeholder_fri_array_swap_test"
        "blueprint_manifest_test"
        "blueprint_detail_huang_lu_test"
        "blueprint_private_input_test"
        "blueprint_verifiers_placeholder_permutation_argument_verifier_test"
        "blueprint_verifiers_placeholder_gate_argument_verifier_test"
        "blueprint_verifiers_placeholder_lookup_argument_verifier_test"
        "blueprint_verifiers_placeholder_f1_loop_test"
        "blueprint_verifiers_placeholder_f3_loop_test"
        "blueprint_verifiers_placeholder_gate_component_test"
        "blueprint_verifiers_flexible_pow_factor_test"
        "blueprint_proxy_test"
        "blueprint_mock_mocked_components_test"
        "blueprint_component_batch_test"
        "blueprint_verifiers_placeholder_expression_evaluation_component_test"
        "blueprint_verifiers_placeholder_final_polynomial_check_test"
        "blueprint_verifiers_flexible_swap_test"
        "blueprint_verifiers_flexible_additions_test"
        "blueprint_verifiers_flexible_multiplications_test"
        "blueprint_verifiers_flexible_poseidon_test"
        "blueprint_verifiers_flexible_constant_pow_test"
        "blueprint_verifiers_placeholder_verifier_test"
      ];

      makeChecks = { pkgs }:
        let
          stdenv = pkgs.llvmPackages_16.stdenv;
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
        in
        stdenv.mkDerivation {
          # TODO: rewrite this using overrideAttrs on makePackage
          name = "zkllvm-blueprint-tests";

          src = self;

          env.CXXFLAGS = toString ([
            "-fPIC"
          ]);

          env.NIX_CFLAGS_COMPILE = toString ([
            "-Wno-unused-but-set-variable"
          ]);

          buildInputs = with pkgs; [
            cmake
            ninja
            pkg-config
            clang_16
            boost
            crypto3
          ];

          cmakeBuildType = "Debug";

          cmakeFlags = [
            "-DCMAKE_CXX_STANDARD=17"
            "-DBUILD_SHARED_LIBS=TRUE"
            "-DBUILD_TESTS=TRUE"
            "-DCMAKE_C_COMPILER=clang"
            "-DCMAKE_CXX_COMPILER=clang++"
          ];

          doCheck = true;

          ninjaFlags = pkgs.lib.strings.concatStringsSep " " testList;

          checkPhase =
            let
              runTest = testName: "echo 'Running ${testName}' && ./test/${testName}";
              commandList = builtins.map runTest testList;
            in ''
              export BOOST_TEST_LOGGER=JUNIT:HRF
              ${pkgs.lib.strings.concatStringsSep "\n" commandList}

              mkdir -p ${placeholder "out"}/test-logs
              find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
            '';

          dontInstall = true;
        };

      makeDevShell = { pkgs }:
        let
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            cmake
            pkg-config
            boost
            clang_16
            clang-tools_16
            crypto3
          ];

          shellHook = ''
            echo "zkllvm-blueprint dev environment activated"
          '';
        };
    in
    {
      packages = forAllSystems ({ pkgs }: { default = makePackage { inherit pkgs; }; });
      checks = forAllSystems ({ pkgs }: { default = makeChecks { inherit pkgs; }; });
      devShells = forAllSystems ({ pkgs }: { default = makeDevShell { inherit pkgs; }; });
    };
}
