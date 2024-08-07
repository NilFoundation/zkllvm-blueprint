#!/usr/bin/env bash
set -e

declare -a TEST_LIST=(\
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
    "blueprint_component_batch_test"
    "blueprint_verifiers_placeholder_expression_evaluation_component_test"
    "blueprint_verifiers_placeholder_final_polynomial_check_test"
    "blueprint_verifiers_flexible_swap_test"
    "blueprint_verifiers_flexible_additions_test"
    "blueprint_verifiers_flexible_multiplications_test"
    "blueprint_verifiers_flexible_poseidon_test"
    "blueprint_verifiers_flexible_constant_pow_test"
    "blueprint_verifiers_placeholder_verifier_test"
    "blueprint_zkevm_zkevm_word_test"
    "blueprint_zkevm_bytecode_test"
    "blueprint_zkevm_state_selector_test"
    "blueprint_zkevm_state_transition_test"
    "blueprint_zkevm_opcodes_iszero_test"
    "blueprint_zkevm_opcodes_add_sub_test"
    "blueprint_zkevm_opcodes_mul_test"
    "blueprint_zkevm_opcodes_div_test"
)
#blueprint_non_native_plonk_scalar_non_native_range_test, TODO: enable once fixed.
#blueprint_mock_mocked_components_test, TODO: Enable after code and test re-written.

echo "building ${TEST_LIST[*]}"
ninja -k 0 -j $NIX_BUILD_CORES ${TEST_LIST[*]}

echo "finish"
