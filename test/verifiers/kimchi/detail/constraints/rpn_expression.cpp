//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_detail_rpn_expression_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_string_literal.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/recursion_test.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_test.hpp"

#include "test_plonk_component.hpp"
#include "../../proof_data.hpp"

using namespace nil::crypto3;
BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proof(zk::snark::proof_type<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvalRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i][0]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z[0]);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i][0]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                public_input.push_back(original_proof.evals[point_idx].lookup.sorted[i][0]);
                circuit_proof.proof_evals[point_idx].lookup.sorted[i] =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }

            public_input.push_back(original_proof.evals[point_idx].lookup.aggreg[0]);
            circuit_proof.proof_evals[point_idx].lookup.aggreg = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            public_input.push_back(original_proof.evals[point_idx].lookup.table[0]);
            circuit_proof.proof_evals[point_idx].lookup.table = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            if (KimchiParamsType::circuit_params::lookup_runtime) {
                public_input.push_back(original_proof.evals[point_idx].lookup.runtime[0]);
                circuit_proof.proof_evals[point_idx].lookup.runtime = 
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector[0]);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector[0]);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    // public_input
    circuit_proof.public_input.resize(KimchiParamsType::public_input_size);
    for (std::size_t i = 0; i < KimchiParamsType::public_input_size; ++i) {
        public_input.push_back(original_proof.public_input[i]);
        circuit_proof.public_input[i] =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    // prev_chal
    circuit_proof.prev_challenges.resize(KimchiParamsType::prev_challenges_size);
    for (std::size_t i = 0; i < KimchiParamsType::prev_challenges_size; ++i) {
        for (std::size_t j = 0; j < EvalRounds; ++j) {
            public_input.push_back(original_proof.prev_challenges[i].first[j]);
            circuit_proof.prev_challenges[i][j] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }
    // ft_eval
    public_input.push_back(original_proof.ft_eval1);
    circuit_proof.ft_eval = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_lagrange) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    typename BlueprintFieldType::value_type result = 0x1E2AE13562C642ED35261EB5927960C75105852F6F962D463BF981EF969050C4_cppui255;
    constexpr const char *s ="UnnormalizedLagrangeBasis(-4);\0";

    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0C0D3C26FCD47AFF64D9055FCE9858335ADE6B0706289AB4019630784E8B7527_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000059E5EE71CFF4B24FA2A3A131F77CFFC8_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000085D434481165E938FEA628354AA5B9E5_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x00_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x35ABB5BAFCAFF26391BB9A23EA996222FD0D4B0F392A78E4AFD5610ECE614E49_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x1421DEB15F5CE205068512B010382353DC0AA1B40386A1C14774C65664BB8182_cppui256;
    std::size_t domain_size = 1024;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val, &result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(assignment.var_value(real_res.output)== result);

    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_vanishes) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    typename BlueprintFieldType::value_type result = 0x2692756edf321604d16f4d2151fbad0a9780c75ebb49f9b56a89adde2f6a1f48_cppui255;
    constexpr const char *s ="Alpha;Pow(24);VanishesOnLast4Rows;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type group_gen = BlueprintFieldType::value_type::one();

    typename BlueprintFieldType::value_type alpha_val =
        0x0C0D3C26FCD47AFF64D9055FCE9858335ADE6B0706289AB4019630784E8B7527_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000059E5EE71CFF4B24FA2A3A131F77CFFC8_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000085D434481165E938FEA628354AA5B9E5_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x00_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x35ABB5BAFCAFF26391BB9A23EA996222FD0D4B0F392A78E4AFD5610ECE614E49_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x1421DEB15F5CE205068512B010382353DC0AA1B40386A1C14774C65664BB8182_cppui256;
    std::size_t domain_size = 1024;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val, &result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(assignment.var_value(real_res.output)== result);

    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_dup) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Dup;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(gamma_val == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_sub) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Sub;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((beta_val - gamma_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_add) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Add;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val + beta_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_mul) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Mul;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val * beta_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_pow) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(10), row: Curr });Pow(2);\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[10] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val * gamma_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_load) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Store;Beta;Alpha;Pow(20);Add;Alpha;Load(0);Sub;Add;Sub;Literal 0000000000000000000000000000000000000000000000000000000000000001;Add;\0"; // - alpha^20 - beta + alpha + 1
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    typename BlueprintFieldType::value_type expected_result = -alpha_val.pow(20) + alpha_val - beta_val + 1;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_complete_add) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Store;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(7), row: Curr });Load(0);Mul;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Dup;Add;Sub;Load(1);Sub;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Load(0);Cell(Variable { col: Witness(8), row: Curr });Mul;Cell(Variable { col: Witness(3), row: Curr });Cell(Variable { col: Witness(1), row: Curr });Sub;Store;Sub;Mul;Add;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Add;Cell(Variable { col: Witness(4), row: Curr });Add;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Mul;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(4), row: Curr });Sub;Mul;Cell(Variable { col: Witness(1), row: Curr });Sub;Cell(Variable { col: Witness(5), row: Curr });Sub;Mul;Add;Alpha;Pow(5);Load(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Mul;Add;Alpha;Pow(6);Load(2);Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Add;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type expected_result = 0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
            0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
            0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
            0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
            0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
            0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
            0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
            0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
            0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
            0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
            0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
            0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
            0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
            0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
            0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256
        };

    typename BlueprintFieldType::value_type eval0_z = 0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256
    };

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
            0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
            0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
            0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
            0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
            0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
            0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
            0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
            0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
            0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
            0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
            0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
            0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
            0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
            0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256
        };

    typename BlueprintFieldType::value_type eval1_z = 0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    typename BlueprintFieldType::value_type alpha_val =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    var joint_combiner = zero;

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_endo_mul) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Cell(Variable { col: Witness(11), row: Curr });Dup;Mul;Cell(Variable { col: Witness(11), row: Curr });Sub;Alpha;Pow(1);Cell(Variable { col: Witness(12), row: Curr });Dup;Mul;Cell(Variable { col: Witness(12), row: Curr });Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(13), row: Curr });Dup;Mul;Cell(Variable { col: Witness(13), row: Curr });Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(14), row: Curr });Dup;Mul;Cell(Variable { col: Witness(14), row: Curr });Sub;Mul;Add;Alpha;Pow(4);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(11), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(4), row: Curr });Sub;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(12), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(4), row: Curr });Dup;Add;Cell(Variable { col: Witness(9), row: Curr });Dup;Mul;Store;Sub;Load(0);Add;Cell(Variable { col: Witness(4), row: Curr });Cell(Variable { col: Witness(7), row: Curr });Sub;Store;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(5), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(5), row: Curr });Dup;Add;Load(2);Mul;Sub;Mul;Add;Alpha;Pow(6);Load(3);Dup;Mul;Load(2);Dup;Mul;Load(1);Load(0);Sub;Cell(Variable { col: Witness(7), row: Curr });Add;Mul;Sub;Mul;Add;Alpha;Pow(7);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(13), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(7), row: Curr });Sub;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(14), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(7), row: Curr });Dup;Add;Cell(Variable { col: Witness(10), row: Curr });Dup;Mul;Store;Sub;Load(4);Add;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(4), row: Next });Sub;Store;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(8), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Load(6);Mul;Sub;Mul;Add;Alpha;Pow(9);Load(7);Dup;Mul;Load(6);Dup;Mul;Load(5);Load(4);Sub;Cell(Variable { col: Witness(4), row: Next });Add;Mul;Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(6), row: Curr });Dup;Add;Cell(Variable { col: Witness(11), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(12), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(13), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(14), row: Curr });Add;Cell(Variable { col: Witness(6), row: Next });Sub;Mul;Add;\0";

    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type expected_result = 0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
            0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
            0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
            0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
            0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
            0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
            0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
            0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
            0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
            0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
            0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
            0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
            0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
            0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
            0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256
        };

    typename BlueprintFieldType::value_type eval0_z = 0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256
    };

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
            0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
            0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
            0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
            0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
            0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
            0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
            0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
            0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
            0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
            0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
            0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
            0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
            0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
            0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256
        };

    typename BlueprintFieldType::value_type eval1_z = 0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    typename BlueprintFieldType::value_type alpha_val =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    var joint_combiner = zero;

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_endo_mul_recursion) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 32;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_recursion_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Cell(Variable { col: Witness(11), row: Curr });Dup;Mul;Cell(Variable { col: Witness(11), row: Curr });Sub;Alpha;Pow(1);Cell(Variable { col: Witness(12), row: Curr });Dup;Mul;Cell(Variable { col: Witness(12), row: Curr });Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(13), row: Curr });Dup;Mul;Cell(Variable { col: Witness(13), row: Curr });Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(14), row: Curr });Dup;Mul;Cell(Variable { col: Witness(14), row: Curr });Sub;Mul;Add;Alpha;Pow(4);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(11), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(4), row: Curr });Sub;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(12), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(4), row: Curr });Dup;Add;Cell(Variable { col: Witness(9), row: Curr });Dup;Mul;Store;Sub;Load(0);Add;Cell(Variable { col: Witness(4), row: Curr });Cell(Variable { col: Witness(7), row: Curr });Sub;Store;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(5), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(5), row: Curr });Dup;Add;Load(2);Mul;Sub;Mul;Add;Alpha;Pow(6);Load(3);Dup;Mul;Load(2);Dup;Mul;Load(1);Load(0);Sub;Cell(Variable { col: Witness(7), row: Curr });Add;Mul;Sub;Mul;Add;Alpha;Pow(7);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(13), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(7), row: Curr });Sub;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(14), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(7), row: Curr });Dup;Add;Cell(Variable { col: Witness(10), row: Curr });Dup;Mul;Store;Sub;Load(4);Add;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(4), row: Next });Sub;Store;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(8), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Load(6);Mul;Sub;Mul;Add;Alpha;Pow(9);Load(7);Dup;Mul;Load(6);Dup;Mul;Load(5);Load(4);Sub;Cell(Variable { col: Witness(4), row: Next });Add;Mul;Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(6), row: Curr });Dup;Add;Cell(Variable { col: Witness(11), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(12), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(13), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(14), row: Curr });Add;Cell(Variable { col: Witness(6), row: Next });Sub;Mul;Add;\0";

    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type expected_result = 0x04F0AE93737FF95171B129AEA745BE69608584EAFD43A801D73588C86D07F3A2_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x2A016E5F91F6C33552FC86A7A88C034E5CF1301E4982545A15AB709ECE150E09_cppui256,
            0x1D1B8F16A3DF52F90BA4856A11D397FDD175DEBBDC84F9D9FD71C46E5CB311CC_cppui256,
            0x034EB5403A85D023EFD87CE7E37CD027921DBC8F5A59C6338A12965B2E1D2D9B_cppui256,
            0x3D708DC37C2985BD9E8F39D40FFB35A8C1D1D4106AC17CEA1668C944007FE789_cppui256,
            0x23ACD65BE15FC86FB7FC4FD45701CF7F348C13DD6DFF400DF808BE97006E06C8_cppui256,
            0x3F6D999688174F2CC9C37FBFDA241825F50505E56EF660E29FBC52F06008F2EF_cppui256,
            0x054FF59489820600DB800466FDF3063D387CAFC5464741417FAD07A00E2B558A_cppui256,
            0x078062AB9E022D286A47F28A6A57C368598416D076C558A8288A05AD9A1451DE_cppui256,
            0x09B0CFC2B282544FF90FE0ADD6BC80937A8B7DDBA743700ED16703BB25FD4E32_cppui256,
            0x0BE13CD9C7027B7787D7CED143213DBE9B92E4E6D7C187757A4401C8B1E64A86_cppui256,
            0x0E11A9F0DB82A29F169FBCF4AF85FAE9BC9A4BF2083F9EDC2320FFD63DCF46DA_cppui256,
            0x10421707F002C9C6A567AB181BEAB814DDA1B2FD38BDB642CBFDFDE3C9B8432E_cppui256,
            0x1272841F0482F0EE342F993B884F753FFEA91A08693BCDA974DAFBF155A13F82_cppui256,
            0x14A2F13619031815C2F7875EF4B4326B1FB0811399B9E5101DB7F9FEE18A3BD6_cppui256,
            0x16D35E4D2D833F3D51BF75826118EF9640B7E81ECA37FC76C694F80C6D73382A_cppui256
        };

    typename BlueprintFieldType::value_type eval0_z = 0x38C5D08C61572A0F233A3732575F3A07AD484107EC7366FEB0903FCC30253C1A_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256,
        0x264CBA1EFD870553869EC32E652FE2FC5DB4DF0C8B8550816F1947F66858B238_cppui256,
        0x21D7D3F53426BA3024217C852D5B1944031F52E784E95CA0539A9F88FB3F3FBE_cppui256,
        0x260E6148F06FA79CD3C8C4A379955A8823017E730AD3624A578304A44B5113AC_cppui256,
        0x2E901B006A7D080B6566A472AC9DEA73BB53A57A190B1A21ECEB698A869374BA_cppui256,
        0x2E70F1D4AE3E1DE24337D33C4F61C88A628368CA7FBE9BF67C16F0944C64B7DE_cppui256
    };

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x119301E40E2E7C7D465D44663295D7EA620FBCC1F53517ABDD2ECF5C944C5CA1_cppui256,
            0x2796DF6969578BE116556794B60EFDD9D3686F8BFE336F0309CA3AA73393C8A0_cppui256,
            0x06A9EE581EC0C7F41B9E54F192948200F0045C21B4BA021DBCB6C8EBA3BFF30C_cppui256,
            0x0EA289935EE95E8D771A681893AC0E4C33CB9BB88A2D0DB18F3C0CED5D37EBAA_cppui256,
            0x244FF116C46C3E79427E298089212A35DFB57750BDCD97A159A98DC014870F83_cppui256,
            0x3F04F2BDEBB8E5E732AB024C699E2481A82CA6205E3E34481A0D57BA0AEB997E_cppui256,
            0x014FCC504DEC8FE403ED2DB233134CD28CAD4F9E54DEE00C3384740355203132_cppui256,
            0x2AE2D234C19E20C167FAC3AB796EB0F1524B62DD459AE8FE0997B0544AC69E29_cppui256,
            0x1475D819354FB19ECC0859A4BFCA150FF5A2DD202D09F8D4467DBBB8406D0B1F_cppui256,
            0x3E08DDFDA901427C3015EF9E0625792EBB40F05F1DC601C61C90F80936137816_cppui256,
            0x279BE3E21CB2D359942385974C80DD4D5E986AA20535119C5977036D2BB9E50C_cppui256,
            0x112EE9C690646436F8311B9092DC416C01EFE4E4ECA42172965D0ED121605202_cppui256,
            0x3AC1EFAB0415F5145C3EB189D937A58AC78DF823DD602A646C704B221706BEF9_cppui256,
            0x2454F58F77C785F1C04C47831F9309A96AE57266C4CF3A3AA95656860CAD2BEF_cppui256,
            0x0DE7FB73EB7916CF2459DD7C65EE6DC80E3CECA9AC3E4A10E63C61EA025398E5_cppui256
        };

    typename BlueprintFieldType::value_type eval1_z = 0x2DEFB3CFB41140464BF709B147777123731468F528CF8F14C032CA136A477469_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x11039196D240AC7CC0D1A88749F716B6B025F6BCA2CBBD0B41D2DA46FCC90558_cppui256,
        0x022CE995D1CA16666888BED84A062994F864C180A393E76F3C2D14786D3FF82E_cppui256,
        0x3B4C505BF9C0962541FA4597D037BF217AF2B2CD893239A05FC64E8674967F83_cppui256,
        0x02F194EC301411C828DAC6A83F90299F99441F0EDEAB5A2D0700C32553C5A10B_cppui256,
        0x2AA071813813CCB09C5C6F5BB6E3F6BEDA421DC5E30A71518BCB05AFDFB4DDA9_cppui256,
        0x3F82F6EF12DD276FAF8BC01CE8477BC9AF5B81D28586B8EF56CB0E025FA97276_cppui256
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    typename BlueprintFieldType::value_type alpha_val =
        0x220B73274823F8B0E46273FA8546B238F1E58529E061A811AB584A97C146AF87_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000AD39D811EFCE0FAD50EC0E161A0EF76E_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256;

    typename BlueprintFieldType::value_type omega_val =
        0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    std::size_t domain_size = 32;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    var joint_combiner = zero;

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_lookup_chacha) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 8192;
    constexpr static std::size_t eval_rounds = 0;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 8192;
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_chacha_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Pow(24);VanishesOnLast4Rows;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: LookupAggreg, row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Gamma;JointCombiner;Pow(3);Literal 0000000000000000000000000000000000000000000000000000000000000000;Mul;Add;Gamma;JointCombiner;Pow(3);Literal 0000000000000000000000000000000000000000000000000000000000000000;Mul;Add;Mul;Gamma;JointCombiner;Pow(3);Literal 0000000000000000000000000000000000000000000000000000000000000000;Mul;Add;Mul;Gamma;JointCombiner;Pow(3);Literal 0000000000000000000000000000000000000000000000000000000000000000;Mul;Add;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Beta;Add;Pow(4);Mul;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Beta;Add;Pow(4);Gamma;JointCombiner;JointCombiner;Cell(Variable { col: Witness(11), row: Curr });Mul;Cell(Variable { col: Witness(7), row: Curr });Add;Mul;Cell(Variable { col: Witness(3), row: Curr });Add;Add;Mul;Gamma;JointCombiner;JointCombiner;Cell(Variable { col: Witness(12), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Add;Mul;Cell(Variable { col: Witness(4), row: Curr });Add;Add;Mul;Gamma;JointCombiner;JointCombiner;Cell(Variable { col: Witness(13), row: Curr });Mul;Cell(Variable { col: Witness(9), row: Curr });Add;Mul;Cell(Variable { col: Witness(5), row: Curr });Add;Add;Mul;Gamma;JointCombiner;JointCombiner;Cell(Variable { col: Witness(14), row: Curr });Mul;Cell(Variable { col: Witness(10), row: Curr });Add;Mul;Cell(Variable { col: Witness(6), row: Curr });Add;Add;Mul;Add;Gamma;Beta;Literal 0000000000000000000000000000000000000000000000000000000000000001;Add;Mul;Cell(Variable { col: LookupTable, row: Curr });Add;Beta;Cell(Variable { col: LookupTable, row: Next });Mul;Add;Mul;Mul;Mul;Mul;Mul;\0";

    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega_val =
        0x03B402C2CBD0A0660626F1948867533CFD2A80ABD33D0E808075A3EFC92D52D2_cppui256;
    std::size_t domain_size = 8192;

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_chacha();

    typename BlueprintFieldType::value_type joint_combiner_val = 
        0x20E959472C74FBEA783D62870B979033E1BD490EDF01DD51D69F4C89B52DAA3B_cppui256;
    typename BlueprintFieldType::value_type beta_val = 0x000000000000000000000000000000001FE90F184CF0D23228FC49E7F4BDF537_cppui256;
    typename BlueprintFieldType::value_type gamma_val = 0x00000000000000000000000000000000ADE5F3B85395C4FCA12723C1322622EF_cppui256;
    typename BlueprintFieldType::value_type alpha_val =
        0x32A5FB8A849C5CFC39656701462421AA5A9C88FCC7D7C342063D66486096D8ED_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x24A32849C8B99B6CB2D1A514C0EC7B5F5A15799EA2428C6DCA8B332CEACE9DC0_cppui256;
    typename BlueprintFieldType::value_type fq_digest_val =
        0x2C85FCC264A1C8E1082E97E5686196CB1A7EF642F7B162EB21723CCCB6344341_cppui256;

    typename BlueprintFieldType::value_type expected_result = 0x171D8F459023B125DC92B64C54190124CA4390C701160D8DA6F34192B1B6E1A0_cppui256;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, proof.proof_evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()