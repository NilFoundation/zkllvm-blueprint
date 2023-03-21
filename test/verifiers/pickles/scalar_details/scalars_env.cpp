//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_pickles_scalars_env_test

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
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/scalars_env.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_pickles_scalars_env) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
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

    constexpr static std::size_t srs_len = 10;
    constexpr static std::size_t perm_size = 7;

    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description =
        zk::components::kimchi_circuit_description<index_terms_list, WitnessColumns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type = zk::components::scalars_env<ArithmetizationType, kimchi_params, 
                                                       0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type group_gen = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type alpha = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type beta = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type gamma = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type zeta = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type joint_combiner = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type srs_length_log2 = algebra::random_element<BlueprintFieldType>();
    std::size_t domain_size_log2 = 8;
    std::size_t domain_size = 1 << domain_size_log2;
    typename BlueprintFieldType::value_type group_gen_pow = group_gen.pow(domain_size - 3);
    typename BlueprintFieldType::value_type expected_poly = (zeta - group_gen_pow) * (zeta - group_gen_pow * group_gen) * 
                                                            (zeta - group_gen_pow * group_gen * group_gen);

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        // plonk
        alpha,
        beta,
        gamma,
        zeta,
        joint_combiner,
        srs_length_log2, group_gen};

    typename component_type::params_type params = {
        {
            var(0, 0, false, var::column_type::public_input),
            var(0, 1, false, var::column_type::public_input),
            var(0, 2, false, var::column_type::public_input),
            var(0, 3, false, var::column_type::public_input),
            var(0, 4, false, var::column_type::public_input)
        },
        var(0, 5, false, var::column_type::public_input), var(0, 6, false, var::column_type::public_input),
        domain_size_log2
    };

    std::vector<typename BlueprintFieldType::value_type> expected_powers(kimchi_params::alpha_powers_n);
    typename BlueprintFieldType::value_type last_value = alpha;
    if (expected_powers.size() > 0) {
        expected_powers[0] = 1;
    }
    if (expected_powers.size() > 1) {
        expected_powers[1] = alpha;
    }
    for (std::size_t i = 2; i < kimchi_params::alpha_powers_n; i++) {
        last_value = last_value * alpha;
        expected_powers[i] = last_value;
    }

    typename BlueprintFieldType::value_type two = 2;
    typename BlueprintFieldType::value_type expected_zeta_to_n_minus_1 = power(zeta, domain_size) - 1;

    auto result_check = [&expected_powers, &srs_length_log2, &group_gen, 
                         &expected_zeta_to_n_minus_1, &expected_poly,
                         domain_size](AssignmentType &assignment,
        component_type::result_type &real_res) {

        assert(expected_zeta_to_n_minus_1 == assignment.var_value(real_res.output.zeta_to_n_minus_1));
        assert(srs_length_log2 == assignment.var_value(real_res.output.srs_length_log2));
        assert(expected_poly == assignment.var_value(real_res.output.zk_polynomial));
        assert(group_gen == assignment.var_value(real_res.output.domain_generator));
        assert(domain_size == real_res.output.domain_size);
        for (std::size_t i = 0; i < kimchi_params::alpha_powers_n; i++) {
            assert(expected_powers[i] == assignment.var_value(real_res.output.alphas[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "scalars_env: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

