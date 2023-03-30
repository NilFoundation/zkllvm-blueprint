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

#define BOOST_TEST_MODULE blueprint_cip_combine_test

#include <boost/test/unit_test.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/combine.hpp>

#include "test_plonk_component.hpp"

#include <iostream>
#include <limits>

using namespace nil::crypto3;

template<typename BlueprintFieldType, std::size_t N>
typename BlueprintFieldType::value_type b_poly(std::array<typename BlueprintFieldType::value_type, N> challenges_values,
                                               typename BlueprintFieldType::value_type zeta_value){
    std::vector<typename BlueprintFieldType::value_type> powers_twos;
    powers_twos.resize(N);
    powers_twos[0] = zeta_value;
    for (std::size_t i = 1; i < N; i++) {
        powers_twos[i] = powers_twos[i - 1] * powers_twos[i - 1];
    }

    typename BlueprintFieldType::value_type expected_result = 1;
    for (std::size_t i = 0; i < N; i++) {
        typename BlueprintFieldType::value_type term = 1 + challenges_values[i] * powers_twos[N - 1 - i];
        expected_result = expected_result * term;
    }

    return expected_result;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_cip_combine_test) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    using value_type = typename BlueprintFieldType::value_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 16;

    constexpr static std::size_t public_input_size = 1;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static const std::size_t eval_rounds = 1;
    constexpr static const std::size_t max_poly_size = 1;
    constexpr static const std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size,
            srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;

    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using evals_type = typename zk::components::proof_type<BlueprintFieldType, kimchi_params>::prev_evals_type;

    using proof_eval = zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;

    const std::size_t chal_amount = 4;
    using component_type = zk::components::combine<ArithmetizationType, curve_type, chal_amount, kimchi_params,
                                                   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename component_type::params_type params;
    std::vector<value_type> public_input = {};

    params.ft = var(0, public_input.size(), false, var::column_type::public_input);
    value_type ft = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(ft);

    params.pt = var(0, public_input.size(), false, var::column_type::public_input);
    value_type pt = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(pt);

    params.xi = var(0, public_input.size(), false, var::column_type::public_input);
    value_type xi = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(xi);

    const std::size_t eval_idx = 0;
    params.eval_idx = eval_idx;
    std::array<std::array<value_type, 16>, chal_amount> old_bulletproof_challenges;
    for (std::size_t i = 0; i < chal_amount; i++) {
        for (std::size_t j = 0; j < 16; j++) {
            params.old_bulletproof_challenges[i][j] =
                var(0, public_input.size(), false, var::column_type::public_input);
            old_bulletproof_challenges[i][j] = algebra::random_element<BlueprintFieldType>();
            public_input.push_back(old_bulletproof_challenges[i][j]);
        }
    }

    params.prev_evals.public_input[0] = var(0, public_input.size(), false, var::column_type::public_input);
    value_type prev_evals_public_input_0 = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(prev_evals_public_input_0);

    std::array<std::array<value_type, kimchi_params::witness_columns>, 2> w;
    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < kimchi_params::witness_columns; j++) {
            params.prev_evals.evals[eval_idx][i].w[j] =
                var(0, public_input.size(), false, var::column_type::public_input);
            w[i][j] = algebra::random_element<BlueprintFieldType>();
            public_input.push_back(w[i][j]);
        }
    }

    std::array<std::array<value_type, kimchi_params::permut_size - 1>, 2> s;
    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < kimchi_params::permut_size - 1; j++) {
            params.prev_evals.evals[eval_idx][i].s[j] =
                var(0, public_input.size(), false, var::column_type::public_input);
            s[i][j] = algebra::random_element<BlueprintFieldType>();
            public_input.push_back(s[i][j]);
        }
    }

    std::array<value_type, 2> z;
    for (std::size_t i = 0; i < 2; i++) {
        params.prev_evals.evals[eval_idx][i].z =
            var(0, public_input.size(), false, var::column_type::public_input);
        z[i] = algebra::random_element<BlueprintFieldType>();
        public_input.push_back(z[i]);
    }

    std::array<value_type, 2> generic_selector;
    for (std::size_t i = 0; i < 2; i++) {
        params.prev_evals.evals[eval_idx][i].generic_selector =
            var(0, public_input.size(), false, var::column_type::public_input);
        generic_selector[i] = algebra::random_element<BlueprintFieldType>();
        public_input.push_back(generic_selector[i]);
    }

    std::array<value_type, 2> poseidon_selector;
    for (std::size_t i = 0; i < 2; i++) {
        params.prev_evals.evals[eval_idx][i].poseidon_selector =
            var(0, public_input.size(), false, var::column_type::public_input);
        poseidon_selector[i] = algebra::random_element<BlueprintFieldType>();
        public_input.push_back(poseidon_selector[i]);
    }
    // TODO: lookup test

    std::array<value_type, chal_amount> chal_polys;
    for (std::size_t i = 0; i < chal_amount; i++) {
        chal_polys[i] = b_poly<BlueprintFieldType, 16>(old_bulletproof_challenges[i], pt);
    }

    std::array<value_type, component_type::items_size> items;
    std::copy(chal_polys.begin(), chal_polys.end(), items.begin());
    std::size_t idx = chal_amount;
    items[idx] = prev_evals_public_input_0;
    idx++;
    items[idx] = ft;
    idx++;
    for (std::size_t j = 0; j < kimchi_params::split_size; j++) {
        items[idx] = z[j];
        idx++;
    }
    for (std::size_t j = 0; j < kimchi_params::split_size; j++) {
        items[idx] = generic_selector[j];
        idx++;
    }
    for (std::size_t j = 0; j < kimchi_params::split_size; j++) {
        items[idx] = poseidon_selector[j];
        idx++;
    }
    for (std::size_t i = 0; i < kimchi_params::witness_columns; i++) {
        for (std::size_t j = 0; j < kimchi_params::split_size; j++) {
            items[idx] = w[j][i];
            idx++;
        }
    }
    for (std::size_t i = 0; i < kimchi_params::permut_size - 1; i++) {
        for (std::size_t j = 0; j < kimchi_params::split_size; j++) {
            items[idx] = s[j][i];
            idx++;
        }
    }

    value_type expected_result = items.back();
    for (std::size_t i = items.size() - 2; i != std::numeric_limits<size_t>::max(); i--) {
        expected_result *= xi;
        expected_result += items[i];
    }

    assert(idx == component_type::items_size);

    auto result_check = [expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "combine: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
