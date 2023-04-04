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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_scalar_details_batch_dlog_accumulator_check_scalar_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/batch_dlog_accumulator_check_scalar.hpp>
#include "test_plonk_component.hpp"

#include <algorithm>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_pickles_base_details_batch_dlog_accumulator_check_base_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_base_details_batch_dlog_accumulator_check_base_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    using value_type = typename BlueprintFieldType::value_type;
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
    constexpr static std::size_t max_poly_size = 4;
    constexpr static std::size_t eval_rounds = 4;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 2;
    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t prev_chal_size = 1;

    constexpr static const std::size_t max_state_size = 3;
    constexpr static const std::size_t bulletproofs_size = 3;
    constexpr static const std::size_t challenge_polynomial_commitments_size = batch_size;

    constexpr const std::size_t comms_len = 4;
    constexpr const std::size_t urs_size = 1 << eval_rounds;

    using component_type =
        zk::components::batch_dlog_accumulator_check_scalar<
            ArithmetizationType, curve_type, comms_len, eval_rounds,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    typename component_type::params_type params;

    std::array<std::array<value_type, eval_rounds>, comms_len> challenges;
    for (std::size_t i = 0 ; i < comms_len; i++) {
        for (std::size_t j = 0; j < eval_rounds; j++) {
            params.challenges[i][j] = var(0, public_input.size(), false, var::column_type::public_input);
            challenges[i][j] = algebra::random_element<BlueprintFieldType>();
            public_input.push_back(challenges[i][j]);
        }
    }
    params.rand_base = var(0, public_input.size(), false, var::column_type::public_input);
    value_type rand_base = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(rand_base);
    assert(public_input.size() == eval_rounds * comms_len + 1);

    std::array<value_type, component_type::output_len> expected_result;
    std::fill(expected_result.begin(), expected_result.end(), 0);

    std::array<value_type, comms_len> rs;
    rs[0] = 1;
    rs[1] = rand_base;
    for (std::size_t i = 2; i < comms_len; i++) {
        rs[i] = rs[i - 1] * rs[1];
    }

    std::array<std::array<value_type, urs_size>, comms_len> termss;

    for (std::size_t i = 0; i < comms_len; i++) {
        std::array<value_type, urs_size> b_poly_coefficients;
        std::fill(b_poly_coefficients.begin(), b_poly_coefficients.end(), 1);
        std::size_t k = 0;
        std::size_t pow = 1;
        for (std::size_t j = 1; j < urs_size; j++) {
            k += j == pow ? 1 : 0;
            pow <<= j == pow ? 1 : 0;
            b_poly_coefficients[j] = b_poly_coefficients[j - (pow >> 1)] * (1 / challenges[i][eval_rounds - k]);
        }
        for (std::size_t j = 0; j < urs_size; j++) {
            termss[i][j] = rs[i] * b_poly_coefficients[j];
            expected_result[j] -= termss[i][j];
        }
    }

    for (std::size_t i = urs_size; i < component_type::output_len; i++) {
        expected_result[i] = rs[i - urs_size];
    }

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < component_type::output_len; i++) {
            assert(assignment.var_value(real_res.output[i]) == expected_result[i]);
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()