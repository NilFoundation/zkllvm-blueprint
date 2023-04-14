//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_base_details_batch_dlog_accumulator_check_base_test

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
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/batch_dlog_accumulator_check_base.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_pickles_base_details_batch_dlog_accumulator_check_base_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_base_details_batch_dlog_accumulator_check_base_test) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using curve_point_type = typename curve_type::template g1_type<algebra::curves::coordinates::affine>;
    using curve_point = curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
    using base_value_type = typename curve_type::base_field_type::value_type;

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
    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 4;
    constexpr static std::size_t eval_rounds = 2;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 2;
    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t prev_chal_size = 1;

    constexpr static const std::size_t max_state_size = 3;
    constexpr static const std::size_t bulletproofs_size = 3;
    constexpr static const std::size_t challenge_polynomial_commitments_size = batch_size;

    constexpr const std::size_t num_points = 3;
    constexpr const std::size_t urs_len = 4;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::batch_dlog_accumulator_check_base<ArithmetizationType, curve_type, kimchi_params, num_points,
                                                          urs_len, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    using verifier_index_type = zk::components::kimchi_verifier_index_base<curve_type, kimchi_params>;

    using proof_type = zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    typename component_type::params_type params;

    std::array<curve_point, num_points> points;
    std::array<scalar_value_type, urs_len + num_points> scalars;

    for (std::size_t i = 0; i < num_points; i++) {
        points[i] = algebra::random_element<curve_point_type>();
        params.comms[i] = {
            var(0, public_input.size(), false, var::column_type::public_input),
            var(0, public_input.size() + 1, false, var::column_type::public_input)
        };
        public_input.push_back(points[i].X);
        public_input.push_back(points[i].Y);
    }

    scalar_value_type shift = 2;
    shift = shift.pow(255) + 1;
    for (std::size_t i = 0; i < scalars.size(); i++) {
        scalars[i] = algebra::random_element<scalar_field_type>();
        params.scalars[i] = var(0, public_input.size(), false, var::column_type::public_input);
        scalar_value_type b = (scalars[i] - shift) / 2;
        base_value_type scalar_base = multiprecision::uint256_t(b.data);

        public_input.push_back(scalar_base);
    }

    auto result_check = [&scalars, &points](AssignmentType &assignment, component_type::result_type &real_res) {
        curve_point expected_result;
        for (std::size_t i = 0; i < scalars.size(); i++) {
            scalar_value_type x = scalars[i];
            curve_point p;
            if (i < urs_len) {
                p.X = assignment.var_value(real_res.urs.g[i].X);
                p.Y = assignment.var_value(real_res.urs.g[i].Y);
            } else {
                p = points[i - urs_len];
            }
            typename curve_type::scalar_field_type::value_type shift = 2;
            expected_result = expected_result + x * p;
        }
        assert(expected_result.X == assignment.var_value(real_res._debug_msm_result.X));
        assert(expected_result.Y == assignment.var_value(real_res._debug_msm_result.Y));
    };

    // because we are randomly generating the data the test is 'guaranteed' to fail
    // we still require result_check to pass though
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check, false);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "base_scalar_mul: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()