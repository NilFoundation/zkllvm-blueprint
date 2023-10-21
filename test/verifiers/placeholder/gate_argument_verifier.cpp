//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estonia@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_gate_argument_verifier_test

#include <set>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/gate_argument_verifier.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::size_t WitnessAmount>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          typename BlueprintFieldType::value_type &expected_res, std::vector<std::size_t> signature) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2 * WitnessAmount + 1 + 3;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::basic_constraints_verifier<ArithmetizationType>;

    std::size_t m = signature.size();

    std::vector<std::size_t>::iterator min_degree = std::min_element(signature.begin(), signature.end());

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                      signature);

    std::vector<var> gates;
    std::vector<var> selectors;
    std::size_t ctr = 0;
    var theta = var(0, ctr++, false, var::column_type::public_input);
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < signature[i]; j++) {
            gates.push_back(var(0, ctr++, false, var::column_type::public_input));
        }
        selectors.push_back(var(0, ctr++, false, var::column_type::public_input));
    }
    typename component_type::input_type instance_input = {theta, gates, selectors};

    auto result_check = [expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        std::cout << "F: 0x" << std::hex << var_value(assignment, real_res.output).data << std::endl;
        assert(var_value(assignment, real_res.output) == expected_res);
        // std::cout << "expected F: " << expected_res.data << std::endl;
    };
    if (*min_degree == 1) {
        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input,
            nil::crypto3::detail::connectedness_check_type::NONE, signature);
    } else {
        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input,
            nil::crypto3::detail::connectedness_check_type::STRONG, signature);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test0) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,      // theta
        0x854a9d175f7eece4dd7bb82babe799b2369571e75d2386264b512bc4f049ee6_cppui255,      // C_1_0
        0x25815c120bb2f1c57d7e4d505fb7b901a9e4c4f92b623ddfb3546ecc33482c37_cppui255,     // q_1
        0x38e1a856aae5cf012d142449cfe878b1a827f08fec4ac2d1724b7ebf37d3a637_cppui255,     // C_2_0
        0x393d97b04bc5d4490ae53903974c1d0aa65e11b4e9ae487a1d3aede2f6edec92_cppui255};    // q_2

    typename BlueprintFieldType::value_type expected_res =
        0x1272cd18bbf5cc452e221febe8a6ead95cd8f36cc3f6d5776f3e565fc464171d_cppui255;    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, {1, 1});
    test<BlueprintFieldType, 5>(public_input, expected_res, {1, 1});
    test<BlueprintFieldType, 6>(public_input, expected_res, {1, 1});
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test1) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x107af4ffd5e6a759be7c279d5eac2d5e893a89d703e52a3184b2331d3acbdfc1_cppui255,    // theta
        0x815ea6af6ba30435bfe42b04942a42354b7ac5bcb970d2c7fd29600afba4c76_cppui255,     // C_3_0
        0xca85be77a54d63ae5d08aa369c21df7cc559803fa92d44cf06ad801165ba0eb_cppui255,     // C_3_1
        0x11ee26b867cf7bce6b41152282cadb4bf8044b9e2722acf91c8fa01fa634bafb_cppui255,    // C_3_2
        0x32df974641fa733bfafde92e7f86e0f967af2744d6b1d239530419921f8460be_cppui255,    // q_3
        0x2c3c7fd7ad540677c20238e931ab15eec3f30b0d19c0465dcbb2c79500f52959_cppui255,    // C_1_0
        0x39d9d3ce89500f9bbaeefb254fff8d0c25c17cebe2a1c4586630b3c168622e8c_cppui255,    // q_1
        0x37fb8feeafe97cc91109beeda57125d20266990bbbeff2d0f206e51fa447d72_cppui255,     // C_2_0
        0x2b673c52209b43e4735ecb7fe0ba59f4b5cce80ccc1643f56a067ecbbeeba8c3_cppui255     // q_2
    };

    typename BlueprintFieldType::value_type expected_res =
        0xf335699d7ec4a77dda90354e42f908f80fccd1f32c367ed493bd8610993986d_cppui255;    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, {3, 1, 1});
    test<BlueprintFieldType, 5>(public_input, expected_res, {3, 1, 1});
    test<BlueprintFieldType, 6>(public_input, expected_res, {3, 1, 1});
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test2) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x107af4ffd5e6a759be7c279d5eac2d5e893a89d703e52a3184b2331d3acbdfc1_cppui255,    // theta
        0x2c3c7fd7ad540677c20238e931ab15eec3f30b0d19c0465dcbb2c79500f52959_cppui255,    // C_1_0
        0x39d9d3ce89500f9bbaeefb254fff8d0c25c17cebe2a1c4586630b3c168622e8c_cppui255,    // q_1
        0x37fb8feeafe97cc91109beeda57125d20266990bbbeff2d0f206e51fa447d72_cppui255,     // C_2_0
        0x2b673c52209b43e4735ecb7fe0ba59f4b5cce80ccc1643f56a067ecbbeeba8c3_cppui255,    // q_2
        0x815ea6af6ba30435bfe42b04942a42354b7ac5bcb970d2c7fd29600afba4c76_cppui255,     // C_3_0
        0xca85be77a54d63ae5d08aa369c21df7cc559803fa92d44cf06ad801165ba0eb_cppui255,     // C_3_1
        0x11ee26b867cf7bce6b41152282cadb4bf8044b9e2722acf91c8fa01fa634bafb_cppui255,    // C_3_2
        0x32df974641fa733bfafde92e7f86e0f967af2744d6b1d239530419921f8460be_cppui255     // q_3
    };

    typename BlueprintFieldType::value_type expected_res =
        0xf335699d7ec4a77dda90354e42f908f80fccd1f32c367ed493bd8610993986d_cppui255;    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, {1, 1, 3});
    test<BlueprintFieldType, 5>(public_input, expected_res, {1, 1, 3});
    test<BlueprintFieldType, 6>(public_input, expected_res, {1, 1, 3});
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test3) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x107af4ffd5e6a759be7c279d5eac2d5e893a89d703e52a3184b2331d3acbdfc1_cppui255,    // theta
        0x2c3c7fd7ad540677c20238e931ab15eec3f30b0d19c0465dcbb2c79500f52959_cppui255,    // C_1_0
        0x39d9d3ce89500f9bbaeefb254fff8d0c25c17cebe2a1c4586630b3c168622e8c_cppui255,    // q_1
        0x815ea6af6ba30435bfe42b04942a42354b7ac5bcb970d2c7fd29600afba4c76_cppui255,     // C_3_0
        0xca85be77a54d63ae5d08aa369c21df7cc559803fa92d44cf06ad801165ba0eb_cppui255,     // C_3_1
        0x11ee26b867cf7bce6b41152282cadb4bf8044b9e2722acf91c8fa01fa634bafb_cppui255,    // C_3_2
        0x32df974641fa733bfafde92e7f86e0f967af2744d6b1d239530419921f8460be_cppui255,    // q_3
        0x37fb8feeafe97cc91109beeda57125d20266990bbbeff2d0f206e51fa447d72_cppui255,     // C_2_0
        0x2b673c52209b43e4735ecb7fe0ba59f4b5cce80ccc1643f56a067ecbbeeba8c3_cppui255     // q_2
    };

    typename BlueprintFieldType::value_type expected_res =
        0xf335699d7ec4a77dda90354e42f908f80fccd1f32c367ed493bd8610993986d_cppui255;    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, {1, 3, 1});
    test<BlueprintFieldType, 5>(public_input, expected_res, {1, 3, 1});
    test<BlueprintFieldType, 6>(public_input, expected_res, {1, 3, 1});
}

BOOST_AUTO_TEST_SUITE_END()
