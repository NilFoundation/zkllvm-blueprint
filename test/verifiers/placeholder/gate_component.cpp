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

#define BOOST_TEST_MODULE plonk_gate_compoent_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/gate_component.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::uint32_t WitnessAmount>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          typename BlueprintFieldType::value_type &expected_res) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2 * WitnessAmount + 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::detail::gate_component<ArithmetizationType>;

    std::size_t m = public_input.size() - 3;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), m);

    std::vector<std::vector<var>> gates;
    std::vector<var> selectors;
    std::size_t ctr = 0;
    var theta = var(0, ctr++, false, var::column_type::public_input);
    std::vector<var> constraints;
    for (int i = 0; i <= m; i++) {
        constraints.push_back(var(0, ctr++, false, var::column_type::public_input));
    }
    var selector = var(0, ctr++, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {theta, constraints, selector};

    auto result_check = [expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        std::cout << "F: 0x" << std::hex << var_value(assignment, real_res.output).data << std::endl;
        assert(var_value(assignment, real_res.output) == expected_res);
    };

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input, m);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test1) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,      // theta
        0x38e1a856aae5cf012d142449cfe878b1a827f08fec4ac2d1724b7ebf37d3a637_cppui255,     // c0
        0x854a9d175f7eece4dd7bb82babe799b2369571e75d2386264b512bc4f049ee6_cppui255,      // c1
        0x393d97b04bc5d4490ae53903974c1d0aa65e11b4e9ae487a1d3aede2f6edec92_cppui255};    // q

    typename BlueprintFieldType::value_type expected_res =
        0xf60c8e3799f676371137e184244aaf6859123322600128b05aed7e26223cfd1_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test2) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,      // theta
        0x38e1a856aae5cf012d142449cfe878b1a827f08fec4ac2d1724b7ebf37d3a637_cppui255,     // c0
        0x854a9d175f7eece4dd7bb82babe799b2369571e75d2386264b512bc4f049ee6_cppui255,      // c1
        0xf60c8e3799f676371137e184244aaf6859123322600128b05aed7e26223cfd1_cppui255,      // c2
        0x393d97b04bc5d4490ae53903974c1d0aa65e11b4e9ae487a1d3aede2f6edec92_cppui255};    // q

    typename BlueprintFieldType::value_type expected_res =
        0x1ab9e0ab4db80e2649fe1c44791b231a165329cb8e1cb3186fd42311dfb96ba7_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
    test<BlueprintFieldType, 8>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test3) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,      // theta
        0x38e1a856aae5cf012d142449cfe878b1a827f08fec4ac2d1724b7ebf37d3a637_cppui255,     // c0
        0x854a9d175f7eece4dd7bb82babe799b2369571e75d2386264b512bc4f049ee6_cppui255,      // c1
        0xf60c8e3799f676371137e184244aaf6859123322600128b05aed7e26223cfd1_cppui255,      // c2
        0x42d09cbf0dbb3ec8e566f3835b8c70cdc6ffb4ee160b7e974174cb84b656c94_cppui255,      // c3
        0x393d97b04bc5d4490ae53903974c1d0aa65e11b4e9ae487a1d3aede2f6edec92_cppui255};    // q

    typename BlueprintFieldType::value_type expected_res =
        0x1d8aaff35b7c1a8afe535c508bda43c907bc059ced7720df45cb83fcce35d632_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
    test<BlueprintFieldType, 8>(public_input, expected_res);
}


BOOST_AUTO_TEST_SUITE_END()