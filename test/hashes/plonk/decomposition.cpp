//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE plonk_decomposition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/decomposition.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_decomposition(std::vector<typename BlueprintFieldType::value_type> public_input,
                        std::vector<typename BlueprintFieldType::value_type> expected_res,
                        const bool expected_to_pass) {

    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 8;
    constexpr std::size_t SelectorColumns = 3;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using component_type = blueprint::components::decomposition<ArithmetizationType, BlueprintFieldType>;

    //check computation
    auto output = component_type::calculate({public_input[0], public_input[1]});
    for (std::size_t i = 0; i < output.size(); i++){
        assert(expected_res[i] == output[i]);
    }

    std::array<var, 2> input_state_var = {var(0, 0, false, var::column_type::public_input),
                                          var(0, 1, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {input_state_var};

    auto result_check = [&expected_res](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            // for (std::size_t i = 0; i < real_res.output.size(); i++){
            //     std::cout << var_value(assignment, real_res.output[i]).data << std::endl;
            // }
            // for (std::size_t i = 0; i < expected_res.size(); i++){
            //     std::cout << expected_res[i].data << std::endl;
            // }
            for (std::size_t i = 0; i < real_res.output.size(); i++){
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };
    auto result_check_to_fail = [](AssignmentType &assignment,
        typename component_type::result_type &real_res) {};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

    if (expected_to_pass) {
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::WEAK);
    } else {
        crypto3::test_component_to_fail<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check_to_fail, instance_input,
        nil::blueprint::connectedness_check_type::type::WEAK);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

template<typename FieldType>
std::vector<typename FieldType::value_type> calculate_decomposition(
        const std::vector<typename FieldType::value_type> &data_value) {

    std::array<typename FieldType::integral_type, 2> data = {
        typename FieldType::integral_type(data_value[0].data),
        typename FieldType::integral_type(data_value[1].data)};
    std::size_t shift = 0;
    std::array<typename FieldType::integral_type, 8> output;
    const typename FieldType::integral_type one = 1;

    for (std::size_t i = 0; i < 4; i++, shift += 32) {
        output[i + 4] = (data[0] >> shift) & ((one << 32) - 1);
        output[i] = (data[1] >> shift) & ((one << 32) - 1);
    }

    std::vector<typename FieldType::value_type> output_value(output.size());

    for (std::size_t i = 0; i < output.size(); i++){
        output_value[output.size() - 1 - i] = typename FieldType::value_type(output[i]);
    }
    return output_value;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_decomposition_test0) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    test_decomposition<field_type>(
        {0x1_cppui255, 0x2_cppui255},
        calculate_decomposition<field_type>({0x1_cppui255, 0x2_cppui255}),
        true);

    test_decomposition<field_type>(
        {0x8d741211e928fdd4d33a13970d0ce7f3_cppui255, 0x92f209334030f9ec8fa8a025e987a5dd_cppui255},
        calculate_decomposition<field_type>({0x8d741211e928fdd4d33a13970d0ce7f3_cppui255, 0x92f209334030f9ec8fa8a025e987a5dd_cppui255}),
        true);

    test_decomposition<field_type>(
        {0, 0},
        calculate_decomposition<field_type>({0, 0}),
        true);

    test_decomposition<field_type>(
        {0xffffffffffffffffffffffffffffffff_cppui255, 0xffffffffffffffffffffffffffffffff_cppui255},
        calculate_decomposition<field_type>({0xffffffffffffffffffffffffffffffff_cppui255, 0xffffffffffffffffffffffffffffffff_cppui255}),
        true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_decomposition_must_fail) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    typename field_type::value_type bad = 0x100000000000000000000000000000000_cppui255;

    test_decomposition<field_type>(
        {0, bad},
        calculate_decomposition<field_type>({0, bad}),
        false);

    test_decomposition<field_type>(
        {bad, 0},
        calculate_decomposition<field_type>({bad, 0}),
        false);

        bad = 0x4000000000000000000000000000000000000000000000000000000000000000_cppui255;

    test_decomposition<field_type>(
        {0, bad},
        calculate_decomposition<field_type>({0, bad}),
        false);

    test_decomposition<field_type>(
        {bad, 0},
        calculate_decomposition<field_type>({bad, 0}),
        false);
}

BOOST_AUTO_TEST_SUITE_END()