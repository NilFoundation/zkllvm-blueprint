//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_bit_decomposition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_modes.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

using mode = blueprint::components::bit_composition_mode;
using nil::blueprint::components::detail::bit_builder_component_constants_required;

template <typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode>
void test_bit_decomposition(std::vector<typename BlueprintFieldType::value_type> public_input,
        std::vector<typename BlueprintFieldType::value_type> expected_res){

    constexpr std::size_t WitnessColumns = WitnessesAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = bit_builder_component_constants_required(WitnessesAmount, BitsAmount);
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::bit_decomposition<
        ArithmetizationType, WitnessesAmount, BitsAmount, Mode>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "input: " << std::hex << public_input[0].data << "\n";
            for (std::size_t i = 0; i < expected_res.size(); i++){
                std::cout << expected_res[i].data;
            }
            std::cout << std::endl;

            for (std::size_t i = 0; i < real_res.output.size(); i++){
                std::cout << var_value(assignment, real_res.output[i]).data;
            }
            std::cout << std::endl;
            #endif

            for (std::size_t i = 0; i < real_res.output.size(); i++) {
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };

    if (WitnessesAmount == 9) {
        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    } else if (WitnessesAmount == 15) {
        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {});

        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

constexpr static const std::size_t random_tests_amount = 10;

template<typename FieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode>
void calculate_expected_and_test_bit_decomposition(typename FieldType::value_type input) {

    typename FieldType::integral_type input_integral = 1;
    typename FieldType::integral_type max = BitsAmount < FieldType::modulus_bits ?
                                             (input_integral << BitsAmount) - 1
                                            : 0;

    input_integral = typename FieldType::integral_type(input.data);
    if (max != 0) {
        input_integral = input_integral % max;
    }

    std::vector <typename FieldType::value_type> expected_res =
        std::vector <typename FieldType::value_type>(BitsAmount);
    for (std::size_t i = 0; i < BitsAmount; i++) {
        expected_res[Mode == blueprint::components::bit_composition_mode::MSB ? BitsAmount - i - 1 : i] =
            ((input_integral >> i) & 0b1) == 1 ? FieldType::value_type::one() : FieldType::value_type::zero();
    }
    input = typename FieldType::value_type(input_integral);
    test_bit_decomposition<FieldType, WitnessesAmount, BitsAmount, Mode>({input}, expected_res);
}

template<std::uint32_t WitnessesAmount, std::uint32_t BitsAmount>
void test_decomposition() {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    const mode msb = blueprint::components::bit_composition_mode::MSB;
    const mode lsb = blueprint::components::bit_composition_mode::LSB;

    auto max_elem = []() {
        return BitsAmount < field_type::modulus_bits ?
               (typename field_type::integral_type(1) << BitsAmount) - 1
              : field_type::modulus;
    };

    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, msb>(1);
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, msb>(0);
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, msb>(45524);
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, msb>(max_elem());
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, lsb>(1);
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, lsb>(0);
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, lsb>(45524);
    calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, lsb>(max_elem());

    using generator_type = nil::crypto3::random::algebraic_engine<field_type>;
    generator_type rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    for (std::size_t j = 0; j < random_tests_amount; j++) {
        field_type::value_type random = rand();
        calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, msb>(random);
        calculate_expected_and_test_bit_decomposition<field_type, WitnessesAmount, BitsAmount, lsb>(random);
    }
}


BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_8) {
    test_decomposition<15, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_16) {
    test_decomposition<15, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_32) {
    test_decomposition<15, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_64) {
    test_decomposition<15, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_128) {
    test_decomposition<15, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_253) {
    test_decomposition<15, 253>();
}


BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_8) {
    test_decomposition<9, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_16) {
    test_decomposition<9, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_32) {
    test_decomposition<9, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_64) {
    test_decomposition<9, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_128) {
    test_decomposition<9, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_253) {
    test_decomposition<9, 253>();
}

BOOST_AUTO_TEST_SUITE_END()