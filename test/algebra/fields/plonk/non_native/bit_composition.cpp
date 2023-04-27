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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_bit_composition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_modes.hpp>

#include <boost/random/mersenne_twister.hpp>

#include <numeric>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

using mode = blueprint::components::bit_composition_mode;
using nil::blueprint::components::detail::bit_builder_component_constants_required;

template <typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode>
void test_bit_composition(std::array<bool, BitsAmount> &bits,
                          typename BlueprintFieldType::value_type expected_res){

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

    using component_type = blueprint::components::bit_composition<ArithmetizationType, WitnessColumns,
                                                                  BitsAmount, Mode, true>;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    public_input.resize(BitsAmount);
    for (std::size_t i = 0; i < BitsAmount; i++) {
        public_input[i] = typename BlueprintFieldType::value_type(bits[i]);
    }

    typename component_type::input_type instance_input;
    for (std::size_t i = 0; i < BitsAmount; i++) {
        instance_input.bits[i] = var(0, i, false, var::column_type::public_input);
    }

    auto result_check = [&expected_res](AssignmentType &assignment,
                                        typename component_type::result_type &real_res) {
        //std::cout << "Expected: " << expected_res.data << std::endl;
        //std::cout << "Real: " << var_value(assignment, real_res.output).data << std::endl;
        assert(expected_res == var_value(assignment, real_res.output));
    };

    if (WitnessesAmount == 9) {
        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {0}, {});

        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    } else if (WitnessesAmount == 15) {
        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {0}, {});

        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

constexpr static const std::size_t random_tests_amount = 10;

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode>
void calculate_expected_and_test_bit_decomposition(std::array<bool, BitsAmount> &bits) {

    typename BlueprintFieldType::value_type composed = 0;
    auto accumulator = [](typename BlueprintFieldType::value_type acc, bool b) {
        return typename BlueprintFieldType::value_type(2 * acc + (b ? 1 : 0));
    };
    if (Mode == mode::LSB) {
        composed = std::accumulate(bits.rbegin(), bits.rend(), composed, accumulator);
    } else {
        composed = std::accumulate(bits.begin(), bits.end(), composed, accumulator);
    }

    test_bit_composition<BlueprintFieldType, WitnessesAmount, BitsAmount, Mode>(bits, composed);
}

template<typename BlueprintFieldType, std::uint32_t BitsAmount>
std::array<bool, BitsAmount> generate_random_bitstring(boost::random::mt19937 &rng) {
    std::array<bool, BitsAmount> res;
    for (std::size_t i = 0; i < BitsAmount; i++) {
        res[i] = rng() % 2;
    }
    return res;
}

template<std::uint32_t WitnesesAmount, std::uint32_t BitsAmount>
void test_composition() {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    boost::random::mt19937 rng;
    rng.seed(1337);

    std::array<bool, BitsAmount> test_bits;

    for (std::size_t i = 0; i < BitsAmount; i++) {
        test_bits[i] = 0;
    }
    calculate_expected_and_test_bit_decomposition<field_type, WitnesesAmount, BitsAmount, mode::MSB>(test_bits);
    calculate_expected_and_test_bit_decomposition<field_type, WitnesesAmount, BitsAmount, mode::LSB>(test_bits);

    for (std::size_t i = 0; i < BitsAmount; i++) {
        test_bits[i] = 1;
    }
    calculate_expected_and_test_bit_decomposition<field_type, WitnesesAmount, BitsAmount, mode::MSB>(test_bits);
    calculate_expected_and_test_bit_decomposition<field_type, WitnesesAmount, BitsAmount, mode::LSB>(test_bits);

    for (std::size_t j = 0; j < random_tests_amount; j++) {
        auto bits = generate_random_bitstring<field_type, BitsAmount>(rng);
        calculate_expected_and_test_bit_decomposition<field_type, WitnesesAmount, BitsAmount, mode::MSB>(bits);
        calculate_expected_and_test_bit_decomposition<field_type, WitnesesAmount, BitsAmount, mode::LSB>(bits);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_8) {
    test_composition<15, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_16) {
    test_composition<15, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_32) {
    test_composition<15, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_64) {
    test_composition<15, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_128) {
    test_composition<15, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_15_253) {
    test_composition<15, 253>();
}


BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_8) {
    test_composition<9, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_16) {
    test_composition<9, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_32) {
    test_composition<9, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_64) {
    test_composition<9, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_128) {
    test_composition<9, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_9_253) {
    test_composition<9, 253>();
}

BOOST_AUTO_TEST_SUITE_END()