//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_keccak_test

#include <array>
#include <cstdlib>
#include <ctime>
#include <random>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_padding.hpp>

#include "../../test_plonk_component.hpp"

template<typename BlueprintFieldType>
std::size_t number_bits(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    integral_type integral_value = integral_type(value.data);
    std::size_t result = 0;
    while (integral_value > 0) {
        integral_value >>= 1;
        ++result;
    }
    return result;
}

template<typename BlueprintFieldType>
std::vector<typename BlueprintFieldType::value_type> padding_function(std::vector<typename BlueprintFieldType::value_type> message, 
                                                                    std::size_t num_bits) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::vector<value_type> result;
    std::size_t shift = 64 * message.size() - num_bits;
    std::cout << "shift: " << shift << ' ' << num_bits << std::endl;

    if (shift > 0) {
        integral_type relay_value = integral_type(message[0].data);
        for (int i = 1; i < message.size(); ++i) {
            integral_type mask = (integral_type(1) << (64-shift)) - 1;
            integral_type left_part = integral_type(message[i].data >> (64-shift));
            integral_type right_part = integral_type(message[i].data) & mask;
            result.push_back(value_type((relay_value << shift) + left_part));
            relay_value = right_part;
        }
        result.push_back(value_type(relay_value << shift));
    } else {
        for (int i = 0; i < message.size(); ++i) {
            result.push_back(message[i]);
        }
    }
    while (result.size() % 17 != 0) {
        result.push_back(value_type(0));
    }
    return result;
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns>
auto test_keccak_padding_inner(std::vector<typename BlueprintFieldType::value_type> message,
                               std::vector<typename BlueprintFieldType::value_type> expected_result,
                               const std::size_t num_blocks, const std::size_t num_bits) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using component_type = nil::blueprint::components::keccak_padding<ArithmetizationType, WitnessesAmount>;
    using var = typename component_type::var;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    // std::cout << "message:\n";
    for (int i = 0; i < num_blocks; ++i) {
        public_input.push_back(message[i]);
        // std::cout << message[i].data << std::endl;
    }

    std::vector<var> message_vars;
    for (int i = 0; i < num_blocks; ++i) {
        message_vars.push_back(var(0, i, false, var::column_type::public_input));
    }
    typename component_type::input_type instance_input = {message_vars};

    auto result_check = [expected_result]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        // std::cout << "sizes: " << expected_result.size() << " " << real_res.padded_message.size() << std::endl;
        assert(expected_result.size() == real_res.padded_message.size());
        for (int i = 0; i < real_res.padded_message.size(); ++i) {
            // std::cout << "res:\n" << expected_result[i].data << "\n" << var_value(assignment, real_res.padded_message[i]).data << std::endl;
            assert(expected_result[i] == var_value(assignment, real_res.padded_message[i]));
        }
    };

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0},
                                                           {1}, LookupRows, LookupColumns, num_blocks, num_bits, 7)
                                            : component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {1},
                                                            LookupRows, LookupColumns, num_blocks, num_bits, 7);

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        boost::get<component_type>(component_instance), public_input, result_check, instance_input);
}

// works
template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns>
void test_keccak_padding_0() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::vector<value_type> message = {0};
    const std::size_t num_blocks = 1;
    const std::size_t num_bits = 1;

    std::vector<value_type> expected_result = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    test_keccak_padding_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>
                            (message, expected_result, num_blocks, num_bits);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns>
void test_keccak_padding_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    integral_type mask = (integral_type(1) << 64) - 1;
    integral_type mask_zero = (integral_type(1) << 60) - 1;
    std::vector<value_type> message = {value_type(integral_type(dis(gen)) & mask_zero),
                                        value_type(integral_type(dis(gen)) & mask_zero)};
    std::size_t num_bits = 64 * (message.size() - 1) + number_bits<BlueprintFieldType>(message[0]);
    std::size_t num_blocks = message.size();

    for (int i = 0; i < message.size(); ++i) {
        std::cout << "message: " << message[i].data << std::endl;
    }
    
    auto expected_result = padding_function<BlueprintFieldType>(message, num_bits);

    test_keccak_padding_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>
                            (message, expected_result, num_blocks, num_bits);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    // test_keccak_round_random<field_type, 9, 65536, 10>();
    // test_keccak_padding_random<field_type, 9, 65536, 10>();
    test_keccak_padding_random<field_type, 15, 65536, 10>();
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas_15) {
//     using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
// }

BOOST_AUTO_TEST_SUITE_END()
