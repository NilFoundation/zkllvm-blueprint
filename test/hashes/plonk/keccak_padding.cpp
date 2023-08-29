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

template<typename BlueprintFieldType, std::size_t num_bits>
std::vector<typename BlueprintFieldType::value_type> padding_function(std::vector<typename BlueprintFieldType::value_type> message) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::vector<value_type> result;
    std::size_t shift = 64 * message.size() - num_bits

    if (shift > 0) {
        integral_type relay_value = message[0];
        for (int i = 1; i < message.size(); ++i) {
            integral_type mask = (integral_type(1) << shift) - 1;
            integral_type left_part = message[i].data >> shift;
            integral_type right_part = message[i].data & mask;
            result.push_back(value_type((relay_value << (64 - shift)) | left_part));
            relay_value = right_part;
        }
        result.push_back(value_type(relay_value << (64 - shift)));
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
         std::size_t LookupColumns, std::size_t num_blocks, std::size_t first_bits>
auto test_keccak_padding_inner(std::vector<typename BlueprintFieldType::value_type> message,
                               std::vector<typename BlueprintFieldType::value_type> expected_result) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 150;
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

    auto mes_size = message.size();

    std::vector<typename BlueprintFieldType::value_type> public_input;
    // std::cout << "message:\n";
    for (int i = 0; i < mes_size; ++i) {
        public_input.push_back(message[i]);
        // std::cout << message[i].data << std::endl;
    }
    public_input.push_back(first_bits);
    // std::cout << "first_bits: " << first_bits.data << std::endl;

    std::vector<var> message_vars;
    var first_bits_var;
    for (int i = 0; i < mes_size; ++i) {
        message_vars[i] = var(0, i, false, var::column_type::public_input);
    }
    first_bits_var = var(0, mes_size, false, var::column_type::public_input);
    typename component_type::input_type instance_input = {message_vars, first_bits_var};

    auto result_check = [expected_result]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        for (int i = 0; i < expected_result.size(); ++i) {
            // std::cout << "res:\n" << expected_result[i].data << "\n" << var_value(assignment, real_res.inner_state[i]).data << std::endl;
            // assert(expected_result[i] == var_value(assignment, real_res.inner_state[i]));
        }
    };

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0},
                                                           {1}, LookupRows, LookupColumns, num_blocks, first_bits)
                                            : component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {1},
                                                            LookupRows, LookupColumns, num_blocks, first_bits);

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        boost::get<component_type>(component_instance), public_input, result_check, instance_input);
}

// works
template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns>
void test_keccak_round_0() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;


    std::vector<value_type> message = {0};
    std::size_t first_bits = 0;

    std::vector<value_type> expected_result = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>
                            (message, first_bits, expected_result);
}

// template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
//          std::size_t LookupColumns>
// void test_keccak_round_1() {
//     using value_type = typename BlueprintFieldType::value_type;
//     using integral_type = typename BlueprintFieldType::integral_type;

//     std::vector<value_type> message = {0};
//     std::size_t first_bits = 0;

//     std::vector<value_type> expected_result = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

//     std::array<value_type, 25> expected_result = {
//         32899, 17592186044416, 32768, 1, 17592186077184,
//         0, 35184374185984, 0, 35184372088832, 2097152,
//         2, 512, 0, 514, 0,
//         268436480, 0, 1024, 268435456, 0,
//         1099511627776, 0, 1099511627780, 0, 4};
//     for (int i = 0; i < 25; ++i) {
//         expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
//     }

//     test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, level>
//                             (inner_state, padded_message_chunk, RC, expected_result);
// }

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns>
void test_keccak_round_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::size_t num_bits = 62;
    integral_type mask = (integral_type(1) << num_bits) - 1;
    std::vector<value_type> message = {value_type(integral_type(dis(gen)) & mask)};

    // for (int i = 0; i < 25; ++i) {
    //     auto random_value = integral_type(dis(gen));
    //     inner_state[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    // }
    
    auto expected_result = padding_function<BlueprintFieldType, num_bits>(message);

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, 1, num_bits>
                            (message, expected_result);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    // test_keccak_round_random<field_type, 9, 65536, 10>();
    test_keccak_round_random<field_type, 9, 65536, 10>();
    // test_keccak_round_random<field_type, 15, 65536, 10>();
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas_15) {
//     using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
// }

BOOST_AUTO_TEST_SUITE_END()
