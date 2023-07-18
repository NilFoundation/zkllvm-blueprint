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
#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

#include "../../test_plonk_component.hpp"

const int r[5][5] = {{0, 1, 62, 28, 27}, 
                    {36, 44, 6, 55, 20}, 
                    {3, 10, 43, 25, 39},
                    {41, 45, 15, 21, 8},
                    {18, 2, 61, 56, 14}};

// here for level we use:
// 0 - inner ^ chunk, 1 - theta, 2 - rho/phi, 3 - chi, 4 - iota (full round, by default)
template<typename BlueprintFieldType, int level = 4>
std::array<typename BlueprintFieldType, 25> round_function(std::array<typename BlueprintFieldType, 25> inner_state,
                                                            std::array<typename BlueprintFieldType, 17> padded_message_chunk,
                                                            typename BlueprintFieldType::value_type RC) {
    #define rot(x, s) (((x) << s) | ((x) >> (64 - s)));
    for (int i = 0; i < 17; ++i) {
        inner_state[i] = inner_state[i] ^ padded_message_chunk[i];
    }
    if (level == 0) {
        return inner_state;
    }
    // theta
    std::array<typename BlueprintFieldType, 5> C;
    for (int x = 0; x < 5; ++x) {
        C[x] = inner_state[5 * x] ^ inner_state[5 * x + 1] ^ inner_state[5 * x + 2] ^ inner_state[5 * x + 3] ^
               inner_state[5 * x + 4];
        for (int y = 0; y < 5; ++y) {
            inner_state[5 * x + y] = inner_state[5 * x + y] ^ C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1);
        }
    }
    if (level == 1) {
        return inner_state;
    }
    // rho and pi
    std::array<typename BlueprintFieldType, 25> B;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            B[5 * y + ((2 * x + 3 * y) % 5)] = rot(inner_state[5 * x + y], r[x, y]);
        }
    }
    if (level == 2) {
        return B;
    }
    // chi
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state[5 * x + y] = B[5 * x + y] ^ ((~B[5 * x + ((y + 1) % 5)]) & B[5 * x + ((y + 2) % 5)]);
        }
    }
    if (level == 3) {
        return inner_state;
    }
    // iota
    inner_state[0] = inner_state[0] ^ RC;

    return inner_state;
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, int level>
auto test_keccak_round_inner(std::array<typename BlueprintFieldType::value_type, 25> inner_state,
                             std::array<typename BlueprintFieldType::value_type, 17> padded_message_chunk,
                             typename BlueprintFieldType::value_type RC) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using component_type = nil::blueprint::components::keccak_round<ArithmetizationType, WitnessesAmount>;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    for (int i = 0; i < 25; ++i) {
        public_input.push_back(inner_state[i]);
    }
    for (int i = 0; i < 17; ++i) {
        public_input.push_back(padded_message_chunk[i]);
    }
    public_input.push_back(RC);

    std::array<var, 25> inner_state_vars;
    std::array<var, 17> padded_message_chunk_vars;
    var RC_var;
    for (int i = 0; i < 25; ++i) {
        inner_state_vars[i] = var(0, i, false, var::column_type::public_input);
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk_vars[i] = var(0, i + 25, false, var::column_type::public_input);
    }
    RC_var = var(0, 42, false, var::column_type::public_input);
    typename component_type::input_type instance_input = {inner_state_vars, padded_message_chunk_vars, RC_var};

    auto expected_result = round_function<BlueprintFieldType, level>(inner_state, padded_message_chunk, RC);

    auto result_check = [expected_result]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        for (int i = 0; i < 25; ++i) {
            assert(expected_result[i] == var_value(assignment, real_res.inner_state[i]));
        }
    };

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0},
                                                           {0}, LookupRows, LookupColumns)
                                            : component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {0},
                                                            LookupRows, LookupColumns);

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        boost::get<component_type>(component_instance), public_input, result_check, instance_input);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, int level>
void test_keccak_round_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);
    uint64_t range = value_type(2).pow(64) - 1;

    boost::random::uniform_int_distribution<std::uint64_t> distribution(0, range);

    std::array<value_type, 25> inner_state;
    std::array<value_type, 17> padded_message_chunk;
    value_type RC = value_type(0);

    for (int i = 0; i < 25; ++i) {
        inner_state[i] = value_type(distribution(generate_random));
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk[i] = value_type(distribution(generate_random));
    }
    RC = value_type(distribution(generate_random));

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, level>
                            (inner_state, padded_message_chunk, RC);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_keccak_round<field_type, 9, 65536, 10, 0>();
    test_keccak_round<field_type, 15, 65536, 10, 0>();
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas_15) {
//     using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
// }

BOOST_AUTO_TEST_SUITE_END()
