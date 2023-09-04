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

#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

#include "../../test_plonk_component.hpp"

const int r[5][5] = {{0, 36, 3, 41, 18}, 
                    {1, 44, 10, 45, 2}, 
                    {62, 6, 43, 15, 61},
                    {28, 55, 25, 21, 56},
                    {27, 20, 39, 8, 14}};

template<typename BlueprintFieldType>
typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = integral_type(value.data);
    integral_type result_integral = 0;
    integral_type power = 1;
    for (int i = 0; i < 64; ++i) {
        integral_type bit = value_integral & 1;
        result_integral = result_integral + bit * power;
        value_integral = value_integral >> 1;
        power = power << 3;
    }
    return value_type(result_integral);
}
template<typename BlueprintFieldType>
bool check_sparse(typename BlueprintFieldType::value_type value, typename BlueprintFieldType::value_type sparse_value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = integral_type(value.data);
    integral_type sparse_value_integral = integral_type(sparse_value.data);
    bool result = 1;
    for (int i = 0; i < 64; ++i) {
        integral_type bit = value_integral & 1;
        integral_type sparse_bit = sparse_value_integral & 7;
        result *= (bit == sparse_bit);
    }
    return result;
}

template<typename BlueprintFieldType, bool xor_with_mes, bool eth_perm>
std::array<typename BlueprintFieldType::value_type, 25> sparse_round_function(std::array<typename BlueprintFieldType::value_type, 25> inner_state,
                                                            std::array<typename BlueprintFieldType::value_type, 17> padded_message_chunk,
                                                            typename BlueprintFieldType::value_type RC) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::array<integral_type, 25> inner_state_integral;
    std::array<integral_type, 17> padded_message_chunk_integral;
    integral_type RC_integral = integral_type(RC.data);
    for (int i = 0; i < 25; ++i) {
        inner_state_integral[i] = integral_type(inner_state[i].data);
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk_integral[i] = integral_type(padded_message_chunk[i].data);
    }

    auto rot = [](integral_type x, const int s) {
        return ((x << (3 * s)) | (x >> (192 - 3 * s))) & ((integral_type(1) << 192) - 1);
    };

    if (xor_with_mes) {
        for (int i = 0; i < 17; ++i) {
            inner_state_integral[i] = inner_state_integral[i] ^ padded_message_chunk_integral[i];
        }
    }
    // std::cout << "expected inner_state ^ chunk:\n";
    // for (int i = 0; i < 25; ++i) {
    //     std::cout << inner_state_integral[i] << "\n";
    // }

    // theta
    std::array<integral_type, 5> C;
    for (int x = 0; x < 5; ++x) {
        C[x] = inner_state_integral[5 * x] ^ inner_state_integral[5 * x + 1] ^ inner_state_integral[5 * x + 2] ^ inner_state_integral[5 * x + 3] ^
               inner_state_integral[5 * x + 4];
    }
    // std::cout << "expected theta 0:\n";
    // for (int i = 0; i < 5; ++i) {
    //     std::cout << C[i] << "\n";
    // }
    std::array<integral_type, 5> C_rot;
    for (int x = 0; x < 5; ++x) {
        C_rot[x] = rot(C[x], 1);
    }
    // std::cout << "expected theta 1:\n";
    // for (int i = 0; i < 5; ++i) {
    //     std::cout << C_rot[i] << "\n";
    // }
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[5 * x + y] = inner_state_integral[5 * x + y] ^ C[(x + 4) % 5] ^ C_rot[(x + 1) % 5];
        }
    }
    // std::cout << "expected theta 2:\n";
    // for (int i = 0; i < 25; ++i) {
    //     std::cout << inner_state_integral[i] << "\n";
    // }

    // rho and pi
    std::array<std::array<integral_type, 5>, 5> B;
    for (int i = 0; i < 25; ++i) {
        int x = i / 5;
        int y = i % 5;
        B[y][(2 * x + 3 * y) % 5] = rot(inner_state_integral[i], r[x][y]);
    }
    // std::cout << "expected rho/pi:\n";
    // for (int i = 0; i < 25; ++i) {
    //     std::cout << B[i / 5][i % 5] << "\n";
    // }

    // chi
    for (int i = 0; i < 25; ++i) {
        int x = i / 5;
        int y = i % 5;
        inner_state_integral[i] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
    }
    // std::cout << "expected chi:\n";
    // for (int i = 0; i < 25; ++i) {
    //     std::cout << inner_state_integral[i] << "\n";
    // }

    // iota
    inner_state_integral[0] = inner_state_integral[0] ^ RC_integral;
    // std::cout << "expected iota:\n";
    // std::cout << inner_state_integral[0] << "\n";
    for (int i = 0; i < 25; ++i) {
        inner_state[i] = value_type(inner_state_integral[i]);
    }
    return inner_state;
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, bool xor_with_mes, bool eth_perm>
auto test_keccak_round_inner(std::array<typename BlueprintFieldType::value_type, 25> inner_state,
                             std::array<typename BlueprintFieldType::value_type, 17> padded_message_chunk,
                             typename BlueprintFieldType::value_type RC,
                             std::array<typename BlueprintFieldType::value_type, 25> expected_result) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 20;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using component_type = nil::blueprint::components::keccak_round<ArithmetizationType, WitnessesAmount>;
    using var = typename component_type::var;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    // std::cout << "inner state:\n";
    for (int i = 0; i < 25; ++i) {
        public_input.push_back(inner_state[i]);
        // std::cout << inner_state[i].data << std::endl;
    }
    // std::cout << "padded message chunk:\n";
    for (int i = 0; i < 17; ++i) {
        public_input.push_back(padded_message_chunk[i]);
        // std::cout << padded_message_chunk[i].data << std::endl;
    }
    public_input.push_back(RC);
    // std::cout << "RC: " << RC.data << std::endl;

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

    auto result_check = [expected_result]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        for (int i = 0; i < 25; ++i) {
            // std::cout << "res:\n" << expected_result[i].data << "\n" << var_value(assignment, real_res.inner_state[i]).data << std::endl;
            // assert(expected_result[i] == var_value(assignment, real_res.inner_state[i]));
        }
    };

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0},
                                                           {1}, LookupRows, LookupColumns, xor_with_mes, eth_perm)
                                            : component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {1},
                                                            LookupRows, LookupColumns, xor_with_mes, eth_perm);

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        boost::get<component_type>(component_instance), public_input, result_check, instance_input);
}

// works
template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, int level>
void test_keccak_round_0() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;


    std::array<value_type, 25> inner_state = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    std::array<value_type, 17> padded_message_chunk = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    value_type RC = to_sparse<BlueprintFieldType>(value_type(1));

    std::array<value_type, 25> expected_result = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, level>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, int level>
void test_keccak_round_1() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::array<value_type, 25> inner_state = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    std::array<value_type, 17> padded_message_chunk = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    value_type RC = to_sparse<BlueprintFieldType>(value_type(0x8082ULL));

    std::array<value_type, 25> expected_result = {
        32899, 17592186044416, 32768, 1, 17592186077184,
        0, 35184374185984, 0, 35184372088832, 2097152,
        2, 512, 0, 514, 0,
        268436480, 0, 1024, 268435456, 0,
        1099511627776, 0, 1099511627780, 0, 4};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, level>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, int level>
void test_keccak_round_7() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;


    std::array<value_type, 25> inner_state = {
        4891766363406797400, 15439122233753343804, 13823342620960621853, 11746433691194652646, 4017314498112237324,
        815207819430446539, 4967747420293129338, 3818588911347179217, 12982395987346120149, 8831006501622048216,
        3273200702990303769, 11925911941096385939, 11818410238024184151, 6855937196075990472, 6813782227838587502,
        5749709705375199086, 198532287281302992, 3986921420170929948, 2084732521627207926, 3955984847012879536,
        17540298648724239738, 14973796877054370773, 9207394463793105740, 13336242423054526618, 2223831538796077986
    };
    for (int i = 0; i < 25; ++i) {
        inner_state[i] = to_sparse<BlueprintFieldType>(inner_state[i]);
    }
    std::array<value_type, 17> padded_message_chunk = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk[i] = to_sparse<BlueprintFieldType>(padded_message_chunk[i]);
    }
    value_type RC = to_sparse<BlueprintFieldType>(value_type(0x8000000080008081ULL));

    std::array<value_type, 25> expected_result = {
        898454936699210940, 8026835929569667841, 7594412717710188589, 17691297879001667639, 12039682773981733750,
        4806751406901749727, 11830785691895369039, 6215100860000502273, 3084694277248389144, 16700214332683074198,
        1701067029580549681, 2935021215067160996, 10064659787097191500, 7604822824502759976, 1494105689337672248,
        12626178481354463734, 2395136601172298592, 4068135589652482799, 15567196270789777948, 4732526861918809121,
        2821496240805205513, 5710775155925759758, 9794593245826189275, 17281148776925903127, 7447477925633355381
    };
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }

    auto check_expected_result = sparse_round_function<BlueprintFieldType, level>(inner_state, padded_message_chunk, RC);

    // BOOST_ASSERT_MSG(check_expected_result == expected_result, "Wrong expected result!") ;

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, level>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, bool xor_with_mes, bool eth_perm>
void test_keccak_round_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::array<value_type, 25> inner_state;
    std::array<value_type, 17> padded_message_chunk;
    value_type RC = value_type(0);

    for (int i = 0; i < 25; ++i) {
        auto random_value = integral_type(dis(gen));
        inner_state[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    }
    for (int i = 0; i < 17; ++i) {
        auto random_value = integral_type(dis(gen));
        padded_message_chunk[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    }
    auto random_value = integral_type(dis(gen));
    RC = to_sparse<BlueprintFieldType>(value_type(random_value));
    
    auto expected_result = sparse_round_function<BlueprintFieldType, xor_with_mes, eth_perm>(inner_state, padded_message_chunk, RC);

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, xor_with_mes, eth_perm>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows,
         std::size_t LookupColumns, bool xor_with_mes, bool eth_perm>
void test_keccak_round_not_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::array<value_type, 25> inner_state;
    std::array<value_type, 17> padded_message_chunk;
    value_type RC = value_type(0);

    for (int i = 0; i < 25; ++i) {
        inner_state[i] = to_sparse<BlueprintFieldType>(i + 1);
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk[i] = 1;
    }
    RC = to_sparse<BlueprintFieldType>(0x1000);
    
    auto expected_result = sparse_round_function<BlueprintFieldType, xor_with_mes, eth_perm>(inner_state, padded_message_chunk, RC);

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns, xor_with_mes, eth_perm>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    // test_keccak_round_random<field_type, 9, 65536, 10, true, false>();
    test_keccak_round_not_random<field_type, 15, 65536, 10, true, true>();
    // test_keccak_round_random<field_type, 15, 65536, 10, 4>();
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas_15) {
//     using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
// }

BOOST_AUTO_TEST_SUITE_END()
