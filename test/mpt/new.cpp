//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_mpt_nonce_changed

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <typeinfo>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/constant_pow.hpp>

#include "../test_plonk_component.hpp"

#include <random>
#include <iostream>

using namespace nil;
using namespace nil::crypto3::hashes::detail;

// template<typename BlueprintFieldType, size_t Rate>
// void test_poseidon_permutation(
//         typename poseidon_policy<BlueprintFieldType, 128, Rate>::state_type input,
//         typename poseidon_policy<BlueprintFieldType, 128, Rate>::state_type expected_result) {
//          using policy = poseidon_policy<BlueprintFieldType, 128, Rate>;

//     // This permutes in place.
//     poseidon_permutation<policy>::permute(input);
//     BOOST_CHECK_EQUAL(input, expected_result);
// }

template <typename BlueprintFieldType, std::size_t WitnessColumns>
void test_flexible_constant_pow(const typename BlueprintFieldType::value_type x, const typename BlueprintFieldType::integral_type pow
){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 20;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::flexible_constant_pow<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input;
    instance_input.x = var(0, 0, false, var::column_type::public_input);

    std::vector<value_type> public_input = {x};

    auto result_check = [&x, &pow](AssignmentType &assignment, typename component_type::result_type &real_res) {
            BOOST_ASSERT(var_value(assignment, real_res.y) == x.pow(pow));
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0}, pow);
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
    (component_instance, desc, public_input, result_check, instance_input, nil::blueprint::connectedness_check_type::type::STRONG, pow);
}

template <typename BlueprintFieldType, std::size_t WitnessAmount, std::size_t RandomTestsAmount>
void flexible_constant_pow_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;
    using policy = poseidon_policy<BlueprintFieldType, 128, /*Rate=*/ 4>;
    using hash_t = hashes::poseidon<policy>;   

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    // boost::random::uniform_int_distribution<> t_dist(0, 1);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    // std::uniform_int_distribution<uint64_t> dis;

    value_type balance = generate_random();
    value_type new_balance = generate_random();
    uint64_t old_nonce = gen();
    uint64_t new_nonce = gen();
    uint64_t code_size = gen();

    std::cout << "balance = " << balance << std::endl;
    std::cout << "oldNonce = " << old_nonce << std::endl;
    std::cout << "newNonce = " << new_nonce << std::endl;
    std::cout << "codeSize = " << code_size << std::endl;

    std::string nonce_string = std::to_string(old_nonce);
    std::cout << "nonce_string = " << nonce_string << std::endl;
    std::string code_size_string = std::to_string(code_size);
    std::cout << "code_size_string = " << code_size_string << std::endl;
    std::string sum_string = nonce_string + code_size_string;
    std::cout << "sum_string = " << sum_string << std::endl;

    uint64_t method_two   = 0ULL;
    std::string fmt = "0000000000000000000000000000000000000000000000000000000000000000";
    std::cout << "method_two = " << method_two << std::endl;

    // const int total = 64;
    // uint64_t myarray[total] = {};
    // std::cout << "myarray = " << myarray[63] << std::endl;
    std::string sum_string_new = sum_string + fmt;
    std::cout << "sum_string_new = " << sum_string_new << std::endl;

    // std::string new_string = old_nonce + code_size;
    // std::cout << "new_string = " << new_string << std::endl;

    std::string out = hash<hashes::keccak_1600<256>>(new_nonce);
    std::cout << "out = " << out << std::endl;
    std::string out2 = hash<hashes::keccak_1600<256>>(old_nonce);
    std::cout << "out2 = " << out2 << std::endl;
    std::string out3 = hash<hashes::keccak_1600<256>>(out2);
    std::cout << "out3 = " << out3 << std::endl;

     std::vector<uint64_t> keccak_input = {
                gen(),
                gen(),
                gen(),
                gen(),
        };

    std::cout << "keccak input = " << keccak_input[0] << std::endl;
    std::string out4 = hash<hashes::keccak_1600<256>>(keccak_input);
    std::cout << "out4 = " << out4 << std::endl;

    typename policy::digest_type d = hash<hash_t>(balance);
    std::cout << "d = " << d << std::endl;
    typename policy::digest_type d2 = hash<hash_t>(new_balance);
    std::cout << "d2 = " << d2 << std::endl;

    std::vector<typename BlueprintFieldType::value_type> field_input = {
                balance,
                new_balance,
        };
        
    typename policy::digest_type d3 = hash<hash_t>(field_input);
    std::cout << "d3 = " << d3 << std::endl;

    typename policy::digest_type d4 = hash<hash_t>(d3);
    std::cout << "d4 = " << d4 << std::endl;

    typename policy::digest_type d5 = hash<hash_t>(old_nonce);
    std::cout << "d5 = " << d5 << std::endl;

    typename policy::digest_type d6 = hash<hash_t>(nonce_string);
    std::cout << "d6 = " << d6 << std::endl;

    typename policy::digest_type d7 = hash<hash_t>(sum_string);
    std::cout << "d7 = " << d7 << std::endl;

    typename policy::digest_type d8 = hash<hash_t>(sum_string_new);
    std::cout << "d8 = " << d8 << std::endl;

    integral_type test; 
    test = integral_type(generate_random().data);
    std::cout << "test_value = " << test << std::endl;

    std::mt19937 gen2(rd());
    uint256_t byteCode = gen2();
    byteCode = byteCode*byteCode;
    std::cout << "byteCode = " << byteCode << std::endl;

    test_flexible_constant_pow<BlueprintFieldType, WitnessAmount>(2, 20);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_flexible_constant_pow<BlueprintFieldType, WitnessAmount>(generate_random(), (BlueprintFieldType::modulus - 1)/ 4294967296);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

// BOOST_AUTO_TEST_CASE(blueprint_plonk_test_vesta) {
//     using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;

//     flexible_constant_pow_tests<field_type, 150, random_tests_amount>();
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_test_pallas) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;

//     flexible_constant_pow_tests<field_type, 42, random_tests_amount>();
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_test_bls12) {
    using field_type = nil::crypto3::algebra::curves::bls12<381>::scalar_field_type;
    
    flexible_constant_pow_tests<field_type, 15, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
