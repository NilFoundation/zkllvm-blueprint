//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_ecdsa_non_native_multiplication_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/secp_k1.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/flexible_multiplication.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, typename NonNativeFieldType,
        std::size_t num_chunks, std::size_t bit_size_chunk,
        std::size_t WitnessColumns, bool to_pass = true>
void test_mult(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 10;
    constexpr std::size_t SelectorColumns = 10;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = typename blueprint::components::flexible_mult<ArithmetizationType, BlueprintFieldType, NonNativeFieldType,
                                                                            num_chunks, bit_size_chunk>;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using foreign_basic_integral_type = typename NonNativeFieldType::integral_type;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;

//std::cout << "Non-native p = " << NonNativeFieldType::modulus << std::endl;

    typename component_type::input_type instance_input;
    for (std::size_t i = 0; i < num_chunks; i++) {
        instance_input.x[i] = var(0, i, false, var::column_type::public_input);
        instance_input.y[i] = var(0, i + num_chunks, false, var::column_type::public_input);
        instance_input.p[i] = var(0, i + 2*num_chunks, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, i + 3*num_chunks, false, var::column_type::public_input);
    }
    instance_input.zero = var(0,4*num_chunks, false, var::column_type::public_input);

    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                       x = 0,
                       y = 0;
    for(std::size_t i = num_chunks; i > 0; i--) {
        x *= B;
        x += foreign_integral_type(integral_type(public_input[i-1].data));
        y *= B;
        y += foreign_integral_type(integral_type(public_input[num_chunks + i-1].data));
    }
    foreign_value_type r = x*y;

    auto result_check = [&r, &B](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
         foreign_integral_type R = 0;
         for(std::size_t i = num_chunks; i > 0; i--) {
             R *= B;
             R += foreign_integral_type(integral_type(var_value(assignment,real_res.r[i-1]).data));
         }

         #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
         std::cout << "Flexible multiplication test" << std::endl;
         std::cout << "Expected res: " << std::dec << foreign_basic_integral_type(r.data) << std::endl;
         std::cout << "Real res:     " << std::dec << R  << std::endl;
         #endif
         assert(foreign_integral_type(foreign_basic_integral_type(r.data)) == R);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );
    if (to_pass) {
        nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
    } else {
        std::cout << "Testing to fail" << std::endl;
        nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
    }
}

template <typename BlueprintFieldType, typename NonNativeFieldType,
        std::size_t num_chunks, std::size_t bit_size_chunk,
        std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void mult_tests() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using foreign_integral_type = typename NonNativeFieldType::integral_type;
    using foreign_extended_integral_type = typename NonNativeFieldType::extended_integral_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    foreign_extended_integral_type mask = (foreign_extended_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        foreign_value_type src_x = generate_random(),
                           src_y = generate_random();

        foreign_extended_integral_type x = foreign_extended_integral_type(foreign_integral_type(src_x.data)),
                                       y = foreign_extended_integral_type(foreign_integral_type(src_y.data)),
                                       extended_base = 1,
                                       ext_pow = extended_base << (num_chunks*bit_size_chunk),
                                       p = NonNativeFieldType::modulus,
                                       pp = ext_pow - p;

        public_input.resize(4*num_chunks+1); // public_input should contain x,y,p,pp
//std::cout << "PI x = " << x << std::endl;
//std::cout << "PI y = " << y << std::endl;
//std::cout << "PI p = " << p << std::endl;
        for(std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(x & mask);
            x >>= bit_size_chunk;

            public_input[num_chunks + j] = value_type(y & mask);
            y >>= bit_size_chunk;

            public_input[2*num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[3*num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;
        }
        public_input[4*num_chunks] = 0;

        test_mult<BlueprintFieldType, NonNativeFieldType,
                num_chunks, bit_size_chunk, WitnessColumns>(public_input);
    }
}
/*
template <typename BlueprintFieldType, typename NonNativeFieldType,
        std::size_t num_chunks, std::size_t bit_size_chunk,
        std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void mult_tests_to_fail() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    integral_type mask = (integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        integral_type most_significant_bit = integral_type(1) << (bit_size_chunk + i % 2);
        std::vector<typename BlueprintFieldType::value_type> public_input;
        for(std::size_t j = 0; j < 2*num_chunks; j++) {
            // public_input.push_back(value_type(integral_type(generate_random().data) & mask | most_significant_bit));
        }
        test_mult<BlueprintFieldType, NonNativeFieldType,
                num_chunks, bit_size_chunk, WitnessColumns>(public_input);
    }
}
*/
constexpr static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using bls12_381_field_type = typename crypto3::algebra::curves::bls12<381>::scalar_field_type;
    using goldilocks_field_type = typename crypto3::algebra::fields::goldilocks64_base_field;
    using bls12_381_base_field_type = typename crypto3::algebra::curves::bls12<381>::base_field_type;
    using secp256k1_scalar_field_type = typename crypto3::algebra::curves::secp256k1::scalar_field_type;

// <BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk, WitnessColumns, RandomTestsAmount>
//    std::cout << "Scenario 0\n";
//    mult_tests<pallas_field_type, bls12_381_base_field_type, 9, 64, 16, random_tests_amount>();

    std::cout << "Scenario 1\n";
    mult_tests<pallas_field_type, vesta_field_type, 4, 64, 15, random_tests_amount>();

    std::cout << "Scenario 2\n";
    mult_tests<vesta_field_type, secp256k1_scalar_field_type, 5, 64, 16, random_tests_amount>();

    std::cout << "Scenario 3\n";
    mult_tests<pallas_field_type, vesta_field_type, 4, 65, 10, random_tests_amount>();

    std::cout << "Scenario 4\n";
    mult_tests<pallas_field_type, vesta_field_type, 5, 63, 13, random_tests_amount>();

    std::cout << "Scenario 5\n";
    mult_tests<pallas_field_type, goldilocks_field_type, 2, 32, 10, random_tests_amount>();

    std::cout << "Scenario 6\n";
    mult_tests<pallas_field_type, goldilocks_field_type, 3, 22, 9, random_tests_amount>();

}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_to_fail) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    // mult_tests_to_fail<pallas_field_type, 30, 15, random_tests_amount>();
    // mult_tests_to_fail<pallas_field_type, 12, 5, random_tests_amount>();
    // mult_tests_to_fail<pallas_field_type, 128, 10, random_tests_amount>();

    // mult_tests_to_fail<vesta_field_type, 252, 15, random_tests_amount>();
    // mult_tests_to_fail<vesta_field_type, 220, 9, random_tests_amount>();
    // mult_tests_to_fail<vesta_field_type, 65, 5, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
