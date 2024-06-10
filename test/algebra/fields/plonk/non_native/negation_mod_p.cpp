//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_negation_mod_p_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/negation_mod_p.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_negation_mod_p(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 5; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_integral_type = typename NonNativeFieldType::integral_type;

    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::negation_mod_p<ArithmetizationType, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;

    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.x[i] = var(0, i, false, var::column_type::public_input);
        instance_input.p[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.zero = var(0, 3*num_chunks, false, var::column_type::public_input);

    // the representation base and x_full, p_full, y_full: the full integer representations of x, p, y
    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                     x_full = 0,
                     p_full = 0,
                     y_full;

    for(std::size_t i = num_chunks; i > 0; i--) {
        x_full *= B;
        p_full *= B;
        x_full += foreign_integral_type(integral_type(public_input[i - 1].data));
        p_full += foreign_integral_type(integral_type(public_input[num_chunks + i - 1].data));
    }

    y_full = (x_full == 0) ? 0 : p_full - x_full; // if x = 0, then y = 0

    value_type expected_res[num_chunks];

    for(std::size_t i = 0; i < num_chunks; i++) {
        expected_res[i] = value_type(y_full % B);
        y_full /= B;
    }

    auto result_check = [&expected_res, &public_input](AssignmentType &assignment, typename component_type::result_type &real_res) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            BOOST_ASSERT(var_value(assignment, real_res.y[i]) == expected_res[i]);
        }
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
}

template <typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk,
        std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void negation_mod_p_tests() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_basic_integral_type = typename NonNativeFieldType::integral_type;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;

    static boost::random::mt19937 seed_seq;
    nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    const foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::cout << "Random test # " << (i+1) << "\n";
        std::vector<typename BlueprintFieldType::value_type> public_input;
        foreign_integral_type p = NonNativeFieldType::modulus,
                              ext_pow = foreign_integral_type(1) << num_chunks*bit_size_chunk,
                              pp = ext_pow - p;

        foreign_integral_type x = foreign_integral_type(foreign_basic_integral_type(generate_random().data));

        for(std::size_t j = 0; j < num_chunks; j++) { // the x's
            public_input.push_back(value_type(x % B));
            x /= B;
        }
        for(std::size_t j = 0; j < num_chunks; j++) {  // the p's
            public_input.push_back(value_type(p % B)); // these are B-base digits of p
            p /= B;
        }
        for(std::size_t j = 0; j < num_chunks; j++) {   // the pp's
            public_input.push_back(value_type(pp % B)); // these are B-base digits of pp
            pp /= B;
        }
        public_input.push_back(value_type(0)); // the zero

        test_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk,WitnessColumns>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using bls12_381_field_type = typename crypto3::algebra::curves::bls12<381>::scalar_field_type;
    using goldilocks_field_type = typename crypto3::algebra::fields::goldilocks64_base_field;

    std::cout << "Seq 1\n";
    negation_mod_p_tests<pallas_field_type, vesta_field_type, 8, 32, 15, random_tests_amount>();

    std::cout << "Seq 2\n";
    negation_mod_p_tests<pallas_field_type, bls12_381_field_type, 4, 65, 5, random_tests_amount>();

    std::cout << "Seq 3\n";
    negation_mod_p_tests<pallas_field_type, goldilocks_field_type, 2, 32, 10, random_tests_amount>();

    std::cout << "Seq 4\n";
    negation_mod_p_tests<vesta_field_type, pallas_field_type, 2, 253, 15, random_tests_amount>();

    std::cout << "Seq 5\n";
    negation_mod_p_tests<vesta_field_type, bls12_381_field_type, 12, 22, 13, random_tests_amount>();

    std::cout << "Seq 6\n";
    negation_mod_p_tests<vesta_field_type, goldilocks_field_type, 4, 16, 5, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
