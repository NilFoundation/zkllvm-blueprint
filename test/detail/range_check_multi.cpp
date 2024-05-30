//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_detail_range_check_multi_test

#include <boost/test/unit_test.hpp>

//#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
//#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/detail/plonk/range_check_multi.hpp>

#include "../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk,
            std::size_t WitnessColumns, bool to_pass = true>
void test_range_check(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 3;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::range_check_multi<ArithmetizationType, BlueprintFieldType, num_chunks, bit_size_chunk>;

    typename component_type::input_type instance_input;
    for (std::size_t i = 0; i < num_chunks; i++) {
        instance_input.x[i] = var(0, i, false, var::column_type::public_input);
    }

    auto result_check = [](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {};

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

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk,
        std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void range_check_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    integral_type mask = (integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;
        for (std::size_t j = 0; j < num_chunks; j++) {
            public_input.push_back(value_type(integral_type(generate_random().data) & mask));
        }
        test_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(public_input);
    }
}

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk,
        std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void range_check_tests_to_fail() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    integral_type mask = (integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::size_t for_faulty_chunks = bit_size_chunk % num_chunks + 1;
        integral_type most_significant_bit = integral_type(1) << (bit_size_chunk + i % 2);
        std::vector<typename BlueprintFieldType::value_type> public_input;
        for (std::size_t j = 0; j < num_chunks; j++) {
            if (j % for_faulty_chunks != 0) {
                public_input.push_back(value_type(integral_type(generate_random().data) & mask));
            } else {
                public_input.push_back(value_type(integral_type(generate_random().data) & mask | most_significant_bit));
            }
        }
        test_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns,false>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    range_check_tests<pallas_field_type, 8, 32, 15, random_tests_amount>();
    range_check_tests<pallas_field_type, 8, 65, 5, random_tests_amount>();
    range_check_tests<pallas_field_type, 4, 63, 10, random_tests_amount>();

    range_check_tests<vesta_field_type, 5, 254, 15, random_tests_amount>();
    range_check_tests<vesta_field_type, 1, 22, 9, random_tests_amount>();
    range_check_tests<vesta_field_type, 16, 129, 5, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_to_fail) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    range_check_tests_to_fail<pallas_field_type, 15, 30, 15, random_tests_amount>();
    range_check_tests_to_fail<pallas_field_type, 10, 12, 5, random_tests_amount>();
    range_check_tests_to_fail<pallas_field_type, 9, 128, 10, random_tests_amount>();

    range_check_tests_to_fail<vesta_field_type, 11, 252, 15, random_tests_amount>();
    range_check_tests_to_fail<vesta_field_type, 19, 220, 9, random_tests_amount>();
    range_check_tests_to_fail<vesta_field_type, 5, 65, 5, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
