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

#define BOOST_TEST_MODULE blueprint_detail_carry_on_addition_test

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
#include <nil/blueprint/components/detail/plonk/carry_on_addition.hpp>

#include "../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_carry_on_addition(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::carry_on_addition<ArithmetizationType, BlueprintFieldType, num_chunks, bit_size_chunk>;

    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.x[i] = var(0, i, false, var::column_type::public_input);
        instance_input.y[i] = var(0, num_chunks + i, false, var::column_type::public_input);
    }

    value_type expected_res[num_chunks], carry[num_chunks];
    for(std::size_t i = 0; i < num_chunks; i++) {
        expected_res[i] = public_input[i] + public_input[num_chunks + i];
        if (i == 0){
            if (expected_res[i] < (integral_type(1) << bit_size_chunk)){
                carry[i] = 0;
            }
            else{
                carry[i] = 1;
            }
            expected_res[i] = expected_res[i] - carry[i]*(integral_type(1) << bit_size_chunk);
        }
        else{
            if (expected_res[i] < (integral_type(1) << bit_size_chunk)){
                carry[i] = 0;
            }
            else{
                carry[i] = 1;
            }
            expected_res[i] = expected_res[i] + carry[i - 1] - carry[i]*(integral_type(1) << bit_size_chunk);
        }
    }

    auto result_check = [&expected_res, &public_input](AssignmentType &assignment, typename component_type::result_type &real_res) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            BOOST_ASSERT(var_value(assignment, real_res.z[i]) == expected_res[i]);
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
        (component_instance, desc, public_input, result_check, instance_input, nil::blueprint::connectedness_check_type::type::NONE);
    // NB: turning off connectedness_check is a TEMPORARY solution. It needs to be reverted as soon as possible!
}

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void carry_on_addition_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;
    integral_type chunk_size = (integral_type(1) << bit_size_chunk);

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input = {};
        for(std::size_t j = 0; j < 2*num_chunks; j++) {
            public_input.push_back(value_type(integral_type(generate_random().data) % chunk_size));
        }
        test_carry_on_addition<BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    carry_on_addition_tests<field_type, 2, 16, 4, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 32, 6, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 64, 8, random_tests_amount>();

    carry_on_addition_tests<field_type, 4, 64, 8, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 128, 12, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 16, 16, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 32, 10, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 64, 10, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 128, 10, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, 10, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 32, 15, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 64, 15, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 128, 15, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, 15, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    carry_on_addition_tests<field_type, 2, 16, 4, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 32, 6, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 64, 8, random_tests_amount>();

    carry_on_addition_tests<field_type, 4, 17, 8, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 18, 12, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 19, 16, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 128, 10, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 32, 10, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 64, 10, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, 10, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 16, 15, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 32, 15, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 64, 15, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 128, 15, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
