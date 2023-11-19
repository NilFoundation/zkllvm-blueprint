//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_fields_non_native_fp12_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/fp12_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/fp12_inversion.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/fp12_small_power.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType, std::size_t WitnessColumns>
void test_fp12_multiplication(std::vector<typename FieldType::value_type> public_input) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::fp12_multiplication<ArithmetizationType, FieldType>;

    typename component_type::input_type instance_input;
    typename std::array<value_type,12> A, B;
    typename std::array<value_type,12> expected_res;

    for(std::size_t i = 0; i < 12; i++) {
        instance_input.a[i] = var(0,i, false, var::column_type::public_input);
        instance_input.b[i] = var(0,i+12, false, var::column_type::public_input);
        A[i] = public_input[i];
        B[i] = public_input[i+12];
    }

    using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<FieldType>;
    using fp12_element = typename policy_type_fp12::value_type;

    fp12_element e1 = fp12_element({ {A[0],A[1]}, {A[2],A[3]}, {A[4],A[5]} }, { {A[6],A[7]}, {A[8],A[9]}, {A[10],A[11]} }),
                 e2 = fp12_element({ {B[0],B[1]}, {B[2],B[3]}, {B[4],B[5]} }, { {B[6],B[7]}, {B[8],B[9]}, {B[10],B[11]} }),
                 e = e1 * e2; // fp12 multiplication

    expected_res = {
       e.data[0].data[0].data[0], e.data[0].data[0].data[1],
       e.data[0].data[1].data[0], e.data[0].data[1].data[1],
       e.data[0].data[2].data[0], e.data[0].data[2].data[1],
       e.data[1].data[0].data[0], e.data[1].data[0].data[1],
       e.data[1].data[1].data[0], e.data[1].data[1].data[1],
       e.data[1].data[2].data[0], e.data[1].data[2].data[1] };


    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
            typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "Fp12 multiplication res vs output\n";
            for(std::size_t i = 0; i < 12; i++) {
                std::cout << std::dec << expected_res[i].data << " =? " << var_value(assignment, real_res.output[i]).data << "\n";
            }
            #endif
            for(std::size_t i = 0; i < 12; i++) {
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{},  // constants
                                      std::array<std::uint32_t, 0>{} // public inputs
                                     );

    nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
}

template <typename FieldType, std::size_t WitnessColumns>
void test_fp12_inversion(std::vector<typename FieldType::value_type> public_input) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::fp12_inversion<ArithmetizationType, FieldType>;

    typename component_type::input_type instance_input;
    typename std::array<value_type,12> X;
    typename std::array<value_type,12> expected_res;

    for(std::size_t i = 0; i < 12; i++) {
        instance_input.x[i] = var(0,i, false, var::column_type::public_input);
        X[i] = public_input[i];
    }

    using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<FieldType>;
    using fp12_element = typename policy_type_fp12::value_type;

    fp12_element e1 = fp12_element({ {X[0],X[1]}, {X[2],X[3]}, {X[4],X[5]} }, { {X[6],X[7]}, {X[8],X[9]}, {X[10],X[11]} }),
                 e = (e1 == fp12_element::zero())? fp12_element::zero() : e1.inversed(); // fp12 inversion

    const bool expected_to_pass = (e1 != fp12_element::zero());

    expected_res = {
       e.data[0].data[0].data[0], e.data[0].data[0].data[1],
       e.data[0].data[1].data[0], e.data[0].data[1].data[1],
       e.data[0].data[2].data[0], e.data[0].data[2].data[1],
       e.data[1].data[0].data[0], e.data[1].data[0].data[1],
       e.data[1].data[1].data[0], e.data[1].data[1].data[1],
       e.data[1].data[2].data[0], e.data[1].data[2].data[1] };


    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
            typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "Fp12 inversion res vs output\n";
            for(std::size_t i = 0; i < 12; i++) {
                std::cout << std::dec << expected_res[i].data << " =? " << var_value(assignment, real_res.output[i]).data << "\n";
            }
            #endif
            for(std::size_t i = 0; i < 12; i++) {
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{},  // constants
                                      std::array<std::uint32_t, 0>{} // public inputs
                                     );

    if (expected_to_pass) {
        nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
    } else {
        nil::crypto3::test_component_to_fail<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
    }
}

template <typename FieldType, std::size_t WitnessColumns, small_power Power>
void test_fp12_small_power(std::vector<typename FieldType::value_type> public_input) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::fp12_small_power<ArithmetizationType, FieldType, Power>;

    typename component_type::input_type instance_input;
    typename std::array<value_type,12> X;
    typename std::array<value_type,12> expected_res;

    for(std::size_t i = 0; i < 12; i++) {
        instance_input.x[i] = var(0,i, false, var::column_type::public_input);
        X[i] = public_input[i];
    }

    using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<FieldType>;
    using fp12_element = typename policy_type_fp12::value_type;

    fp12_element e1 = fp12_element({ {X[0],X[1]}, {X[2],X[3]}, {X[4],X[5]} }, { {X[6],X[7]}, {X[8],X[9]}, {X[10],X[11]} }),
                 e = e1.pow(int(Power)); // fp12 power raising

    expected_res = {
       e.data[0].data[0].data[0], e.data[0].data[0].data[1],
       e.data[0].data[1].data[0], e.data[0].data[1].data[1],
       e.data[0].data[2].data[0], e.data[0].data[2].data[1],
       e.data[1].data[0].data[0], e.data[1].data[0].data[1],
       e.data[1].data[1].data[0], e.data[1].data[1].data[1],
       e.data[1].data[2].data[0], e.data[1].data[2].data[1] };


    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
            typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "Fp12 inversion res vs output\n";
            for(std::size_t i = 0; i < 12; i++) {
                std::cout << std::dec << expected_res[i].data << " =? " << var_value(assignment, real_res.output[i]).data << "\n";
            }
            #endif
            for(std::size_t i = 0; i < 12; i++) {
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{},  // constants
                                      std::array<std::uint32_t, 0>{} // public inputs
                                     );

    nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
}

static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_non_native_fp12_test) {
    using field_type = typename crypto3::algebra::fields::bls12_fq<381>;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for(std::size_t i = 0; i < random_tests_amount; i++) {
        std::cout << "Random test # " << i << "\n";
        std::vector<field_type::value_type> ab = {},
                                            x = {};

        for(std::size_t j = 0; j < 2*12; j++) {
            ab.push_back(generate_random());
        }
        test_fp12_multiplication<field_type,12>(ab);
        test_fp12_multiplication<field_type,18>(ab);
        test_fp12_multiplication<field_type,24>(ab);
        test_fp12_multiplication<field_type,36>(ab);

        for(std::size_t j = 0; j < 12; j++) {
            x.push_back(generate_random());
        }

        test_fp12_inversion<field_type,12>(x);
        test_fp12_inversion<field_type,18>(x);
        test_fp12_inversion<field_type,24>(x);

        test_fp12_small_power<field_type,12,square>(x);
        test_fp12_small_power<field_type,18,cube>(x);
        test_fp12_small_power<field_type,24,power4>(x);
    }


    std::vector<field_type::value_type> x = {};
    x.resize(12,field_type::value_type::zero());
    // test to fail
    test_fp12_inversion<field_type,12>(x);

}

BOOST_AUTO_TEST_SUITE_END()
