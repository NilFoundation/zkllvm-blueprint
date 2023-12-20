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
#include <nil/blueprint/components/algebra/fields/plonk/non_native/fp12_fixed_power.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType>
void test_fp12_fixed_power(std::vector<typename FieldType::value_type> public_input, unsigned long long Power) {
    constexpr std::size_t WitnessColumns = 12;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 4;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::fp12_fixed_power<ArithmetizationType, FieldType>;

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
                 e = e1.pow(Power); // fp12 power raising

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
            std::cout << "Fp12 small power res vs output\n";
            for(std::size_t i = 0; i < 12; i++) {
                std::cout << std::dec << expected_res[i].data << " =? " << var_value(assignment, real_res.output[i]).data << "\n";
            }
            #endif
            for(std::size_t i = 0; i < 12; i++) {
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };

    component_type component_instance({0,1,2,3,4,5,6,7,8,9,10,11}, // witnesses
                                      {},  // constants
                                      {}, // public inputs
                                      Power);

    nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG, Power);
}

static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_non_native_fp12_test) {
    using field_type = typename crypto3::algebra::fields::bls12_fq<381>;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for(std::size_t i = 0; i < random_tests_amount; i++) {
        std::cout << "Random test # " << (i+1) << "\n";
        std::vector<field_type::value_type> x = {};

        for(std::size_t j = 0; j < 12; j++) {
            x.push_back(generate_random());
        }
        unsigned long long Power = 0xD201000000010000;
        test_fp12_fixed_power<field_type>(x,Power);

        Power = 0x460055555555aaab;
        test_fp12_fixed_power<field_type>(x,Power);

        Power = 4965661367192848881;
        test_fp12_fixed_power<field_type>(x,Power);
    }

}

BOOST_AUTO_TEST_SUITE_END()
