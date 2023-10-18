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

#define BOOST_TEST_MODULE blueprint_plonk_fri_cosets_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_cosets.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename FieldType, std::size_t WitnessColumns>
void test_fri_cosets(std::vector<typename FieldType::value_type> public_input,
    std::size_t n,
    std::size_t total_bits,
    typename FieldType::value_type omega){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::fri_cosets<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input)};

    typename BlueprintFieldType::integral_type pi_num = typename BlueprintFieldType::integral_type(public_input[0].data);
    std::array<typename BlueprintFieldType::value_type,3> expected_res = {1,-1,0};
    typename BlueprintFieldType::value_type w_powers = omega;
    for(std::size_t i = 0; i < n; i++) {
        expected_res[0] *= (pi_num % 2 == 1) ? w_powers : 1;
        expected_res[2] = typename BlueprintFieldType::value_type(pi_num % 2);
        pi_num /= 2;
        w_powers *= w_powers;
    }
    expected_res[1] = expected_res[0]*(-1);

    auto result_check = [&expected_res, public_input, omega](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "fri_cosets test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << omega.data << "\n";
            std::cout << "expected: {" << expected_res[0].data << "," << expected_res[1].data << "," << expected_res[2].data << "}\n";
            std::cout << "real    : {" << var_value(assignment, real_res.output[0]).data << "," <<
                                          var_value(assignment, real_res.output[1]).data << "," <<
                                          var_value(assignment, real_res.output[2]).data << "}\n\n";
            #endif
            assert(expected_res[0] == var_value(assignment, real_res.output[0]));
            assert(expected_res[1] == var_value(assignment, real_res.output[1]));
            assert(expected_res[2] == var_value(assignment, real_res.output[2]));
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 1>{0}, // constants 
                                      std::array<std::uint32_t, 0>{},  // public inputs
                                      n, total_bits, omega);

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input, n, total_bits);
}

template <typename FieldType>
void field_operations_test() {   
//  Format: test_fri_cosets<FieldType,WitnessColumns>(public_input, n, total_bits, omega)
    for (int i = 14; i < 25; i++){
         test_fri_cosets<FieldType,6>({i}, 3, 64, 2);
    }
    test_fri_cosets<FieldType,12>({46744073709551615}, 4, 64, 2);
    test_fri_cosets<FieldType,12>({46744073709551615}, 3, 64, 2);
    test_fri_cosets<FieldType,12>({46744073709551615}, 5, 64, 2);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fri_cosets_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<field_type>();
}

BOOST_AUTO_TEST_SUITE_END()
