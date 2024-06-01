//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
//
// exponentiation to a fixed power in Fp4 for MNT4 GT
//
#define BOOST_TEST_MODULE blueprint_plonk_mnt4_fp4_fixed_power_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt4/298/params.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/mnt4_fp4_fixed_power.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename CurveType, std::size_t WitnessAmount>
void test_mnt4_fp4_fixed_power(
        std::vector<typename CurveType::base_field_type::value_type> public_input,
        typename CurveType::base_field_type::integral_type power,
        typename CurveType::gt_type::value_type expected_res)
{
    using curve_type = CurveType;
    using BlueprintFieldType = typename curve_type::base_field_type;

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 5;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::mnt4_fp4_fixed_power<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input),
        var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input),
        var(0, 3, false, var::column_type::public_input)
    };

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "GT (MNT4_FP4) fixed power test: " << "\n";
        std::cout << "input   : " << public_input[0].data << "," << public_input[1].data << "\n";
        std::cout << "input   : " << public_input[2].data << "," << public_input[3].data << "\n";
        std::cout << "expected: " << expected_res.data[0].data[0] << "," << expected_res.data[0].data[1] << ",\n";
        std::cout << "        : " << expected_res.data[1].data[0] << "," << expected_res.data[1].data[1] << ",\n";
        std::cout << "real    : " << var_value(assignment, real_res.output[0]).data << "," << var_value(assignment, real_res.output[1]).data << ",\n";
        std::cout << "          " << var_value(assignment, real_res.output[2]).data << "," << var_value(assignment, real_res.output[3]).data << "\n\n";
        #endif
        assert(expected_res.data[0].data[0] == var_value(assignment, real_res.output[0]));
        assert(expected_res.data[0].data[1] == var_value(assignment, real_res.output[1]));
        assert(expected_res.data[1].data[0] == var_value(assignment, real_res.output[2]));
        assert(expected_res.data[1].data[1] == var_value(assignment, real_res.output[3]));
        return true;
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses,
             std::array<std::uint32_t, 0>{},
             std::array<std::uint32_t, 0>{},
             power);

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
            component_instance, desc, public_input, result_check, instance_input,
            nil::blueprint::connectedness_check_type::type::STRONG,
            power);
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_mnt4_fp4_fixed_power_test) {
    using curve_type = crypto3::algebra::curves::mnt4_298;
    using group_type = typename curve_type::gt_type;
    using base_field_value = curve_type::base_field_type::value_type;

    typedef typename group_type::value_type group_value_type;
    typedef typename group_type::underlying_field_type::value_type underlying_field_type;
    typedef typename group_type::base_field_type::value_type field_value_type;
    typedef typename group_type::base_field_type::integral_type integral_type;

    std::vector<group_value_type> test_gt_elems = {
        group_value_type(
                underlying_field_type(
//                    4,3
        0x22c26a3c19d56fc8790485554be5dc4351961a5162c3634965dc8ae56701157e_cppui254,
        0x1e3305b98bf381650491b7b63559d20d662b70f1616e680a19170715b59a3426_cppui254
                ),
                underlying_field_type(
//                    2,1
        0x148a1f438a4cd0d807549cb7f9ec9f41dba3d8b14a6b0f2489d9b9f626d6fd31_cppui254,
        0x3cc907ef65b0eff91d027e4771e9116a0b125325627b6bdf55037702220b1b2_cppui254
                )
        ),
    };

    auto fixed_power = pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0;
//    auto fixed_power = pairing::detail::pairing_params<curve_type>::final_exponent;
//    auto fixed_power = integral_type("100");

    for(std::size_t i = 0; i < test_gt_elems.size(); i++) {
        std::cout << "Test instance # " << (i+1) << "\n";
        group_value_type P = test_gt_elems[i];
        group_value_type R = P.pow(fixed_power);

        test_mnt4_fp4_fixed_power<curve_type, 4>(
                std::vector<base_field_value>{ P.data[0].data[0], P.data[0].data[1], P.data[1].data[0], P.data[1].data[1] },
                fixed_power,
                R);
    }
}

BOOST_AUTO_TEST_SUITE_END()
