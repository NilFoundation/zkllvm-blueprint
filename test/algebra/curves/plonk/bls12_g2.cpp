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
//
// BLS12-381 g2 group operations tests
//
#define BOOST_TEST_MODULE blueprint_plonk_bls12_g2_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/curves/detail/plonk/bls12_g2_point_double.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

template <typename CurveType>
void test_bls12_g2_doubling(std::vector<typename CurveType::base_field_type::value_type> public_input,
    typename CurveType::template g2_type<>::value_type expected_res){

    using curve_type = CurveType;
    using BlueprintFieldType = typename curve_type::g2_type<>::field_type::base_field_type;

    constexpr std::size_t WitnessColumns = 8;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::bls12_g2_point_double<ArithmetizationType,BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        typename curve_type::g2_type<>::field_type::value_type expected_x = expected_res.X / expected_res.Z.pow(2),
                                                               expected_y = expected_res.Y / expected_res.Z.pow(3);
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "unified_addition test: " << "\n";
        std::cout << "input   : " << public_input[0].data << "," << public_input[1].data << "\n";
        std::cout << "input   : " << public_input[2].data << "," << public_input[3].data << "\n";
        std::cout << "expected: " << expected_x.data[0] << "," << expected_x.data[1] << ",\n";
        std::cout << "        : " << expected_y.data[0] << "," << expected_y.data[1] << ",\n";
        std::cout << "real    : " << var_value(assignment, real_res.R[0]).data << "," << var_value(assignment, real_res.R[1]).data << ",\n";
        std::cout << "          " << var_value(assignment, real_res.R[2]).data << "," << var_value(assignment, real_res.R[3]).data << "\n\n";
        #endif
        assert(expected_x.data[0] == var_value(assignment, real_res.R[0]));
        assert(expected_x.data[1] == var_value(assignment, real_res.R[1]));
        assert(expected_y.data[0] == var_value(assignment, real_res.R[2]));
        assert(expected_y.data[1] == var_value(assignment, real_res.R[3]));
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7},{},{});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bls12_g2_test_381) {
    using curve_type = crypto3::algebra::curves::bls12_381;
    using group_type = typename curve_type::g2_type<>;
    using base_field_value = curve_type::base_field_type::value_type;

    typedef typename group_type::value_type group_value_type;
    typedef typename group_type::field_type::value_type field_value_type;
    typedef typename group_type::field_type::integral_type integral_type;

    group_value_type g2elem = group_value_type(field_value_type(integral_type("19354805336845174941142151562851080662656573665208680741935"
                                                           "4395577367693778571452628423727082668900187036482254730"),
                                               integral_type("89193000964309942330810277795125089969455920364772498836102"
                                                           "2851024990473423938537113948850338098230396747396259901")),
                              field_value_type(integral_type("77171727205583415237828170597267125700535714547880090837365"
                                                           "9404991537354153455452961747174765859335819766715637138"),
                                               integral_type("28103101185821266340411334541807053043930791391032529565024"
                                                           "04531123692847658283858246402311867775854528543237781718")),
                              field_value_type::one()),
                      expected_res = g2elem * 2;

    field_value_type g2x = g2elem.X / g2elem.Z.pow(2),
                     g2y = g2elem.Y / g2elem.Z.pow(3);

    std::vector<base_field_value> input = {g2x.data[0], g2x.data[1], g2y.data[0], g2y.data[1]};

    test_bls12_g2_doubling<curve_type>(input, expected_res);
}

BOOST_AUTO_TEST_SUITE_END()
