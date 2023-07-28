//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pochtkovbra@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/complete_addition.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/doubling.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication_per_bit.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename CurveType>
void test_mul(typename CurveType::base_field_type::value_type b_val){
    
    using ed25519_type = crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename CurveType::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::variable_base_multiplication<
        ArithmetizationType,
        CurveType, 
        ed25519_type, 
        WitnessColumns, 
        nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    var b = var(0, 8, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {
        {input_var_Xa, input_var_Xb}, b};

    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T = crypto3::algebra::random_element<ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P = T * b_val;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask, (Tx >> 66) & mask, (Tx >> 132) & mask, (Tx >> 198) & mask,
        Ty & mask, (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & mask,
        b_val};

    auto result_check = [Px, Py](AssignmentType &assignment, typename component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   var_value(assignment, real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   var_value(assignment, real_res.output.y[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template <typename CurveType>
void test_mul_per_bit(){
    
    using ed25519_type = crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename CurveType::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::variable_base_multiplication_per_bit<
        ArithmetizationType,
        CurveType, 
        ed25519_type, 
        WitnessColumns, 
        nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<var, 4> input_var_Ya = {
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Yb = {
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};

    var b = var(0, 16, false, var::column_type::public_input);

    typename component_type::input_type instance_input
        = {
        {input_var_Xa, input_var_Xb}, 
        {input_var_Ya, input_var_Yb}, 
        b};

    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T = crypto3::algebra::random_element<ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type R = crypto3::algebra::random_element<ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>>();
    typename BlueprintFieldType::value_type b_val = 1;

    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type bool_res = T * b_val;
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type doub_res = R + R;
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P = bool_res + doub_res;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask, (Tx >> 66) & mask, (Tx >> 132) & mask, (Tx >> 198) & mask,
        Ty & mask, (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & mask,
        Rx & mask, (Rx >> 66) & mask, (Rx >> 132) & mask, (Rx >> 198) & mask,
        Ry & mask, (Ry >> 66) & mask, (Ry >> 132) & mask, (Ry >> 198) & mask,
        b_val};

    auto result_check = [Px, Py](AssignmentType &assignment, typename component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) 
                == var_value(assignment, real_res.output.y[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) 
                == var_value(assignment, real_res.output.y[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template <typename CurveType>
void test_doubling(){
    
    using ed25519_type = crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename CurveType::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::doubling<ArithmetizationType,
        CurveType, ed25519_type, WitnessColumns, 
        nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {{input_var_Xa, input_var_Xb}};

    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T = crypto3::algebra::random_element<ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P = T + T;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask, (Tx >> 66) & mask, (Tx >> 132) & mask, (Tx >> 198) & mask,
        Ty & mask, (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & mask};

    auto result_check = [Px, Py](AssignmentType &assignment, typename component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) == 
                   var_value(assignment, real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   var_value(assignment, real_res.output.y[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template <typename CurveType>
void test_complete_addition(){
    
    using ed25519_type = crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename CurveType::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::complete_addition<ArithmetizationType,
        CurveType, ed25519_type, WitnessColumns, 
        nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<var, 4> input_var_Ya = {
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Yb = {
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};

    var b = var(0, 16, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {{input_var_Xa, input_var_Xb}, {input_var_Ya, input_var_Yb}};

    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T = crypto3::algebra::random_element<ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type R = crypto3::algebra::random_element<ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P = T + R;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask, (Tx >> 66) & mask, (Tx >> 132) & mask, (Tx >> 198) & mask,
        Ty & mask, (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & mask,
        Rx & mask, (Rx >> 66) & mask, (Rx >> 132) & mask, (Rx >> 198) & mask,
        Ry & mask, (Ry >> 66) & mask, (Ry >> 132) & mask, (Ry >> 198) & mask};

    auto result_check = [Px, Py](AssignmentType &assignment, typename component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   var_value(assignment, real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   var_value(assignment, real_res.output.y[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_complete_addition) {
    test_complete_addition<typename crypto3::algebra::curves::pallas>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_doubling) {
    test_doubling<typename crypto3::algebra::curves::pallas>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_mul_per_bit) {
    test_mul_per_bit<typename crypto3::algebra::curves::pallas>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_mul_1) {
    using CurveType = typename crypto3::algebra::curves::pallas;
    typename CurveType::base_field_type::value_type b_val = 0;
    test_mul<CurveType>(b_val);
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_mul_2) {
    using CurveType = typename crypto3::algebra::curves::pallas;
    typename CurveType::base_field_type::value_type b_val = typename CurveType::base_field_type::value_type(98572345);
    test_mul<CurveType>(b_val);
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_mul_3) {
    using CurveType = typename crypto3::algebra::curves::pallas;
    typename CurveType::base_field_type::value_type b_val = 
        typename CurveType::base_field_type::value_type(
            0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed);

    test_mul<CurveType>(b_val);
}

BOOST_AUTO_TEST_SUITE_END()