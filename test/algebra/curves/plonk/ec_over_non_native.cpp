//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE blueprint_plonk_ec_over_non_native_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_double.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_incomplete_add.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_full_add.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_two_t_plus_q.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_scalar_mult.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

template <typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_doubling(typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_Q,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type expected_res){

    using curve_type = CurveType;
    using NonNativeFieldType = typename curve_type::base_field_type;

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 10; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::ec_double<ArithmetizationType, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    // transform EC point coords into chunks and put them into public input column
    std::vector<typename BlueprintFieldType::value_type> public_input;
    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          xQ = foreign_integral_type(point_Q.X.data),
                          yQ = foreign_integral_type(point_Q.Y.data),
                          p = NonNativeFieldType::modulus,
                          ext_pow = foreign_integral_type(1) << num_chunks*bit_size_chunk,
                          pp = ext_pow - p;

    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % B));
            t /= B;
        }
    };

    chunks_to_public_input(xQ);
    chunks_to_public_input(yQ);
    chunks_to_public_input(p);
    chunks_to_public_input(pp);
    public_input.push_back(value_type(0)); // the zero

    // put references to public input column into instance input
    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.xQ[i] = var(0, i, false, var::column_type::public_input);
        instance_input.yQ[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.p[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, 3*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.zero = var(0, 4*num_chunks, false, var::column_type::public_input);

    auto result_check = [&expected_res, &B](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        foreign_integral_type xR = 0,
                              yR = 0;
        for(std::size_t i = num_chunks; i > 0; i--) {
            xR *= B;
            yR *= B;
            xR += foreign_integral_type(var_value(assignment, real_res.xR[i-1]).data);
            yR += foreign_integral_type(var_value(assignment, real_res.yR[i-1]).data);
        }
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "ec_double test: " << "\n";
        std::cout << "expected: " << expected_res.X.data << " " << expected_res.Y.data << "\n";
        std::cout << "real    : " << xR << " " << yR << "\n\n";
        #endif
        assert(foreign_integral_type(expected_res.X.data) == xR);
        assert(foreign_integral_type(expected_res.Y.data) == yR);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_full_add(
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_P,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_Q,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type expected_res){

    using curve_type = CurveType;
    using NonNativeFieldType = typename curve_type::base_field_type;

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 6; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::ec_full_add<ArithmetizationType, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    // transform EC point coords into chunks and put them into public input column
    std::vector<typename BlueprintFieldType::value_type> public_input;
    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          xP = point_P.is_zero() ? 0 : foreign_integral_type(point_P.X.data),
                          yP = point_P.is_zero() ? 0 : foreign_integral_type(point_P.Y.data),
                          xQ = point_Q.is_zero() ? 0 : foreign_integral_type(point_Q.X.data),
                          yQ = point_Q.is_zero() ? 0 : foreign_integral_type(point_Q.Y.data),
                          p = NonNativeFieldType::modulus,
                          ext_pow = foreign_integral_type(1) << num_chunks*bit_size_chunk,
                          pp = ext_pow - p;
    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % B));
            t /= B;
        }
    };

    chunks_to_public_input(xP);
    chunks_to_public_input(yP);
    chunks_to_public_input(xQ);
    chunks_to_public_input(yQ);
    chunks_to_public_input(p);
    chunks_to_public_input(pp);
    public_input.push_back(value_type(0)); // the zero

    // put references to public input column into instance input
    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.xP[i] = var(0, i, false, var::column_type::public_input);
        instance_input.yP[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.xQ[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
        instance_input.yQ[i] = var(0, 3*num_chunks + i, false, var::column_type::public_input);
        instance_input.p[i] = var(0, 4*num_chunks + i, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, 5*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.zero = var(0, 6*num_chunks, false, var::column_type::public_input);

    auto result_check = [&expected_res, &B](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        foreign_integral_type xR = 0,
                              yR = 0;
        for(std::size_t i = num_chunks; i > 0; i--) {
            xR *= B;
            yR *= B;
            xR += foreign_integral_type(var_value(assignment, real_res.xR[i-1]).data);
            yR += foreign_integral_type(var_value(assignment, real_res.yR[i-1]).data);
        }
        if (yR == 0) {
            yR = 1; // the encoding for the neutral point outside of the circuit is (0,1)
        }
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "ec_incomplete_add test: " << "\n";
        std::cout << "expected: " << expected_res.X.data << " " << expected_res.Y.data << "\n";
        std::cout << "real    : " << xR << " " << yR << "\n\n";
        #endif
        assert(foreign_integral_type(expected_res.X.data) == xR);
        assert(foreign_integral_type(expected_res.Y.data) == yR);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_incomplete_add(
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_P,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_Q,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type expected_res){

    using curve_type = CurveType;
    using NonNativeFieldType = typename curve_type::base_field_type;

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 10; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::ec_incomplete_add<ArithmetizationType, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    // transform EC point coords into chunks and put them into public input column
    std::vector<typename BlueprintFieldType::value_type> public_input;
    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          xP = foreign_integral_type(point_P.X.data),
                          yP = foreign_integral_type(point_P.Y.data),
                          xQ = foreign_integral_type(point_Q.X.data),
                          yQ = foreign_integral_type(point_Q.Y.data),
                          p = NonNativeFieldType::modulus,
                          ext_pow = foreign_integral_type(1) << num_chunks*bit_size_chunk,
                          pp = ext_pow - p;
    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % B));
            t /= B;
        }
    };
    chunks_to_public_input(xP);
    chunks_to_public_input(yP);
    chunks_to_public_input(xQ);
    chunks_to_public_input(yQ);
    chunks_to_public_input(p);
    chunks_to_public_input(pp);
    public_input.push_back(value_type(0)); // the zero

    // put references to public input column into instance input
    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.xP[i] = var(0, i, false, var::column_type::public_input);
        instance_input.yP[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.xQ[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
        instance_input.yQ[i] = var(0, 3*num_chunks + i, false, var::column_type::public_input);
        instance_input.p[i] = var(0, 4*num_chunks + i, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, 5*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.zero = var(0, 6*num_chunks, false, var::column_type::public_input);

    auto result_check = [&expected_res, &B](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        foreign_integral_type xR = 0,
                              yR = 0;
        for(std::size_t i = num_chunks; i > 0; i--) {
            xR *= B;
            yR *= B;
            xR += foreign_integral_type(var_value(assignment, real_res.xR[i-1]).data);
            yR += foreign_integral_type(var_value(assignment, real_res.yR[i-1]).data);
        }
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "ec_incomplete_add test: " << "\n";
        std::cout << "expected: " << expected_res.X.data << " " << expected_res.Y.data << "\n";
        std::cout << "real    : " << xR << " " << yR << "\n\n";
        #endif
        assert(foreign_integral_type(expected_res.X.data) == xR);
        assert(foreign_integral_type(expected_res.Y.data) == yR);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_two_t_plus_q(
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_T,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_Q,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type expected_res){

    using curve_type = CurveType;
    using NonNativeFieldType = typename curve_type::base_field_type;

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 10; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::ec_two_t_plus_q<ArithmetizationType, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    // transform EC point coords into chunks and put them into public input column
    std::vector<typename BlueprintFieldType::value_type> public_input;
    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          xT = foreign_integral_type(point_T.X.data),
                          yT = foreign_integral_type(point_T.Y.data),
                          xQ = foreign_integral_type(point_Q.X.data),
                          yQ = foreign_integral_type(point_Q.Y.data),
                          p = NonNativeFieldType::modulus,
                          ext_pow = foreign_integral_type(1) << num_chunks*bit_size_chunk,
                          pp = ext_pow - p;
    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % B));
            t /= B;
        }
    };

    chunks_to_public_input(xT);
    chunks_to_public_input(yT);
    chunks_to_public_input(xQ);
    chunks_to_public_input(yQ);
    chunks_to_public_input(p);
    chunks_to_public_input(pp);
    public_input.push_back(value_type(0)); // the zero

    // put references to public input column into instance input
    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.xT[i] = var(0, i, false, var::column_type::public_input);
        instance_input.yT[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.xQ[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
        instance_input.yQ[i] = var(0, 3*num_chunks + i, false, var::column_type::public_input);
        instance_input.p[i] = var(0, 4*num_chunks + i, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, 5*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.zero = var(0, 6*num_chunks, false, var::column_type::public_input);

    auto result_check = [&expected_res, &B](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        foreign_integral_type xR = 0,
                              yR = 0;
        for(std::size_t i = num_chunks; i > 0; i--) {
            xR *= B;
            yR *= B;
            xR += foreign_integral_type(var_value(assignment, real_res.xR[i-1]).data);
            yR += foreign_integral_type(var_value(assignment, real_res.yR[i-1]).data);
        }
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "ec_two_t_plus_q test: " << "\n";
        std::cout << "expected: " << expected_res.X.data << " " << expected_res.Y.data << "\n";
        std::cout << "real    : " << xR << " " << yR << "\n\n";
        #endif
        assert(foreign_integral_type(expected_res.X.data) == xR);
        assert(foreign_integral_type(expected_res.Y.data) == yR);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_scalar_mult(typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point_P,
    typename CurveType::scalar_field_type::value_type scalar,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type expected_res){

    using curve_type = CurveType;
    using NonNativeFieldType = typename curve_type::base_field_type;
    using ScalarFieldType = typename curve_type::scalar_field_type;

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 10; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::ec_scalar_mult<ArithmetizationType, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
    using foreign_integral_type = typename NonNativeFieldType::extended_integral_type;
    using scalar_integral_type = typename ScalarFieldType::extended_integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    // transform EC point coords into chunks and put them into public input column
    std::vector<typename BlueprintFieldType::value_type> public_input;
    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          xP = foreign_integral_type(point_P.X.data),
                          yP = foreign_integral_type(point_P.Y.data),
                          p = NonNativeFieldType::modulus,
                          ext_pow = foreign_integral_type(1) << num_chunks*bit_size_chunk,
                          pp = ext_pow - p;
    scalar_integral_type BS = scalar_integral_type(1) << bit_size_chunk,
                         s = scalar_integral_type(scalar.data),
                         n = ScalarFieldType::modulus,
                         m = (n-1)/2 + 1,
                         s_ext_pow = scalar_integral_type(1) << num_chunks*bit_size_chunk,
                         mp = s_ext_pow - m;

    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % B));
            t /= B;
        }
    };
    auto scalar_chunks_to_public_input = [&public_input, &BS](scalar_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % BS));
            t /= BS;
        }
    };
    scalar_chunks_to_public_input(s);
    chunks_to_public_input(xP);
    chunks_to_public_input(yP);
    chunks_to_public_input(p);
    chunks_to_public_input(pp);
    scalar_chunks_to_public_input(n);
    scalar_chunks_to_public_input(mp);
    public_input.push_back(value_type(0)); // the zero

    // put references to public input column into instance input
    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.s[i] = var(0, i, false, var::column_type::public_input);
        instance_input.x[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.y[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
        instance_input.p[i] = var(0, 3*num_chunks + i, false, var::column_type::public_input);
        instance_input.pp[i] = var(0, 4*num_chunks + i, false, var::column_type::public_input);
        instance_input.n[i] = var(0, 5*num_chunks + i, false, var::column_type::public_input);
        instance_input.mp[i] = var(0, 6*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.zero = var(0, 7*num_chunks, false, var::column_type::public_input);

    auto result_check = [&expected_res, &B](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        foreign_integral_type xR = 0,
                              yR = 0;
        for(std::size_t i = num_chunks; i > 0; i--) {
            xR *= B;
            yR *= B;
            xR += foreign_integral_type(var_value(assignment, real_res.xR[i-1]).data);
            yR += foreign_integral_type(var_value(assignment, real_res.yR[i-1]).data);
        }
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "ec_scalar_mul test: " << "\n";
        std::cout << "expected: " << expected_res.X.data << " " << expected_res.Y.data << "\n";
        std::cout << "real    : " << xR << " " << yR << "\n\n";
        #endif
        assert(foreign_integral_type(expected_res.X.data) == xR);
        assert(foreign_integral_type(expected_res.Y.data) == yR);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );
    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}

template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount>
void multi_test_doubling() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Q;

    for (std::size_t i = 0; i < RandomTestAmount; i++){
        Q = generate_random_point();
        std::cout << "Random test # " << (i+1) << "\n";
        test_doubling<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(Q, Q+Q);
    }
}

template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount>
void multi_test_incomplete_add() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P, Q;

    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        do {
           P = generate_random_point();
           Q = generate_random_point();
        } while(P.X == Q.X);
        std::cout << "Random test # " << (i+1) << "\n";
        test_incomplete_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, Q, P+Q);
    }
}

template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount>
void multi_test_full_add() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P, Q;

    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        do {
           P = generate_random_point();
           Q = generate_random_point();
        } while(P.X == Q.X);
        std::cout << "Random test # " << (i+1) << "\n";
        test_full_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, Q, P+Q);
    }
}

template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount>
void multi_test_full_add_with_zero() {
    using ec_point_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

//    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P,
//                                 Z = zero();
    ec_point_type P, Z = ec_point_type();

    std::cout << "O + O = O" << std::endl;
    test_full_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(Z, Z, Z);
    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        P = generate_random_point();
        std::cout << "Random test # " << (i+1) << "\n";
        std::cout << "P + P = 2P" << std::endl;
        test_full_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, P, P*2);
        std::cout << "P + O = P" << std::endl;
        test_full_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, Z, P);
        std::cout << "O + P = P" << std::endl;
        test_full_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(Z, P, P);
        std::cout << "P - P = O" << std::endl;
        test_full_add<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, -P, Z);
    }
}
template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount>
void multi_test_two_t_plus_q() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P, Q;

    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        do {
           P = generate_random_point();
           Q = generate_random_point();
        } while(P.X == Q.X);
        std::cout << "Random test # " << (i+1) << "\n";
        test_two_t_plus_q<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, Q, P+Q+P);
    }
}

template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount>
void multi_test_scalar_mult() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    nil::crypto3::random::algebraic_engine<typename CurveType::scalar_field_type> generate_random_scalar;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);
    generate_random_scalar.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P;
    typename CurveType::scalar_field_type::value_type s;

    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        P = generate_random_point();
        s = generate_random_scalar();
        std::cout << "Random test # " << (i+1) << "\n";
        test_scalar_mult<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(P, s, P*s);
        std::cout << "test done\n";
    }
}


constexpr static const std::size_t random_tests_amount = 1;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_ec_pallas) {
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using curve_type = crypto3::algebra::curves::pallas;
    std::cout << "Vesta base field\n";

    std::cout << "Doubling\n";
    multi_test_doubling<curve_type, vesta_field_type, 4, 64, 15, random_tests_amount>();
    std::cout << "Incomplete addition\n";
    multi_test_incomplete_add<curve_type, vesta_field_type, 4, 64, 10, random_tests_amount>();
    std::cout << "Full addition\n";
    multi_test_full_add<curve_type, vesta_field_type, 4, 64, 10, random_tests_amount>();
    multi_test_full_add_with_zero<curve_type, vesta_field_type, 4, 64, 10, random_tests_amount>();
    std::cout << "Two T plus Q\n";
    multi_test_two_t_plus_q<curve_type, vesta_field_type, 4, 64, 15, random_tests_amount>();
    std::cout << "Scalar multiplication\n";
    multi_test_scalar_mult<curve_type, vesta_field_type, 4, 64, 16, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_ec_vesta) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using curve_type = crypto3::algebra::curves::vesta;
    std::cout << "Pallas base field\n";

    std::cout << "Doubling\n";
    multi_test_doubling<curve_type, pallas_field_type, 4, 64, 10, random_tests_amount>();
    std::cout << "Incomplete addition\n";
    multi_test_incomplete_add<curve_type, pallas_field_type, 4, 64, 15, random_tests_amount>();
    std::cout << "Full addition\n";
    multi_test_full_add<curve_type, pallas_field_type, 4, 64, 15, random_tests_amount>();
    multi_test_full_add_with_zero<curve_type, pallas_field_type, 4, 64, 15, random_tests_amount>();
    std::cout << "Two T plus Q\n";
    multi_test_two_t_plus_q<curve_type, pallas_field_type, 4, 64, 10, random_tests_amount>();
    std::cout << "Scalar multiplication\n";
    multi_test_scalar_mult<curve_type, pallas_field_type, 4, 64, 10, random_tests_amount>();
}

// NB: this produces unsatisfied constraints
/*
BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_ec_bls381) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using curve_type = crypto3::algebra::curves::bls12<381>;

    std::cout << "Doubling\n";
    multi_test_doubling<curve_type, pallas_field_type, 6, 96, 16, random_tests_amount>();
    std::cout << "Incomplete addition\n";
    multi_test_incomplete_add<curve_type, pallas_field_type, 6, 96, 16, random_tests_amount>();
    std::cout << "Two T plus Q\n";
    multi_test_two_t_plus_q<curve_type, pallas_field_type, 6, 96, 16, random_tests_amount>();
}
*/
BOOST_AUTO_TEST_SUITE_END()
