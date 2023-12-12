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

#define BOOST_TEST_MODULE blueprint_plonk_pairing_bls12_381

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/detail/fp12_power_tminus1sq_over3.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/bls12_exponentiation.hpp>
#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/bls12_miller_loop.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType, std::size_t WitnessColumns>
void test_fp12_power_tm1sq3(std::vector<typename FieldType::value_type> public_input) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = (WitnessColumns == 12)? 5 : 6;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::fp12_power_tm1sq3<ArithmetizationType, FieldType>;

    typename component_type::input_type instance_input;
    typename std::array<value_type,12> X;
    typename std::array<value_type,12> expected_res;

    for(std::size_t i = 0; i < 12; i++) {
        instance_input.x[i] = var(0,i, false, var::column_type::public_input);
        X[i] = public_input[i];
    }

    using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<FieldType>;
    using fp12_element = typename policy_type_fp12::value_type;

    fp12_element e0 = fp12_element({ {X[0],X[1]}, {X[2],X[3]}, {X[4],X[5]} }, { {X[6],X[7]}, {X[8],X[9]}, {X[10],X[11]} }),
                 y = e0.pow((0xD201000000010000 + 1)/3), // fp12 power raising
                 e = y.pow(0xD201000000010000 + 1); // the power is too big to be computed in one pow( ) operation

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
            std::cout << "Fp12 power (1-t)^2/3 res vs output\n";
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
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
}

template <typename FieldType, std::size_t WitnessColumns>
void test_bls12_exponentiation(std::vector<typename FieldType::value_type> public_input) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = (WitnessColumns == 12)? 9 : 10;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::bls12_exponentiation<ArithmetizationType, FieldType>;

    typename component_type::input_type instance_input;
    typename std::array<value_type,12> X;
    typename std::array<value_type,12> expected_res;

    for(std::size_t i = 0; i < 12; i++) {
        instance_input.x[i] = var(0,i, false, var::column_type::public_input);
        X[i] = public_input[i];
    }

    using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<FieldType>;
    using fp12_element = typename policy_type_fp12::value_type;

    typename FieldType::integral_type field_p = FieldType::modulus,
                                      minus_t = 0xD201000000010000;

    fp12_element e0 = fp12_element({ {X[0],X[1]}, {X[2],X[3]}, {X[4],X[5]} }, { {X[6],X[7]}, {X[8],X[9]}, {X[10],X[11]} }),
                 e = e0, f;

    for(std::size_t i = 0; i < 6; i++) {
        e = e.pow(field_p);
    } // e0^{p^6}
    e = e * e0.inversed(); // e0^{p^6 - 1}
    e = e.pow(field_p).pow(field_p) * e; // (e0^{p^6 - 1})^{p^2 + 1}
    f = e.pow((minus_t + 1)*(minus_t + 1)/3);

    e = e * f.pow(field_p).pow(field_p).pow(field_p) * f.pow(minus_t).inversed().pow(field_p).pow(field_p) *
            f.pow(minus_t*minus_t-1).pow(field_p - minus_t);

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
            std::cout << "BLS12-381 exponentiation expected res vs output\n";
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
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
}

template <typename CurveType, std::size_t WitnessColumns>
void test_bls12_miller_loop(std::vector<typename CurveType::base_field_type::value_type> public_input,
    typename CurveType::template g2_type<>::value_type expected_res) {

    using curve_type = CurveType;
    using FieldType = typename curve_type::g2_type<>::field_type::base_field_type;

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = (WitnessColumns == 12)? 5 : 6;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::bls12_miller_loop<ArithmetizationType, FieldType>;

    typename component_type::input_type instance_input;
/*
    value_type xP, yP;
    std::array<value_type,2> xQ, yQ;
    std::array<value_type,12> expected_res;
*/
    instance_input.P[0] = var(0,0, false, var::column_type::public_input); // xP    = public_input[0];
    instance_input.P[1] = var(0,1, false, var::column_type::public_input); // yP    = public_input[1];
    instance_input.Q[0] = var(0,2, false, var::column_type::public_input); // xQ[0] = public_input[2];
    instance_input.Q[1] = var(0,3, false, var::column_type::public_input); // xQ[1] = public_input[3];
    instance_input.Q[2] = var(0,4, false, var::column_type::public_input); // yQ[0] = public_input[4];
    instance_input.Q[3] = var(0,5, false, var::column_type::public_input); // yQ[1] = public_input[5];

/*
    using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<FieldType>;
    using fp12_element = typename policy_type_fp12::value_type;


    fp12_element e = fp12_element::zero();
    fp12_element({ {X[0],X[1]}, {X[2],X[3]}, {X[4],X[5]} }, { {X[6],X[7]}, {X[8],X[9]}, {X[10],X[11]} }),
                 e = e0, f;

    for(std::size_t i = 0; i < 6; i++) {
        e = e.pow(field_p);
    } // e0^{p^6}
    e = e * e0.inversed(); // e0^{p^6 - 1}
    e = e.pow(field_p).pow(field_p) * e; // (e0^{p^6 - 1})^{p^2 + 1}
    f = e.pow((minus_t + 1)*(minus_t + 1)/3);

    e = e * f.pow(field_p).pow(field_p).pow(field_p) * f.pow(minus_t).inversed().pow(field_p).pow(field_p) *
            f.pow(minus_t*minus_t-1).pow(field_p - minus_t);

    expected_res = {
       e.data[0].data[0].data[0], e.data[0].data[0].data[1],
       e.data[0].data[1].data[0], e.data[0].data[1].data[1],
       e.data[0].data[2].data[0], e.data[0].data[2].data[1],
       e.data[1].data[0].data[0], e.data[1].data[0].data[1],
       e.data[1].data[1].data[0], e.data[1].data[1].data[1],
       e.data[1].data[2].data[0], e.data[1].data[2].data[1] };

*/

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
            typename component_type::result_type &real_res) {
        typename curve_type::g2_type<>::field_type::value_type expected_x = expected_res.X / expected_res.Z.pow(2),
                                                               expected_y = expected_res.Y / expected_res.Z.pow(3);

        std::array<value_type,4> exp_res_arr = {expected_x.data[0],
                                                expected_x.data[1],
                                                expected_y.data[0],
                                                expected_y.data[1]
                                               };
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "BLS12-381 Miller loop expected res vs output\n";
        std::cout << "expected: " << expected_x.data[0] << "," << expected_x.data[1] << ",\n";
        std::cout << "        : " << expected_y.data[0] << "," << expected_y.data[1] << ",\n";
        std::cout << "real    : " << var_value(assignment, real_res.output[8]).data << ","
                                  << var_value(assignment, real_res.output[9]).data << ",\n";
        std::cout << "          " << var_value(assignment, real_res.output[10]).data << ","
                                  << var_value(assignment, real_res.output[11]).data << "\n\n";
        #endif
        for(std::size_t i = 0; i < 4; i++) {
//            assert(exp_res_arr[i] == var_value(assignment, real_res.output[8 + i]));
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

    nil::crypto3::test_component<component_type, FieldType, ArithmetizationParams, hash_type, Lambda> (
           component_instance, public_input, result_check, instance_input, nil::crypto3::detail::connectedness_check_type::STRONG);
}


static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_non_native_fp12_test) {
    using curve_type = crypto3::algebra::curves::bls12_381;
    using g2_group_type = typename curve_type::g2_type<>;
    using base_field_value = curve_type::base_field_type::value_type;
    using field_type = typename curve_type::g2_type<>::field_type::base_field_type; //typename crypto3::algebra::fields::bls12_fq<381>;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);
/*
    for(std::size_t i = 0; i < random_tests_amount; i++) {
        std::cout << "Random test # " << (i+1) << "\n";

        std::vector<field_type::value_type> x = {};

        for(std::size_t j = 0; j < 12; j++) {
            x.push_back(generate_random());
        }
        std::cout << "Power (1-t)^2/3\n";
        std::cout << "12 columns\n";
        test_fp12_power_tm1sq3<field_type,12>(x);
        std::cout << "24 columns\n";
        test_fp12_power_tm1sq3<field_type,24>(x);

        std::cout << "Complete exponentiation\n";
        std::cout << "12 columns\n";
        test_bls12_exponentiation<field_type,12>(x);
        std::cout << "24 columns\n";
        test_bls12_exponentiation<field_type,24>(x);
    }
*/
    std::cout << "The Miller loop\n";
    typedef typename g2_group_type::value_type g2_group_value_type;
    typedef typename g2_group_type::field_type::value_type g2_field_value_type;
    typedef typename g2_group_type::field_type::integral_type g2_integral_type;

    g2_integral_type minus_t = 0xD201000000010000;

    std::vector<g2_group_value_type> test_g2elems = {  g2_group_value_type(
                                g2_field_value_type(g2_integral_type("19354805336845174941142151562851080662656573665208680741935"
                                                             "4395577367693778571452628423727082668900187036482254730"),
                                                 g2_integral_type("89193000964309942330810277795125089969455920364772498836102"
                                                             "2851024990473423938537113948850338098230396747396259901")),
                                g2_field_value_type(g2_integral_type("77171727205583415237828170597267125700535714547880090837365"
                                                             "9404991537354153455452961747174765859335819766715637138"),
                                                 g2_integral_type("28103101185821266340411334541807053043930791391032529565024"
                                                             "04531123692847658283858246402311867775854528543237781718")),
                                g2_field_value_type::one()),
                              g2_group_value_type(
                                g2_field_value_type(g2_integral_type("424958340463073975547762735517193206833255107941790909009827635"
                                                             "556634414746056077714431786321247871628515967727334"),
                                                 g2_integral_type("301867980397012787726282639381447252855741350432919474049536385"
                                                             "2840690589001358162447917674089074634504498585239512")),
                                g2_field_value_type(g2_integral_type("362130818512839545988899552652712755661476860447213217606042330"
                                                             "2734876099689739385100475320409412954617897892887112"),
                                                 g2_integral_type("102447784096837908713257069727879782642075240724579670654226801"
                                                       "345708452018676587771714457671432122751958633012502")),
                                g2_field_value_type::one()),
                              g2_group_value_type(
                                g2_field_value_type(g2_integral_type("278579072823914661770244330824853538101603574852069839969013232"
                                                             "5213972292102741627498014391457605127656937478044880"),
                                                 g2_integral_type("385570939363183188091016781827643518714796337112619879965480309"
                                                             "9743427431977934703201153169947378798970358200024876")),
                                g2_field_value_type(g2_integral_type("821938378705205565995357931232097952117504537366318395539093959"
                                                             "918654729488074273868834599496909844419980823111624"),
                                                 g2_integral_type("180242033557577995098293558042145430208756792638522270794752735"
                                                             "3462942499437987207287862072369052390195154530059198")),
                                g2_field_value_type::one()),
                              g2_group_value_type(
                                g2_field_value_type(g2_integral_type("394904109851368845549123118074972479469719294319673003085328501"
                                                             "1755806989731870696216017360514887069032515603535834"),
                                                 g2_integral_type("141689369450613197680900293521221631713294194257076384932306538"
                                                             "1335907430566747765697423320407614734575486820936593")),
                                g2_field_value_type(g2_integral_type("322745371086383503299296260585144940139139935513544272889379018"
                                                             "6263669279022343042444878900124369614767241382891922"),
                                                 g2_integral_type("149873883407375987188646612293399676447188951453282792720277792"
                                                             "2460876335493588931070034160657995151627624577390178")),
                                g2_field_value_type::one()),
                              g2_group_value_type(
                                g2_field_value_type(g2_integral_type("254155017921606149907129844368549510385368618440139550318910532"
                                                             "874259603395336903946742408725761795820224536519988"),
                                                 g2_integral_type("276843145929673042677916621854414979160158598623313058301150172"
                                                             "7704972362141149700714785450629498506208393873593705")),
                                g2_field_value_type(g2_integral_type("175533934474433745731856511606202566998475061793772124522071142"
                                                             "5551575490663761638802010265668157125441634554205566"),
                                                 g2_integral_type("560643043433789571968941329642646582974304556331567393300563909"
                                                             "451776257854214387388500126524984624222885267024722")),
                                g2_field_value_type::one())};

//    for(std::size_t i = 0; i < test_g2elems.size(); i++) {
        std::size_t i = 0; // TODO remove!
        std::cout << "Test instance # " << (i+1) << "\n";

        g2_group_value_type Q = test_g2elems[i];

        std::vector<field_type::value_type> x = {};
        for(std::size_t j = 0; j < 2; j++) {
            x.push_back(generate_random());
        }
        x.push_back(Q.X.data[0]);
        x.push_back(Q.X.data[1]);
        x.push_back(Q.Y.data[0]);
        x.push_back(Q.Y.data[1]);
        std::cout << "12 columns\n";
        test_bls12_miller_loop<curve_type,12>(x, Q*minus_t);
        std::cout << "24 columns\n";
        test_bls12_miller_loop<curve_type,24>(x, Q*minus_t);
//    }
}

BOOST_AUTO_TEST_SUITE_END()
