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

// #include <nil/blueprint/components/algebra/curves/detail/plonk/bls12_g2_point_double.hpp>
#include <nil/blueprint/components/algebra/curves/detail/plonk/bls12_g2_point_addition.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

/*
template <typename CurveType>
void test_bls12_g2_doubling(std::vector<typename CurveType::base_field_type::value_type> public_input,
    typename CurveType::template g2_type<>::value_type expected_res){

    using curve_type = CurveType;
    using BlueprintFieldType = typename curve_type::g2_type<>::field_type::base_field_type;

    constexpr std::size_t WitnessColumns = 10;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlurprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::bls12_g2_point_double<ArithmetizationType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        typename curve_type::g2_type<>::field_type::value_type expected_x = expected_res.X / expected_res.Z.pow(2),
                                                               expected_y = expected_res.Y / expected_res.Z.pow(3);
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "G2 doubling test: " << "\n";
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

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9},{},{});

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}
*/

template <typename CurveType>
void test_bls12_g2_adding(std::vector<typename CurveType::base_field_type::value_type> public_input,
    typename CurveType::template g2_type<>::value_type expected_res){

    using curve_type = CurveType;
    using BlueprintFieldType = typename curve_type::g2_type<>::field_type::base_field_type;

    constexpr std::size_t WitnessColumns = 12;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::bls12_g2_point_addition<ArithmetizationType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        typename curve_type::g2_type<>::field_type::value_type expected_x = expected_res.X / expected_res.Z.pow(2),
                                                               expected_y = expected_res.Y / expected_res.Z.pow(3);
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "G2 addition test: " << "\n";
        std::cout << "input   : " << public_input[0].data << "," << public_input[1].data << "\n";
        std::cout << "input   : " << public_input[2].data << "," << public_input[3].data << "\n";
        std::cout << "input   : " << public_input[4].data << "," << public_input[5].data << "\n";
        std::cout << "input   : " << public_input[6].data << "," << public_input[7].data << "\n";
        std::cout << "expected: " << expected_x.data[0] << "," << expected_x.data[1] << ",\n";
        std::cout << "        : " << expected_y.data[0] << "," << expected_y.data[1] << ",\n";
        std::cout << "real    : " << var_value(assignment, real_res.R[0]).data << "," << var_value(assignment, real_res.R[1]).data << ",\n";
        std::cout << "          " << var_value(assignment, real_res.R[2]).data << "," << var_value(assignment, real_res.R[3]).data << "\n";
        std::cout << "Real adv: B1 = " << var_value(assignment,real_res.B1).data << ", B2 = " << var_value(assignment,real_res.B2).data << "\n";
        if ((public_input[4].data != 0) && (public_input[5].data != 0) &&
            (public_input[6].data != 0) && (public_input[7].data != 0)) {
            std::cout << "Expected adv: ";
            if (((public_input[0].data == 0) && (public_input[1].data == 0) &&
                 (public_input[2].data == 0) && (public_input[3].data == 0)) ||
                ((expected_x.data[0] == 0) && (expected_x.data[1] == 0) &&
                 (expected_y.data[0] == 0) && (expected_y.data[1] == 0))) {
                std::cout << "B1 = 1\n";
            } else {
                std::cout << "B1 = 0, ";
                if ((public_input[0].data == public_input[4].data) && (public_input[1].data == public_input[5].data) &&
                    (public_input[2].data == public_input[6].data) && (public_input[3].data == public_input[7].data)) {
                    std::cout << "B2 = 1\n";
                } else {
                    std::cout << "B2 = 0\n";
                }
            }
        }
        std::cout << "\n";
        #endif
        assert(expected_x.data[0] == var_value(assignment, real_res.R[0]));
        assert(expected_x.data[1] == var_value(assignment, real_res.R[1]));
        assert(expected_y.data[0] == var_value(assignment, real_res.R[2]));
        assert(expected_y.data[1] == var_value(assignment, real_res.R[3]));
        if ((public_input[4].data != 0) && (public_input[5].data != 0) &&
            (public_input[6].data != 0) && (public_input[7].data != 0)) {
            if (((public_input[0].data == 0) && (public_input[1].data == 0) &&
                 (public_input[2].data == 0) && (public_input[3].data == 0)) ||
                ((expected_x.data[0] == 0) && (expected_x.data[1] == 0) &&
                 (expected_y.data[0] == 0) && (expected_y.data[1] == 0))) {
                assert(var_value(assignment, real_res.B1) == 1);
            } else {
                assert(var_value(assignment, real_res.B1) == 0);
                if ((public_input[0].data == public_input[4].data) && (public_input[1].data == public_input[5].data) &&
                    (public_input[2].data == public_input[6].data) && (public_input[3].data == public_input[7].data)) {
                    assert(var_value(assignment, real_res.B2) == 1);
                } else {
                    assert(var_value(assignment, real_res.B2) == 0);
                }
            }
        }

    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},{},{});

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
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

    std::vector<group_value_type> test_g2elems = {  group_value_type(
                                field_value_type(integral_type("19354805336845174941142151562851080662656573665208680741935"
                                                             "4395577367693778571452628423727082668900187036482254730"),
                                                 integral_type("89193000964309942330810277795125089969455920364772498836102"
                                                             "2851024990473423938537113948850338098230396747396259901")),
                                field_value_type(integral_type("77171727205583415237828170597267125700535714547880090837365"
                                                             "9404991537354153455452961747174765859335819766715637138"),
                                                 integral_type("28103101185821266340411334541807053043930791391032529565024"
                                                             "04531123692847658283858246402311867775854528543237781718")),
                                field_value_type::one()),
                              group_value_type(
                                field_value_type(integral_type("424958340463073975547762735517193206833255107941790909009827635"
                                                             "556634414746056077714431786321247871628515967727334"),
                                                 integral_type("301867980397012787726282639381447252855741350432919474049536385"
                                                             "2840690589001358162447917674089074634504498585239512")),
                                field_value_type(integral_type("362130818512839545988899552652712755661476860447213217606042330"
                                                             "2734876099689739385100475320409412954617897892887112"),
                                                 integral_type("102447784096837908713257069727879782642075240724579670654226801"
                                                       "345708452018676587771714457671432122751958633012502")),
                                field_value_type::one()),
                              group_value_type(
                                field_value_type(integral_type("278579072823914661770244330824853538101603574852069839969013232"
                                                             "5213972292102741627498014391457605127656937478044880"),
                                                 integral_type("385570939363183188091016781827643518714796337112619879965480309"
                                                             "9743427431977934703201153169947378798970358200024876")),
                                field_value_type(integral_type("821938378705205565995357931232097952117504537366318395539093959"
                                                             "918654729488074273868834599496909844419980823111624"),
                                                 integral_type("180242033557577995098293558042145430208756792638522270794752735"
                                                             "3462942499437987207287862072369052390195154530059198")),
                                field_value_type::one()),
                              group_value_type(
                                field_value_type(integral_type("394904109851368845549123118074972479469719294319673003085328501"
                                                             "1755806989731870696216017360514887069032515603535834"),
                                                 integral_type("141689369450613197680900293521221631713294194257076384932306538"
                                                             "1335907430566747765697423320407614734575486820936593")),
                                field_value_type(integral_type("322745371086383503299296260585144940139139935513544272889379018"
                                                             "6263669279022343042444878900124369614767241382891922"),
                                                 integral_type("149873883407375987188646612293399676447188951453282792720277792"
                                                             "2460876335493588931070034160657995151627624577390178")),
                                field_value_type::one()),
                              group_value_type(
                                field_value_type(integral_type("254155017921606149907129844368549510385368618440139550318910532"
                                                             "874259603395336903946742408725761795820224536519988"),
                                                 integral_type("276843145929673042677916621854414979160158598623313058301150172"
                                                             "7704972362141149700714785450629498506208393873593705")),
                                field_value_type(integral_type("175533934474433745731856511606202566998475061793772124522071142"
                                                             "5551575490663761638802010265668157125441634554205566"),
                                                 integral_type("560643043433789571968941329642646582974304556331567393300563909"
                                                             "451776257854214387388500126524984624222885267024722")),
                                field_value_type::one())};

    for(std::size_t i = 0; i < test_g2elems.size(); i++) {
        std::cout << "Test instance # " << (i+1) << "\n";
        group_value_type P = test_g2elems[i];
        field_value_type px = field_value_type::zero(),
                         py = field_value_type::zero();
        if (P.Z != field_value_type::zero()) {
            px = P.X / P.Z.pow(2);
            py = P.Y / P.Z.pow(3);
        }
/*
        // doubling test
        std::cout << "Doubling\n";
        test_bls12_g2_doubling<curve_type>(
            std::vector<base_field_value>{px.data[0],px.data[1],py.data[0],py.data[1]},
            P*2);

        // test doubling within addition
        std::cout << "Doubling by addition\n";
        test_bls12_g2_adding<curve_type>(
            std::vector<base_field_value>{
                  px.data[0],px.data[1],
                  py.data[0],py.data[1],
                  px.data[0],px.data[1],
                  py.data[0],py.data[1]},
            P*2);

*/
        // addition tests
        field_value_type qx = field_value_type::zero(),
                         qy = field_value_type::zero();

        // test zero addition
        std::cout << "Addition P + 0\n";
        test_bls12_g2_adding<curve_type>(
            std::vector<base_field_value>{
                  px.data[0],px.data[1],
                  py.data[0],py.data[1],
                  qx.data[0],qx.data[1],
                  qy.data[0],qy.data[1]},
            P);
        std::cout << "Addition 0 + P\n";
        test_bls12_g2_adding<curve_type>(
            std::vector<base_field_value>{
                  qx.data[0],qx.data[1],
                  qy.data[0],qy.data[1],
                  px.data[0],px.data[1],
                  py.data[0],py.data[1]},
            P);

        // test opposite addition
        std::cout << "Addition of opposites\n";
        group_value_type g2zero = group_value_type(field_value_type::zero(), field_value_type::zero(),field_value_type::zero());

        test_bls12_g2_adding<curve_type>(
            std::vector<base_field_value>{
                  px.data[0],px.data[1],
                  py.data[0],py.data[1],
                  px.data[0],px.data[1],
                  -py.data[0],-py.data[1]},
            g2zero);


        std::cout << "Doubling addition\n";
        group_value_type Q = test_g2elems[i];
        if (Q.Z != field_value_type::zero()) {
            qx = Q.X / Q.Z.pow(2);
            qy = Q.Y / Q.Z.pow(3);
        }
        test_bls12_g2_adding<curve_type>(
            std::vector<base_field_value>{
                px.data[0],px.data[1],
                py.data[0],py.data[1],
                qx.data[0],qx.data[1],
                qy.data[0],qy.data[1]},
            P + Q);

        // non-trivial addition tests
        if (i + 1 < test_g2elems.size()) {
            std::cout << "Non-trivial additions\n";
        }
        for(std::size_t j = i + 1; j < test_g2elems.size(); j++) {
            group_value_type Q = test_g2elems[j];
            if (Q.Z != field_value_type::zero()) {
                qx = Q.X / Q.Z.pow(2);
                qy = Q.Y / Q.Z.pow(3);
            }
            test_bls12_g2_adding<curve_type>(
                std::vector<base_field_value>{
                    px.data[0],px.data[1],
                    py.data[0],py.data[1],
                    qx.data[0],qx.data[1],
                    qy.data[0],qy.data[1]},
                P + Q);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
