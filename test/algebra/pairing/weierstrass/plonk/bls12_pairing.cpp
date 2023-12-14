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
#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/bls12_381_pairing.hpp>

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

template <typename FieldType, std::size_t WitnessColumns>
void test_bls12_381_pairing(std::vector<typename FieldType::value_type> public_input,
                            std::vector<typename FieldType::value_type> expected_res) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = (WitnessColumns == 12)? (5 + 9) : (6 + 10);

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::bls12_381_pairing<ArithmetizationType, FieldType>;

    typename component_type::input_type instance_input = {
        var(0,0, false, var::column_type::public_input), // xP
        var(0,1, false, var::column_type::public_input), // yP
        var(0,2, false, var::column_type::public_input), // xQ[0]
        var(0,3, false, var::column_type::public_input), // xQ[1]
        var(0,4, false, var::column_type::public_input), // yQ[0]
        var(0,5, false, var::column_type::public_input)  // yQ[1]
      };

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "BLS12-381 pairing: expected res VS output\n";
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

     std::vector<field_type::value_type> x = {
         0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb_cppui381,
         0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1_cppui381,
         0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8_cppui381,
         0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e_cppui381,
         0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801_cppui381,
         0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be_cppui381
     },
/*
     // reference result values from draft-irtf-cfrg-pairing-friendly-curves-11
     // (https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html)
     // FAULTY!!! values 0-5 are OK, but 6-11 don't match!
     e = {
         0x11619b45f61edfe3b47a15fac19442526ff489dcda25e59121d9931438907dfd448299a87dde3a649bdba96e84d54558_cppui381,
         0x153ce14a76a53e205ba8f275ef1137c56a566f638b52d34ba3bf3bf22f277d70f76316218c0dfd583a394b8448d2be7f_cppui381,
         0x095668fb4a02fe930ed44767834c915b283b1c6ca98c047bd4c272e9ac3f3ba6ff0b05a93e59c71fba77bce995f04692_cppui381,
         0x16deedaa683124fe7260085184d88f7d036b86f53bb5b7f1fc5e248814782065413e7d958d17960109ea006b2afdeb5f_cppui381,
         0x09c92cf02f3cd3d2f9d34bc44eee0dd50314ed44ca5d30ce6a9ec0539be7a86b121edc61839ccc908c4bdde256cd6048_cppui381,
         0x111061f398efc2a97ff825b04d21089e24fd8b93a47e41e60eae7e9b2a38d54fa4dedced0811c34ce528781ab9e929c7_cppui381,
         0x01ecfcf31c86257ab00b4709c33f1c9c4e007659dd5ffc4a735192167ce197058cfb4c94225e7f1b6c26ad9ba68f63bc_cppui381,
         0x08890726743a1f94a8193a166800b7787744a8ad8e2f9365db76863e894b7a11d83f90d873567e9d645ccf725b32d26f_cppui381,
         0x0e61c752414ca5dfd258e9606bac08daec29b3e2c57062669556954fb227d3f1260eedf25446a086b0844bcd43646c10_cppui381,
         0x0fe63f185f56dd29150fc498bbeea78969e7e783043620db33f75a05a0a2ce5c442beaff9da195ff15164c00ab66bdde_cppui381,
         0x10900338a92ed0b47af211636f7cfdec717b7ee43900eee9b5fc24f0000c5874d4801372db478987691c566a8c474978_cppui381,
         0x1454814f3085f0e6602247671bc408bbce2007201536818c901dbd4d2095dd86c1ec8b888e59611f60a301af7776be3d_cppui381
     };
*/
     // reference result values generated by python code from https://github.com/algorand/bls_sigs_ref/tree/master/python-impl
     e = {
         0x11619b45f61edfe3b47a15fac19442526ff489dcda25e59121d9931438907dfd448299a87dde3a649bdba96e84d54558_cppui381,
         0x153ce14a76a53e205ba8f275ef1137c56a566f638b52d34ba3bf3bf22f277d70f76316218c0dfd583a394b8448d2be7f_cppui381,
         0x95668fb4a02fe930ed44767834c915b283b1c6ca98c047bd4c272e9ac3f3ba6ff0b05a93e59c71fba77bce995f04692_cppui381,
         0x16deedaa683124fe7260085184d88f7d036b86f53bb5b7f1fc5e248814782065413e7d958d17960109ea006b2afdeb5f_cppui381,
         0x9c92cf02f3cd3d2f9d34bc44eee0dd50314ed44ca5d30ce6a9ec0539be7a86b121edc61839ccc908c4bdde256cd6048_cppui381,
         0x111061f398efc2a97ff825b04d21089e24fd8b93a47e41e60eae7e9b2a38d54fa4dedced0811c34ce528781ab9e929c7_cppui381,
         0x181414f71cf9c11f9b1060ac800c903b1676d52b16251674f3df408a79cf5f1e91b0b36a8ef580e44dd85264597046ef_cppui381,
         0x11780ac3c545c705a3026d9fdb4af55eed32a2d765557f598bba4c626d657c12466c6f263dfd816255a2308da4ccd83c_cppui381,
         0xb9f4a97f83340ba78c2be55d79fa3fc784d97a22e14b058d1da3d5144892232f89d120c5d0d5f79097ab432bc9b3e9b_cppui381,
         0xa1ad2d1da290971360be31d875d054dfa8f6401ef4ef1e43339789b560e27c7da8014ff13b26a00a4e8b3ff5498eccd_cppui381,
         0x9710eb1905115e5d0299652d3ceaeeaf2fbcca0ba8423d5b134adb0f6a49daf4a2bec8bd60c767850e2a99573b86133_cppui381,
         0x5ac909b08f9f5b3eaf9604f2787a41b96574464de4e9132d7131553d61b189d5cbf747622fa9ee0595bfe508888ec6e_cppui381
     };

     std::cout << "BLS12-381 pairing test\n 12 columns\n";
     test_bls12_381_pairing<field_type,12>(x, e);
     std::cout << "24 columns\n";
     test_bls12_381_pairing<field_type,24>(x, e);
}

BOOST_AUTO_TEST_SUITE_END()
