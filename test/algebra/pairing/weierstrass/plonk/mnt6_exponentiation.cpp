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

#define BOOST_TEST_MODULE blueprint_plonk_pairing_mnt6_298

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/mnt6_exponentiation.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType, std::size_t WitnessColumns>
void test_mnt6_298_exponentiation(std::vector<typename FieldType::value_type> public_input,
                            std::vector<typename FieldType::value_type> expected_res) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 8;

    zk::snark::plonk_table_description<FieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::mnt6_exponentiation<ArithmetizationType>;

    typename component_type::input_type instance_input = {
        var(0,0, false, var::column_type::public_input), // f[0]
        var(0,1, false, var::column_type::public_input), // f[1]
        var(0,2, false, var::column_type::public_input), // f[2]
        var(0,3, false, var::column_type::public_input), // f[3]
        var(0,4, false, var::column_type::public_input), // f[3]
        var(0,5, false, var::column_type::public_input), // f[3]
      };

    auto result_check = [&expected_res](AssignmentType const& assignment,
        typename component_type::result_type const& real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "mnt6-298 Final exponentiation: expected res VS output\n";
        for(std::size_t i = 0; i < 6; i++) {
            std::cout << std::dec << expected_res[i].data << " =? " << var_value(assignment, real_res.output[i]).data << "\n";
        }
        #endif
        for(std::size_t i = 0; i < 6; i++) {
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

    nil::crypto3::test_component<component_type, FieldType, hash_type, Lambda> (
           component_instance, desc, public_input, result_check, instance_input);
}

static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_mnt6_pairing_test) {
    using curve_type = crypto3::algebra::curves::mnt6_298;
    using gt_group_type = typename curve_type::gt_type;
    using base_field_value = curve_type::base_field_type::value_type;
    using field_type = typename curve_type::gt_type::base_field_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    std::vector<field_type::value_type>
        AB_ML = {
            0x02f487892d5db56458de095daa86a1ebb90a07517cccad41a46b48438ca24173be6f3a32c6cb_cppui298,
            0x01217e7c9d35c9c75d1fbcb5d46e482d053c9da4ab9f3c37b741900af9ca42ff9b50001aec5f_cppui298,
            0x01f0324b79887ef191ff8d0c9152cfed7445abb63faa598eaa51ddfea0af7a642f7cf6ba70fe_cppui298,
            0x033f650fdb078d7fb4a8153c8c621d84dd01460a4173bd01371d360e71c6cb46392dd0e00f1f_cppui298,
            0x0023d3795211bb71c579250426dc77d6c7a32a24136b0f02780be3b2f4c674b54a6a5989f9f4_cppui298,
            0x01b5c328e47a03bddb00f0992ddbd9945af3e0f4bb8244d29b9b24ca2390e92ecc5666a76191_cppui298
        },
        AB_FE = {
            /*
            0x15dec519566f20aa6a3bd4ddb0cee93f9ea157499f20273124883934daeea1867ea53ac4b9b_cppui298,
            0x3b5fc396c41a54c7c661b3d34ead6f284a50886534f036c004eb31d8d7cb061d3419f6a9d58_cppui298,
            0x1b79ac259f41bfdc8aa623c65075d0a0fb1823467b174c4ac82cada904d96f3640fd491baf7_cppui298,
            0x667fef1c7f96557416d9728951128edb921b4ecad5592fd898db5867bf40dfa20de956a717_cppui298,
            0x39143f4b1cee4646b2a1a77d27fc21aead95a0922a4a5f9facb82d88120b01737fafb1f1d8d_cppui298,
            0x2f84e7545b29729839b5871c25a131756558cd8bba38d2ef7439f20b5cb54be2a271a3c1bba_cppui298,
            */
            0x025aba200efbefa81017a858457abfc1e83ce8f7e92788e414fe90bacd465395dec8463bf09a_cppui298,
            0x002ca86c9adeb0cfd62db143cc3fc5b6adb9fd09419a43b6c5b841f129a0ef71fa3881a4b743_cppui298,
            0x00e7bc013d484cc770ddcaa994422f153265c143a64549b916f6893c2e2ab5458e7c3ea5f3d7_cppui298,
            0x01b26a752dd48454cc5361994c65bbea4f5315383c0051be7285afebd49608614a17945879ff_cppui298,
            0x0378d4dd54964822cabd59be83661224fb84a4820c190c62d3a701e2eaf60ac8dc13e0db1c99_cppui298,
            0x037f4a31f3bc24e9876d57a5b224d8f6475d36407e092bc03144d1bf042a0aee471639db2439_cppui298
        };

     std::cout << "mnt6-298 Final exponentiation test\n";
     test_mnt6_298_exponentiation<field_type, 6>(AB_ML, AB_FE);
}

BOOST_AUTO_TEST_SUITE_END()
