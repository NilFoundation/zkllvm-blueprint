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

#define BOOST_TEST_MODULE blueprint_plonk_mnt6_298_miller_loop

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

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

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/mnt6_miller_loop.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType, std::size_t WitnessColumns>
void test_mnt6_298_miller_loop(std::vector<typename FieldType::value_type> public_input,
                            std::vector<typename FieldType::value_type> expected_res) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = (WitnessColumns == 12)? (4 + 8) : (4 + 9);

    zk::snark::plonk_table_description<FieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::mnt6_miller_loop<ArithmetizationType>;

    typename component_type::input_type instance_input = {
        var(0,0, false, var::column_type::public_input), // xP
        var(0,1, false, var::column_type::public_input), // yP
        var(0,2, false, var::column_type::public_input), // xQ[0]
        var(0,3, false, var::column_type::public_input), // xQ[1]
        var(0,4, false, var::column_type::public_input), // xQ[2]
        var(0,5, false, var::column_type::public_input), // yQ[0]
        var(0,6, false, var::column_type::public_input), // yQ[1]
        var(0,7, false, var::column_type::public_input)  // yQ[2]
      };

    auto result_check = [&expected_res](AssignmentType const& assignment,
        typename component_type::result_type const& real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "mnt6-298 Miller loop: expected res VS output\n";
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
            std::array<std::uint32_t, 1>{0}, // constants
            std::array<std::uint32_t, 0>{}  // public inputs
            );

    nil::crypto3::test_component<component_type, FieldType, hash_type, Lambda> (
           component_instance, desc, public_input, result_check, instance_input);
}

static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_mnt6_miller_loop_test) {
    using curve_type = crypto3::algebra::curves::mnt6_298;
    using g2_group_type = typename curve_type::g2_type<>;
    using base_field_value = curve_type::base_field_type::value_type;
    using field_type = typename curve_type::g2_type<>::field_type::base_field_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    std::vector<field_type::value_type>
        AB = {
            // A :[
            0x013db0919ea4c2e5f62f79066ece6331ac4ca87e016bdbd7ac867d46a425b7fa24855c7a6ae3_cppui298,
            0x01a9409846dc9b92c558f3b99b90e1cc3027d9c0960b336be3939efd12c0fcc2321def266305_cppui298,
            // ]
            
            // B :[ [
            0x02962e2327b49141eb2d2435895ff40c49b3e071d5a18cddc504dd6ef5b62980bb8e8c0f5299_cppui298,
            0x002728d4acbbea319d32c137e09fe8fb40511ffbd4b6ae02a0d5c76b675b766a1c9bc91c0cf8_cppui298,
            0x025846902d06ccb8f14964d331ced68468f31441f366aaff4b0b5dd6eb720cd8f2460b789237_cppui298,
            0x0243124387533c863787fbaa1d58a942fe571660b77d80f3df036874309c7f1fcaef47611977_cppui298,
            0x00b5be310d4b9f76606e3206c435d1bee679ff0e1efe668e437e720d0e6e31965db04109f38c_cppui298,
            0x001638d3b614667d3bb2c0c2e6e2e8b675d5453cdf3dd15810e4b06fde235f90d7b48f4676c0_cppui298,

            // ]]
        },
        AB_ML = {
            0x014034d3b8d52de5928a1b9073c373ce4107cbc98f9e34f6668de3898348133a193f2e34bfbc_cppui298,
            0x01261e232991430aa026545185afa3f20a4c86805f16e4c8ac27dffca62c23f1a7ca593f688e_cppui298,
            0x0069b3852c840dcc9563ecab53e1e649a5a4d4d268426b97bc8f9e77ffe3d555af7aebe41f69_cppui298,
            0x0230b995ed242adb3cea7e18971999dac6183622d15672f4b7e429dde4ce31be6d71619285d6_cppui298,
            0x02e690f97b2447b0c0f5a4349bc4d65cf87bc7f076df4ea689873e9231f0ad49520ea3e439c6_cppui298,
            0x016b1fef1c14c52e7f400545f8b548aed78670a0a47d7681b36ec686f504975ad26df1201fdc_cppui298
        };

     std::cout << "mnt6-298 Miller loop test\n";
     test_mnt6_298_miller_loop<field_type,26>(AB, AB_ML);
}

BOOST_AUTO_TEST_SUITE_END()
