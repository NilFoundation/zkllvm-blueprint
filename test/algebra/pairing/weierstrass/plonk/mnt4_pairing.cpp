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

#define BOOST_TEST_MODULE blueprint_plonk_pairing_mnt4_298

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/mnt4_miller_loop.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType, std::size_t WitnessColumns>
void test_mnt4_298_miller_loop(std::vector<typename FieldType::value_type> public_input,
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

    using component_type = blueprint::components::mnt4_miller_loop<ArithmetizationType>;

    typename component_type::input_type instance_input = {
        var(0,0, false, var::column_type::public_input), // xP
        var(0,1, false, var::column_type::public_input), // yP
        var(0,2, false, var::column_type::public_input), // xQ[0]
        var(0,3, false, var::column_type::public_input), // xQ[1]
        var(0,4, false, var::column_type::public_input), // yQ[0]
        var(0,5, false, var::column_type::public_input)  // yQ[1]
      };

    auto result_check = [&expected_res](AssignmentType const& assignment,
        typename component_type::result_type const& real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "MNT4-298 Miller loop: expected res VS output\n";
        for(std::size_t i = 0; i < 4; i++) {
            std::cout << std::dec << expected_res[i].data << " =? " << var_value(assignment, real_res.output[i]).data << "\n";
        }
        #endif
        for(std::size_t i = 0; i < 4; i++) {
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

BOOST_AUTO_TEST_CASE(blueprint_plonk_mnt4_pairing_test) {
    using curve_type = crypto3::algebra::curves::mnt4_298;
    using g2_group_type = typename curve_type::g2_type<>;
    using base_field_value = curve_type::base_field_type::value_type;
    using field_type = typename curve_type::g2_type<>::field_type::base_field_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    std::vector<field_type::value_type>
        AB = {
            // A :[
            0x02ee42725289d05230b6700ba1696044a839c30e114c65ab98d5d0764b9c79c06d207c5f3d12_cppui298,
            0x0377ea5dd66341cb88b291c103eec911946c7266fabbda487ef3ac48e5954253df56f89ebe49_cppui298,
            // ]
            
            // B :[ [
                0x012212f4ac5a2b6262dcd15a0fb4e54d276d734d80e3868dc93a074b3a9ebeb598641aa2310d_cppui298,
                0x017600e8757679e06b66de2c48b3370e582443d4c0091ef1e6d96dadb92150ff642709dd806b_cppui298,
                0x02a1135b45f576b0988c2f5e852def5e829508beddae07427cc68929ffbeaa49de4d370cfa69_cppui298,
                0x0246c479956c92096a1dfa7cdb992b53ecb05f96d581fcb755045898fb459fd569753da2c2a7_cppui298
                // ]]
        },
        AB_ML = {
            0x01f3f02a39499cca91c7c3a108cc0721047455bc2def95bcb613a1749c1bbe0fb0d88088699b_cppui298,
            0x00eeaea28cc850898e84e44ec6ae59fb0079c1d1c93f0f6e30c541695c45c4b9e3df07db6b77_cppui298,
            0x030ffc05991f5ac550b3c37b44c253e2c2a39359ec30d0ec24f4c42e3a6b937d02653c92e7d5_cppui298,
            0x001e339f66ccb68e51bab41310a5d30d2f51a002ae9b7bcf506c0c44447c725f0e2b618e9571_cppui298
        };

     std::cout << "MNT4-298 Miller loop test\n";
     test_mnt4_298_miller_loop<field_type,18>(AB, AB_ML);
}

BOOST_AUTO_TEST_SUITE_END()
