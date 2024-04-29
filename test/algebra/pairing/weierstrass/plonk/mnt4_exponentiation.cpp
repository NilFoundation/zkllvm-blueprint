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

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/mnt4_exponentiation.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;
using namespace blueprint::components::detail;

template <typename FieldType, std::size_t WitnessColumns>
void test_mnt4_298_exponentiation(std::vector<typename FieldType::value_type> public_input,
                            std::vector<typename FieldType::value_type> expected_res) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 8;

    zk::snark::plonk_table_description<FieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::mnt4_exponentiation<ArithmetizationType>;

    typename component_type::input_type instance_input = {
        var(0,0, false, var::column_type::public_input), // f[0]
        var(0,1, false, var::column_type::public_input), // f[1]
        var(0,2, false, var::column_type::public_input), // f[2]
        var(0,3, false, var::column_type::public_input), // f[3]
      };

    auto result_check = [&expected_res](AssignmentType const& assignment,
        typename component_type::result_type const& real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "MNT4-298 Final exponentiation: expected res VS output\n";
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
            std::array<std::uint32_t, 0>{}, // constants
            std::array<std::uint32_t, 0>{}  // public inputs
            );

    nil::crypto3::test_component<component_type, FieldType, hash_type, Lambda> (
           component_instance, desc, public_input, result_check, instance_input);
}

static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_mnt4_pairing_test) {
    using curve_type = crypto3::algebra::curves::mnt4_298;
    using gt_group_type = typename curve_type::gt_type;
    using field_type = typename curve_type::gt_type::base_field_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    std::vector<field_type::value_type>
        AB_ML = {
            0x01f3f02a39499cca91c7c3a108cc0721047455bc2def95bcb613a1749c1bbe0fb0d88088699b_cppui298,
            0x00eeaea28cc850898e84e44ec6ae59fb0079c1d1c93f0f6e30c541695c45c4b9e3df07db6b77_cppui298,
            0x030ffc05991f5ac550b3c37b44c253e2c2a39359ec30d0ec24f4c42e3a6b937d02653c92e7d5_cppui298,
            0x001e339f66ccb68e51bab41310a5d30d2f51a002ae9b7bcf506c0c44447c725f0e2b618e9571_cppui298
        },
        AB_FE = {
            0x01fbabaf3b011714d2d119340016213db9fb8b5eeefbf32a082b4f8ee40cb6f79825d082f2b0_cppui298,
            0x038ae7fa7f91cc2ab005a8ea5c8c475820d848c5f0aa942a27da982b18fe96514c682a9bb227_cppui298,
            0x00fed8ea05b7600bea786cb3bb779876cb8623e11466112530237b9a2d296b4367033969b515_cppui298,
            0x008957e24bff45f132925d25383fbd0c1e1a0bea95fdae5346b0f42b2b44fbe3a80ce4a49d98_cppui298
        };

     std::cout << "MNT4-298 Final exponentiation test\n";
     test_mnt4_298_exponentiation<field_type, 4>(AB_ML, AB_FE);

    for(std::size_t i = 0; i < random_tests_amount; ++i) {
        typename gt_group_type::value_type 
            A = crypto3::algebra::random_element<gt_group_type>(),
            A_FE = final_exponentiation<curve_type>(A);

        std::vector<field_type::value_type>
            input = {
                A.data[0].data[0],
                A.data[0].data[1],
                A.data[1].data[0],
                A.data[1].data[1],
            },
            result = {
                A_FE.data[0].data[0],
                A_FE.data[0].data[1],
                A_FE.data[1].data[0],
                A_FE.data[1].data[1],
            };

        std::cout << "mnt4-298 Final exponentiation random test " << i << std::endl;
        test_mnt4_298_exponentiation<field_type, 4>(input, result);

    }
}

BOOST_AUTO_TEST_SUITE_END()
