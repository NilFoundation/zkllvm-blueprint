//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_auxiliary_transcript_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <../test/verifiers/kimchi/sponge/aux_transcript_fr.hpp>
#include <../test/verifiers/kimchi/sponge/aux_transcript_fr_points.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

// BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_0) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 16;

//     constexpr static std::size_t public_input_size = 3;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static const std::size_t eval_rounds = 1;
//     constexpr static const std::size_t max_poly_size = 1;
//     constexpr static const std::size_t srs_len = 1;
//     constexpr static const std::size_t prev_chal_size = 1;

//     using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
//         PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
//                 ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size,
//             srs_len>;
//     using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;

//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;

//     constexpr size_t num_squeezes = 1;
//     using component_type = zk::components::aux_fr<num_squeezes, ArithmetizationType, curve_type, kimchi_params,
//                                                             0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     std::vector<var> input;
//     var zero(0, 0, false, var::column_type::public_input);
//     typename component_type::params_type params = {input, zero};
//     std::vector<typename BlueprintFieldType::value_type> public_input = {0};
//     typename BlueprintFieldType::value_type result = 0x00000000000000000000000000000000C873AF205DFABB8A304600F3E09EEBA8_cppui256;
//     std::array<typename BlueprintFieldType::value_type, component_type::state_size> state = {0, 0, 0};
//     auto result_check = [&result, &state](AssignmentType &assignment,
//         component_type::result_type &real_res) {
//         assert(result == assignment.var_value(real_res.squeezed));
//         for (std::size_t i = 0; i < component_type::state_size; ++i) {
//             // assert(state[i] == assignment.var_value(real_res.state[i]));
//         }
//     };
//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "kimchi transcript_fr: " << duration.count() << "ms" << std::endl;
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_1) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 16;

    constexpr static std::size_t public_input_size = 3;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static const std::size_t eval_rounds = 1;
    constexpr static const std::size_t max_poly_size = 1;
    constexpr static const std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size,
            srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_recursion_test<ArithmetizationType>;

    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr size_t num_squeezes = 0;
    using component_type = zk::components::aux_fr<num_squeezes, ArithmetizationType, curve_type, kimchi_params,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    std::vector<var> input = {var(0, 1, false, var::column_type::public_input), var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
                            var(0, 4, false, var::column_type::public_input)};
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};
    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0,
        0x38C5D08C61572A0F233A3732575F3A07AD484107EC7366FEB0903FCC30253C1A_cppui256,
        0x2C1E20B5D662CE38070228313FD0D968116779CC3CD2FFF662707412EEBD04C7_cppui256,
        0x2A016E5F91F6C33552FC86A7A88C034E5CF1301E4982545A15AB709ECE150E09_cppui256,
        0x1D1B8F16A3DF52F90BA4856A11D397FDD175DEBBDC84F9D9FD71C46E5CB311CC_cppui256,
    };
    assert(public_input.size() == input.size() + 1);
    typename BlueprintFieldType::value_type squeezed = 0;
    std::array<typename BlueprintFieldType::value_type, component_type::state_size> state = {0x26555890DED4608F1784FA12097118D174CAA2778607E4B7A1430EDC247C96B1_cppui256,
     0x0A4D29BDF3B953B147E66E9CFFE0E3E8148320C9DC0112EAB43139FB9A86B128_cppui256,
     0x0D75665FBACB493BD0A43E265D4A6E71E7F5BCE7FCB7F27E497F62FEDFA7E9FE_cppui256};
    auto result_check = [&squeezed, &state](AssignmentType &assignment,
        component_type::result_type &real_res) {
        // assert(squeezed == assignment.var_value(real_res.squeezed));
        for (std::size_t i = 0; i < component_type::state_size; ++i) {
            assert(state[i] == assignment.var_value(real_res.state[i]));
        }
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi transcript_fr: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
