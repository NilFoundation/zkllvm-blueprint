//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_scalar_details_hash_messages_for_next_wrap_proof_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/hash_messages_for_next_wrap_proof.hpp>

#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "test_plonk_component.hpp"

#include <algorithm>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_pickles_scalar_details_hash_messages_for_next_wrap_proof_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_scalar_details_hash_messages_for_next_wrap_proof_test) {

    using curve_type = algebra::curves::pallas;
    using comms_curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    using value_type = typename BlueprintFieldType::value_type;
    using curve_point_type = typename comms_curve_type::template g1_type<algebra::curves::coordinates::affine>;
    using curve_point = comms_curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 4;
    constexpr static std::size_t eval_rounds = 4;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 2;
    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t prev_chal_size = 1;

    constexpr static const std::size_t bulletproofs_size = 3;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::hash_messages_for_next_wrap_proof<
            ArithmetizationType, curve_type, kimchi_params,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<value_type> public_input = {
        0x0ED5F98AC52E204F26A60A364BE1CE8C9A13F9616D3EC2142B1413A5DF2250FD_cppui256,
        0x1E7B13BA33D68C100081BA82CB22CC4DAD93342E0F273C3C36A70274D8D3C9D5_cppui256,
        0x075D478DA7D65CDB4A942F85137E553635CD429D336F5A0E1F58B8FFA2E5E5D6_cppui256,
        0x1E6B26E6449DE860A03F1DFC47A8F174793AB0C9FF383A733BB9AED80E537A82_cppui256,
        0x00C19ED18C1A7228940BAB80DFA90B0E58BF64769ED53F2F18B58321EBD0766E_cppui256,
        0x042B3C7DFFEBD2476E3F15F43F0344FCEF917C69DD279AC916A0C4737338A4A7_cppui256,
        0x3EE2F864A380F19AEB1A4E945A9CCE88E43CE412FB7E85EF4CC3972F89A3439A_cppui256,
        0x1F23CF9EBE5D4D71D149D7987D2A2A0630C5EDFE5D25421666BE43CBCB502A29_cppui256,
        0x2B63DE2692C0B2CACD9F585B38B5D61EF28D8151858DB4834B44AAB9AE3CC83A_cppui256,
        0x041CE2552655A82F608CCD2A1EB359436C295DA409CC24A558325982A5058E34_cppui256,
        0x3E4D1721ABB52EF92429659BC96C069CEDCE74602EF53CB0F3AD58F7E08F9AB4_cppui256,
        0x083B2353A955C2B7E482BEEC039170DD7286CC83C2599474990BD5FEAE608704_cppui256,
        0x29F01F82D4D3076EC4D4C1F9F7C4F830786EF02ED10291F0ACB960A4B0F9BEE8_cppui256,
        0x3531A4BF5851F2C64F36DA0B140A33D9813FCD70E20FF99F7A560A09B5404FFC_cppui256,
        0x28C4A92414B28F0B6CD066B53CBB0767378A1A3EBFF42C0BA249C5E13C9D4DD8_cppui256,
        0x14E21093FB3A468B8B8A27A216A2F5BD95CCA41DF52995900BFE85DB1A740E5A_cppui256,
        0x01077CA81E136DA2CD4D2DFA80BBA6DDBC420FAA8DBCA0300E84FEFF9196443A_cppui256,
    };

    typename component_type::params_type params;
    params.chal_len = 1;

    std::size_t idx = 0;
    params.prepared_challenges.resize(1);
    for (std::size_t i = 0; i < 15; i++) {
        params.prepared_challenges[0][i] = var(0, idx++, false, var::column_type::public_input);
    }
    params.commitment.X = var(0, idx++, false, var::column_type::public_input);
    params.commitment.Y = var(0, idx++, false, var::column_type::public_input);
    assert(idx == public_input.size());

    // generated by running the component with the above public input
    value_type expected_result = 0x102ad47fcd268ef424f34896037f069df7c47fce874b3cca0dfa31a346d9d143_cppui256;
    auto result_check = [expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()