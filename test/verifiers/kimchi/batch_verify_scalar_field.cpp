//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_verifier_scalar_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_scalar_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/recursion_test.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_test.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"
#include "batch_scalars_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proof(zk::snark::proof_type<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvalRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i][0]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z[0]);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i][0]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                public_input.push_back(original_proof.evals[point_idx].lookup.sorted[i][0]);
                circuit_proof.proof_evals[point_idx].lookup.sorted[i] =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }

            public_input.push_back(original_proof.evals[point_idx].lookup.aggreg[0]);
            circuit_proof.proof_evals[point_idx].lookup.aggreg = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            public_input.push_back(original_proof.evals[point_idx].lookup.table[0]);
            circuit_proof.proof_evals[point_idx].lookup.table = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            if (KimchiParamsType::circuit_params::lookup_runtime) {
                public_input.push_back(original_proof.evals[point_idx].lookup.runtime[0]);
                circuit_proof.proof_evals[point_idx].lookup.runtime = 
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector[0]);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector[0]);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    // public_input
    circuit_proof.public_input.resize(KimchiParamsType::public_input_size);
    for (std::size_t i = 0; i < KimchiParamsType::public_input_size; ++i) {
        public_input.push_back(original_proof.public_input[i]);
        circuit_proof.public_input[i] =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    // prev_chal
    circuit_proof.prev_challenges.resize(KimchiParamsType::prev_challenges_size);
    for (std::size_t i = 0; i < KimchiParamsType::prev_challenges_size; ++i) {
        for (std::size_t j = 0; j < EvalRounds; ++j) {
            public_input.push_back(original_proof.prev_challenges[i].first[j]);
            circuit_proof.prev_challenges[i][j] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }
    // ft_eval
    public_input.push_back(original_proof.ft_eval1);
    circuit_proof.ft_eval = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite) {

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 30;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     constexpr static std::size_t public_input_size = 3;
//     constexpr static std::size_t max_poly_size = 32;
//     constexpr static std::size_t eval_rounds = 3;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr std::size_t srs_len = 5;
//     constexpr static const std::size_t prev_chal_size = 1;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;

//     zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
//     typename BlueprintFieldType::value_type zeta =
//         0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
//     typename BlueprintFieldType::value_type omega =
//         0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
//     // verifier_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
//     //     0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
//     //     0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
//     //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
//     std::size_t domain_size = 128;
//     verifier_index.domain_size = domain_size;
//     verifier_index.omega = var(0, 6, false, var::column_type::public_input);

//     constexpr std::size_t batch_size = 2;

//     using component_type = zk::components::batch_verify_scalar_field<ArithmetizationType,
//                                                                      curve_type,
//                                                                      kimchi_params,
//                                                                      commitment_params,
//                                                                      batch_size,
//                                                                      0,
//                                                                      1,
//                                                                      2,
//                                                                      3,
//                                                                      4,
//                                                                      5,
//                                                                      6,
//                                                                      7,
//                                                                      8,
//                                                                      9,
//                                                                      10,
//                                                                      11,
//                                                                      12,
//                                                                      13,
//                                                                      14>;

//     zk::snark::proof_type<curve_type> kimchi_proof = test_proof();

//     typename BlueprintFieldType::value_type joint_combiner = 0;
//     typename BlueprintFieldType::value_type beta = 0;
//     typename BlueprintFieldType::value_type gamma = 0;
//     typename BlueprintFieldType::value_type alpha =
//         0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
//     typename BlueprintFieldType::value_type fq_digest =
//         0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;

//     zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
//     std::array<var, eval_rounds> challenges;

//     std::vector<typename BlueprintFieldType::value_type> public_input = {};

//     std::array<
//         zk::components::
//             batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>,
//         batch_size>
//         batches;

//     for (std::size_t i = 0; i < batch_size; i++) {
//         typename BlueprintFieldType::value_type cip = 12;
//         public_input.push_back(cip);
//         batches[i].cip = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
//             fq_output;

//         std::array<var, eval_rounds> challenges;
//         for (std::size_t j = 0; j < eval_rounds; j++) {
//             public_input.emplace_back(10);
//             challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         }
//         fq_output.challenges = challenges;

//         // joint_combiner
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         fq_output.joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // beta
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         fq_output.beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // gamma
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         fq_output.gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // alpha
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         fq_output.alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // zeta
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         fq_output.zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // fq_digest
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         fq_output.fq_digest = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // c
//         public_input.emplace_back(250);
//         fq_output.c = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         batches[i].fq_output = fq_output;

//         public_input.push_back(zeta);
//         public_input.push_back(zeta * omega);
//         batches[i].eval_points = {var(0, public_input.size() - 2, false, var::column_type::public_input),
//                                   var(0, public_input.size() - 1, false, var::column_type::public_input)};

//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         batches[i].r = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         public_input.push_back(algebra::random_element<BlueprintFieldType>());
//         batches[i].opening = {var(0, public_input.size() - 2, false, var::column_type::public_input),
//                               var(0, public_input.size() - 1, false, var::column_type::public_input)};
//     }

//     typename component_type::params_type params = {batches};

//     auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
//         params, public_input, result_check);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite_chacha) {

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 30;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     constexpr static std::size_t public_input_size = 0;
//     constexpr static std::size_t max_poly_size = 8192;
//     constexpr static std::size_t eval_rounds = 13;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 8192;
//     constexpr static const std::size_t prev_chal_size = 0;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_chacha_test<ArithmetizationType>;
//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;
//     using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

//     typename BlueprintFieldType::value_type omega =
//         0x03B402C2CBD0A0660626F1948867533CFD2A80ABD33D0E808075A3EFC92D52D2_cppui256;

//     constexpr std::size_t batch_size = 1;

//     using component_type = zk::components::batch_verify_scalar_field<ArithmetizationType,
//                                                                      curve_type,
//                                                                      kimchi_params,
//                                                                      commitment_params,
//                                                                      batch_size,
//                                                                      0,
//                                                                      1,
//                                                                      2,
//                                                                      3,
//                                                                      4,
//                                                                      5,
//                                                                      6,
//                                                                      7,
//                                                                      8,
//                                                                      9,
//                                                                      10,
//                                                                      11,
//                                                                      12,
//                                                                      13,
//                                                                      14>;

//     zk::snark::proof_type<curve_type> kimchi_proof = test_proof_chacha();

//     typename BlueprintFieldType::value_type joint_combiner = 
//         0x00000000000000000000000000000000CAAE895531DD8E0A0B0618483C93C727_cppui256;
//     typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000001FE90F184CF0D23228FC49E7F4BDF537_cppui256;
//     typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000ADE5F3B85395C4FCA12723C1322622EF_cppui256;
//     typename BlueprintFieldType::value_type alpha =
//         0x00000000000000000000000000000000919E7EE06FFBFC7EBBDAD14E68BBE21C_cppui256;
//     typename BlueprintFieldType::value_type zeta =
//         0x0000000000000000000000000000000075682BC2C8E8E561028A9B44CB52E0AB_cppui256;
//     typename BlueprintFieldType::value_type fq_digest =
//         0x2C85FCC264A1C8E1082E97E5686196CB1A7EF642F7B162EB21723CCCB6344341_cppui256;
        
//     typename BlueprintFieldType::value_type cip = 0x3F5E1606E8160D4344DE45AD1E7EE9251BFAF143DC919FD43341EA1AFD34A2E3_cppui256;
//     typename BlueprintFieldType::value_type r = 0x2A4D106C58F5A790D319487554375EDCB75B870A5F585D7FF20EF9D71798EBE0_cppui256;
//     typename BlueprintFieldType::value_type xi = 0x2C7C286ACD0842FE37DA945A743780DB32AE9A57A9048650AD4DDD0886AE650D_cppui256;
//     typename BlueprintFieldType::value_type c = 0x000000000000000000000000000000009A74364C89BDD646770B260188701C87_cppui256;
//     std::array<typename BlueprintFieldType::value_type, eval_rounds> challenges = {0x0000000000000000000000000000000093F840EE0BCAD4DC827D1BF58DA96536_cppui256,
//                                                                             0x00000000000000000000000000000000B5DE3805FAB32AEFFA2423D1F4546E76_cppui256,
//                                                                             0x00000000000000000000000000000000D708C74CDFDAF0D2D974A0DC78A7CB9C_cppui256,
//                                                                             0x00000000000000000000000000000000D6D435321968A76F341E174893BFE072_cppui256,
//                                                                             0x000000000000000000000000000000006A490917E56990E623D9B04F348B6AA1_cppui256,
//                                                                             0x0000000000000000000000000000000001DD5395B3B4E0163F9A3A78DEE2CCE5_cppui256,
//                                                                             0x000000000000000000000000000000001AFFD6FB373CB2354DEEEE3A4B3DE8DC_cppui256,
//                                                                             0x0000000000000000000000000000000099EF5D8A9D455F214176D5B80A5AB43D_cppui256,
//                                                                             0x00000000000000000000000000000000769E278B9739FFF6A46F17F291CDB03F_cppui256,
//                                                                             0x00000000000000000000000000000000717509B54112E0FA3285DE19BB053A0A_cppui256,
//                                                                             0x00000000000000000000000000000000CE77ACA68237EF87E5E50284EEB69201_cppui256,
//                                                                             0x000000000000000000000000000000005AF4B53ADCBBA9E03F32927E9369556E_cppui256,
//                                                                             0x000000000000000000000000000000005A4CE311F5D948B666B01BBB3B2A84C7_cppui256};

//     zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

//     std::vector<typename BlueprintFieldType::value_type> public_input = {};

//     std::array<
//         zk::components::
//             batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>,
//         batch_size>
//         batches;

//     for (std::size_t i = 0; i < batch_size; i++) {
//         public_input.push_back(cip);
//         batches[i].cip = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
//             fq_output;

//         // std::array<var, eval_rounds> challenges;
//         for (std::size_t j = 0; j < eval_rounds; j++) {
//             public_input.emplace_back(challenges[i]);
//             fq_output.challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         }
//         // fq_output.challenges = challenges;

//         // joint_combiner
//         public_input.push_back(joint_combiner);
//         fq_output.joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // beta
//         public_input.push_back(beta);
//         fq_output.beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // gamma
//         public_input.push_back(gamma);
//         fq_output.gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // alpha
//         public_input.push_back(alpha);
//         fq_output.alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // zeta
//         public_input.push_back(zeta);
//         fq_output.zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // fq_digest
//         public_input.push_back(fq_digest);
//         fq_output.fq_digest = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // c
//         public_input.emplace_back(250);
//         fq_output.c = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         batches[i].fq_output = fq_output;

//         public_input.push_back(zeta);
//         public_input.push_back(zeta * omega);
//         batches[i].eval_points = {var(0, public_input.size() - 2, false, var::column_type::public_input),
//                                   var(0, public_input.size() - 1, false, var::column_type::public_input)};

//         public_input.push_back(xi);
//         batches[i].xi = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         public_input.push_back(r);
//         batches[i].r = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         public_input.push_back(kimchi_proof.proof.z1);
//         public_input.push_back(kimchi_proof.proof.z2);
//         batches[i].opening = {var(0, public_input.size() - 2, false, var::column_type::public_input),
//                               var(0, public_input.size() - 1, false, var::column_type::public_input)};
//     }

//     typename component_type::params_type params = {batches};

//     std::vector<typename BlueprintFieldType::value_type> expected_result = chacha_scalars();

//     auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
//         for (std::size_t i = 0; i < 72; ++i) {
//             expected_result[i] == assignment.var_value(real_res.output[i]);
//         }
//         std::cout << assignment.var_value(real_res.output.back()).data << '\n';
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
//         params, public_input, result_check);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite_recursion) {

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 30;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     constexpr static std::size_t public_input_size = 0;
//     constexpr static std::size_t max_poly_size = 32;
//     constexpr static std::size_t eval_rounds = 5;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 32;
//     constexpr static const std::size_t prev_chal_size = 1;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_recursion_test<ArithmetizationType>;
//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;
//     using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

//     typename BlueprintFieldType::value_type omega =
//         0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;

//     constexpr std::size_t batch_size = 1;

//     using component_type = zk::components::batch_verify_scalar_field<ArithmetizationType,
//                                                                      curve_type,
//                                                                      kimchi_params,
//                                                                      commitment_params,
//                                                                      batch_size,
//                                                                      0,
//                                                                      1,
//                                                                      2,
//                                                                      3,
//                                                                      4,
//                                                                      5,
//                                                                      6,
//                                                                      7,
//                                                                      8,
//                                                                      9,
//                                                                      10,
//                                                                      11,
//                                                                      12,
//                                                                      13,
//                                                                      14>;

//     zk::snark::proof_type<curve_type> kimchi_proof = test_proof_recursion();

//     typename BlueprintFieldType::value_type joint_combiner = 0;
//     typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D_cppui256;
//     typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000AD39D811EFCE0FAD50EC0E161A0EF76E_cppui256;
//     typename BlueprintFieldType::value_type alpha =
//         0x000000000000000000000000000000001AF1BBFDB43BAF883077CB71813712B4_cppui256;
//     typename BlueprintFieldType::value_type zeta =
//         0x00000000000000000000000000000000BE221A5AA97523F509569F35A40CF587_cppui256;
//     typename BlueprintFieldType::value_type fq_digest =
//         0x2D40D90836130DCC82FDDACBCCA9F17F64C87CE868421AA82A92FF62DA885C45_cppui256;
        
//     typename BlueprintFieldType::value_type cip = 0x0DD1472152367FE7A1D7BB625D04459D9D111E256B2E7A33AA6C27F36954B4E5_cppui256;
//     typename BlueprintFieldType::value_type r = 0x01C2C71FD3EDE15D094876291B2A2217684D581367D500D4A40774FDE78B9077_cppui256;
//     typename BlueprintFieldType::value_type xi = 0x39DA9CD4FE6FD362E83BE4ED4647DE2441DC13F15B8A15985BB607B68B9852A4_cppui256;
//     typename BlueprintFieldType::value_type c = 0x00000000000000000000000000000000ABFD05B4709CE7C3144601797031BB93_cppui256;
//     std::array<typename BlueprintFieldType::value_type, eval_rounds> challenges = {0x00000000000000000000000000000000A595B8A0FBCF5DAD77D0BF136AE529A1_cppui256,
//                                                                             0x000000000000000000000000000000004E53F614FFF00E45837CD3E9A746407F_cppui256,
//                                                                             0x00000000000000000000000000000000F611552B93001B93A8BDAACC79B288F8_cppui256,
//                                                                             0x00000000000000000000000000000000C334F693BD7FD8D56114520F81F4FF85_cppui256,
//                                                                             0x00000000000000000000000000000000696B47BEBCB58F48E7792BB803F5590F_cppui256};

//     zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

//     std::vector<typename BlueprintFieldType::value_type> public_input = {};

//     std::array<
//         zk::components::
//             batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>,
//         batch_size>
//         batches;

//     for (std::size_t i = 0; i < batch_size; i++) {
//         public_input.push_back(cip);
//         batches[i].cip = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
//             fq_output;

//         // std::array<var, eval_rounds> challenges;
//         for (std::size_t j = 0; j < eval_rounds; j++) {
//             public_input.emplace_back(challenges[i]);
//             fq_output.challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         }
//         // fq_output.challenges = challenges;

//         // joint_combiner
//         public_input.push_back(joint_combiner);
//         fq_output.joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // beta
//         public_input.push_back(beta);
//         fq_output.beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // gamma
//         public_input.push_back(gamma);
//         fq_output.gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // alpha
//         public_input.push_back(alpha);
//         fq_output.alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // zeta
//         public_input.push_back(zeta);
//         fq_output.zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // fq_digest
//         public_input.push_back(fq_digest);
//         fq_output.fq_digest = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         // c
//         public_input.emplace_back(c);
//         fq_output.c = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         batches[i].fq_output = fq_output;

//         public_input.push_back(zeta);
//         public_input.push_back(zeta * omega);
//         batches[i].eval_points = {var(0, public_input.size() - 2, false, var::column_type::public_input),
//                                   var(0, public_input.size() - 1, false, var::column_type::public_input)};

//         public_input.push_back(xi);
//         batches[i].xi = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         public_input.push_back(r);
//         batches[i].r = var(0, public_input.size() - 1, false, var::column_type::public_input);

//         public_input.push_back(kimchi_proof.proof.z1);
//         public_input.push_back(kimchi_proof.proof.z2);
//         batches[i].opening = {var(0, public_input.size() - 2, false, var::column_type::public_input),
//                               var(0, public_input.size() - 1, false, var::column_type::public_input)};
//     }

//     typename component_type::params_type params = {batches};

//     std::vector<typename BlueprintFieldType::value_type> expected_result = recursion_scalars();

//     auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
//         for (std::size_t i = 0; i < 72; ++i) {
//             expected_result[i] == assignment.var_value(real_res.output[i]);
//         }
//         std::cout << assignment.var_value(real_res.output[72]).data << '\n';
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
//         params, public_input, result_check);
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite_generic) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
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

    constexpr static std::size_t public_input_size = 5;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 32;
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_generic_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    typename BlueprintFieldType::value_type omega =
        0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;

    constexpr std::size_t batch_size = 1;

    using component_type = zk::components::batch_verify_scalar_field<ArithmetizationType,
                                                                     curve_type,
                                                                     kimchi_params,
                                                                     commitment_params,
                                                                     batch_size,
                                                                     0,
                                                                     1,
                                                                     2,
                                                                     3,
                                                                     4,
                                                                     5,
                                                                     6,
                                                                     7,
                                                                     8,
                                                                     9,
                                                                     10,
                                                                     11,
                                                                     12,
                                                                     13,
                                                                     14>;

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_generic();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0x0000000000000000000000000000000070A593FE2201A0520B51FB2131B0EC50_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000C19F7BFFF732734AB7E1461DB30B4098_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x00000000000000000000000000000000F643764B3C004B017222923DE86BC103_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x0000000000000000000000000000000098DD898B19D348D4CDA80AE41B836A67_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x11EF8F246F63C43E46E22BC179C7171A3F2A9776AC62E5C488C482403FB00E07_cppui256;
        
    typename BlueprintFieldType::value_type cip = 0x10EFC44BEF0B125C23172AEA94C4BE39BC7CD8F0A353D72BB74680F668796273_cppui256;
    typename BlueprintFieldType::value_type r = 0x02F09286E0F4EA5B8C2DA4C966DC23D900A5DD4D65F805202EF0D38FC8791C37_cppui256;
    typename BlueprintFieldType::value_type xi = 0x38F378C3A58670C0526EECA358159AF2BCD782EA23FA6E7DCC1235220D533C48_cppui256;
    typename BlueprintFieldType::value_type c = 0x000000000000000000000000000000003EBAA1141AF9F8B32C731FF1B98DD36D_cppui256;
    std::array<typename BlueprintFieldType::value_type, eval_rounds> challenges = {0x00000000000000000000000000000000B87CC21A144B0978582E9D3EAD6F9645_cppui256,
                                                                            0x000000000000000000000000000000006E197C0FE9183678F6CD6DDF21E41106_cppui256,
                                                                            0x00000000000000000000000000000000C9B134C1DE1E51CFC432E18E7466AEC3_cppui256,
                                                                            0x00000000000000000000000000000000CA0585EE3E6C4273E29C674F559CDA8C_cppui256,
                                                                            0x000000000000000000000000000000001CFF214FFA9FEEA61473FB1D4B698CBD_cppui256};

    zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    std::array<
        zk::components::
            batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>,
        batch_size>
        batches;

    for (std::size_t i = 0; i < batch_size; i++) {
        public_input.push_back(cip);
        batches[i].cip = var(0, public_input.size() - 1, false, var::column_type::public_input);

        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
            fq_output;

        // std::array<var, eval_rounds> challenges;
        for (std::size_t j = 0; j < eval_rounds; j++) {
            public_input.emplace_back(challenges[i]);
            fq_output.challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // fq_output.challenges = challenges;

        // joint_combiner
        public_input.push_back(joint_combiner);
        fq_output.joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // beta
        public_input.push_back(beta);
        fq_output.beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // gamma
        public_input.push_back(gamma);
        fq_output.gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // alpha
        public_input.push_back(alpha);
        fq_output.alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // zeta
        public_input.push_back(zeta);
        fq_output.zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // fq_digest
        public_input.push_back(fq_digest);
        fq_output.fq_digest = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // c
        public_input.emplace_back(250);
        fq_output.c = var(0, public_input.size() - 1, false, var::column_type::public_input);

        batches[i].fq_output = fq_output;

        public_input.push_back(zeta);
        public_input.push_back(zeta * omega);
        batches[i].eval_points = {var(0, public_input.size() - 2, false, var::column_type::public_input),
                                  var(0, public_input.size() - 1, false, var::column_type::public_input)};

        public_input.push_back(xi);
        batches[i].xi = var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(r);
        batches[i].r = var(0, public_input.size() - 1, false, var::column_type::public_input);

        public_input.push_back(kimchi_proof.proof.z1);
        public_input.push_back(kimchi_proof.proof.z2);
        batches[i].opening = {var(0, public_input.size() - 2, false, var::column_type::public_input),
                              var(0, public_input.size() - 1, false, var::column_type::public_input)};
    }

    typename component_type::params_type params = {batches};

    std::vector<typename BlueprintFieldType::value_type> expected_result = generic_scalars();

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < 72; ++i) {
            expected_result[i] == assignment.var_value(real_res.output[i]);
        }
        std::cout << assignment.var_value(real_res.output[72]).data << '\n';
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()