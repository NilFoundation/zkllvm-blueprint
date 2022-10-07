//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_oracles_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/oracles_scalar.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/recursion_test.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_test.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_oracles_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvelRounds>
void prepare_proof(zk::snark::pickles_proof<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvelRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                public_input.push_back(original_proof.evals[point_idx].lookup.sorted[i]);
                circuit_proof.proof_evals[point_idx].lookup.sorted[i] =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }

            public_input.push_back(original_proof.evals[point_idx].lookup.aggreg);
            circuit_proof.proof_evals[point_idx].lookup.aggreg = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            public_input.push_back(original_proof.evals[point_idx].lookup.table);
            circuit_proof.proof_evals[point_idx].lookup.table = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            if (KimchiParamsType::circuit_params::lookup_runtime) {
                public_input.push_back(original_proof.evals[point_idx].lookup.runtime);
                circuit_proof.proof_evals[point_idx].lookup.runtime = 
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // ft_eval
    public_input.push_back(original_proof.ft_eval1);
    circuit_proof.ft_eval = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_test) {

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
//     constexpr static std::size_t eval_rounds = 5;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 10;
//     constexpr static const std::size_t prev_chal_size = 1;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;

//     zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
//     typename BlueprintFieldType::value_type omega =
//         0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
//     // verifier_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
//     //     0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
//     //     0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
//     //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
//     std::size_t domain_size = 128;
//     verifier_index.domain_size = domain_size;
//     verifier_index.omega = var(0, 6, false, var::column_type::public_input);

//     using component_type =
//         zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
//                                        5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

//     zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

//     typename BlueprintFieldType::value_type joint_combiner = 0;
//     typename BlueprintFieldType::value_type beta = 0;
//     typename BlueprintFieldType::value_type gamma = 0;
//     typename BlueprintFieldType::value_type alpha =
//         0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
//     typename BlueprintFieldType::value_type zeta =
//         0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
//     typename BlueprintFieldType::value_type fq_digest =
//         0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;
//     typename BlueprintFieldType::value_type expected_alpha =
//         0x23A8600917236F0E644D49DD5E6CA89537CE3047DA7E29D2A7B8CA6006616092_cppui256;
//     std::cout << "Expected alpha: " << expected_alpha.data << std::endl;
//     typename BlueprintFieldType::value_type expected_zeta =
//         0x3D0F1F3A3D07DC73FBDF3718FFE270122AA367FB5BA667AD4A4AB81167D21BE4_cppui256;
//     std::cout << "Expected zeta: " << expected_zeta.data << std::endl;

//     zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
//     std::array<var, eval_rounds> challenges;
//     typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
//         fq_output = {var(0, 0, false, var::column_type::public_input),
//                      var(0, 1, false, var::column_type::public_input),
//                      var(0, 2, false, var::column_type::public_input),
//                      var(0, 3, false, var::column_type::public_input),
//                      var(0, 4, false, var::column_type::public_input),
//                      var(0, 5, false, var::column_type::public_input),
//                      challenges};

//     std::vector<typename BlueprintFieldType::value_type> public_input = {joint_combiner, beta,      gamma, alpha,
//                                                                          zeta,           fq_digest, omega};

//     // TODO prepare real data
//     for (std::size_t i = 0; i < public_input_size; i++) {
//         typename BlueprintFieldType::value_type tmp = algebra::random_element<BlueprintFieldType>();
//         public_input.push_back(tmp);
//         proof.public_input[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     }

//     for (std::size_t i = 0; i < kimchi_params::prev_challenges_size; i++) {
//         for (std::size_t j = 0; j < eval_rounds; j++) {
//             typename BlueprintFieldType::value_type tmp = algebra::random_element<BlueprintFieldType>();
//             public_input.push_back(tmp);
//             proof.prev_challenges[i][j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         }
//     }

//     prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

//     typename component_type::params_type params = {verifier_index, proof, fq_output};

//     auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
//                                                                                                  result_check);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_real_data_test_chacha) {

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
//     constexpr static std::size_t eval_rounds = 0; // ?L402?

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 1024;
//     constexpr static const std::size_t prev_chal_size = 0;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_chacha_test<ArithmetizationType>;
//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;

//     zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
//     typename BlueprintFieldType::value_type omega =
//         0x03B402C2CBD0A0660626F1948867533CFD2A80ABD33D0E808075A3EFC92D52D2_cppui256;
//     // verifier_index.zkpm = {0x24E57A6ADCFF9FC440722CF97BDB49BA19E10E3052205148DD969C3F05AFBBE9_cppui256,
//     //     0x1B7FAAF3DDC0D9B51F589BF3FA8F63DABDDDE689865ECB01271CC42440D03BEB_cppui256,
//     //     0x371834008CF1500AEC352AEF981ED41024B5A3D5AA22A27E928A7F71425C5723_cppui256,
//     //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
//     std::size_t domain_size = 8192;
//     verifier_index.domain_size = domain_size;
//     verifier_index.omega = var(0, 6, false, var::column_type::public_input);

//     using component_type =
//         zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
//                                        5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

//     zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof_chacha();

//     typename BlueprintFieldType::value_type joint_combiner = 
//         0x00000000000000000000000000000000CAAE895531DD8E0A0B0618483C93C727_cppui256;
//     typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000001FE90F184CF0D23228FC49E7F4BDF537_cppui256;
//     typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000ADE5F3B85395C4FCA12723C1322622EF_cppui256;
//     typename BlueprintFieldType::value_type alpha =
//         0x00000000000000000000000000000000919E7EE06FFBFC7EBBDAD14E68BBE21C_cppui256;
//     typename BlueprintFieldType::value_type zeta =
//         0x0000000000000000000000000000000075682BC2C8E8E561028A9B44CB52E0AB_cppui256;
//     typename BlueprintFieldType::value_type fq_digest =
//         0x3A3374A061464EC0AAC7E0FF04346926C579D542F9D205A670CE4C18C004E5C1_cppui256;
//     typename BlueprintFieldType::value_type expected_alpha =
//         0x32A5FB8A849C5CFC39656701462421AA5A9C88FCC7D7C342063D66486096D8ED_cppui256;
//     std::cout << "Expected alpha: " << expected_alpha.data << std::endl;
//     typename BlueprintFieldType::value_type expected_zeta =
//         0x24A32849C8B99B6CB2D1A514C0EC7B5F5A15799EA2428C6DCA8B332CEACE9DC0_cppui256;
//     std::cout << "Expected zeta: " << expected_zeta.data << std::endl;

//     zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
//     std::array<var, eval_rounds> challenges;
//     typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
//         fq_output = {var(0, 0, false, var::column_type::public_input),
//                      var(0, 1, false, var::column_type::public_input),
//                      var(0, 2, false, var::column_type::public_input),
//                      var(0, 3, false, var::column_type::public_input),
//                      var(0, 4, false, var::column_type::public_input),
//                      var(0, 5, false, var::column_type::public_input),
//                      challenges};

//     std::vector<typename BlueprintFieldType::value_type> public_input = {joint_combiner, beta,      gamma, alpha,
//                                                                          zeta,           fq_digest, omega};

//     prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

//     typename component_type::params_type params = {verifier_index, proof, fq_output};

//     auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
//                                                                                                  result_check);
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_test_recursion) {

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

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 1; // ?L402?

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 32;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_recursion_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega =
        0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    // verifier_index.zkpm = {0x24E57A6ADCFF9FC440722CF97BDB49BA19E10E3052205148DD969C3F05AFBBE9_cppui256,
    //     0x1B7FAAF3DDC0D9B51F589BF3FA8F63DABDDDE689865ECB01271CC42440D03BEB_cppui256,
    //     0x371834008CF1500AEC352AEF981ED41024B5A3D5AA22A27E928A7F71425C5723_cppui256,
    //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    std::size_t domain_size = 32;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 6, false, var::column_type::public_input);

    using component_type =
        zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof_recursion();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D7_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000AD39D811EFCE0FAD50EC0E161A0EF76E_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x000000000000000000000000000000001AF1BBFDB43BAF883077CB71813712B4_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x00000000000000000000000000000000BE221A5AA97523F509569F35A40CF587_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x2D40D90836130DCC82FDDACBCCA9F17F64C87CE868421AA82A92FF62DA885C45_cppui256;
    typename BlueprintFieldType::value_type expected_alpha =
        0x220B73274823F8B0E46273FA8546B238F1E58529E061A811AB584A97C146AF87_cppui256;
    std::cout << "Expected alpha: " << expected_alpha.data << std::endl;
    typename BlueprintFieldType::value_type expected_zeta =
        0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256;
    std::cout << "Expected zeta: " << expected_zeta.data << std::endl;

    zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
    std::array<var, eval_rounds> challenges;
    typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
        fq_output = {var(0, 0, false, var::column_type::public_input),
                     var(0, 1, false, var::column_type::public_input),
                     var(0, 2, false, var::column_type::public_input),
                     var(0, 3, false, var::column_type::public_input),
                     var(0, 4, false, var::column_type::public_input),
                     var(0, 5, false, var::column_type::public_input),
                     challenges};

    std::vector<typename BlueprintFieldType::value_type> public_input = {joint_combiner, beta,      gamma, alpha,
                                                                         zeta,           fq_digest, omega};

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    typename component_type::params_type params = {verifier_index, proof, fq_output};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_real_data_test_generic) {

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

//     constexpr static std::size_t public_input_size = 5;
//     constexpr static std::size_t max_poly_size = 32;
//     constexpr static std::size_t eval_rounds = 0;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 32;
//     constexpr static const std::size_t prev_chal_size = 0;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_generic_test<ArithmetizationType>;
//     using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
//         witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//         public_input_size, prev_chal_size>;

//     zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
//     typename BlueprintFieldType::value_type omega =
//         0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
//     // verifier_index.zkpm = {0x1FF2863FD35BFC59E51F3693BF37E2D841D1B5FBED4138F755A638BEC8750ABD_cppui256,
//     //     0x242530F683AB67D7304C5C8D79F2D27BD75AB8E0654D68BC32B6CC524EAE4B71_cppui256,
//     //     0x30AA77F490E7D1F90F95BB2418D8BF255536A9E853355C223112CBB7C1664F2A_cppui256,
//     //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
//     std::size_t domain_size = 32;
//     verifier_index.domain_size = domain_size;
//     verifier_index.omega = var(0, 6, false, var::column_type::public_input);

//     using component_type =
//         zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
//                                        5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

//     zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof_generic();

//     typename BlueprintFieldType::value_type joint_combiner = 0;
//     typename BlueprintFieldType::value_type beta = 0x0000000000000000000000000000000070A593FE2201A0520B51FB2131B0EC50_cppui256;
//     typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000C19F7BFFF732734AB7E1461DB30B4098_cppui256;
//     typename BlueprintFieldType::value_type alpha =
//         0x00000000000000000000000000000000F643764B3C004B017222923DE86BC103_cppui256;
//     typename BlueprintFieldType::value_type zeta =
//         0x0000000000000000000000000000000098DD898B19D348D4CDA80AE41B836A67_cppui256;
//     typename BlueprintFieldType::value_type fq_digest =
//         0x3A3374A061464EC0AAC7E0FF04346926C579D542F9D205A670CE4C18C004E5C1_cppui256;
//     typename BlueprintFieldType::value_type expected_alpha =
//         0x0265E71776BF443E4B298DB910BC81DDB1F1E74913F8A2A121BD0C853D9F01AA_cppui256;
//     std::cout << "Expected alpha: " << expected_alpha.data << std::endl;
//     typename BlueprintFieldType::value_type expected_zeta =
//         0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256;
//     std::cout << "Expected zeta: " << expected_zeta.data << std::endl;

//     zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
//     std::array<var, eval_rounds> challenges;
//     typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
//         fq_output = {var(0, 0, false, var::column_type::public_input),
//                      var(0, 1, false, var::column_type::public_input),
//                      var(0, 2, false, var::column_type::public_input),
//                      var(0, 3, false, var::column_type::public_input),
//                      var(0, 4, false, var::column_type::public_input),
//                      var(0, 5, false, var::column_type::public_input),
//                      challenges};

//     std::vector<typename BlueprintFieldType::value_type> public_input = {joint_combiner, beta,      gamma, alpha,
//                                                                          zeta,           fq_digest, omega};

//     prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

//     typename component_type::params_type params = {verifier_index, proof, fq_output};

//     auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
//                                                                                                  result_check);
// }

BOOST_AUTO_TEST_SUITE_END()