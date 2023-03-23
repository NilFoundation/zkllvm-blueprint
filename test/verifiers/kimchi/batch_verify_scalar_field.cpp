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
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"
#include "batch_scalars_data.hpp"
#include "shift_scalar.hpp"

#include <verifiers/kimchi/mina_state_proof_constants.hpp>

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

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite_ec) {

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

    constexpr static std::size_t public_input_size = ec_constants.public_input_size;
    constexpr static std::size_t max_poly_size = ec_constants.max_poly_size;
    constexpr static std::size_t eval_rounds = ec_constants.eval_rounds;

    constexpr static std::size_t witness_columns = ec_constants.witness_columns;
    constexpr static std::size_t perm_size = ec_constants.perm_size;

    constexpr static std::size_t srs_len = ec_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = ec_constants.prev_chal_size;
    constexpr static const std::size_t batch_size = ec_constants.batch_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;

    std::size_t domain_size = 512;
    verifier_index.domain_size = domain_size;

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

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_ec_test();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;
    typename BlueprintFieldType::value_type omega =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x0ACB65E0765F80498D643313EAAEBFBC7899766A4A337EAF61261344E8C2C551_cppui256;
        
    typename BlueprintFieldType::value_type cip = 0x354a5816578a0f9d8d9ddb7fa580573882cb771454a716e4838c1b29e24034a2_cppui256;
    typename BlueprintFieldType::value_type r = 0x0CD95BF326F609A8D27F9CD8CFA5C1A0662C588EEA1E5B84CD517DC5BA09C502_cppui256;
    typename BlueprintFieldType::value_type xi = 0x1A27603517D952BB0060BB01DE0DA94CFC587748DD85D4987C14883E3BA51BAB_cppui256;////
    typename BlueprintFieldType::value_type c = 0x00000000000000000000000000000000F3E2A1DA06AB7FF243038DECB4B237F5_cppui255;

    std::array<typename BlueprintFieldType::value_type, eval_rounds> challenges = {
        0x00000000000000000000000000000000C496E601A3F7783E33D70D00C667DC2E_cppui255,
        0x000000000000000000000000000000008CDADFE37FD121BD88CB26028DA17F56_cppui255,
        0x00000000000000000000000000000000D6D170FA7018F32B29B4C82A4A9939B8_cppui255,
        0x000000000000000000000000000000008DDE766597BE74882B378893045D7889_cppui255,
        0x00000000000000000000000000000000D3DFB4FB562192333F3D1688B57B045B_cppui255,
        0x000000000000000000000000000000002614E96B977BDFA429C40795EA641233_cppui255,
        0x000000000000000000000000000000001A81273D0CBFF75EC9BEE35AA1130B6B_cppui255,
        0x00000000000000000000000000000000FC061EE3B48344DFF0D3CECA25A75DCC_cppui255,
        0x0000000000000000000000000000000044F1CA82A6260564A6DD44E54E9B96A7_cppui255
    };

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
            public_input.emplace_back(challenges[j]);
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
        public_input.emplace_back(c);
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

    std::vector<typename BlueprintFieldType::value_type> expected_result;

    std::string scalars_filename = "../../../../libs/blueprint/test/verifiers/kimchi/data/ec/scalars.txt";

    std::ifstream scalars_fstream(scalars_filename);
        if (scalars_fstream) {
            while (true) {
                std::string input_string;
        
                scalars_fstream >> input_string;
                if (input_string.empty()) {
                    std::cerr << "empty line in " << scalars_filename << "!" << std::endl;
                    break;
                }

                typename curve_type::base_field_type::extended_integral_type number(input_string);
                assert(number < curve_type::scalar_field_type::modulus && "input does not fit into BlueprintFieldType");
                expected_result.push_back(shift_scalar_scalar<curve_type>(number));

                if (scalars_fstream.eof()) {
                    break;
                }

            }
        }
    else {
        std::cerr <<  "cannot open " << scalars_filename << " file" << std::endl;
        assert(1==0 && "cannot open scalars file");
    }
    scalars_fstream.close();
    std::cout << "scalars amount: " << expected_result.size() << std::endl;
    

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < real_res.output.size(); i++) {
            if (!(expected_result[i] == assignment.var_value(real_res.output[i]))) {
                    std::cout << "ASSERTION[" << i <<"] FAILED!\n";
                    std::cout << std::hex << "assert" << expected_result[i].data << " == " << assignment.var_value(real_res.output[i]).data << std::dec << "\n";
                }
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite_chacha) {
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

    constexpr static std::size_t public_input_size = chacha_constants.public_input_size;
    constexpr static std::size_t max_poly_size = chacha_constants.max_poly_size;
    constexpr static std::size_t eval_rounds = chacha_constants.eval_rounds;

    constexpr static std::size_t witness_columns = chacha_constants.witness_columns;
    constexpr static std::size_t perm_size = chacha_constants.perm_size;

    constexpr static std::size_t srs_len = chacha_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = chacha_constants.prev_chal_size;
    constexpr static const std::size_t batch_size = chacha_constants.batch_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_chacha_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

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

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_chacha();

    typename BlueprintFieldType::value_type joint_combiner = 
        0x00000000000000000000000000000000CAAE895531DD8E0A0B0618483C93C727_cppui256;
    typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000001FE90F184CF0D23228FC49E7F4BDF537_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000ADE5F3B85395C4FCA12723C1322622EF_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x00000000000000000000000000000000919E7EE06FFBFC7EBBDAD14E68BBE21C_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x24A32849C8B99B6CB2D1A514C0EC7B5F5A15799EA2428C6DCA8B332CEACE9DC0_cppui256;
    typename BlueprintFieldType::value_type omega =
        0x03B402C2CBD0A0660626F1948867533CFD2A80ABD33D0E808075A3EFC92D52D2_cppui256;

    typename BlueprintFieldType::value_type fq_digest =
        0x2C85FCC264A1C8E1082E97E5686196CB1A7EF642F7B162EB21723CCCB6344341_cppui256;
        
    typename BlueprintFieldType::value_type cip = 0x388DEEF0601DB0933C25593324191E84942675DA8701B0BB504A064BECAE9525_cppui256;
    typename BlueprintFieldType::value_type r = 0x2A4D106C58F5A790D319487554375EDCB75B870A5F585D7FF20EF9D71798EBE0_cppui256;
    typename BlueprintFieldType::value_type xi = 0x2C7C286ACD0842FE37DA945A743780DB32AE9A57A9048650AD4DDD0886AE650D_cppui256;
    typename BlueprintFieldType::value_type c = 0x000000000000000000000000000000009A74364C89BDD646770B260188701C87_cppui256;
    std::array<typename BlueprintFieldType::value_type, eval_rounds> challenges = {0x0000000000000000000000000000000093F840EE0BCAD4DC827D1BF58DA96536_cppui256,
                                                                            0x00000000000000000000000000000000B5DE3805FAB32AEFFA2423D1F4546E76_cppui256,
                                                                            0x00000000000000000000000000000000D708C74CDFDAF0D2D974A0DC78A7CB9C_cppui256,
                                                                            0x00000000000000000000000000000000D6D435321968A76F341E174893BFE072_cppui256,
                                                                            0x000000000000000000000000000000006A490917E56990E623D9B04F348B6AA1_cppui256,
                                                                            0x0000000000000000000000000000000001DD5395B3B4E0163F9A3A78DEE2CCE5_cppui256,
                                                                            0x000000000000000000000000000000001AFFD6FB373CB2354DEEEE3A4B3DE8DC_cppui256,
                                                                            0x0000000000000000000000000000000099EF5D8A9D455F214176D5B80A5AB43D_cppui256,
                                                                            0x00000000000000000000000000000000769E278B9739FFF6A46F17F291CDB03F_cppui256,
                                                                            0x00000000000000000000000000000000717509B54112E0FA3285DE19BB053A0A_cppui256,
                                                                            0x00000000000000000000000000000000CE77ACA68237EF87E5E50284EEB69201_cppui256,
                                                                            0x000000000000000000000000000000005AF4B53ADCBBA9E03F32927E9369556E_cppui256,
                                                                            0x000000000000000000000000000000005A4CE311F5D948B666B01BBB3B2A84C7_cppui256};

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
            public_input.emplace_back(challenges[j]);
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
        public_input.emplace_back(c);
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

    std::vector<typename BlueprintFieldType::value_type> expected_result;

    std::string scalars_filename = "../../../../libs/blueprint/test/verifiers/kimchi/data/chacha/scalars.txt";
    std::ifstream scalars_fstream(scalars_filename);
        if (scalars_fstream) {
            while (true) {
                std::string input_string;
        
                scalars_fstream >> input_string;
                if (input_string.empty()) {
                    std::cerr << "empty line in " << scalars_filename << "!" << std::endl;
                    break;
                }


                typename curve_type::base_field_type::extended_integral_type number(input_string);
                assert(number < curve_type::scalar_field_type::modulus && "input does not fit into BlueprintFieldType");
                expected_result.push_back(shift_scalar_scalar<curve_type>(number));

                if (scalars_fstream.eof()) {
                    break;
                }
            }
        }
    else {
        std::cerr <<  "cannot open " << scalars_filename << " file" << std::endl;
        assert(1==0 && "cannot open scalars file");
    }
    scalars_fstream.close();
    std::cout << "scalars amount: " << expected_result.size() << std::endl;
    
    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < expected_result.size(); ++i) {
            if (!(expected_result[i] == assignment.var_value(real_res.output[i]))) {
                std::cout << "ASSERTION[" << i <<"] FAILED!\n";
                std::cout <<  expected_result[i].data << " != " << assignment.var_value(real_res.output[i]).data <<  "\n";
            }

            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite_recursion) {

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

    constexpr static std::size_t public_input_size = recursion_constants.public_input_size;
    constexpr static std::size_t max_poly_size = recursion_constants.max_poly_size;
    constexpr static std::size_t eval_rounds = recursion_constants.eval_rounds;

    constexpr static std::size_t witness_columns = recursion_constants.witness_columns;
    constexpr static std::size_t perm_size = recursion_constants.perm_size;

    constexpr static std::size_t srs_len = recursion_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = recursion_constants.prev_chal_size;

    constexpr static const std::size_t batch_size = recursion_constants.batch_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_recursion_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

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

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_recursion();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000AD39D811EFCE0FAD50EC0E161A0EF76E_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x000000000000000000000000000000001AF1BBFDB43BAF883077CB71813712B4_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256;
    typename BlueprintFieldType::value_type omega =
        0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x2D40D90836130DCC82FDDACBCCA9F17F64C87CE868421AA82A92FF62DA885C45_cppui256;
        
    typename BlueprintFieldType::value_type cip = 0x0DD1472152367FE7A1D7BB625D04459D9D111E256B2E7A33AA6C27F36954B4E5_cppui256;
    typename BlueprintFieldType::value_type r = 0x01C2C71FD3EDE15D094876291B2A2217684D581367D500D4A40774FDE78B9077_cppui256;
    typename BlueprintFieldType::value_type xi = 0x39DA9CD4FE6FD362E83BE4ED4647DE2441DC13F15B8A15985BB607B68B9852A4_cppui256;
    typename BlueprintFieldType::value_type c = 0x00000000000000000000000000000000ABFD05B4709CE7C3144601797031BB93_cppui256;
    std::array<typename BlueprintFieldType::value_type, eval_rounds> challenges = {0x00000000000000000000000000000000A595B8A0FBCF5DAD77D0BF136AE529A1_cppui256,
                                                                            0x000000000000000000000000000000004E53F614FFF00E45837CD3E9A746407F_cppui256,
                                                                            0x00000000000000000000000000000000F611552B93001B93A8BDAACC79B288F8_cppui256,
                                                                            0x00000000000000000000000000000000C334F693BD7FD8D56114520F81F4FF85_cppui256,
                                                                            0x00000000000000000000000000000000696B47BEBCB58F48E7792BB803F5590F_cppui256};

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

        for (std::size_t j = 0; j < eval_rounds; j++) {
            public_input.emplace_back(challenges[j]);
            fq_output.challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }

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
        public_input.emplace_back(c);
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

    std::vector<typename BlueprintFieldType::value_type> expected_result;

    std::string scalars_filename = "../../../../libs/blueprint/test/verifiers/kimchi/data/recursion/scalars.txt";
    std::ifstream scalars_fstream(scalars_filename);
        if (scalars_fstream) {
            while (true) {
                std::string input_string;
                scalars_fstream >> input_string;
                if (input_string.empty()) {
                    std::cerr << "empty line in " << scalars_filename << "!" << std::endl;
                    break;
                }

                typename curve_type::base_field_type::extended_integral_type number(input_string);
                assert(number < curve_type::scalar_field_type::modulus && "input does not fit into BlueprintFieldType");
                expected_result.push_back(shift_scalar_scalar<curve_type>(number));

                if (scalars_fstream.eof()) {
                    break;
                }
            }
        }
    else {
        std::cerr <<  "cannot open " << scalars_filename << " file" << std::endl;
        assert(1==0 && "cannot open scalars file");
    }
    scalars_fstream.close();
    std::cout << "scalars amount: " << expected_result.size() << std::endl;
    
    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < expected_result.size(); ++i) {
            if (!(expected_result[i] == assignment.var_value(real_res.output[i]))) {
                std::cout << "ASSERTION[" << i <<"] FAILED!\n";
                std::cout <<  expected_result[i].data << " != " << assignment.var_value(real_res.output[i]).data <<  "\n";
            }
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

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

    constexpr static std::size_t public_input_size = generic_constants.public_input_size;
    constexpr static std::size_t max_poly_size = generic_constants.max_poly_size;
    constexpr static std::size_t eval_rounds = generic_constants.eval_rounds;

    constexpr static std::size_t witness_columns = generic_constants.witness_columns;
    constexpr static std::size_t perm_size = generic_constants.perm_size;

    constexpr static std::size_t srs_len = generic_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = generic_constants.prev_chal_size;

    constexpr static const std::size_t batch_size = generic_constants.batch_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_generic_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

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
        0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256;
    typename BlueprintFieldType::value_type omega =
        0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;

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

        for (std::size_t j = 0; j < eval_rounds; j++) {
            public_input.emplace_back(challenges[j]);
            fq_output.challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }

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
        public_input.emplace_back(c);
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

    std::vector<typename BlueprintFieldType::value_type> expected_result;

    std::string generic_filename = "../../../../libs/blueprint/test/verifiers/kimchi/data/generic/scalars.txt";
    std::ifstream scalars_fstream(generic_filename);
        if (scalars_fstream) {
            while (true) {
                std::string input_string;
        
                scalars_fstream >> input_string;
                if (input_string.empty()) {
                    std::cerr << "empty line in " << generic_filename << "!" << std::endl;
                    break;
                }

                typename curve_type::base_field_type::extended_integral_type number(input_string);
                assert(number < curve_type::scalar_field_type::modulus && "input does not fit into BlueprintFieldType");
                expected_result.push_back(shift_scalar_scalar<curve_type>(number));

                if (scalars_fstream.eof()) {
                    break;
                }
            }
        }
    else {
        std::cerr <<  "cannot open " << generic_filename << " file" << std::endl;
        assert(1==0 && "cannot open scalars file");
    }
    scalars_fstream.close();
    std::cout << "scalars amount: " << expected_result.size() << std::endl;

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < real_res.output.size(); ++i) {
            if (!(expected_result[i] == assignment.var_value(real_res.output[i]))) {
                std::cout << "ASSERTION[" << i <<"] FAILED!\n";
                std::cout <<  expected_result[i].data << " != " << assignment.var_value(real_res.output[i]).data <<  "\n";
            }
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()