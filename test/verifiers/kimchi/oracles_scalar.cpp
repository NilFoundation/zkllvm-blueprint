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
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_oracles_test_suite)

template<typename BlueprintFieldType, typename KimchiParamsType>
struct expected_result_type {
    struct random_oracles {
        typename BlueprintFieldType::value_type alpha;
        typename BlueprintFieldType::value_type zeta;
        typename BlueprintFieldType::value_type v;
        typename BlueprintFieldType::value_type u;
        typename BlueprintFieldType::value_type v_chal;
        typename BlueprintFieldType::value_type u_chal;
    };

    // transcript_type transcript;
    random_oracles oracles;
    // std::array<typename BlueprintFieldType::value_type, KimchiParamsType::alpha_powers_n> alpha_powers;
    std::array<typename BlueprintFieldType::value_type, 2> p_eval;
    std::array<typename BlueprintFieldType::value_type, 2> powers_of_eval_points_for_chunks;
    // std::vector<prev_chal_output> prev_challenges_evals;
    typename BlueprintFieldType::value_type zeta_pow_n;
    typename BlueprintFieldType::value_type ft_eval0;
    // std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, 2>
    //     combined_evals;
    typename BlueprintFieldType::value_type cip;
    std::array<typename BlueprintFieldType::value_type, 2> eval_points;
};

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
        if (KimchiParamsType::poseidon_gate) {
            public_input.push_back(original_proof.evals[point_idx].poseidon_selector[0]);
            circuit_proof.proof_evals[point_idx].poseidon_selector =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
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

BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_test) {

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

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega =
        0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
    // verifier_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
    //     0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
    //     0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
    //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    std::size_t domain_size = 128;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 6, false, var::column_type::public_input);

    using component_type =
        zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0;
    typename BlueprintFieldType::value_type gamma = 0;
    typename BlueprintFieldType::value_type alpha =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;
    typename BlueprintFieldType::value_type expected_alpha =
        0x23A8600917236F0E644D49DD5E6CA89537CE3047DA7E29D2A7B8CA6006616092_cppui256;
    std::cout << "Expected alpha: " << expected_alpha.data << std::endl;
    typename BlueprintFieldType::value_type expected_zeta =
        0x3D0F1F3A3D07DC73FBDF3718FFE270122AA367FB5BA667AD4A4AB81167D21BE4_cppui256;
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

    // TODO prepare real data
    for (std::size_t i = 0; i < public_input_size; i++) {
        typename BlueprintFieldType::value_type tmp = algebra::random_element<BlueprintFieldType>();
        public_input.push_back(tmp);
        proof.public_input[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < kimchi_params::prev_challenges_size; i++) {
        for (std::size_t j = 0; j < eval_rounds; j++) {
            typename BlueprintFieldType::value_type tmp = algebra::random_element<BlueprintFieldType>();
            public_input.push_back(tmp);
            proof.prev_challenges[i][j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    typename component_type::params_type params = {verifier_index, proof, fq_output};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_real_data_test_chacha) {

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

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega =
        0x03B402C2CBD0A0660626F1948867533CFD2A80ABD33D0E808075A3EFC92D52D2_cppui256;
    std::array<typename BlueprintFieldType::value_type, perm_size> ver_ind_shift = 
       {0x0000000000000000000000000000000000000000000000000000000000000001_cppui256,
        0x00B9CDC8FD0BD4B27E2A74AF7AEBD5734D52D75BDF85EBF1CAD03413E914A2E3_cppui256,
        0x0033BFCF8112720332825BD83D44D92CADC0C30466E8102C419C30FA2665695A_cppui256,
        0x0087F4BB29954E16960F2DE3A1FA5AC7B62146DB348C7C9F0E8BF10B2C8E8411_cppui256,
        0x00EC71373B9F6CF15ED1949647365DB60B2E26C3A8ABBA5BB06BF23E9DBE5893_cppui256,
        0x00F39197CC4C55084C68D31F64F1A172406B585CB86445F00C248C721C496D10_cppui256,
        0x00B8DD039799DBEE12D2E6A4299A83E067353C0143C5DFD203190C239159EEA3_cppui256};
    std::size_t domain_size = 8192;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 6, false, var::column_type::public_input);
    verifier_index.shift = {var(0, 7, false, var::column_type::public_input),
                     var(0, 8, false, var::column_type::public_input),
                     var(0, 9, false, var::column_type::public_input),
                     var(0, 10, false, var::column_type::public_input),
                     var(0, 11, false, var::column_type::public_input),
                     var(0, 12, false, var::column_type::public_input),
                     var(0, 13, false, var::column_type::public_input)};

    using component_type =
        zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_chacha();

    typename BlueprintFieldType::value_type joint_combiner = 
        0x00000000000000000000000000000000CAAE895531DD8E0A0B0618483C93C727_cppui256;
    typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000001FE90F184CF0D23228FC49E7F4BDF537_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000ADE5F3B85395C4FCA12723C1322622EF_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x00000000000000000000000000000000919E7EE06FFBFC7EBBDAD14E68BBE21C_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x0000000000000000000000000000000075682BC2C8E8E561028A9B44CB52E0AB_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x2C85FCC264A1C8E1082E97E5686196CB1A7EF642F7B162EB21723CCCB6344341_cppui256;

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
    for (std::size_t i = 0; i < perm_size; ++i) {
        public_input.push_back(ver_ind_shift[i]);
    }

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    typename component_type::params_type params = {verifier_index, proof, fq_output};

    expected_result_type<BlueprintFieldType, kimchi_params> expected_result;
    expected_result.oracles.alpha = 0x32A5FB8A849C5CFC39656701462421AA5A9C88FCC7D7C342063D66486096D8ED_cppui256;
    expected_result.oracles.zeta = 0x24A32849C8B99B6CB2D1A514C0EC7B5F5A15799EA2428C6DCA8B332CEACE9DC0_cppui256;
    expected_result.oracles.v = 0x2C7C286ACD0842FE37DA945A743780DB32AE9A57A9048650AD4DDD0886AE650D_cppui256;
    expected_result.oracles.u = 0x2A4D106C58F5A790D319487554375EDCB75B870A5F585D7FF20EF9D71798EBE0_cppui256;
    expected_result.oracles.v_chal = 0x000000000000000000000000000000001B03AFAFDB93962EA2234ED281E961A8_cppui256;
    expected_result.oracles.u_chal = 0x00000000000000000000000000000000A8960627B66CD3FD62785B4009823B03_cppui256;
    expected_result.p_eval = {0x0_cppui256, 0x0_cppui256};
    expected_result.powers_of_eval_points_for_chunks = 
        {0x2D02AFB9FE82DCFB4656319B003FFD986271A0EDB42C3C0564FC71AC420805A3_cppui256, 
        0x2D02AFB9FE82DCFB4656319B003FFD986271A0EDB42C3C0564FC71AC420805A3_cppui256};
    expected_result.zeta_pow_n = 0x2D02AFB9FE82DCFB4656319B003FFD986271A0EDB42C3C0564FC71AC420805A3_cppui256;
    expected_result.ft_eval0 = 0x2717BC155186C4ED296A12363CA8CCAB31C5B5A77C1DB971FDC9D28282970DE3_cppui256;
    expected_result.cip = 0x388DEEF0601DB0933C25593324191E84942675DA8701B0BB504A064BECAE9525_cppui256;
    expected_result.eval_points = 
        {0x24A32849C8B99B6CB2D1A514C0EC7B5F5A15799EA2428C6DCA8B332CEACE9DC0_cppui256, 
        0x0488CE0ED0A00F3711EC06C76903F5BACC5E5DE0470B254C84DFD277BC561A10_cppui256};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result.oracles.alpha == assignment.var_value(real_res.oracles.alpha));
        assert(expected_result.oracles.zeta == assignment.var_value(real_res.oracles.zeta));
        assert(expected_result.oracles.v == assignment.var_value(real_res.oracles.v));
        assert(expected_result.oracles.u == assignment.var_value(real_res.oracles.u));
        assert(expected_result.oracles.v_chal == assignment.var_value(real_res.oracles.v_chal));
        assert(expected_result.oracles.u_chal == assignment.var_value(real_res.oracles.u_chal));
        assert(expected_result.p_eval[0] == assignment.var_value(real_res.p_eval[0]));
        assert(expected_result.p_eval[1] == assignment.var_value(real_res.p_eval[1]));
        assert(expected_result.powers_of_eval_points_for_chunks[0] == assignment.var_value(real_res.powers_of_eval_points_for_chunks[0]));
        assert(expected_result.powers_of_eval_points_for_chunks[1] == assignment.var_value(real_res.powers_of_eval_points_for_chunks[1]));
        assert(expected_result.zeta_pow_n == assignment.var_value(real_res.zeta_pow_n));
        assert(expected_result.ft_eval0 == assignment.var_value(real_res.ft_eval0));
        assert(expected_result.cip == assignment.var_value(real_res.cip));
        assert(expected_result.eval_points[0] == assignment.var_value(real_res.eval_points[0]));
        assert(expected_result.eval_points[1] == assignment.var_value(real_res.eval_points[1]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

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
    constexpr static std::size_t eval_rounds = 5;

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
    std::array<typename BlueprintFieldType::value_type, perm_size> ver_ind_shift = 
       {0x0000000000000000000000000000000000000000000000000000000000000001_cppui256,
        0x00B9CDC8FD0BD4B27E2A74AF7AEBD5734D52D75BDF85EBF1CAD03413E914A2E3_cppui256,
        0x0033BFCF8112720332825BD83D44D92CADC0C30466E8102C419C30FA2665695A_cppui256,
        0x0087F4BB29954E16960F2DE3A1FA5AC7B62146DB348C7C9F0E8BF10B2C8E8411_cppui256,
        0x00EC71373B9F6CF15ED1949647365DB60B2E26C3A8ABBA5BB06BF23E9DBE5893_cppui256,
        0x00F39197CC4C55084C68D31F64F1A172406B585CB86445F00C248C721C496D10_cppui256,
        0x00B8DD039799DBEE12D2E6A4299A83E067353C0143C5DFD203190C239159EEA3_cppui256};
    std::size_t domain_size = 32;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 6, false, var::column_type::public_input);
    verifier_index.shift = {var(0, 7, false, var::column_type::public_input),
                     var(0, 8, false, var::column_type::public_input),
                     var(0, 9, false, var::column_type::public_input),
                     var(0, 10, false, var::column_type::public_input),
                     var(0, 11, false, var::column_type::public_input),
                     var(0, 12, false, var::column_type::public_input),
                     var(0, 13, false, var::column_type::public_input)};

    using component_type =
        zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::proof_type<curve_type> kimchi_proof = test_proof_recursion();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D_cppui256;
    typename BlueprintFieldType::value_type gamma = 0x00000000000000000000000000000000AD39D811EFCE0FAD50EC0E161A0EF76E_cppui256;
    typename BlueprintFieldType::value_type alpha =
        0x000000000000000000000000000000001AF1BBFDB43BAF883077CB71813712B4_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x00000000000000000000000000000000BE221A5AA97523F509569F35A40CF587_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x2D40D90836130DCC82FDDACBCCA9F17F64C87CE868421AA82A92FF62DA885C45_cppui256;

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
    for (std::size_t i = 0; i < perm_size; ++i) {
        public_input.push_back(ver_ind_shift[i]);
    }

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    typename component_type::params_type params = {verifier_index, proof, fq_output};

    expected_result_type<BlueprintFieldType, kimchi_params> expected_result;
    expected_result.oracles.alpha = 0x220B73274823F8B0E46273FA8546B238F1E58529E061A811AB584A97C146AF87_cppui256;
    expected_result.oracles.zeta = 0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256;
    expected_result.oracles.v = 0x39DA9CD4FE6FD362E83BE4ED4647DE2441DC13F15B8A15985BB607B68B9852A4_cppui256;
    expected_result.oracles.u = 0x01C2C71FD3EDE15D094876291B2A2217684D581367D500D4A40774FDE78B9077_cppui256;
    expected_result.oracles.v_chal = 0x0000000000000000000000000000000091A05F9F554DB9886DB5E15C26186B31_cppui256;
    expected_result.oracles.u_chal = 0x000000000000000000000000000000003BA5F819BB4CFE319879AF328184E916_cppui256;
    expected_result.p_eval = {0x0_cppui256, 0x0_cppui256};
    expected_result.powers_of_eval_points_for_chunks = 
        {0x1BBAA867A1B449CC008FBC0E039F355E2E7C2840493C17DF42739679E4DE7551_cppui256, 
        0x1BBAA867A1B449CC008FBC0E039F355E2E7C2840493C17DF42739679E4DE7551_cppui256};
    expected_result.zeta_pow_n = 0x1BBAA867A1B449CC008FBC0E039F355E2E7C2840493C17DF42739679E4DE7551_cppui256;
    expected_result.ft_eval0 = 0x064EEBAFAC40594BCEACD8091EBC8D085D3D3BEB2CA76A7E1D7935DC0CB73A66_cppui256;
    expected_result.cip = 0x0DD1472152367FE7A1D7BB625D04459D9D111E256B2E7A33AA6C27F36954B4E5_cppui256;
    expected_result.eval_points = 
        {0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256, 
        0x11039196D240AC7CC0D1A88749F716B6B025F6BCA2CBBD0B41D2DA46FCC90558_cppui256};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result.oracles.alpha == assignment.var_value(real_res.oracles.alpha));
        assert(expected_result.oracles.zeta == assignment.var_value(real_res.oracles.zeta));
        assert(expected_result.oracles.v == assignment.var_value(real_res.oracles.v));
        assert(expected_result.oracles.u == assignment.var_value(real_res.oracles.u));
        assert(expected_result.oracles.v_chal == assignment.var_value(real_res.oracles.v_chal));
        assert(expected_result.oracles.u_chal == assignment.var_value(real_res.oracles.u_chal));
        assert(expected_result.p_eval[0] == assignment.var_value(real_res.p_eval[0]));
        assert(expected_result.p_eval[1] == assignment.var_value(real_res.p_eval[1]));
        assert(expected_result.powers_of_eval_points_for_chunks[0] == assignment.var_value(real_res.powers_of_eval_points_for_chunks[0]));
        assert(expected_result.powers_of_eval_points_for_chunks[1] == assignment.var_value(real_res.powers_of_eval_points_for_chunks[1]));
        assert(expected_result.zeta_pow_n == assignment.var_value(real_res.zeta_pow_n));
        assert(expected_result.ft_eval0 == assignment.var_value(real_res.ft_eval0));
        assert(expected_result.cip == assignment.var_value(real_res.cip));
        assert(expected_result.eval_points[0] == assignment.var_value(real_res.eval_points[0]));
        assert(expected_result.eval_points[1] == assignment.var_value(real_res.eval_points[1]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_oracles_real_data_test_generic) {

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
    constexpr static std::size_t eval_rounds = 0;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 32;
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_generic_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega =
        0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    std::array<typename BlueprintFieldType::value_type, perm_size> ver_ind_shift = 
        {0x0000000000000000000000000000000000000000000000000000000000000001_cppui256,
        0x00B9CDC8FD0BD4B27E2A74AF7AEBD5734D52D75BDF85EBF1CAD03413E914A2E3_cppui256,
        0x0033BFCF8112720332825BD83D44D92CADC0C30466E8102C419C30FA2665695A_cppui256,
        0x0087F4BB29954E16960F2DE3A1FA5AC7B62146DB348C7C9F0E8BF10B2C8E8411_cppui256,
        0x00EC71373B9F6CF15ED1949647365DB60B2E26C3A8ABBA5BB06BF23E9DBE5893_cppui256,
        0x00F39197CC4C55084C68D31F64F1A172406B585CB86445F00C248C721C496D10_cppui256,
        0x00B8DD039799DBEE12D2E6A4299A83E067353C0143C5DFD203190C239159EEA3_cppui256};
    std::size_t domain_size = 32;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 6, false, var::column_type::public_input);
    verifier_index.shift = {var(0, 7, false, var::column_type::public_input),
                     var(0, 8, false, var::column_type::public_input),
                     var(0, 9, false, var::column_type::public_input),
                     var(0, 10, false, var::column_type::public_input),
                     var(0, 11, false, var::column_type::public_input),
                     var(0, 12, false, var::column_type::public_input),
                     var(0, 13, false, var::column_type::public_input)};

    using component_type =
        zk::components::oracles_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, 0, 1, 2, 3, 4,
                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

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
    for (std::size_t i = 0; i < perm_size; ++i) {
        public_input.push_back(ver_ind_shift[i]);
    }

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    typename component_type::params_type params = {verifier_index, proof, fq_output};

    expected_result_type<BlueprintFieldType, kimchi_params> expected_result;
    expected_result.oracles.alpha = 0x0265E71776BF443E4B298DB910BC81DDB1F1E74913F8A2A121BD0C853D9F01AA_cppui256;
    expected_result.oracles.zeta = 0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256;
    expected_result.oracles.v = 0x38F378C3A58670C0526EECA358159AF2BCD782EA23FA6E7DCC1235220D533C48_cppui256;
    expected_result.oracles.u = 0x02F09286E0F4EA5B8C2DA4C966DC23D900A5DD4D65F805202EF0D38FC8791C37_cppui256;
    expected_result.oracles.v_chal = 0x00000000000000000000000000000000551AEE8D34A8BB2896BBAA510F326658_cppui256;
    expected_result.oracles.u_chal = 0x0000000000000000000000000000000033E1BCE4A4EF1C19F622D09D128160EF_cppui256;
    expected_result.p_eval = {0x18D62B16440429CDC5B94B8D9DC8A550535487AA7B64822433AD5E762009BD7C_cppui256, 
                            0x32B7DA94FAF98733D833AFE878FA7775452875BCBC8A953CEF1002C7B3D24033_cppui256};
    expected_result.powers_of_eval_points_for_chunks = 
        {0x1F4391D29EFCBC00A2981CA4E752890900F18CBF88DC808F272ED3692FBF28C7_cppui256, 
        0x1F4391D29EFCBC00A2981CA4E752890900F18CBF88DC808F272ED3692FBF28C7_cppui256};
    expected_result.zeta_pow_n = 0x1F4391D29EFCBC00A2981CA4E752890900F18CBF88DC808F272ED3692FBF28C7_cppui256;
    expected_result.ft_eval0 = 0x1EB63A0FF0ECF199DE30AC53401DA46CB768FF0B00052D99A213774CA4DA5769_cppui256;
    expected_result.cip = 0x10EFC44BEF0B125C23172AEA94C4BE39BC7CD8F0A353D72BB74680F668796273_cppui256;
    expected_result.eval_points = 
        {0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256, 
        0x0246EF2FEB792F5373089629FF28E70F0086933E6FD61172905B184D6363DD4C_cppui256};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result.oracles.alpha == assignment.var_value(real_res.oracles.alpha));
        assert(expected_result.oracles.zeta == assignment.var_value(real_res.oracles.zeta));
        assert(expected_result.oracles.v == assignment.var_value(real_res.oracles.v));
        assert(expected_result.oracles.u == assignment.var_value(real_res.oracles.u));
        assert(expected_result.oracles.v_chal == assignment.var_value(real_res.oracles.v_chal));
        assert(expected_result.oracles.u_chal == assignment.var_value(real_res.oracles.u_chal));
        assert(expected_result.p_eval[0] == assignment.var_value(real_res.p_eval[0]));
        assert(expected_result.p_eval[1] == assignment.var_value(real_res.p_eval[1]));
        assert(expected_result.powers_of_eval_points_for_chunks[0] == assignment.var_value(real_res.powers_of_eval_points_for_chunks[0]));
        assert(expected_result.powers_of_eval_points_for_chunks[1] == assignment.var_value(real_res.powers_of_eval_points_for_chunks[1]));
        assert(expected_result.zeta_pow_n == assignment.var_value(real_res.zeta_pow_n));
        assert(expected_result.ft_eval0 == assignment.var_value(real_res.ft_eval0));
        assert(expected_result.cip == assignment.var_value(real_res.cip));
        assert(expected_result.eval_points[0] == assignment.var_value(real_res.eval_points[0]));
        assert(expected_result.eval_points[1] == assignment.var_value(real_res.eval_points[1]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()