//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE BLUEPRINT_VERIFIERS_PICKLES_SCALAR_DETAILS_PLONK_DERIVE_PLONK_TEST

#include <boost/test/unit_test.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/perm_scalars.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/derive_plonk.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>

#include "../../../test_plonk_component.hpp"

#include <iostream>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_pickles_derive_plonk_suite)
BOOST_AUTO_TEST_CASE(blueprint_plonk_pickles_derive_plonk_vesta_scalar_field) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    using value_type = typename BlueprintFieldType::value_type;

    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 7;
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

    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description =
        zk::components::kimchi_circuit_description<index_terms_list, WitnessColumns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;
    using index_terms_list = typename kimchi_params::circuit_params::index_terms_list;
    using component_type = zk::components::derive_plonk<ArithmetizationType, kimchi_params, curve_type, 0, 1, 2, 3, 4,
                                                        5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::array<value_type, WitnessColumns> eval0_w = {
        0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
        0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
        0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
        0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
        0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
        0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
        0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
        0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
        0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
        0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
        0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
        0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
        0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
        0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
        0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256};

    value_type eval0_z =
        0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<value_type, perm_size - 1> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256};

    std::array<value_type, WitnessColumns> eval1_w = {
        0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
        0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
        0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
        0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
        0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
        0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
        0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
        0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
        0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
        0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
        0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
        0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
        0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
        0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
        0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256};

    value_type eval1_z =
        0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<value_type, perm_size - 1> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256
    };

    std::array<std::array<value_type, WitnessColumns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<value_type, perm_size - 1>, 2> eval_s = {eval0_s, eval1_s};

    value_type alpha_val =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    value_type zkp_zeta_val =
        0x10D6264E9E2FD66DF8E432BBA507EA36F9BA431B00A80B80757E56DEADC39D7A_cppui256;

    value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;

    value_type perm_scalar_val =
        0x0E7F540B2F6CE243D4F603210A7EF55620EEC89679E894777E34D1AA3A33C689_cppui256;

    std::size_t domain_size = 512;

    value_type base = 2;
    value_type shift = 0;
    value_type denominator = 0;
    constexpr typename BlueprintFieldType::integral_type vesta_base_field_modulus =
         0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui255;
     constexpr typename BlueprintFieldType::integral_type pallas_base_field_modulus =
         0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;

    if (typename BlueprintFieldType::integral_type(curve_type::base_field_type::modulus) - vesta_base_field_modulus == 0) {
        shift = base.pow(255);
        denominator = 1;
    }
    if (typename BlueprintFieldType::integral_type(curve_type::base_field_type::modulus) - pallas_base_field_modulus == 0) {
        shift = base.pow(255) + 1;
        denominator = base;
    }

    std::vector<value_type> public_input;

    var joint_combiner = var(0, public_input.size(), false, var::column_type::public_input);
    value_type joint_combiner_val = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(joint_combiner_val);

    var generic_selector = var(0, public_input.size(), false, var::column_type::public_input);
    value_type generic_selector_val = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(generic_selector_val);

    var poseidon_selector = var(0, public_input.size(), false, var::column_type::public_input);
    value_type poseidon_selector_val = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(poseidon_selector_val);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < WitnessColumns; j++) {
            evals[i].w[j] = var(0, public_input.size(), false, var::column_type::public_input);
            public_input.push_back(eval_w[i][j]);
        }

        evals[i].z = var(0, public_input.size(), false, var::column_type::public_input);
        public_input.push_back(eval_z[i]);

        for (std::size_t j = 0; j < perm_size - 1; j++) {
            evals[i].s[j] = var(0, public_input.size(), false, var::column_type::public_input);
            public_input.push_back(eval_s[i][j]);
        }
    }

    std::array<var, circuit_description::alpha_powers_n> alpha_powers;
    for (std::size_t i = 0; i < circuit_description::alpha_powers_n; i++) {
        alpha_powers[i] = var(0, public_input.size(), false, var::column_type::public_input);
        public_input.push_back(alpha_val.pow(i));
    }
    var alpha = var(0, public_input.size(), false, var::column_type::public_input);
    public_input.push_back(alpha_val);

    var beta = var(0, public_input.size(), false, var::column_type::public_input);
    public_input.push_back(beta_val);

    var gamma = var(0, public_input.size(), false, var::column_type::public_input);
    public_input.push_back(gamma_val);

    var zeta = var(0, public_input.size(), false, var::column_type::public_input);
    public_input.push_back(zeta_val);

    var omega = var(0, public_input.size(), false, var::column_type::public_input);
    public_input.push_back(omega_val);

    var zkp_zeta = var(0, public_input.size(), false, var::column_type::public_input);
    public_input.push_back(zkp_zeta_val);

    typename component_type::params_type params = {};

    value_type minus_1 = -1;
    typename BlueprintFieldType::integral_type integral_minus_1 =
        typename BlueprintFieldType::integral_type(minus_1.data);
    BlueprintFieldType::value_type minus_one_scalar = integral_minus_1;
    value_type expected_permutation_scalar_inv = perm_scalar_val * minus_one_scalar;

    var srs_length_log2 = var(0, public_input.size(), false, var::column_type::public_input);
    value_type srs_length_log2_val = 9;
    public_input.push_back(srs_length_log2_val);

    var zeta_to_n_minus_1 = var(0, public_input.size(), false, var::column_type::public_input);
    value_type zeta_to_n_minus_1_val = algebra::random_element<BlueprintFieldType>();
    public_input.push_back(zeta_to_n_minus_1_val);

    params.plonk.zeta = zeta;
    params.plonk.alpha = alpha;
    params.plonk.beta = beta;
    params.plonk.gamma = gamma;
    params.plonk.joint_combiner = joint_combiner;

    params.env.domain_size = domain_size;
    params.env.zeta_to_n_minus_1 = zeta_to_n_minus_1;
    params.env.srs_length_log2 = srs_length_log2;
    params.env.zk_polynomial = zkp_zeta;
    params.env.domain_generator = omega;
    params.env.alphas = alpha_powers;

    params.combined_evals = evals;
    params.combined_evals[0].generic_selector = generic_selector;
    params.combined_evals[0].poseidon_selector = poseidon_selector;

    auto prepare = [base, shift, denominator](value_type val) {
        value_type prepared;

        if ((val != 1) & (val != 0) &
            (val != -1)) {
            prepared = (val - base.pow(255) - 1) / 2;
        } else {
            prepared = (val - shift) / denominator;
        }
        return prepared;
    };

    std::pair<std::size_t, std::size_t> alpha_idxs = 
        index_terms_list::alpha_map(zk::components::argument_type::Permutation);
    value_type expected_res_perm_scalar_inv = eval1_z * beta_val * alpha_val.pow(alpha_idxs.first) * zkp_zeta_val;
    for (size_t i = 0; i < eval0_s.size(); ++i) {
        expected_res_perm_scalar_inv *= gamma_val + (beta_val * eval0_s[i]) + eval0_w[i];
    }
    expected_res_perm_scalar_inv = prepare(-expected_res_perm_scalar_inv);

    value_type expected_res_zeta = prepare(zeta_val);
    value_type expected_res_alpha = prepare(alpha_val);
    value_type expected_res_beta = prepare(beta_val);
    value_type expected_res_gamma = prepare(gamma_val);
    //value_type expected_res_zeta_to_srs_length = prepare(zeta_val.pow(srs_length_log2_val), base, shift, denominator);
    value_type expected_res_zeta_to_domain_size = prepare(zeta_to_n_minus_1_val + 1);
    std::array<value_type, 9> expected_generic = {
        prepare(generic_selector_val),
        prepare(eval0_w[0]),
        prepare(eval0_w[1]),
        prepare(eval0_w[2]),
        prepare(eval0_w[0] * eval0_w[1]),
        prepare(eval0_w[3]),
        prepare(eval0_w[4]),
        prepare(eval0_w[5]),
        prepare(eval0_w[3] * eval0_w[4])
    };

    value_type expected_posidon_selector = prepare(poseidon_selector_val);

    value_type expected_joint_combiner = joint_combiner_val;
    if (kimchi_params::use_lookup) {
        expected_joint_combiner = prepare(joint_combiner_val);
    }

    std::array<value_type, 4> expected_index_scalars = {
        prepare(0x017EEEF7695889AFB5311D7B36B31455AFF02B103BDA9BABF5BC29107B8F3AB7_cppui256),    // varBaseMul
        prepare(0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256),    // endoMul
        prepare(0x0F297E2FA4E61DD377911C6B14C03F5CABC1114813C5D5C4CDCBDFBE84C526DB_cppui256),    // endoMulScalar
        prepare(0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256),    // completeAdd
        // TODO: lookup_gate
    };

    auto result_check = [expected_res_zeta, expected_res_alpha,
                         expected_res_beta, expected_res_gamma,
                         /*expected_res_zeta_to_srs_length,*/
                         expected_res_zeta_to_domain_size,
                         expected_res_perm_scalar_inv,
                         &expected_generic,
                         expected_posidon_selector,
                         expected_joint_combiner,
                         &expected_index_scalars]
                        (AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_res_zeta == assignment.var_value(real_res.output.zeta));
        assert(expected_res_alpha == assignment.var_value(real_res.output.alpha));
        assert(expected_res_beta == assignment.var_value(real_res.output.beta));
        assert(expected_res_gamma == assignment.var_value(real_res.output.gamma));
        //  assert(expected_res_zeta_to_srs_length == assignment.var_value(real_res.output.zeta_to_srs_length));
        assert(expected_res_zeta_to_domain_size == assignment.var_value(real_res.output.zeta_to_domain_size));
        assert(expected_res_perm_scalar_inv == assignment.var_value(real_res.output.perm));

        for (size_t i = 0; i < expected_generic.size(); ++i) {
            assert(expected_generic[i] == assignment.var_value(real_res.output.generic[i]));
        }
        
        assert(expected_index_scalars[0] == assignment.var_value(real_res.output.vbmul));
        assert(expected_index_scalars[1] == assignment.var_value(real_res.output.endomul));
        assert(expected_index_scalars[2] == assignment.var_value(real_res.output.endomul_scalar));
        assert(expected_index_scalars[3] == assignment.var_value(real_res.output.complete_add));

        if (kimchi_params::use_lookup) {
            assert(expected_joint_combiner == assignment.var_value(real_res.output.lookup.joint_combiner));
            // TODO: check lookup gate
        }
        assert(expected_posidon_selector == assignment.var_value(real_res.output.poseidon_selector));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "scalars_env: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()