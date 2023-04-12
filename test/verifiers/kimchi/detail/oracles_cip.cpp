//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test

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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/oracles_cip.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_index_terms.hpp"
#include "../../../test_plonk_component.hpp"
#include <fstream>
#include <verifiers/kimchi/mina_state_proof_constants.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_ec) {
    // https://github.com/NilFoundation/o1-labs-proof-systems/blob/master/kimchi/src/tests/ec.rs/#L15

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

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                    5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::vector<
        std::array<
            std::array<var, commitment_params::split_poly_eval_size>,
            eval_points_amount>> polys(kimchi_params::prev_challenges_size);
    std::array<var,eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
               eval_points_amount> evals;
    typename BlueprintFieldType::value_type expected_result = 0x354a5816578a0f9d8d9ddb7fa580573882cb771454a716e4838c1b29e24034a2_cppui255;

    public_input.push_back(0x1A27603517D952BB0060BB01DE0DA94CFC587748DD85D4987C14883E3BA51BAB_cppui255);
    v = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0CD95BF326F609A8D27F9CD8CFA5C1A0662C588EEA1E5B84CD517DC5BA09C502_cppui255);
    u = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0C5FFA9CCCAB64B985EB4467CE3933E6F4BFF202AEA53ACD4E27C0C6BBE902B2_cppui255);
    ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x16FE1AE7F56997161DB512632BE7BFA337F47F422E0D01AF06DE298DD8C429D5_cppui255);
    ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
    p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
    p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui255);
    evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui255);
    evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui255);
    evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui255);
    evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui255);
    evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui255);
    evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui255);
    evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui255);
    evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui255);
    evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui255);
    evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui255);
    evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui255);
    evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui255);
    evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui255);
    evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui255);
    evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui255);
    evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui255);
    evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui255);
    evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui255);
    evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui255);
    evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui255);
    evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui255);
    evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui255);
    evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui255);
    evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui255);
    evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui255);
    evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui255);
    evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui255);
    evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui255);
    evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui255);
    evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui255);
    evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui255);
    evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui255);
    evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui255);
    evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui255);
    evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui255);
    evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui255);
    evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui255);
    evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui255);
    evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui255);
    evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui255);
    evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui255);
    evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui255);
    evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui255);
    evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
    evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
    evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
    evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
    evals[1].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);



    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));

    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_generic) {
    // https://github.com/NilFoundation/o1-labs-proof-systems/blob/master/kimchi/src/tests/generic.rs#L25

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

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_generic_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                    5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::vector<
        std::array<
            std::array<var, commitment_params::split_poly_eval_size>,
            eval_points_amount>> polys(kimchi_params::prev_challenges_size);
    std::array<var,eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
               eval_points_amount> evals;

	public_input.push_back(0x112E840238322C4D910349593305D850B1D7D419CE5948125C58081C6DBC512D_cppui255);
	evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0849FBC0BEC891D6772FAD00A1113B46AEE794EF161D432AAEA14C0369BE0C53_cppui255);
	evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3E4E5BAC9E67BBC4F133230906CA00835E00826F4283028FB19F7374957546D8_cppui255);
	evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x18C7FACD45C938EC7AB686079B5F273659EAAFA29DC0BF0F9C6DCCC8E011889A_cppui255);
	evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0640F132D4D98698E9DE0344E90AE63EE803EF44073E6AF41DFEED5C99EB7B0A_cppui255);
	evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x12CD60B86C136D3677C24A6D30E30702B69265A1FBC52FD2F54A5A693A81EFC6_cppui255);
	evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x21BA2DD3BC339C941900FDCF0E9ED348B77A2490163D3C9C243BBA05F83C36E4_cppui255);
	evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0BB72A4F18E3EE2A3F3B1A907BF20C46146C0FADB8D94C2B6BA134D4B2F60676_cppui255);
	evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x35B426CA75943FC065753751E945454393A493C764C254D64C33E0906DAFD609_cppui255);
	evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1FB12345D24491568BAF541356987E40F0967EE5075E646593995B5F2869A59B_cppui255);
	evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x09AE1FC12EF4E2ECB1E970D4C3EBB73E4D886A02A9FA73F4DAFED62DE323752D_cppui255);
	evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x33AB1C3C8BA53482D8238D96313EF03BCCC0EE1C55E37C9FBB9181E99DDD44C0_cppui255);
	evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1DA818B7E8558618FE5DAA579E92293929B2D939F87F8C2F02F6FCB858971452_cppui255);
	evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x07A515334505D7AF2497C7190BE5623686A4C4579B1B9BBE4A5C77871350E3E4_cppui255);
	evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x31A211AEA1B629454AD1E3DA79389B3405DD48714704A4692AEF2342CE0AB377_cppui255);
	evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui255);
	evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0BBA842C29D0BF850E2059E998D6708924BCF60F16A3A81FAE55B690C9A70669_cppui255);
	evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0953B93EFAC3D69A61643671BB232C6049A099FE5E56587A370BF57D95A5C15E_cppui255);
	evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x15F00D0C7FADC3C7030D4122EF8377A7C699E1DF2B09AE46A6EB6C0C1FE3404B_cppui255);
	evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3B2240CBB9B977AB255EC88A3CC28D009CF416CC194899AF5B0A5A1F915F2469_cppui255);
	evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0906279A9DB6C624BE8E0E54F3C79B4F2F79BE7943EBE1474609417807CAEC92_cppui255);
	evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x085119A00D99F02BFC4D7F452C141C8408604CA839B4C1954A6DD2D41EC6A657_cppui255);
	evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x07E90390ACAD4FB257163C8CA544C86AD4D73FA726B15006ED59A37DC2BF6108_cppui255);
	evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x2B9B971A6B4B55625126E26AFC087911B69F136CC159293D64407A5B5AC53787_cppui255);
	evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3BBDF8A25C9239687FA661F19FCDEE494518F6901820F799972CE1DAF9A9F1A2_cppui255);
	evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x18093FD278D278EA1E74FD9E4586807B1DEB0A725A2307EE478F5FA62837EEEE_cppui255);
	evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x06C5BE2101FE12133C8444201C589B59A1753603901FCE900E7DCD1EBCD031EC_cppui255);
	evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x063412B8BD6EBE01692899817B3E6910BBDE64A78055C7F133BBE9D7CCB1576A_cppui255);
	evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x325A5560859FB1BCDE611B46D4D667D4218A25BDC6936EB55603E65595CFD72C_cppui255);
	evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x30D4215A6FEA8ADED23194AD92D94715D62864CDD3FD3532638852294B063548_cppui255);
	evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x09A62A0C90340C672007A732DBFEC55847A8012C48F5279BB9FE4483E6B35735_cppui255);
	evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x227832BEB07D8DEF6DDDB9B82524439ADB6E3686C73A1320A9A167CB82607923_cppui255);
	evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3B4A3B70D0C70F77BBB3CC3D6E49C1DD6F346BE1457EFEA599448B131E0D9B11_cppui255);
	evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x141C4422F11091000989DEC2B76F401FE0B4083FBA76F10EEFBA7D6DB9BABCFE_cppui255);
	evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2CEE4CD5115A1288575FF1480094BE62747A3D9A38BBDC93DF5DA0B55567DEEC_cppui255);
	evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x05C0558731A39410A53603CD49BA3CA4E5F9D9F8ADB3CEFD35D3930FF11500D9_cppui255);
	evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1E925E3951ED1598F30C165292DFBAE779C00F532BF8BA822576B6578CC222C7_cppui255);
	evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x376466EB7236972140E228D7DC05392A0D8644ADAA3DA6071519D99F286F44B5_cppui255);
	evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x0246EF2FEB792F5373089629FF28E70F0086933E6FD61172905B184D6363DD4C_cppui255);
	evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1767915E609183B233ABC7AFA08EB58A1667CF7554A357BBFDC37799E25C9320_cppui255);
	evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1EC5153ADEED79FE6EDE38A097DC53245F2EC57B40E63A58337AB9DCEE671696_cppui255);
	evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x020B36CE4A95DFE83901F0099002910BA1C81A79EB0C44BF0CB1390CB9531828_cppui255);
	evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2B2753C3A95F484EE8664D18C18571B29F5E21DCFBA080AF6758455D60D1F3B7_cppui255);
	evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0F3FB3BCA61FC552B1D70CBF8C0E617BD85F6F4D82DF8B05C09F98406D41215A_cppui255);
	evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x21163FC825B2EA05C5E3D8966213D9A76196E2866C482B24B879F6A9E6B481B6_cppui255);
	evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x3A37B6776DA1BE6E280141853F3EE0D56BA9B6E02724E6FB12549452A901315D_cppui255);
	evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[1].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x1EB63A0FF0ECF199DE30AC53401DA46CB768FF0B00052D99A213774CA4DA5769_cppui255);
	ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1848E3FB45C4E523924F50453A4561714AB2EA8A2C25D67F4F2D73C6ABA4ACCB_cppui255);
	ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x02F09286E0F4EA5B8C2DA4C966DC23D900A5DD4D65F805202EF0D38FC8791C37_cppui255);
	u = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x38F378C3A58670C0526EECA358159AF2BCD782EA23FA6E7DCC1235220D533C48_cppui255);
	v = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x18D62B16440429CDC5B94B8D9DC8A550535487AA7B64822433AD5E762009BD7C_cppui255);
	p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x32B7DA94FAF98733D833AFE878FA7775452875BCBC8A953CEF1002C7B3D24033_cppui255);
	p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	typename BlueprintFieldType::value_type expected_result = 0x10EFC44BEF0B125C23172AEA94C4BE39BC7CD8F0A353D72BB74680F668796273_cppui255;


    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));

    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_recursion) {
    // https://github.com/NilFoundation/o1-labs-proof-systems/blob/master/kimchi/src/tests/recursion.rs/#L15

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

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_generic_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                    5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::vector<
        std::array<
            std::array<var, commitment_params::split_poly_eval_size>,
            eval_points_amount>> polys(kimchi_params::prev_challenges_size);

    std::array<var,eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
               eval_points_amount> evals;

    public_input.push_back(0x03B060BB64B9D6627C7336873BA524D7B752598E8B3390647BDF6B70B5BB93FF_cppui255);
    polys[0][0][0] = var(0, public_input.size() - 1, false, var::column_type::public_input);;
    public_input.push_back(0x39B7CA68618353B26F521A651FE3F9DD365401BC8B68B07FC6D656EB010A541B_cppui255);
    polys[0][1][0] = var(0, public_input.size() - 1, false, var::column_type::public_input);;

	public_input.push_back(0x2A016E5F91F6C33552FC86A7A88C034E5CF1301E4982545A15AB709ECE150E09_cppui255);
	evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1D1B8F16A3DF52F90BA4856A11D397FDD175DEBBDC84F9D9FD71C46E5CB311CC_cppui255);
	evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x034EB5403A85D023EFD87CE7E37CD027921DBC8F5A59C6338A12965B2E1D2D9B_cppui255);
	evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3D708DC37C2985BD9E8F39D40FFB35A8C1D1D4106AC17CEA1668C944007FE789_cppui255);
	evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x23ACD65BE15FC86FB7FC4FD45701CF7F348C13DD6DFF400DF808BE97006E06C8_cppui255);
	evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3F6D999688174F2CC9C37FBFDA241825F50505E56EF660E29FBC52F06008F2EF_cppui255);
	evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x054FF59489820600DB800466FDF3063D387CAFC5464741417FAD07A00E2B558A_cppui255);
	evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x078062AB9E022D286A47F28A6A57C368598416D076C558A8288A05AD9A1451DE_cppui255);
	evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x09B0CFC2B282544FF90FE0ADD6BC80937A8B7DDBA743700ED16703BB25FD4E32_cppui255);
	evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0BE13CD9C7027B7787D7CED143213DBE9B92E4E6D7C187757A4401C8B1E64A86_cppui255);
	evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0E11A9F0DB82A29F169FBCF4AF85FAE9BC9A4BF2083F9EDC2320FFD63DCF46DA_cppui255);
	evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x10421707F002C9C6A567AB181BEAB814DDA1B2FD38BDB642CBFDFDE3C9B8432E_cppui255);
	evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1272841F0482F0EE342F993B884F753FFEA91A08693BCDA974DAFBF155A13F82_cppui255);
	evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x14A2F13619031815C2F7875EF4B4326B1FB0811399B9E5101DB7F9FEE18A3BD6_cppui255);
	evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x16D35E4D2D833F3D51BF75826118EF9640B7E81ECA37FC76C694F80C6D73382A_cppui255);
	evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui255);
	evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x264CBA1EFD870553869EC32E652FE2FC5DB4DF0C8B8550816F1947F66858B238_cppui255);
	evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x21D7D3F53426BA3024217C852D5B1944031F52E784E95CA0539A9F88FB3F3FBE_cppui255);
	evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x260E6148F06FA79CD3C8C4A379955A8823017E730AD3624A578304A44B5113AC_cppui255);
	evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2E901B006A7D080B6566A472AC9DEA73BB53A57A190B1A21ECEB698A869374BA_cppui255);
	evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2E70F1D4AE3E1DE24337D33C4F61C88A628368CA7FBE9BF67C16F0944C64B7DE_cppui255);
	evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x38C5D08C61572A0F233A3732575F3A07AD484107EC7366FEB0903FCC30253C1A_cppui255);
	evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2C1E20B5D662CE38070228313FD0D968116779CC3CD2FFF662707412EEBD04C7_cppui255);
	evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x119301E40E2E7C7D465D44663295D7EA620FBCC1F53517ABDD2ECF5C944C5CA1_cppui255);
	evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2796DF6969578BE116556794B60EFDD9D3686F8BFE336F0309CA3AA73393C8A0_cppui255);
	evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x06A9EE581EC0C7F41B9E54F192948200F0045C21B4BA021DBCB6C8EBA3BFF30C_cppui255);
	evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0EA289935EE95E8D771A681893AC0E4C33CB9BB88A2D0DB18F3C0CED5D37EBAA_cppui255);
	evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x244FF116C46C3E79427E298089212A35DFB57750BDCD97A159A98DC014870F83_cppui255);
	evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3F04F2BDEBB8E5E732AB024C699E2481A82CA6205E3E34481A0D57BA0AEB997E_cppui255);
	evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x014FCC504DEC8FE403ED2DB233134CD28CAD4F9E54DEE00C3384740355203132_cppui255);
	evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2AE2D234C19E20C167FAC3AB796EB0F1524B62DD459AE8FE0997B0544AC69E29_cppui255);
	evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1475D819354FB19ECC0859A4BFCA150FF5A2DD202D09F8D4467DBBB8406D0B1F_cppui255);
	evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3E08DDFDA901427C3015EF9E0625792EBB40F05F1DC601C61C90F80936137816_cppui255);
	evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x279BE3E21CB2D359942385974C80DD4D5E986AA20535119C5977036D2BB9E50C_cppui255);
	evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x112EE9C690646436F8311B9092DC416C01EFE4E4ECA42172965D0ED121605202_cppui255);
	evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3AC1EFAB0415F5145C3EB189D937A58AC78DF823DD602A646C704B221706BEF9_cppui255);
	evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2454F58F77C785F1C04C47831F9309A96AE57266C4CF3A3AA95656860CAD2BEF_cppui255);
	evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0DE7FB73EB7916CF2459DD7C65EE6DC80E3CECA9AC3E4A10E63C61EA025398E5_cppui255);
	evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x11039196D240AC7CC0D1A88749F716B6B025F6BCA2CBBD0B41D2DA46FCC90558_cppui255);
	evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x022CE995D1CA16666888BED84A062994F864C180A393E76F3C2D14786D3FF82E_cppui255);
	evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3B4C505BF9C0962541FA4597D037BF217AF2B2CD893239A05FC64E8674967F83_cppui255);
	evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x02F194EC301411C828DAC6A83F90299F99441F0EDEAB5A2D0700C32553C5A10B_cppui255);
	evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2AA071813813CCB09C5C6F5BB6E3F6BEDA421DC5E30A71518BCB05AFDFB4DDA9_cppui255);
	evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3F82F6EF12DD276FAF8BC01CE8477BC9AF5B81D28586B8EF56CB0E025FA97276_cppui255);
	evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2DEFB3CFB41140464BF709B147777123731468F528CF8F14C032CA136A477469_cppui255);
	evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x23EA1BB94CD1D2E0E13048E0888501151308AD086CCD0D8E7DED12FF54734259_cppui255);
	evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[1].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x064EEBAFAC40594BCEACD8091EBC8D085D3D3BEB2CA76A7E1D7935DC0CB73A66_cppui255);
	ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0BEEA8845F1FD21B0057ACEA23ADFEB71A4922C0A579A57FA221BFF73BE63511_cppui255);
	ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x01C2C71FD3EDE15D094876291B2A2217684D581367D500D4A40774FDE78B9077_cppui255);
	u = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x39DA9CD4FE6FD362E83BE4ED4647DE2441DC13F15B8A15985BB607B68B9852A4_cppui255);
	v = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0_cppui255);
	p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0_cppui255);
	p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	typename BlueprintFieldType::value_type expected_result = 0x0DD1472152367FE7A1D7BB625D04459D9D111E256B2E7A33AA6C27F36954B4E5_cppui255;



    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));

    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_chacha) {

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

    constexpr static const std::size_t eval_points_amount = 2;



    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_chacha_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                    5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::vector<
        std::array<
            std::array<var, commitment_params::split_poly_eval_size>,
            eval_points_amount>> polys(kimchi_params::prev_challenges_size);
    std::array<var,eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
               eval_points_amount> evals;

	public_input.push_back(0x1832CB426BF30A01AC2F1B44EEF96AFA5FB9F5C04FD2AFF6A237B255C6E2BD83_cppui255);
	evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3E526399777CFAD36CDA3AF41D2F7A42EC9E1CECCCCEB2D7F7D211975A00F40D_cppui255);
	evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x253DA889E908457420FBA0C522F84ECBCAB8EC7A13CAF0995AE2148358E7AE0C_cppui255);
	evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1BDD9BAFD8EC7F5DCE110B2E11C0EF51356795EC8DDD37B415256B86AD2C4A93_cppui255);
	evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0727969A0E7A0F4F93237D236585C13ACB8DFE206F24C7BBF6E62DA542EE03A2_cppui255);
	evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1C2FBBB7ED98EE2B1D2A5449FFA944B5C29768F9CD208491F1C15C79AE15CC7C_cppui255);
	evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1A74EA383021FA8A6D5AE1AB48E90818243D3237A617857697B94AC058ECC3D9_cppui255);
	evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x03DAF3B4211036966434E900B5BA4AE41FD3FD10E10DB0FC1B81EC6D34E8A752_cppui255);
	evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x066B5444E0DF68364FD936E7D2C27DFE197058221F2F7C25CF957F670A3559A5_cppui255);
	evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x17E1458640838FF4E21269CC4C7C02C10F102F64B2133DD4860F0FE5C9BC7C45_cppui255);
	evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x33FA759C44785811A3C4ED0DE2FCC8D6059289C90E36CB8EF1EFB56BF4F1237F_cppui255);
	evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x248FD1BD89244D28B55F88279B2AB785872DB9FB371DF6C2727665DDF826397A_cppui255);
	evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2EF2B4D66ED48B9EF71FEF177F0E7097F2308FF32103C5C183F94A5F599F2057_cppui255);
	evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3F712A2557E2D466FFB1A055C342DF285BCD2D2B6AAA1E3D6A41F57B4E52E2CA_cppui255);
	evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0AA215F88D7CE3D00439C8CE9ADBD062A3701562E17900B2EAE4D66D530D1906_cppui255);
	evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x24A32849C8B99B6CB2D1A514C0EC7B5F5A15799EA2428C6DCA8B332CEACE9DC0_cppui255);
	evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0EE54D5B5C323B650025E68D3F20A2EB76592C2DE5D9F93ECF88C01A390DC12C_cppui255);
	evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1E9908B44F8E57E5FF3521D2F7FF9E1EA4AA922CA3FA1178CF469CDBC247D96B_cppui255);
	evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0FFF01701332F9D78AF783E9447E26B18B1565CF2805B7E131E9AA3A642E24A2_cppui255);
	evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x243C175168314B8F78CBD02A44D77E6756050B11EC4463FE8D52173A1FDA2CC6_cppui255);
	evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x31D344BBC3108D2630F62C6F9DCBE7598D4881E40EA351CEF7BBDAFBA7AD1718_cppui255);
	evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x1F76D655F63054B89DBE0143AC58127DE486B57BA7E5831C13E0051E04689F32_cppui255);
	evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x06B310DB3F89AAF4DBD4443AC42AD4261CF7B4647F8ACFF40F31756E8F43E937_cppui255);
	evals[0].lookup.sorted[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x06E379154092DB7EE80EFA56D1FDC6F627119BFD4D5A5FEAC6BB8F051D239F59_cppui255);
	evals[0].lookup.sorted[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x139C1ED08BAC7CA2B6E8366D256F002075F7F28739C48D5114AD8FF33AA47F93_cppui255);
	evals[0].lookup.sorted[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x18E43502AEE22D3ED360FB2C6B54DE328B236D7C9A905048C638C7FFFD9CE0B9_cppui255);
	evals[0].lookup.sorted[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2585C26F6EF16F894F4A6EF8C22527D41665412FCAB1353DEA75B547A912AA4A_cppui255);
	evals[0].lookup.sorted[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3433B6944E0166485910485598A67FD115E84414B57BD225952E3EF356EB9814_cppui255);
	evals[0].lookup.aggreg = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3F6FEF9E1809F85315FA5A26599B65E2FE75DFF6388443FE3E91B905E4CECDB8_cppui255);
	evals[0].lookup.table = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x1ED864B4A81CB7E14D88B7D329E3C35249C64A0E60655465BC749E8D100CD9F1_cppui255);
	evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x26DA3D6047C79621B2E1A96C8B71A99BEFE4E21082E0D5DAE1018E217F1D6547_cppui255);
	evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x106C850125963DDD8B5E24BA3889B7FB4D3404676C11B63CEE1D251509AF08CE_cppui255);
	evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x05CE43071BC9892363813A00333C9A9E154EED2DB646301C04592371AB79C652_cppui255);
	evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0CB3F1FBBF68DEC4835A2F2CE74E7837A9BB374FC005728BBC2BAF533F3BFD98_cppui255);
	evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3E06BA7A1D5C391724E0BF3B4D0082184C9EDFFC3BB3228A71CEAE1B55446070_cppui255);
	evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0D03EA166B3993A7090C4A7CF256AB6699261F0DA06A9E20ACC425B79E2CF94A_cppui255);
	evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x08C6E38FE481F6BCC23AFEAF67FEA2B7B87348C7CFA9773C7134B91E63AE8B1A_cppui255);
	evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x119D8A62CBC008F6ACB328EB9B7A0DF6772852AB9BBED62EFE77E93BF2D30EF2_cppui255);
	evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x23EC0635ECBE6A6D4896C6FFB73C0E8AD6AFBA03BA71890584221AEE7554A703_cppui255);
	evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x11513559ABB12C4FC1AF24B30A5C802FA86CDD4B744DC98EE8557C90CCF90455_cppui255);
	evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x1FFC3611AC4F3ACB783E38BB2CACACB63DF458C828466D106A5552DB5C5F2306_cppui255);
	evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x166FD2894388D347F088137432519DD868A096DB1F285810BC76D369E36CCD8C_cppui255);
	evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x096E45C408AC3DE1BC929EFD63F0867D7B975B538351F6A2C7F65272B4C324E1_cppui255);
	evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3D11809A46E95428326E05586210224C2D12222B6BE3356CA8CF5739EFA00D90_cppui255);
	evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x0488CE0ED0A00F3711EC06C76903F5BACC5E5DE0470B254C84DFD277BC561A10_cppui255);
	evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x26FE85C57AB082FBB186B25B60304808B8D1DF78585C8ABC895931BBAB5DEB70_cppui255);
	evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x035E9AC363D83C7BE8BA7B763B1412E29040C9DA22A0094D0FBC4BA8FEDBD5AF_cppui255);
	evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x19828EC2690B8557ACCD4D243A5BD92A23B4932BCF3E868FDC50AC1ABDDC3EE0_cppui255);
	evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x24133C116997D5795E290DBB1956989082533807700E8520E20B3489E720DEC6_cppui255);
	evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x305196ADEDB687C060E01847F65998CCA6C830136294899E54933E40ACF1843D_cppui255);
	evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x0FEDBD5A3445AD7C0E84BEDC3E3436BF0D0F40D5EB4C175F947E14268CA56812_cppui255);
	evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x223297CDBEAAA4810C6F6E58ABD88A405D2B6F6B5912519923B61505C5ECAE52_cppui255);
	evals[1].lookup.sorted[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x00AF7E62D3708E7244548C065112B74C644242D553D9064ADB32444F36CF4206_cppui255);
	evals[1].lookup.sorted[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0F0E3527920DBFFDEE36B919F90ED8205AB1C26E9EAC2D9BF8751B745809848C_cppui255);
	evals[1].lookup.sorted[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3480CEB6C91DF7B80055F9CCB18FD2E94A4F3EE72A86EBE455C489B9838783D4_cppui255);
	evals[1].lookup.sorted[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0795BC3253DB9D62AA73CF12EB49E5F07FC82E71E18D253CAC5F0D58A7BEA3C0_cppui255);
	evals[1].lookup.sorted[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3E345482B36A4020356737A8968059F7D943A7721643CDA703A93BE0B6DAA095_cppui255);
	evals[1].lookup.aggreg = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0683B999011ABBB578D58256C30D34CAB4CE03F4BC9929F9F932A845253A5405_cppui255);
	evals[1].lookup.table = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);
	evals[1].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

	public_input.push_back(0x2717BC155186C4ED296A12363CA8CCAB31C5B5A77C1DB971FDC9D28282970DE3_cppui255);
	ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x3D4B1D1398F64294509994EBFA16CA0DC75C2AB5460D7B01DC6DBBFD30DA65EA_cppui255);
	ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2A4D106C58F5A790D319487554375EDCB75B870A5F585D7FF20EF9D71798EBE0_cppui255);
	u = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x2C7C286ACD0842FE37DA945A743780DB32AE9A57A9048650AD4DDD0886AE650D_cppui255);
	v = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0_cppui255);
	p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
	public_input.push_back(0x0_cppui255);
	p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

	typename BlueprintFieldType::value_type expected_result = 0x388deef0601db0933c25593324191e84942675da8701b0bb504a064becae9525_cppui255;


    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()