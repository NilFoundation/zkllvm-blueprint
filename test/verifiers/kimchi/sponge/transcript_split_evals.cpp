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

#define BOOST_TEST_MODULE blueprint_auxiliary_transcript_split_evals_test

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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <../test/verifiers/kimchi/sponge/aux_transcript_split_evals.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/instance.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_split_evals_test) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 16;

    constexpr static std::size_t public_input_size = 1;

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

    using component_type = zk::components::aux_split_evals<ArithmetizationType, curve_type, kimchi_params,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using evals_type = typename zk::components::proof_type<BlueprintFieldType, kimchi_params>::prev_evals_type;

    evals_type input;
    std::vector<BlueprintFieldType::value_type> public_input = {
        0x3652b07799e5da0e2dee4071d4610b135565407a27b5336f063f84941f3774c7_cppui256,
        0x3e5fae8702189214f3991341f03c4fe5d036aec21b5da0a7b8b5d550a7ccf8bc_cppui256,
        0x212a561ed3334f1650443c82faa442614ec1d987d7ac9a473e601cd881f303cf_cppui256,
        0x32ea6ab448190e9e42657682d737dbc36591b750b03d4702b88dac0721f5627f_cppui256,
        0x065898508b7c284b74c1f39ca2c80fa809d0438dcaac1898e6a8f28429a40fd4_cppui256,
        0x3d00cccaaf0487fea7a0ac523920527c8db5bf2b7e03f01e819421f9772fad18_cppui256,
        0x0b93abc9c80d252500f15f475203628595810f1f4fad0ddcfb59019aad8fd2b2_cppui256,
        0x1395a57be7b5a5e1a37f95b5d668b26dfe1af90dd9199d89c71991f461b596ad_cppui256,
        0x3ef81db7aba003c0bbd8795a5ef8b27e2a8a2d364706523eb5c4724ed3ee6994_cppui256,
        0x3b47ec79d00aac4c02cf35cd7604158888fc2b3da4899aa987d609c2c0ced6f9_cppui256,
        0x057c16221f26dccc300d1d7b0417f49a40ff90ecd0e45a11becf823194d141d1_cppui256,
        0x3d1d60d7eb33eb81d6bc31841ac9e51a56a3fcda2e7f24380f170b36642fae97_cppui256,
        0x36c828de6c46d2db8ea1116f9ea6045e4ebc4c020e7ed72a8655712976c60fcd_cppui256,
        0x3524539f81abf8bff4f2c67dc8fba468698da8e2927556fa3b2e70035aa320d9_cppui256,
        0x20d721efa70ba65f7a6d0a471714cb25836dee4a206b80cdbd3b7bee28e6420d_cppui256,
        0x003de49b5023c109908b0d5b1d1b58fb857930ad243accfc5e4e0d21cca6ea43_cppui256,
        0x2a5a45eebe66ae92fe3bee27d625c51f69252d6578db66435b44388880e9572c_cppui256,
        0x03f9ade0fbf9390e1918ad6ca560cab769b3a86e8858a5cf321aebdc706ddabe_cppui256,
        0x38fa9042579fc4f7d3f3789d1c4329aee91fde6fe146cd33fa4b5a5e1cdd1431_cppui256,
        0x188c4a04d436e0d0b28d020800a2f3a1f6b2bf759475e7c920232f87a1942256_cppui256,
        0x1f424c4da89173cc06e5ec3931d8bfbe29f055e34ab1010aae5ee3c61c7827f4_cppui256,
        0x33a91310cd2ab1b15f2ee268c4b51c2e256cc54446f535c9df4a10a2fe637b33_cppui256,
        0x0e3e031187e5a90b7dba983f82942013bbd76e554cb504d6f555baecf886b47d_cppui256,
        0x3d0c4d85f3826fc300afdec4987313ba7130fe573d1b4bcdc7034bec2e6c9ada_cppui256,
        0x2330e57fa856d49ab94298e4dcdfae33dc1a6f3c2c417d633169b9814175c9bd_cppui256,
        0x0296fbb91e605c4ad5e977b754724287a20dd4e4d787f03486fd716d69dd59eb_cppui256,
        0x0268942f8794de04c3150ffae28ee855f7c375ba0a39d7547c9df1805902bdb7_cppui256,
        0x18a803f0c18cb37c59190667df1a9257ed866978c3831af9ee3c00d9a519a7c6_cppui256,
        0x31ce81e8536412160284a1ca0253ed0c92b94ea1a9c4f66205bc0665e3355f7f_cppui256,
        0x051ded6467b90c24c6937366eea3055c8e358451407e4352973d85700c83c4ee_cppui256,
        0x29862ef539a186b84c9c6c782b38ce73dab9cb13b93a76852d2e34cdc4d92876_cppui256,
        0x25c12ceb584456ab4f6b79d4b4649fc8b802c8d199c158331e399c86c1d5bb2e_cppui256,
        0x021815b10e302f2b41c7550d7bd187d19057f35c304557dc4fa8eb620dfc5297_cppui256,
        0x3037ca9c464c613d4037fb7061b414513e162b04755442aae50eb9a3eccac03a_cppui256,
        0x10a1125d087885a35aa3b84a96748b85aa6fdbf31be120acf4322e74ce494109_cppui256,
        0x1bd0c752b14808992854c9113ba12c0e7399e0dfdd91df1ea5203aa5e9ea4a3f_cppui256,
        0x232e07d65359577e14c5967fd3213cad6d4531fedb2e7eaf6abd8552140e05ac_cppui256,
        0x30cc51ae709c6aac0a007d3a7475eea78e5f2b01deed56ea1c435c727916bf80_cppui256,
        0x3411d053ec4c826d6c2d3d5f303023b7e4934c3b118a87cb9bcf25105cadaec6_cppui256,
        0x19b24083983727797ba4b5896918fad8b60e90ea7d8e5627855d68bf174a2ad1_cppui256,
        0x1046537b340db786f78fa7d91b26f8dd916abbd766ec6c1e45656955e4af308b_cppui256,
        0x073554c58a8559d0a5892188596a89e9febc45397a0127f078ebff652b88d5cb_cppui256,
        0x2e7b13d73bd7b6d9f33a8df2d260e0ed797e68ab8267039a73a4bdbacb9eba9a_cppui256,
        0x19bdef149c64f1ae4e22d3e72aa1cc4ca603715f9589138e53044a352391bc28_cppui256,
        0x1faff501763448d60740e251d138111d58d45ed766d96e888b67711ae5ec4f1f_cppui256,
        0x135552819587dd857d08f13bb37cab49e1024618187d942f3f07bd073297d45f_cppui256,
        0x38436545bbfa61c043e8903a28f08c296ef016afd1c65953357427b94e1b2c2b_cppui256,
        0x307ce56fed2996af6114dcc90b3b4d6c0e9573feeae7b28729a07b279dc8d185_cppui256,
        0x1718c46073dc36e8062a8519fcf9c46350b883d8697258e8e9a5e4fcc5c54b95_cppui256,
        0x0691d2ff62a31fd38d22ddfe240352058f8354c1a8ecf898201ca70a418c8bf8_cppui256,
        0x3fdab63dbf4d12c951eb4a6a60b7af906a0f95f6276ebd74c1033e61b5d9331a_cppui256,
        0x02fcdd36081af67c8d8a91be0100216b6f9d78306af736a6f3f2fed103bba93b_cppui256,
        0x0e7c7d012d653d396b09be97be5badc9e155ce8e4cf59bef5a99213f2144e34f_cppui256,
        0x350a2c80389ed70761827569b0844cd7aef31b23b57f7eb0256c4393e387ed9c_cppui256,
        0x062be8351b24743dad1ab8c079a698eb2c6d84b85275419e2b57e512050630c9_cppui256,
        0x24cc1082beba6c16878934c67bf5d8d383ffa5a8ffb2f3097aab8dc10d8e9bcc_cppui256,
        0x1bf0cbf17b02f58d71b697a397c2981118caa0a6bb875127b341d35f48152461_cppui256,
        0x19c3d1d10f36e44009426741e7fdcc5eda1471d60f16561e9a1f628d87b97e48_cppui256,
        0x20ab8e3df0968f0321d68d2a6e79fe819db25ae8ac3aba6d72385e6fdac710e8_cppui256,
        0x2379d730f20cc98429d0542e53f80f33129d0a4a5976a9ed48343ec7eb1fd190_cppui256,
        0x043a5dbde3ea613533e8a96666d0cf28311a4124a73af2f318dc8c38dca63c06_cppui256,
        0x3e198d64b6560d9c05c88c57ea1d5b55ac79b01144103113d88c6c160bb35d26_cppui256,
        0x1c7d67976b363b0780f437f4f099d1ff65f7307bcbe4fd734c1e77c60201be75_cppui256,
        0x277d94404e426b3bdbd7c014212003545979a66d16fa44b3b01b3ff178334b94_cppui256,
        0x043e161d175cbb727b136775f67fec1d1bf3eb13a56600ea514537008408c36f_cppui256,
        0x3960391e543ae1da7946bba1e02831620307dc42849be523c5fd5241aabe82b6_cppui256,
        0x068cf8a80b4b7b6de74bcdba7d089b2449876d0806e85996d892d96ae10fad3d_cppui256,
        0x2255201b5c81ea5fecc7a341f4b7dfd43db4d65a01eab810ac88e6ded8fa8606_cppui256,
        0x1aab62b3dd470565c7d62bb3ae82fd3ee2a6e2d5840fd29e6ac5cbfe0149d2ce_cppui256,
        0x3f0fc1663e075fcc8df810685bc8ae2a7f87b2f1a5da4b2bace4b95c66ee2f8b_cppui256,
        0x1462cfadba1f1849747fea1225732718f500b6f647a9d33c01616f9fe77bd577_cppui256,
        0x05bd8ee0b0e9bbd2cae4803b06a657f10cf0fe7dbf4e984b1804e9c9b077748e_cppui256,
        0x069a5e5fc7ff646fef6748f65e2a142a13d06e0212f54e51032e02b525fe12fd_cppui256,
        0x0945edf0c299cf29a0838d243fc0bc615e68255d036310df963f2e930d1b2731_cppui256,
        0x0810825b67973b6fef5f09fd68e5668f5c2339deb0c74a4a0eab4259cf108125_cppui256,
        0x38412bf167e6cbafc50ecc713024ced8d18ab3cfe1523f381594762e2c13691c_cppui256,
        0x3c89c86f6faf0e1d788b8f45a7b40cae29035d5bcd1ab0819fc27ef64408ced6_cppui256,
        0x1940a1c81edc558ef118e8f4c3935ab81b14f4b44676360b851ab12ac52f0776_cppui256,
        0x0056a0d47cf7ac7d72dbc4a879bf1e3a1f9c039795d68fb0bbca23883b1ecdf6_cppui256,
        0x0ebc3c3cb43334d701ac8d8b8dc8c9e052d6ed472611e019409e28c4272e8bdf_cppui256,
        0x2347e00a5d90770a807b4e6dd1b81055bb078f3589a1047620a823c48c37e3bf_cppui256,
        0x365c1e73ff8219bdea5d2f81668e1a1b200b41c5702684d1bc100e43e690b16f_cppui256,
        0x33587e119372d90142fdc751e44f5e36743d9cc5eb885f4573745044376e9ef8_cppui256,
        0x22c8f701662b26e8f40c93cd343e5cbfefa38dc3ec585353cea64acdb3ab1f4c_cppui256,
        0x31064ab6df74b121e30de5c9be0e5ca51b8a38516b67f241ca75745b07b51ea7_cppui256,
        0x230bce8a42e814e3c640ae0629195124771db1d91e3bed5c47610239b2bfdcb6_cppui256,
        0x370eb37fc43c559268fdea1ed5d5274d54d780d885e5c095471c687e6f87a562_cppui256,
        0x3e0024ce157e5584a498cf31266a8ff42278baafc2d83123389242a491e4a12f_cppui256,
        0x21b6326cbb315987a62a8c4c3f09344627871d8803e7f315fe91cb1d606197bf_cppui256,
        0x34f73dfe13df5775d6d7cf8106fb5253a323efd6077814063cddfaf8102f9f34_cppui256,
        0x02213f4a62f4cdaccfcfb30bd634f4e1bbf9d8e0d6556c7efec40f31e9d931f9_cppui256,
        0x0bb8168624c77564ab79b5f7dfea3c0edfccb1922a43b23ca76d3afa5e6b95f0_cppui256,
        0x2e82fb311761409ebef7ddd6c1882bfca01c4dc51fc4922643b8c8923c9bc392_cppui256,
        0x24ba3b7e5fee625d22a7d6793e04efd9a8cb79972b6aab1048d95f5e9874bae7_cppui256,
        0x0e32ae45f0461e017788549b8752746e6cc14fbc331a8de6489b7161f34c13c7_cppui256,
        0x27b8d0ad2c95c118a93af0e2f8f5e5525d41192241ea2c6d4dd41999494a9a84_cppui256,
        0x10f9f68a13da6f91f65e0f689fa1357c9e127e8dcc235bed105da9f29c165973_cppui256,
        0x1075526f11ecde4375dfcef2f80b8b2e9c072bb3babb2528e98bdd954aa4d41f_cppui256,
        0x2867c3bf4d92a7879be85abaf60744693718c4ade0382c0ed09bdffb85beae03_cppui256,
    };

    std::size_t row = 0;
    input.ft_eval1 = var(0, row, false, var::column_type::public_input);
    row++;
    input.evals.public_input[0] = var(0, row, false, var::column_type::public_input);
    row++;
    input.evals.public_input[1] = var(0, row, false, var::column_type::public_input);
    row++;
    for (std::size_t i = 0; i < kimchi_params::split_size; i++) {
        for (std::size_t j = 0; j < commitment_params::split_poly_eval_size; j++) {
            input.evals.evals[i][j].z = var(0, row, false, var::column_type::public_input);
            row++;
        }
    }
    for (std::size_t i = 0; i < kimchi_params::split_size; i++) {
        for (std::size_t j = 0; j < commitment_params::split_poly_eval_size; j++) {
            input.evals.evals[i][j].generic_selector = var(0, row, false, var::column_type::public_input);
            row++;
        }
    }
    for (std::size_t i = 0; i < kimchi_params::split_size; i++) {
        for (std::size_t j = 0; j < commitment_params::split_poly_eval_size; j++) {
            input.evals.evals[i][j].poseidon_selector = var(0, row, false, var::column_type::public_input);
            row++;
        }
    }

    for (size_t k = 0; k < kimchi_params::witness_columns; k++) {
        for (std::size_t i = 0; i < kimchi_params::split_size; i++) {
            for (std::size_t j = 0; j < commitment_params::split_poly_eval_size; j++) {
                input.evals.evals[i][j].w[k] = var(0, row, false, var::column_type::public_input);
                row++;
            }
        }
    }

    for (size_t k = 0; k < kimchi_params::permut_size - 1; k++) {
        for (std::size_t i = 0; i < kimchi_params::split_size; i++) {
            for (std::size_t j = 0; j < commitment_params::split_poly_eval_size; j++) {
                input.evals.evals[i][j].s[k] = var(0, row, false, var::column_type::public_input);
                row++;
            }
        }
    }
    assert(row == public_input.size());
    // TODO: lookup

    BlueprintFieldType::value_type challenge_1 = 0x65094E5035F652A5F3E1881AF4FA54ED_cppui256;
    BlueprintFieldType::value_type challenge_2 = 0x58C111660A05B0C249884205257448CE_cppui256;
    std::array<BlueprintFieldType::value_type, 3> state = {
        0x3C56D58D0DEC9109A925C3D929B0F33465094E5035F652A5F3E1881AF4FA54ED_cppui256,
        0x31C7897EE9E8F79FE4F0C3627E36B4D958C111660A05B0C249884205257448CE_cppui256,
        0x010A8A822474DD1FFBFF8132F94ED37C31F9B9AAD612F1B28CBD978E1987C75F_cppui256,
    };
    auto result_check = [challenge_1, challenge_2, &state](AssignmentType &assignment,
        component_type::result_type &real_res) {
        assert(challenge_1 == assignment.var_value(real_res.output.challenge_1));
        assert(challenge_2 == assignment.var_value(real_res.output.challenge_2));
        for (size_t i = 0; i < 3; i++) {
            assert(state[i] == assignment.var_value(real_res.output.state[i]));
        }
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> ({input}, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi transcript_fr: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
