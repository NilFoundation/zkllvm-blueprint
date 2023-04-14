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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_scalar_details_hash_messages_for_next_step_proof_test

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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/hash_messages_for_next_step_proof.hpp>

#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "test_plonk_component.hpp"

#include <algorithm>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_pickles_scalar_details_hash_messages_for_next_step_proof_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_scalar_details_hash_messages_for_next_step_proof_test) {

    using curve_type = algebra::curves::vesta;
    using comms_curve_type = algebra::curves::pallas;
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

    constexpr static const std::size_t max_state_size = 3;
    constexpr static const std::size_t bulletproofs_size = 3;

    constexpr const std::size_t state_size = 6;
    constexpr const std::size_t chal_len = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::hash_messages_for_next_step_proof<
            ArithmetizationType, curve_type, kimchi_params, state_size, chal_len,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<value_type> public_input = {
        0x046547d31b3815a0a13903ec3b23bea37a57e14c5ecb31986cf0d07728b3b3a8_cppui256,
        0x27b68acfc9aadc19cee216376320d9c97acdffa2956c3c9ea09ebbefd6f63e74_cppui256,
        0x343efc16b27069124d4ff901fe97c3c179d1afce7d8eb644662caed378d0f968_cppui256,
        0x1db41504a9ea72098fc59c06e100d23bf56ef0151d25163f55759afd6e8d1a12_cppui256,
        0x25d3c702a779751c6d854793f3070be29111aba5e9c029adadd1327f5e64d106_cppui256,
        0x066202c7b2c236f26e2b684d69803432aa9e63cf4c7eb326d1aed63001c0f3e1_cppui256,
        0x3a6d6ca2e29d32e057daa807bc269cf86e782de94c4812af8f452d67963cf713_cppui256,
        0x01c00d708a77374e2ff9de0fd0984bb2cf46a2e14223887ee3f447ad04ebef17_cppui256,
        0x27bb49efadf1d56dbd6cec21c92c0f4823a5c406edb2aff356ebdcc5ab633542_cppui256,
        0x3e05f47e58617de680550e2839958f8673710ca6ebaf323196cb0bc481f4deeb_cppui256,
        0x1b174f1f1311f4446313169f9e5c69be80e246512c49cab49aec50692aff715c_cppui256,
        0x3360a7b8e46033c0231eba10bb848fe66ff3d6901d57fd62f97c5eff400b5284_cppui256,
        0x39ac87cbbd02ac2cb0c0b09de69a5a351e7906f28c8fa40221b6e309dda88c97_cppui256,
        0x014971c6a1d990f885b3dd427112db49009b60ea9930a891a41718f35e3f1f07_cppui256,
        0x3996b6344966f4c039b9e5f0e22e166eea2f353e92e0530c4b62865fc14e2ab7_cppui256,
        0x3880217b20ef1586ad0428ef645d1baa5fdc1afc94bfda7385b93d947cb4b8b2_cppui256,
        0x24b7e22e24bda63b6ec5cb6ae70c0bd00d689aa828556d160819e14170bfae04_cppui256,
        0x0f4a56f3fb537934bad8f353d2bce9ed7930d087048ac25fbc45e6d4ebac05a3_cppui256,
        0x06094506a1a79afd240fad7546bb696e109e8c6ba59476f094b2d241777be703_cppui256,
        0x20ff3f92b731545850a27085ec0ec4ae3929b22948903992769f8ab73ea85fc8_cppui256,
        0x399fd860f76d809974db5fdca0b24724c50e2ed3bff0180422980f1e92541253_cppui256,
        0x03d94a53ae4e23a954b3439ca6c8b8ac1f22a1fa3962017ed62aa4757cc55126_cppui256,
        0x11944c5ad55ebb3fc25facca8044231f949b3447f6b64f9d2a0c5ffc069f10e2_cppui256,
        0x094d9d290ac71c84e04ebec700322c8767f3619dff274b82563221b9895f8e22_cppui256,
        0x18dd4843ca2fdfcac65f3e86af8ba5346ac2048374537bae895c8393fa265713_cppui256,
        0x1cb0fe64b8323f2face7302af56d17c739fa2bb88a8b17eaccc248abd9f43c22_cppui256,
        0x37f8ef535bdd6cf16614f79cece6f4c9f99650133b0a61c253b1fd09e69d0686_cppui256,
        0x034a3aca3ef9b53dce7b6529e1469b9bef4edfd3b45eed090ab7612cc7439b1e_cppui256,
        0x24e8d30f8234df4554f6df4a59a6f2ed8c8b7e7b2a4c1ae9acfd52d5e275c15d_cppui256,
        0x2af63ded084283208d41a852eb0ba2b2708e14e0b83dd13afcd4ebb8669425e0_cppui256,
        0x30845f370e3ee189ee98bc03854d6da6a83e10d6afe7f1ab7fc483e17ea698ab_cppui256,
        0x23c5c0023a8cb8a17d979e4dd8cd6734c4c70a38611e0d4a5f54482636f2a660_cppui256,
        0x23a1fa88bec30ef335459567bdf1be17c74e091fd80db4b0bcdb0ead358729df_cppui256,
        0x381798196f2b527f015ca9b6e22190adf50f3e0021d1c61b1a14c3dbfd703918_cppui256,
        0x25290930a8e08246e6652f1854c952553e6f9fc9e499eaaf6abebd05d0b135f7_cppui256,
        0x3b86f1ae2a89d38805b4c1f6c5aa71dcfe843fee34d2ad8a543600b8e76e6238_cppui256,
        0x24b2a25b1a1c6067c337975f96f3939e34f63000bc5973f04ca751745d2f64c6_cppui256,
        0x021e5ce5a1e4e632e38a130c260b361db6e615a236a8e1f0ac9c107ddf2ea541_cppui256,
        0x136b9045845458e190be7ca59f16290c8bd22b74f85a6610c66314baa510a5f8_cppui256,
        0x077a2402a099f0a9e7eb4ce97379ca74cef078d34d182f5cbc04a56f17679d9a_cppui256,
        0x2ae06d85b6cd417f707230637d1a3aef02cd29b78170cf41e401e1091da3455c_cppui256,
        0x151d070dfa251c7f16d6225bb294eebf4a3862bbcf71c9413811128c99e8149b_cppui256,
        0x2b652762f895326e1224d2035b7bb4288a81f26b47d0677bbc19bcfe566818ef_cppui256,
        0x0c8419206348af6695e80434afc842a668f86ab2e67ab41283d190396fdadc74_cppui256,
        0x236e343b2bf63096ed2e33bbe5d763844f4fdbdc2187fbb7835155793fb5c948_cppui256,
        0x0d21410d9704a6df2e6e90ab48c917716ed0854dcf234684ac06596621558814_cppui256,
        0x2cc3e221f172e7c93df3fab39fcfd6f5c056257661dd3906f17cf7660fb85f7e_cppui256,
        0x045c682ae31bdb53f99a3942f9ab490e936018dd655c83c77d9ddef9e207d6a2_cppui256,
        0x1ba067f62e5dce7bf489e485ed90987b6c6591aa3e278301292c4537eb1b6424_cppui256,
        0x11a415deb18ffd3680b405965513f2f1d1ad1e15fbda3e325287701daa7d9d51_cppui256,
        0x2a8606a5309ff5bc748f49f01d1a5e1a8eae7eea495102ed7107b3132bed0666_cppui256,
        0x04c4de6f6f77badf014c528799ecf791c86a1898395ac7dd9fa983ec7d36bfd9_cppui256,
        0x36b8471b9fb9f8634858168351860c31cb1ebf5412f6e1372773992807acc2da_cppui256,
        0x3d5c7208c1137687555f6dad72d93fb61f210d9d7360029b2477dcee8a78843c_cppui256,
        0x099ba28fc039ed503bba8c230013da7a5dc29085edaf640e800e954d30d3de57_cppui256,
        0x042ff121a9bb5991b3d57c0833084da9953678242fd30d3b7b3053f0e55c3fb9_cppui256,
        0x36e23041af0b04025349171e169dcc7b0b514ca04f142e101d823fe94408f916_cppui256,
        0x024be1f820a6b7ac63883a97ee30e2d724f30c085aa336d331faa13e9a74b0ab_cppui256,
        0x254d3acbe4fb076ba585f44b1f92080b188b5158992c5b04fd8e97f083766af4_cppui256,
        0x2fbccb509bf6d7c8e7fa9f3e55e5416e36dc6706685de6471698dd34b143ffc4_cppui256,
        0x099e6634ddfd12cc33e4fef1c40a383b387bd90eba4fa533bbaec52c0e7e1b89_cppui256,
        0x1063759251d84aeb79d982b5d150400990adbcf0f785bccc743fbaa5778044e9_cppui256,
        0x2996a42f4c851f4c1fb00de88aff245ff3c3f06c0fb6bdf7703ed9ed65cce6fe_cppui256,
        0x3770521f1e9b0f9b9dbc071f317a5138f4077af36fe0feb45737350121e3e924_cppui256,
        0x328637f8b528fe0c7cf0a8864b252c644fc0967376381992e45893a6cafe382a_cppui256,
        0x206039e685459703cb18c10af73aa2888561760e56bfc101db57793a1703cc05_cppui256,
        0x1b3c99617ea22cb640fe314945e23305ff7ae487cd0a4997e9bcb1b6ffbceb9a_cppui256,
        0x2d36eeebeb67922fb22e002158e30da3451b541e71468f001e5776af7c0d73a1_cppui256,
        0x2c9dd4e786e6aee6fafd14ac4af1f85e145a736b1dd4705ad7471c505d3420ef_cppui256,
        0x1c252e2a92c61c8a2784956b44112414a3f7ccca2013c7f81eb99e3c23a6e3b2_cppui256,
        0x0da55a305634f97715ef72dd6be93bbcfede7cc1023267d47b2d5957d7252243_cppui256,
        0x04e781c35cb1e3acae3bd88761fbbc3e031774fa721e689476929546f8b0cfd7_cppui256,
        0x3189a2ec93c29415c8314352b651668d43485b7b914597a66355d452ea63a1b0_cppui256,
        0x06b223b69d0e375525f10c5ee7d60f83fde4e5677922bd65142a5b7a2218e873_cppui256,
        0x0f0ad42b76b7e2bcbd25be09bf3f00402bdd03c2efbbe8bb00c0d30d1a4afd73_cppui256,
        0x387a012ca197353994feb7bc72d6cf656dedd548e871eda7256bdd06290bd021_cppui256,
        0x0bbcecfef309e8f309b1ba44426789985539c9b8eb663cbf7d064ad4fb717c56_cppui256,
        0x3895cd48c107418885dd8f546c05b381bc1284a876dddc4173017aa20fb70dd8_cppui256,
        0x1310d924b8d65344b4b7e1bf54718e91af06747969e5abdb93526ee202c2df8d_cppui256,
        0x1c3fb2e7fbca7695a54feb9270fb444b646f4d392efc510ec57f4f79690cd5ed_cppui256,
        0x1cfbe3f5f6afaa3a0a43f523db5ebc3cc0198d8e73f3b87a2cb56ea2bd2de538_cppui256,
        0x1bd10e3dd47a1e3d498c52f067d14347e9f2b6642872ed4a9c702e668a9baa51_cppui256,
        0x31cae30df3ec7808764343632402749a6a253638b778efd11541756a727baeb2_cppui256,
        0x1c34b4d094c9c679853385383cc2f6dab3ad40015ac3336428c45128d09e4fb7_cppui256,
        0x3de18857505dea82c05f7366e728f6f08502dc316ac6bf05abe42ec9349d5280_cppui256,
        0x2458187db47d99b386d914f699027d95b6c367aa813e305c61544d025e62d6eb_cppui256,
        0x3373d0cf89eba20263418002aee676b147bb2e6374b3953e5ab93cfdadab095f_cppui256,
        0x1929693d81744fb4406e3c9fe0d440ce893a5a021c12316a993a03dda90b9ee7_cppui256,
        0x07e1340ec1a187d4a9d8580edf3d5a3da3bce135fb7a23a0de39a5a24d35e69f_cppui256,
        0x3b6c5442b0914ee98301a8f95b2938acfa2d9e513b45eb588c9a53109f3196e5_cppui256,
        0x338332469365c2ee826106276fea497e28f99f7c5a9f717441c01938a1f051a3_cppui256,
        0x19040a9faba72ec8c5d9c039f74bbe3aff83431c864341367fe34128648423a1_cppui256,
        0x3c561ef71a588d2f71b2a2685263e73fc637e737cc18fc2f6699db5dd42102e8_cppui256,
        0x2c30de4fe7d587537dfac0d46351054bc81e77fc401a9999466f4cf46d8e8517_cppui256,
        0x3be2a531e0feb99d7bdd5d858ea01a19fdb3481c67dcd2a52b2b3e9e6a23e417_cppui256,
        0x2b9796bf4097b88eae48c17e77a402017fdae7bf806e68c48a58df86835d9162_cppui256,
        0x1af436c2add251a6fb51d203abfe43b9a63f7ade930b987d5667a31f7741c831_cppui256,
    };

    typename component_type::params_type params;

    std::size_t idx = 0;

    for (std::size_t i = 0; i < kimchi_params::permut_size; i++) {
        params.commitments.sigma[i].X = var(0, idx++, false, var::column_type::public_input);
        params.commitments.sigma[i].Y = var(0, idx++, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < kimchi_params::witness_columns; i++) {
        params.commitments.coefficient[i].X = var(0, idx++, false, var::column_type::public_input);
        params.commitments.coefficient[i].Y = var(0, idx++, false, var::column_type::public_input);
    }

    params.commitments.generic.X = var(0, idx++, false, var::column_type::public_input);
    params.commitments.generic.Y = var(0, idx++, false, var::column_type::public_input);

    params.commitments.psm.X = var(0, idx++, false, var::column_type::public_input);
    params.commitments.psm.Y = var(0, idx++, false, var::column_type::public_input);

    params.commitments.complete_add.X = var(0, idx++, false, var::column_type::public_input);
    params.commitments.complete_add.Y = var(0, idx++, false, var::column_type::public_input);

    params.commitments.var_base_mul.X = var(0, idx++, false, var::column_type::public_input);
    params.commitments.var_base_mul.Y = var(0, idx++, false, var::column_type::public_input);

    params.commitments.endo_mul.X = var(0, idx++, false, var::column_type::public_input);
    params.commitments.endo_mul.Y = var(0, idx++, false, var::column_type::public_input);

    params.commitments.endo_mul_scalar.X = var(0, idx++, false, var::column_type::public_input);
    params.commitments.endo_mul_scalar.Y = var(0, idx++, false, var::column_type::public_input);

    for (std::size_t i = 0; i < state_size; ++i) {
        params.app_state.zkapp_state[i] = var(0, idx++, false, var::column_type::public_input);
    }

    params.messages.challenge_polynomial_commitments.resize(chal_len);
    for (std::size_t i = 0; i < chal_len; i++) {
        params.messages.challenge_polynomial_commitments[i].X =
            var(0, idx++, false, var::column_type::public_input);
        params.messages.challenge_polynomial_commitments[i].Y =
            var(0, idx++, false, var::column_type::public_input);

        for (std::size_t j = 0; j < 16; j++) {
            params.prepared_challenges[i][j] = var(0, idx++, false, var::column_type::public_input);
        }
    }
    // generated by running the component with the above public input
    value_type expected_result = 0x2d60c435e1947dffbfdfa17e4c19333a6fa53e17bad8bf0d1487031091448d04_cppui256;

    auto result_check = [expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()