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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALARS_DATA_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALARS_DATA_HPP

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

using namespace nil::crypto3;

std::vector<typename algebra::curves::vesta::scalar_field_type::value_type> recursion_scalars() {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;

    std::vector<typename BlueprintFieldType::value_type> scalars(72); // prepared
    scalars[0] = 0x2d8dfd30fdb5c4ce5df402500fa7cb28301252011a09900f71db3dda492c9f81_cppui256;
    scalars[1] = 0x448d31f81299f237325a61da00000003_cppui256;
    scalars[2] = 0x8930bb3f6c1fd9afd7bf192543fecf400839c22377c0b5ce773727021fcdbc5_cppui256;
    scalars[3] = 0x2559b564430501762814c528923f38eedc97439867c7a600a18050b692e73642_cppui256;
    scalars[4] = 0x393d7a7cc3a4741b46c8d8d64969c87b7c5a157801535c2a2101cf8be549cd14_cppui256;
    scalars[5] = 0x2932c1e583294952de5e22fe1e999133b6dc376535305244fd0002aa83564c4_cppui256;
    scalars[6] = 0x15747e8be4ed98d959e55fa2a41ad6652cee59e9a3efa29bd2ec4926325b94c3_cppui256;
    scalars[7] = 0x15e68fd4ac22eb078ac9ea6a3a616c829e1e1d45d735a74747e5c970b7905857_cppui256;
    scalars[8] = 0x242e117bbedf620ce9e358a72d98e35b6cda98664667587c216d01487ba46d20_cppui256;
    scalars[9] = 0x247d82b549cd6c57ac16a73532bc0827f8ab480c0cc0a303ba92db2d5cfa011a_cppui256;
    scalars[10] = 0x268fb8512edd24176ebc7545943779e893178d288079d0895739562c0523e3a9_cppui256;
    scalars[11] = 0x3a75fca219059e4e34d33d2ab13d7e5a15b383c9fc5bb3a7e845ee0bb7d38f23_cppui256;
    scalars[12] = 0x2c393fafd72fb25c295e5c52f89d2f977f2ceed5345d79d8658400e2f538bec5_cppui256;
    scalars[13] = 0x5475f211f4dbbdbc8649aee99cb446b44f3d3752b61bbbc84589219586485c4_cppui256;
    scalars[14] = 0xbd85a287ecb2435591b78d16c278985769c775c228e3fb1901841230b5bf608_cppui256;
    scalars[15] = 0x3713e678531cce0aa4277ac52fb857b9bd22f88466ae30a9713bfb6f08c5cd2e_cppui256;
    scalars[16] = 0x3857d4560a3ba090ef552e3b2f03bd7f9a2cf89ab1dc4684504ce5dd6227ea91_cppui256;
    scalars[17] = 0x35e04881ca080b3792ab24a72b10e0f19a7cb8776f2b0d2c1aa9241595237a3d_cppui256;
    scalars[18] = 0x167756108383127735d448bc6286a2df1015fdf79f042b0d6a881a248b817f6a_cppui256;
    scalars[19] = 0x1b16cbc538ffe1eb92dabd420a0e328782df63ecccc0a99a573622c202fbb8d0_cppui256;
    scalars[20] = 0x68daa89ea178857f97c3edf64bf5992ab7738ded8f9dea29a524975289ba5b6_cppui256;
    scalars[21] = 0x1c0d0794b20e6f3106d96c25e62cce64b7f95d5cde0c4bcbf7e33938c902b9de_cppui256;
    scalars[22] = 0x21af44e1a64529b2aadc6862dc5f7f736bcf7739b750fd1d0ef3083b87595572_cppui256;
    scalars[23] = 0x114944ee53389026683ddc5562b4defe8871bec5e74c6ec98dd1004bf3897a1c_cppui256;
    scalars[24] = 0x2268af93dfa630e12aad0a948e760b1fa7c0a4a1dce057c53936ffde38c0496f_cppui256;
    scalars[25] = 0x197aea42261e67bc73df2ecc26afef914b03874e34d1df6d7ff68148f6e03002_cppui256;
    scalars[26] = 0xaa9295720da2962635fe057d3e7c70102be45756aa91ad6392c287cc2f63dd1_cppui256;
    scalars[27] = 0x324ddbffdbdb197888cb7b07f92171697dd7b9049582fe8f83d8c38f87c3c4a1_cppui256;
    scalars[28] = 0x3ffd3b925757577348871fa91fce73950984ba53dfdd7d2f115c80178fd6c056_cppui256;
    scalars[29] = 0xd4d689c4a81429f1da5ae34dcc6f16f6a2e4ad340732dc7bf25c755b89e2333_cppui256;
    scalars[30] = 0x379d4bd2d85c8d30abc48cdebae99627b5a052e37b11d71e389fdab4170a8748_cppui256;
    scalars[31] = 0x13c747ba74fa8592cd7460a59aaf7d8d01eb1611b1e541dbd140abf61faf478c_cppui256;
    scalars[32] = 0x379634fa9a2d2a82d3affcf660195406a63387b394ffababb62d37592e33729b_cppui256;
    scalars[33] = 0x27adde083fba5e1dcd1e0f0d91d4e3af101c11b12e1460a9611bbc80e2c1d922_cppui256;
    scalars[34] = 0x57fccb6c084673c1bb9ccaffb6fb987ee783b288351e191ba7602081f23a7d5_cppui256;
    scalars[35] = 0x3c6f8dab3466b1a336ebdf5364ab91e0f5feb9c0497bec6bbd82a4da708d7c78_cppui256;
    scalars[36] = 0x1ad10fbd3de442d834f3bf43072dfaf8707813cf71aaf507407a2595a79cf2d2_cppui256;
    scalars[37] = 0xc793bed88ba2b48f34b0da272f16e7763f2c423624feefd0631ad2a1d8816b0_cppui256;
    scalars[38] = 0x1ec3e9e81d1fb79bcfe6b2d74b3f1887d0cc6249ce80fd939ebf00d837f826da_cppui256;
    scalars[39] = 0x1654765a80266dd6b7cd1e6c4886c55f9e13b61d31a79d089901258860e101dc_cppui256;
    scalars[40] = 0x31f7485041b379d893584e701ce8de1baff297164622cdbe2600d240b7e7e57e_cppui256;
    scalars[41] = 0x1430410d8e2be5eb4d434c6686f94a18873b161da4e1cfda94c67ad5f3fbb3a3_cppui256;
    scalars[42] = 0x1ec4399abb528df93e67b926e47a360191ea47d5531795b1ea3c99afee8b3b8_cppui256;
    scalars[43] = 0x1465f2d299e3beb5b2ae09d42e0248f3e6e11c4fafcb93888914a8aa39045a85_cppui256;
    scalars[44] = 0x28901b237478b8f26075acdf8f98f86798c89b48e602542b84fb7cdffd991891_cppui256;
    scalars[45] = 0x2eb466ca6b4f28b60cd2d23b49ce3e0773e826ca15ce919bfa2ff524be4cb592_cppui256;
    scalars[46] = 0x2c3406cbb52ffe40242c1aea979c53e25e200a75bab1e756c25cdae5db5411a4_cppui256;
    scalars[47] = 0x153914fd242207c60b18cde713dcf2c7bf677b5dab8da0604ebf70cf9e99b7fe_cppui256;
    scalars[48] = 0x1edb09c7e7bcb3a092f467091552710b23dda447c033cbbffd0b50729288d16c_cppui256;
    scalars[49] = 0x15fd8f2eabe91aca2ddb7faf82d17d533430f1278662d2a02ea909c64ae3ce36_cppui256;
    scalars[50] = 0x3772c64f3b5c8c0d14924fe4d2826765c0b1618d033e913d17d525a9d7e3ee89_cppui256;
    scalars[51] = 0x1e1c7fe5b3536151858c3e2d12f115bf1968c8d59e96e3737d7c5abfc84bee89_cppui256;
    scalars[52] = 0x3a40d9859407e96e5eb180c54b59272d9410dd058f5f56d9fd2c0a28bc3e23a9_cppui256;
    scalars[53] = 0x3650b8b68734bc03e3b8bc47572ac63d4deb03b76f81b07534157b834b94c0e2_cppui256;
    scalars[54] = 0x2978af8c2d28f9d9aa4b955dd94c2ed80259a70693a5f5e23dc83690c81ace95_cppui256;
    scalars[55] = 0x357102cd9df29f3feaa4fcf052ac174e0526c09a2ebaafabd64228b1ddb3f9ad_cppui256;
    scalars[56] = 0x214717fb2d18e6bd84db33fad1c781d5e0c25132e84a3b1704d9d64da84907f4_cppui256;
    scalars[57] = 0x23af4d6abf87e49d6ebdbb1ab34493fe67337758693f71b74fd6375a608474e4_cppui256;
    scalars[58] = 0x2bdd33b213b0f02485d6031f93b0a223b30f17190e2c0012a84b34813b212b07_cppui256;
    scalars[59] = 0x26df1593bcde04aa76a8148eb0641c424ec03a41c6b511f303f0fbe7b2b186d1_cppui256;
    scalars[60] = 0xece21b2a516b911afaefee62a284f51e38ec510745607ac402c4e491c74b319_cppui256;
    scalars[61] = 0x4025965c3927a08f8ade437618632abb835f94b679af3fc80b1268b7dd98bee_cppui256;
    scalars[62] = 0xb5f8b5dc9841433fc7f1b64bfaa87959fbbf79826e842ecd67c7e3d0eeb9077_cppui256;
    scalars[63] = 0x16dcc013be746c721c7a47b245baae561ca00e05cbc08998ca8b707116552bf3_cppui256;
    scalars[64] = 0x34f0258dbcccb0e14901628fb7a127547a2a5c2736a15f363374b7cc9dc7c9fe_cppui256;
    scalars[65] = 0x25d815ca9f50f2ece1a629dd0c2e5fb01fc4cd6f877ea9e11bb3d8ccb4a03cd9_cppui256;
    scalars[66] = 0x377d007a5ef8bd4b2f0e34c5884fc56a237bd2a456ed58ae16b1eb07f992a098_cppui256;
    scalars[67] = 0x27ab5f3368c119cbb0be1629fe8935ef5aed5e0d4c7fbebdce5220c2cd721e0f_cppui256;
    scalars[68] = 0x11dcd119cfbcf164ac429e787580b78676e4d79606911f0d552aa4c8c80806b3_cppui256;
    scalars[69] = 0x107e6a25867e3728da700123cd176b8f931d5b6e10443e70084043c70c4df5a2_cppui256;
    scalars[70] = 0x39f887a3b264bd5e88dfc44fa65a377a8fdd4a15ba80ff220a2516e5f4bdce6d_cppui256;
    scalars[71] = 0x448d31f81299f237325a61da00000003_cppui256;


    return scalars;
}

std::vector<typename algebra::curves::vesta::scalar_field_type::value_type> generic_scalars() {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;

    std::vector<typename BlueprintFieldType::value_type> scalars(72); // prepared
    scalars[0] = 0x26cd1d91d33771e9dfa05b3ea76e575b140f16a80f21cb8017b467f80d6ae598_cppui256;
    scalars[1] = 0x448d31f81299f237325a61da00000003_cppui256;
    scalars[2] = 0x7cbee1314455f31fdf9534a8ccbd494b060c0dccf5acf8fb551fbb08edde063_cppui256;
    scalars[3] = 0x174390ebc21b7c6dc0a5417842021fb9193340b6ebd6ba8ad7c94fcdf4afced7_cppui256;
    scalars[4] = 0x270c583de3efab3ef41e012137db178740b3b2ec7590735ed5cb00179bf1ee51_cppui256;
    scalars[5] = 0x341fe94bdf0d1a26ba1c763febe5ce566254769aea7322bd6065f3995e1cc29c_cppui256;
    scalars[6] = 0x1db6df7aae9735dc09b254baae90236eb4f7e846ec10d1fddff81773e1bc8d59_cppui256;
    scalars[7] = 0xd59779724b5d8082faba2c2655a8c4e3e6f9dc7e53056b1a599d33505c2f53d_cppui256;
    scalars[8] = 0x23d66e49edf94f838d08d45b31eeabaed786812c3b1a63fd7016e0563bf7321c_cppui256;
    scalars[9] = 0x22dc83f2c2c25fb977bc2c59b52c70bf5099f17ee146e6e8cb35c3a6f123a43a_cppui256;
    scalars[10] = 0x3692f5054e9350e458aa5a57eb445b597c44652b441c734f71ad071177f4ed78_cppui256;
    scalars[11] = 0x26f2d22ca25fc9ff78eba3709c12dd5bedb93434a7e3703718ecd8694ca891c3_cppui256;
    scalars[12] = 0x75fb2c9b8913563b4dc3a8c3dfb716f23ac1509395bf60201ce77eb449ace4_cppui256;
    scalars[13] = 0x1d0b2811a938f775569dd418d6ac42c585aab87e2b32ec86ae132eae22264e1_cppui256;
    scalars[14] = 0x2251fb43e547a92dd56deb89c3dbdbc401453790b6c382cee7c54e6e5f068104_cppui256;
    scalars[15] = 0x29f0f0dd53c8ff637193139e939fa8515e2d16fba4177707041959dab6b233fb_cppui256;
    scalars[16] = 0xe8d0876dedd485a95e16941f1ada4ad5ebaae5b8e7ed325528f008ed543e6_cppui256;
    scalars[17] = 0x8c391a91594bfda2063aa54dbae013c838fb7c76ed31c46b71f3d32b91857dc_cppui256;
    scalars[18] = 0x141bda9c55f29c2042412cfdd48f4ae03f3493907685b0f714a4394ebf234459_cppui256;
    scalars[19] = 0x26ffe8b49538aabe20ca5ace7447cd43a6958cf242007beeee5df4662d766371_cppui256;
    scalars[20] = 0xfc128f4bd1f35043b6cc619d9882ae6e50d93a5115b476c311e1da97421ee0_cppui256;
    scalars[21] = 0x171014f334dfb64be126260a34da54aa2c41a765c954b540056bbf86ca5f94d3_cppui256;
    scalars[22] = 0x1efc7bf166e69c4c35741f3eaa82a38a16fb7703f9eb4416cd8b914826796a79_cppui256;
    scalars[23] = 0x124681d0a4319d09e9fba59cc5fd6b404debe7c8f4910d7055a7b930fc3cee0_cppui256;
    scalars[24] = 0x10eaad187352e09c9acf988a84404445717a50d4b8fb11afa597bfc4b8db4066_cppui256;
    scalars[25] = 0x66187c89bf8c7d447584605f58b2e49a6046699e07274bbc5b2da935c0ffe8e_cppui256;
    scalars[26] = 0x38e99d6abf2a16783d5009aa34a9af5a2989d9f7a70dc5e747db5eb84e9d796e_cppui256;
    scalars[27] = 0xac5f962d5a25835e2d3ce06283fc1ce6ae9431bac82f572804f83f66862e679_cppui256;
    scalars[28] = 0x3fb5c6a89439d08374f8a817351dab95a302a4ec69072b069ccdb67338ea53c5_cppui256;
    scalars[29] = 0x1f238a3cbed412fdac42d849f1a66981bb6628f48197c12233c91acb94c9063a_cppui256;
    scalars[30] = 0x1dc2feba144f1ce13b5f571c9d3180e93587f67caeb30f29d00bd4593e6996a2_cppui256;
    scalars[31] = 0x211cc1e04b3b927ac464131898e3e71e2cedc3adb7ad9c5bf8e4cf325d307145_cppui256;
    scalars[32] = 0x1cbf615fdfc2bfa327047f3f312aede05f637cc635fc0204a309ef2ee8c69b63_cppui256;
    scalars[33] = 0xb7232fc06b9bb06f5821c60912ecd002e95fb5f1e9794beb4ea4fbed5c0e8d0_cppui256;
    scalars[34] = 0x37e9a89776f3d508a4f6219f392a264bd0d5fed10e651657314642a8e18b0520_cppui256;
    scalars[35] = 0x3df60a0f21bfe4efe772d1023222d9a62cc1844ce8710101aaab91d54e96dd87_cppui256;
    scalars[36] = 0x316e66f3669901d346180f75845171c028094c2489aeebe9f4c018e0ef3ff107_cppui256;
    scalars[37] = 0x3c98c0246542beba3c51536e9cb060c061b3c4ecd8edeae595375c8edbbb2f18_cppui256;
    scalars[38] = 0x2c2fb9aabbf8fa0579a072801573344e7493a819a6c429a3fa017c2a0caf47a1_cppui256;
    scalars[39] = 0x168d2cbddba5c47f8f5ed1c3443ea9217ce7dfb4b3f4f1af584aa849e56450be_cppui256;
    scalars[40] = 0x2ccb338c7c61daf774dd69ca6ba3018e2accdf266ee54af04d4ff2be435c3271_cppui256;
    scalars[41] = 0x321d645dc566507ee29fd7f17999cf333279859690d4afaf0f23500cdcae7309_cppui256;
    scalars[42] = 0x1a287d0a709ff08ae8b8f76a698aab3b303f5d43057de66b5907f21c1128a8ed_cppui256;
    scalars[43] = 0x1b3f18613589a08e7110592d069c020835dc2f21510938f3344be4f553f8f29e_cppui256;
    scalars[44] = 0x321857cd7e5158161cac239ebd49b1148f10151eedd518b11a99dd7b851da4ea_cppui256;
    scalars[45] = 0x9bca3f7385f44cd8e5ef8e12a386488fcb5924b3928604f1eaf77c87d9e622d_cppui256;
    scalars[46] = 0xf5cb7b325385671f5c30173a6e685f11f40437966e82f9f9ae23104feb2ba0d_cppui256;
    scalars[47] = 0x3be6264de9fb442a498efe2c19807eeab77cf06a42ad9dbacf6d34f97022d5b8_cppui256;
    scalars[48] = 0x1c2bd8c6ee6e3d9f9ddf5f39bb92ca717e5f8b8029837d0dd4d778923ab39da1_cppui256;
    scalars[49] = 0x13e1f0ee5a18aa74f93a2e960317825689e8ce9c4dcce721463b53d7b49fa3cb_cppui256;
    scalars[50] = 0x1dad568f59a5d50f415491ea396f9895071f7f56575b02737e98d508d34b96be_cppui256;
    scalars[51] = 0x1591f1dc4493a989629d6bd373272ba60f4d641958c05293c96acd0ee64a90ab_cppui256;
    scalars[52] = 0x11a53221406eab9fe24e56c713f41afbc7f99fba5b1390323f11460d52d057b5_cppui256;
    scalars[53] = 0x26be633a3939091e3afb8ffdbd7ae63e84c511c357015d32491c54b0fe3ca9ae_cppui256;
    scalars[54] = 0x34453f6fcc3b2c9c98d1bf8de93114e959fcbed61a0d77c9e3cc12ffd3964d52_cppui256;
    scalars[55] = 0x60e59353df80962d95053c5c176d3bfc0868b2255f946527ae0547087bfc7e3_cppui256;
    scalars[56] = 0x3bbd04cc5b59b236c45d7a88dd9088fb979ad75219f6f2db54b262ae90d35b0b_cppui256;
    scalars[57] = 0x3d2d7e5252bec64debfa31e0f41363188bec6ab433409bc5c31f810c5cd1a13f_cppui256;
    scalars[58] = 0x36df0b54dd53e949468f8d323584ed31b2bae0efacfecc8a8dd7d1fba3c2ac23_cppui256;
    scalars[59] = 0xed9d50c55ab8ed41d67bcbdf28b2501e64425f9967644a48f2d8f6991032fd8_cppui256;
    scalars[60] = 0x85c2227d6da53cacf5b4a57557eb5b36e21e2a09d8787331a61aa94456aa832_cppui256;
    scalars[61] = 0xeb23365f88ab686916424c76caa77e621ceeac8ff04042d8a89aa7e61bdc858_cppui256;
    scalars[62] = 0x1afbef2b234e1be9b46f0a721a71a7479c2529d6cfb5c6022ce88c6ff4f7114b_cppui256;
    scalars[63] = 0xbd230f849a9882a3a39e9346d885ed51facc09de13efb129d739af9f663eb2a_cppui256;
    scalars[64] = 0x37149af7ff120607585be27f6c49470c7804e782d334df339c8d1deccc9a3d77_cppui256;
    scalars[65] = 0x23fe83891e43c239b9b27885de30aba8a020d1ed74344f74cebaa7954e86680d_cppui256;
    scalars[66] = 0x1a8dd987643320b9ef239b40828c2c3f130725663deb94278d32d7298ff780b5_cppui256;
    scalars[67] = 0xb67575bf8b2f9fb26a179153d8247afc03dc9f958c9c8096495fd7805219f83_cppui256;
    scalars[68] = 0x41d70ea2bcd31360b9e4bf5741812f0ce1e6afdc78406a1cb4520a34b6db9b1_cppui256;
    scalars[69] = 0x2f30a95f8ef943d17f777b04ed63ad914911e8f5235e0a02e755229a42c33b0c_cppui256;
    scalars[70] = 0x3d7779be1824256adaae7ab981eb8b507f308defa40ce9b23e08cad80eafba1f_cppui256;
    scalars[71] = 0x448d31f81299f237325a61da00000003_cppui256;


    return scalars;
}


#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALARS_DATA_HPP