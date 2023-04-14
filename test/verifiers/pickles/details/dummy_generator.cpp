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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_details_dummy_generator_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/details/dummy_generator.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_verifiers_pickles_details_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_details_dummy_generator_vesta_test) {
    using curve_type = algebra::curves::vesta;
    using value_type = curve_type::scalar_field_type::value_type;
    using dummy_type = zk::components::dummy_generator<curve_type>;

    dummy_type dummy;
    // test data can be recomputed using endo_scalar.cpp test
    std::array<value_type, 16> expected_challenges = {
        0x15ADB43B7D2DB05FB352F60E359CC52C63814E4A82ADECEDF96DF7438D9E54CC_cppui256,
        0x36B7F60D770F6BB6B84D54EE9DD4FE0BF429613CBEB580641BE734EC34FD2A07_cppui256,
        0x2804B96A785A7FC3923495573E3A9F4D8C6B900750CD98EF47F73F6FA07F0AC0_cppui256,
        0x3C9C5F2CD8C0C8AD91E7D40C8104EC63A63FFCAD5C9DACDAB4EDC289753738E3_cppui256,
        0x21F94BB8BAA9081666AF0F638AED6AEB53E9AA858B0357DE1CD734542F08465B_cppui256,
        0x0CB93BB4740FEADBB8BFC750069EE19109243E6345EF6779635258C14ECF22F0_cppui256,
        0x01B1B29EF91CA2CF74994068DB3C5C372A220C1741E351C85D09D907BB9CEC3E_cppui256,
        0x04816594188E720C6BEB63758FCEA67316261C84AD1720B6FC30098CFB7EB50A_cppui256,
        0x0BFDE87780D27763A7EC2A140BBBC7F4F00BDABFD22CA9477790F01C3E75513B_cppui256,
        0x06AF94CCC97C40D9CDC127F81932761DDC26D9EFFD27768EDA22B1853CA07C59_cppui256,
        0x15A82A2875F4F42B0D2DC7F740134B0225552A0843117C90CA7D195E40FDC54A_cppui256,
        0x0CC6E4B08B876D810F5127F8FC6CEC05DD2351625DD4DC11B94EF15005A8BBCF_cppui256,
        0x2A5649C5B6EF80DE45E3B48C551A286059543B515CC3B994294EA4581BE07FCB_cppui256,
        0x3760A1287523096B58D68028B0AFC6877126D532B359670D69C4F16F06355517_cppui256,
        0x34E12F473A932C220C0FE0A4750306E6E1E5210242EC143B06861B3147D7AA89_cppui256,
        0x153E2B807619245DA56D31AA6FBA1740BF53EDF0A1DE4B5AA371F8C627D5293C_cppui256,
    };

    for (std::size_t i = 0; i < 16; i++) {
        assert(dummy.computed_challenges[i] == expected_challenges[i]);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_details_dummy_generator_pallas_test) {
    using curve_type = algebra::curves::pallas;
    using value_type = curve_type::scalar_field_type::value_type;
    using dummy_type = zk::components::dummy_generator<curve_type>;

    dummy_type dummy;
    // test data can be recomputed using endo_scalar.cpp test
    std::array<value_type, 15> expected_challenges = {
        0x0A9C694CF11A14E9B669FFB177100A3DDB212EFE718A36CA4DEBA1D469036566_cppui256,
        0x1CDC8A66BBB606FCD4922673EC9AA25750673FFF298ABD2393F9B8295161E335_cppui256,
        0x31129D83A3D6616AD7DC9A4D6D00302F76374B84980538BAFF42DA835AC5ED49_cppui256,
        0x29730D7526B703CF84C899D4680047B4A83479D4CA7CAE6387B0D1768DE8D12A_cppui256,
        0x3205F14229442E2439881FCA459408FE127C9A8C104A958093EB3B4FC3B63F48_cppui256,
        0x06384C652C8D838C0050BB4A3F9DF699DC99CA0D0F0717A53226610B6E268C61_cppui256,
        0x3738EA5BA40B54912B346C3AE8E0A566A6FFA18EF8A47A2A18748E3255316FFE_cppui256,
        0x18A9F2391A4C0B123BA1E7CD4F208F3566091638ACD793B955B9D942A622DB4F_cppui256,
        0x34769191AC9AE3D94A1C152C68C81C540C52D19230E61C0CFF8E9D4BDEB26498_cppui256,
        0x0124625BB02F3441D3FC1D6DD7EB623D0A5DFBDEEDAFC8F266305BF980D99A03_cppui256,
        0x2B83BDAB0EA9DFA4BF2F995AE17E7D861263553BDACD2765E487537EAD3D5DE3_cppui256,
        0x00D4C4B61AC97DA93C9418A753F35E170EF3AF3F97F6ED0D729895351601EC79_cppui256,
        0x2CEA2930215577E1F74B058AB7AEE65023FCF3906AA56B4160F3B52F64F66A59_cppui256,
        0x0D24C97B0B4684843433F92C3FD8D45C344E49F82E438C42FC22982638219AF3_cppui256,
        0x0F958DB2EBF51F4E42484F0A027A4D1BBD270C81E09DB91067F31DF72B6E402A_cppui256,
    };

    for (std::size_t i = 0; i < 15; i++) {
        assert(dummy.computed_challenges[i] == expected_challenges[i]);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_details_dummy_generator_sg_pallas_test) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using dummy_type = zk::components::dummy_generator<curve_type>;
    using point_type = typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;

    dummy_type dummy;
    point_type sg = dummy.compute_sg();
    point_type expected;
    expected.X = 0x3DDD6F63416CA65CEB8DB0EA6D5751A0E9A81815C31BB108C8D68A01DC013304_cppui256;
    expected.Y = 0x265D14AC0624EC76098F1EC4523B2F870CF86FC70EE6F0F869E3963311A54A89_cppui256;

    assert(sg == expected);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "dummy sg pallas: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_details_dummy_generator_sg_vesta_test) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using dummy_type = zk::components::dummy_generator<curve_type>;
    using point_type = typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;

    dummy_type dummy;
    point_type sg = dummy.compute_sg();
    point_type expected;
    expected.X = 0x2CB5BEA29A2AC9C52FFB7D85C5BCC17817F0FF408EFFDDA853B9C12311035A1B_cppui256;
    expected.Y = 0x106CF9263C22E41236C2417C315409E074742E9D3633D9AC9687DD37659DDF85_cppui256;

    assert(sg == expected);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "dummy sg vesta: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
