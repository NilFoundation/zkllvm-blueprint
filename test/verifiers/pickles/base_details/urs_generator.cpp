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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_base_details_urs_generator_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/urs_generator.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_base_details_urs_generator_test) {
    using curve_type = algebra::curves::vesta;
    using value_type = algebra::curves::vesta::g1_type<algebra::curves::coordinates::affine>::value_type;
    constexpr std::size_t urs_size = 4;
    using urs_type = zk::components::urs<curve_type, urs_size>;
    urs_type urs = urs_type::generate_mina_urs();

    std::array<value_type, 4> g;

    g[0].X = 0x121C4426885FD5A9701385AAF8D43E52E7660F1FC5AFC5F6468CC55312FC60F8_cppui256;
    g[0].Y = 0x21B439C01247EA3518C5DDEB324E4CB108AF617780DDF766D96D3FD8AB028B70_cppui256;
    g[1].X = 0x26C9349FF7FB4AB230A6F6AEF045F451FBBE9B37C43C3274E2AA4B82D131FD26_cppui256;
    g[1].Y = 0x1996274D67EC0464C51F79CCFA1F511C2AABB666ABE67733EE8185B71B27A504_cppui256;
    g[2].X = 0x26985F27306586711466C5B2C28754AA62FE33516D75CEF1F7751F1A169713FD_cppui256;
    g[2].Y = 0x2E8930092FE6A18B331CE0E6E27B413AA18E76394F18A2835DA9FAE10AA3229D_cppui256;
    g[3].X = 0x014B2DB7B753A74D454061FCB3AC537E1B4BA512F9ED258C996A59D9DACD13E5_cppui256;
    g[3].Y = 0x06F392D371494FC39174C4B70C692B96F3B7C42DA288F6B7AABF463334A952D0_cppui256;


    for (std::size_t i = 0; i < urs_size; i++) {
        assert(urs.g[i].X == g[i].X);
        assert(urs.g[i].Y == g[i].Y);
    }

    value_type h;
    h.X = 0x092060386301C999AAB4F263757836369CA27975E28BC7A8E5B2CE5B26262201_cppui256;
    h.Y = 0x314FC4D83AE66A509F9D41BE6165F2606A209A9B5805EE85CE20249C5EBCBE26_cppui256;

    assert(urs.h.X == h.X);
    assert(urs.h.Y == h.Y);
}
