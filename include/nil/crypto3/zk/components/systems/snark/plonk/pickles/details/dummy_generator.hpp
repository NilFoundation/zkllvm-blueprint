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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_DUMMY_GENERATOR_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_DUMMY_GENERATOR_HPP

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/urs_generator.hpp>

#include <limits>
#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename CurveType>
                struct dummy_generator_params;

                template<>
                struct dummy_generator_params<algebra::curves::vesta> {
                    static constexpr std::size_t num_rounds = 16;
                    constexpr static const typename algebra::curves::vesta::scalar_field_type::value_type endo_r =
                        0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                };

                template<>
                struct dummy_generator_params<algebra::curves::pallas> {
                    static constexpr std::size_t num_rounds = 15;
                    constexpr static const typename algebra::curves::pallas::scalar_field_type::value_type endo_r =
                        0x397E65A7D7C1AD71AEE24B27E308F0A61259527EC1D4752E619D1840AF55F1B1_cppui255;
                };

                template<typename CurveType>
                class dummy_generator {
                    using curve_type = CurveType;
                    using field_type = typename curve_type::scalar_field_type;
                    using value_type = typename field_type::value_type;
                    using point_type = typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;
                    using params = dummy_generator_params<curve_type>;

                    // I've just hardcoded the values as we currently don't have Blake2s hash function implemented
                    // afaik these are not used in the circuit directly and are only used through computed challenges
                    static constexpr std::array<value_type, 16> ro_chal = {
                        0x000000000000000000000000000000005BD1DE3CF264021D2CD1CCBEB20747B3_cppui256,
                        0x00000000000000000000000000000000951FA2E06193C8404B7DB27121979954_cppui256,
                        0x00000000000000000000000000000000EFE66A55155C429499CA3D5BFFFD6E77_cppui256,
                        0x0000000000000000000000000000000097A927D7D0AFB7BC429882844BBCAA4E_cppui256,
                        0x000000000000000000000000000000009D40C715FC8CCDE54445E35E373F2BC9_cppui256,
                        0x00000000000000000000000000000000C1C68B39DB4E8E129007D7B55E76646E_cppui256,
                        0x00000000000000000000000000000000A6888B7340A96DED22C0B35C51E06B48_cppui256,
                        0x000000000000000000000000000000005A8C718CF210F79B5C2B8ADFDBE9604D_cppui256,
                        0x00000000000000000000000000000000A1FE6369FACEF1E89C75747C56805F11_cppui256,
                        0x000000000000000000000000000000004D1B97E2E95F26A01DBDA72D07B09C87_cppui256,
                        0x00000000000000000000000000000000F85C5F00DF6B0CEEE29C77B18F10078B_cppui256,
                        0x00000000000000000000000000000000A921BCB02A656F7B532C59A287691A13_cppui256,
                        0x0000000000000000000000000000000007DDBB65CDA09CDDC6E8E530F49C9FCB_cppui256,
                        0x00000000000000000000000000000000DD7AE6402944A1C7DD3A2B06E9888797_cppui256,
                        0x0000000000000000000000000000000079974358F97618633382B3C9ACE6BF6F_cppui256,
                        0x000000000000000000000000000000001B6604E3C071B1CE48C1B0A2B1CAB8D1_cppui256,
                    };

                    static constexpr value_type compute_challenge(const value_type &ro_chal) {
                        value_type a = 2,
                                   b = 2;
                        value_type one = 1,
                                   neg_one = -one;
                        std::array<bool, 128> bits = {};
                        auto data = ro_chal.data;
                        for (std::size_t i = 0; i < 128; i++) {
                            bits[i] = (data - (data >> 1 << 1)) != 0;
                            data >>= 1;
                        }

                        for (std::size_t i = (128 / 2) - 1; i != std::numeric_limits<std::size_t>::max(); i--) {
                            a = a + a;
                            b = b + b;
                            value_type s = bits[2 * i] ? one : neg_one;
                            if (bits[(2 * i) + 1]) {
                                a += s;
                            } else {
                                b += s;
                            }
                        }
                        return a * params::endo_r + b;
                    }

                    static constexpr std::array<value_type, params::num_rounds> compute_challenges() {
                        std::array<value_type, params::num_rounds> results;
                        for (std::size_t i = 0; i < params::num_rounds; ++i) {
                            results[i] = compute_challenge(ro_chal[i]);
                        }
                        return results;
                    }

                public:
                    // this can be made static constexpr, but I've found that compilation time gets significantly worse
                    std::array<value_type, params::num_rounds> computed_challenges;

                    dummy_generator() {
                        computed_challenges = compute_challenges();
                    }

                    point_type compute_sg() {
                        // we don't use the shifted element in comm
                        // thus we only compute the unshifted part
                        const std::size_t msm_size = 1 << params::num_rounds;
                        using urs_type = typename zk::components::urs<curve_type, msm_size>;
                        urs_type urs;
                        // we use vector here as array is 'on the stack', which might lead to stack overflow
                        std::vector<value_type> scalars;
                        scalars.resize(msm_size);
                        std::fill(scalars.begin(), scalars.end(), value_type::one());
                        std::size_t k = 0;
                        std::size_t pow = 1;
                        for (std::size_t i = 1; i < msm_size; i++) {
                            k += (i == pow) ? 1 : 0;
                            pow <<= (i == pow) ? 1 : 0;
                            scalars[i] = scalars[i - (pow >> 1)] * computed_challenges[params::num_rounds - 1 - (k - 1)];
                        }

                        point_type result = scalars[0] * urs.g[0];
                        for (std::size_t i = 1; i < msm_size; i++) {
                            result = result + scalars[i] * urs.g[i];
                        }

                        return result;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_DUMMY_GENERATOR_HPP
