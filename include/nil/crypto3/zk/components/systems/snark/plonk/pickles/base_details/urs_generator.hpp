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

#ifndef CRYPTO3_ZK_COMPONENTS_SYSTEMS_SNARK_PLONK_PICKLES_BASE_DETAILS_URS_GENERATOR_HPP
#define CRYPTO3_ZK_COMPONENTS_SYSTEMS_SNARK_PLONK_PICKLES_BASE_DETAILS_URS_GENERATOR_HPP

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/blake2b.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/buffers.hpp>
#include <string>

using namespace boost::endian;
using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename CurveType, std::size_t UrsLen>
                struct urs {
                    using ec_point = typename CurveType::template
                            g1_type<algebra::curves::coordinates::affine>::value_type;
                    using value_type = typename CurveType::base_field_type::value_type;

                    std::array<ec_point, UrsLen> g;
                    ec_point h;

                    static multiprecision::uint256_t digest_to_uint256_t(std::string digest) {
                        multiprecision::uint256_t result = 0;
                        std::array<unsigned char, 31> bytes;
                        for (std::size_t i = 0; i < 31; i++) {
                            std::string hex = digest.substr(i * 2, 2);
                            bytes[i] = std::stoi(hex, 0, 16);
                        }

                        for (std::size_t i = 0; i < 31; i++) {
                            for (std::size_t j = 0; j < 8; j++) {
                                result <<= 1;
                                result |= (bytes[i] >> j) & 1;
                            }
                        }

                        return result;
                    }

                    static std::vector<value_type> potential_xs(value_type x) {
                        // u/fu specific to pasta: u is the smallest positive integer
                        // which is a valid x coordinate; fu is y^2 corresponding to u
                        constexpr value_type u = 1;
                        constexpr value_type fu = 6;
                        constexpr value_type inv_three_u_squared = 1 / (3 * u * u);
                        constexpr value_type sqrt_neg_three_u_squared = (-(3 * u * u)).sqrt();
                        constexpr value_type sqrt_neg_three_u_squared_minus_u_over_2 =
                            (sqrt_neg_three_u_squared - u) / 2;

                        value_type x2 = x * x;
                        value_type alpha = (x2 + fu) * x2;
                        if (alpha != 0) {
                            alpha = 1 / alpha;
                        }
                        std::vector<value_type> result;
                        result.resize(3);
                        // (sqrt(-3u^2)-u)/2 - x2^2 * alpha * sqrt(-3u^2)
                        result[0] = sqrt_neg_three_u_squared_minus_u_over_2 - x2 * x2 * alpha * sqrt_neg_three_u_squared;
                        result[1] = -u - result[0];
                        result[2] = u - inv_three_u_squared * alpha * (x2 + fu) * (x2 + fu) * (x2 + fu);
                        return result;
                    }

                    static ec_point point_of_random_bytes(std::string digest) {
                        assert(digest.size() == 128);
                        value_type x = value_type(digest_to_uint256_t(digest));
                        ec_point p;

                        auto xs = potential_xs(x);
                        bool found = false;
                        for (auto x : xs) {
                            value_type y = x * x * x + 5;
                            if (y.is_square()) {
                                p = ec_point(x, y.sqrt());
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            throw std::runtime_error("no valid y coordinate found");
                        }

                        return p;
                    }

                    static std::string big_uint_to_string(big_uint32_t i) {
                        std::string result;
                        result.resize(sizeof(big_uint32_t));
                        for (std::size_t j = 0; j < sizeof(big_uint32_t); j++) {
                            char last_byte = (char)(i & 0xff);
                            result[result.size() - j - 1] = last_byte;
                            i >>= 8;
                        }
                        return result;
                    }

                    static urs<CurveType, UrsLen> generate_mina_urs() {
                        using hash_type = hashes::blake2b<512>;
                        urs<CurveType, UrsLen> urs;

                        for (big_uint32_t i = 0; i < UrsLen; i++) {
                            std::string digest = hash<hash_type>(big_uint_to_string(i));
                            urs.g[i] = point_of_random_bytes(digest);
                        }
                        std::array<char, 12> hash_str = {
                            's', 'r', 's', '_', 'm', 'i', 's', 'c', '\0', '\0', '\0', '\0'
                        };
                        std::string h = hash<hash_type>(hash_str);
                        urs.h = point_of_random_bytes(h);

                        return urs;
                    }

                    /*void load(std::string filename) {
                        std::ifstream in(filename);
                        std::string line;
                        std::size_t idx = 0;
                        while (std::getline(in, line)) {
                            if (idx < 2) {
                                if (idx % 2) {
                                    h.X = multiprecision::uint256_t(line);
                                } else {
                                    h.Y = multiprecision::uint256_t(line);
                                }
                            } else {
                                if (idx % 2) {
                                    g[(idx - 2) / 2].X = multiprecision::uint256_t(line);
                                } else {
                                    g[(idx - 2) / 2].Y = multiprecision::uint256_t(line);
                                }
                            }
                            idx++;
                        }
                        BOOST_ASSERT_MSG(idx == 2 + 2 * UrsLen, "invalid urs file");
                    }*/
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_ZK_COMPONENTS_SYSTEMS_SNARK_PLONK_PICKLES_BASE_DETAILS_URS_GENERATOR_HPP
