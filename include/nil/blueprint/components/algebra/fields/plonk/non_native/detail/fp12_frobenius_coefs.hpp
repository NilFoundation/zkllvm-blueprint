//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of coefficients for F_p^{12} computation of p^k (k = 1,2,3)
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(non_residue[1] u + non_residue[0])),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FROBENIUS_COEFS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FROBENIUS_COEFS_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                enum small_p_power {p_one = 1, p_two = 2, p_three = 3};

                template<typename BlueprintFieldType>
                std::array<typename BlueprintFieldType::value_type,12> get_fp12_frobenius_coefficients(small_p_power Power) {

                    using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                    using fp2_element = typename policy_type_fp2::value_type;

                    std::array<typename BlueprintFieldType::value_type,12> res;

                    if constexpr (std::is_same_v<BlueprintFieldType, typename crypto3::algebra::fields::bls12_fq<381>>) {
                        // for BLS12-381 we have all the constants precomputed
                        if (Power == p_one) {
                            res[0] = 0x1_cppui381;
                            res[1] = 0x0_cppui381;
                            res[2] = 0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8_cppui381;
                            res[3] = 0xfc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3_cppui381;
                            res[4] = 0x0_cppui381;
                            res[5] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac_cppui381;
                            res[6] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[7] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[8] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad_cppui381;
                            res[9] = 0x0_cppui381;
                            res[10] = 0x5b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116_cppui381;
                            res[11] = 0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995_cppui381;
                        } else if (Power == p_two) {
                            res[0] = 0x1_cppui381;
                            res[1] = 0x0_cppui381;
                            res[2] = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff_cppui381;
                            res[3] = 0x0_cppui381;
                            res[4] = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe_cppui381;
                            res[5] = 0x0_cppui381;
                            res[6] = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa_cppui381;
                            res[7] = 0x0_cppui381;
                            res[8] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac_cppui381;
                            res[9] = 0x0_cppui381;
                            res[10] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad_cppui381;
                            res[11] = 0x0_cppui381;
                        } else {
                            res[0] = 0x1_cppui381;
                            res[1] = 0x0_cppui381;
                            res[2] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                            res[3] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[4] = 0x0_cppui381;
                            res[5] = 0x1_cppui381;
                            res[6] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                            res[7] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                            res[8] = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa_cppui381;
                            res[9] = 0x0_cppui381;
                            res[10] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[11] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                        }
                    } else {
                        // otherwise fallback to computation of constants
//std::cout << "We have to recompute Frobenius coefs for power = " << int(Power) << "\n";
                        // to obtain the correct non-residue values for the extension field
                        using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;

                        typename BlueprintFieldType::integral_type field_p = BlueprintFieldType::modulus,
                                                                   coef_exp = (field_p - 1)/6;
                        fp2_element frob_coef = fp2_element::one(),
                                    non_residue_pow = fp2_element(policy_type_fp12::extension_policy::non_residue.data[0],
                                                                  policy_type_fp12::extension_policy::non_residue.data[1]
                                                                 ).pow(coef_exp);
                        int k = int(Power);

                        for(std::size_t i = 0; i < 6; i++) {
                            res[2*i] = frob_coef.data[0];
                            res[2*i+1] = frob_coef.data[1];
                            frob_coef *= non_residue_pow;
                        }

                        if (k > 1) {
                            std::array<typename BlueprintFieldType::value_type,6> gamma_2;

                            for(std::size_t i = 0; i < 6; i++) gamma_2[i] = res[2*i].pow(2) + res[2*i+1].pow(2);

                            if (k > 2) {
                                for(std::size_t i = 0; i < 6; i++) {
                                    res[2*i] *= gamma_2[i];
                                    res[2*i+1] *= gamma_2[i];
                                }
                            } else {
                                res.fill(BlueprintFieldType::value_type::zero());
                                for(std::size_t i = 0; i < 6; i++) {
                                    res[2*i] = gamma_2[i];
                                }
                            }
                        }
                    }
//for(std::size_t i = 0; i < 12; i++) std::cout << "c[" << std::dec << i << "] = " << std::hex << res[i] << "\n";
                    return res;
                }
            } // namespace detail
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FROBENIUS_COEFS_HPP
