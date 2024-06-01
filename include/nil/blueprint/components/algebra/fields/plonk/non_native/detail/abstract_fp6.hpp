//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// @file Declaration of F_p^6 elements over an abstract entity (to be used with constraints)
// with F_p^6 = Fp^2 over Fp^3:
// Fp^6 = Fp^2[x]/(x^2 - u), u = (0,1,0)
// Fp^3 = Fp[y]/(y^3 - v), for MNT6: v = 5
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP4_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP4_HPP

#include <array>
#include <cstddef>

#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename T, typename UnderlyingFieldType>
                class abstract_fp6_element{
                public:
                    using policy_type_fp6 = crypto3::algebra::fields::fp6_2over3<UnderlyingFieldType>;
                    std::array<T, 6> x;

                    T& operator[](std::size_t idx) {
                        return x[idx];
                    }
                    const T& operator[](std::size_t idx) const {
                        return x[idx];
                    }

                    constexpr abstract_fp6_element operator*(abstract_fp6_element const& y) {
                        // Devegili et al - Multiplication and squaring in pairing-friendly fields
                        // https://eprint.iacr.org/2006/471.pdf, page 15, direct sextic
                        // Take note on isomorphism between a (Fp 2 over 3) and c (direct sextic)
                        // Indices map is on page 17
                        constexpr std::size_t
                            _0 = 0, _1 = 3, _2 = 1,
                            _3 = 4, _4 = 2, _5 = 5;

                        constexpr auto s = policy_type_fp6::extension_policy::non_residue;

                        T c[6] = {
                            x[_0]*y[_0] + s*(x[_1]*y[_5] +    x[_2]*y[_4] +    x[_3]*y[_3] +    x[_4]*y[_2] +    x[_5]*y[_1]),
                            x[_0]*y[_1] +    x[_1]*y[_0] + s*(x[_2]*y[_5] +    x[_3]*y[_4] +    x[_4]*y[_3] +    x[_5]*y[_2]),
                            x[_0]*y[_2] +    x[_1]*y[_1] +    x[_2]*y[_0] + s*(x[_3]*y[_5] +    x[_4]*y[_4] +    x[_5]*y[_3]),
                            x[_0]*y[_3] +    x[_1]*y[_2] +    x[_2]*y[_1] +    x[_3]*y[_0] + s*(x[_4]*y[_5] +    x[_5]*y[_4]),
                            x[_0]*y[_4] +    x[_1]*y[_3] +    x[_2]*y[_2] +    x[_3]*y[_1] +    x[_4]*y[_0] + s* x[_5]*y[_5],
                            x[_0]*y[_5] +    x[_1]*y[_4] +    x[_2]*y[_3] +    x[_3]*y[_2] +    x[_4]*y[_1] +    x[_5]*y[_0]
                        };

                        return { c[0], c[2], c[4], c[1], c[3], c[5]};
                    }

                    constexpr abstract_fp6_element operator*(const int a) {
                        return { x[0]*a, x[1]*a, x[2]*a, x[3]*a, x[4]*a, x[5]*a };
                    }
                    friend abstract_fp6_element operator*(const int a, abstract_fp6_element const& x) {
                        return { x[0]*a, x[1]*a, x[2]*a, x[3]*a, x[4]*a, x[5]*a };
                    }
                    constexpr abstract_fp6_element operator+(abstract_fp6_element const& y) {
                        return { x[0] + y[0], x[1] + y[1], x[2] + y[2], x[3] + y[3], x[4] + y[4], x[5] + y[5]};
                    }
                    constexpr abstract_fp6_element operator-(abstract_fp6_element const& y) {
                        return { x[0] - y[0], x[1] - y[1], x[2] - y[2], x[3] - y[3], x[4] - y[4], x[5] - y[5]};
                    }
                };

            } // namespace detail
        }     // namespace components
    }         // namespace blueprint
}             // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_abstract_FP4_HPP
