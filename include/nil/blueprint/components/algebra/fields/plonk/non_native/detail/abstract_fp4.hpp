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
// @file Declaration of F_p^4 elements over an abstract entity (to be used with constraints)
// with F_p^4 = Fp^2 over Fp^2:
// Fp^4 = Fp^2[x]/(x^2 - u), u = (0,1)
// Fp^2 = Fp[y]/(y^2 - v), v = 17 (0x11), u^2 = v
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP4_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP4_HPP

#include <array>
#include <cstddef>

#include <nil/crypto3/algebra/fields/fp4.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename T, typename UnderlyingFieldType>
                class abstract_fp4_element{
                public:
                    using policy_type_fp4 = crypto3::algebra::fields::fp4<UnderlyingFieldType>;
                    std::array<T,4> x;

                    T& operator[](std::size_t idx) {
                        return x[idx];
                    }
                    const T& operator[](std::size_t idx) const {
                        return x[idx];
                    }

                    constexpr abstract_fp4_element operator*(abstract_fp4_element const& y) {
                        // Devegili et al - Multiplication and squaring in pairing-friendly fields
                        // https://eprint.iacr.org/2006/471.pdf
                        constexpr auto s = policy_type_fp4::extension_policy::non_residue;
                        auto d00 = x[0b00]*y[0b00] + s*(x[0b01]*y[0b01] + x[0b10]*y[0b11] + x[0b11]*y[0b10]);
                        auto d01 = x[0b00]*y[0b01] + x[0b10]*y[0b10] + x[0b01]*y[0b00] + s*x[0b11]*y[0b11];
                        auto d10 = x[0b00]*y[0b10] + x[0b10]*y[0b00] + s*(x[0b01]*y[0b11] + x[0b11]*y[0b01]);
                        auto d11 = x[0b00]*y[0b11] + x[0b01]*y[0b10] + x[0b10]*y[0b01] + x[0b11]*y[0b00];

                        return { d00, d01, d10, d11};
                    }

                    constexpr abstract_fp4_element operator*(const int a) {
                        return { x[0]*a, x[1]*a, x[2]*a, x[3]*a };
                    }
                    friend abstract_fp4_element operator*(const int a, abstract_fp4_element const& x) {
                        return { x[0]*a, x[1]*a, x[2]*a, x[3]*a };
                    }
                    constexpr abstract_fp4_element operator+(abstract_fp4_element const& y) {
                        return { x[0] + y[0], x[1] + y[1], x[2] + y[2], x[3] + y[3] };
                    }
                    constexpr abstract_fp4_element operator-(abstract_fp4_element const& y) {
                        return { x[0] - y[0], x[1] - y[1], x[2] - y[2], x[3] - y[3] };
                    }
                };

            } // namespace detail
        }     // namespace components
    }         // namespace blueprint
}             // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_abstract_FP4_HPP
