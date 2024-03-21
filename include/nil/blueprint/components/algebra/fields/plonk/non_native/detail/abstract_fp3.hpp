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
// @file Declaration of F_p^3 elements over an abstract entity (to be used with constraints)
// with F_p^3 = F_p[u]/(u^3 + non_residue).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP3_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP3_HPP

#include <array>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<typename T, typename UnderlyingFieldType>
                class abstract_fp3_element {
                public:
                    std::array<T,3> data;

                    T& operator[](std::size_t idx) {
                        return data[idx];
                    }
                    const T& operator[](std::size_t idx) const {
                        return data[idx];
                    }

                    constexpr abstract_fp3_element operator*(abstract_fp3_element const& other) {
                        auto s = UnderlyingFieldType::non_residue;
                        return {
                            data[0]*other[0] + s*(data[1]*other[2] + data[2]*other[1]),
                            data[0]*other[1] + data[1]*other[0] + s*data[2]*other[2],
                            data[0]*other[2] + data[1]*other[1] + data[2]*other[0]
                        };
                    }

                    constexpr abstract_fp3_element operator*(const int x) {
                        return { data[0]*x, data[1]*x, data[2]*x };
                    }
                    friend abstract_fp3_element operator*(const int x, abstract_fp3_element const& e) {
                        return { e[0]*x, e[1]*x, e[2]*x };
                    }
                    constexpr abstract_fp3_element operator+(abstract_fp3_element const& other) {
                        return { data[0] + other[0], data[1] + other[1], data[2] + other[2] };
                    }
                    constexpr abstract_fp3_element operator-(abstract_fp3_element const& other) {
                        return { data[0] - other[0], data[1] - other[1], data[2] - other[2] };
                    }
                };

            } // namespace detail
        }     // namespace components
    }         // namespace blueprint
}             // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP3_HPP
