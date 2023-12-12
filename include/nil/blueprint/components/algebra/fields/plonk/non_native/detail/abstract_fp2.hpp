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
// @file Declaration of F_p^2 elements over an abstract entity (to be used with constraints)
// with F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP2_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP2_HPP

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<typename T>
                class abstract_fp2_element {
                public:
                    std::array<T,2> data;

                    T& operator[](std::size_t idx) {
                        return data[idx];
                    }
                    const T& operator[](std::size_t idx) const {
                        return data[idx];
                    }


                    constexpr abstract_fp2_element operator*(const abstract_fp2_element& other) {
                        return { data[0] * other.data[0] - data[1] * other.data[1],
                                 data[0] * other.data[1] + data[1] * other.data[0]};
                    }
                    constexpr abstract_fp2_element operator*(const int x) {
                        return { data[0]*x, data[1]*x };
                    }
                    friend abstract_fp2_element operator*(const int x, const abstract_fp2_element& e) {
                        return { e[0]*x, e[1]*x };
                    }
                    constexpr abstract_fp2_element operator+(const abstract_fp2_element& other) {
                        return { data[0] + other.data[0], data[1] + other.data[1] };
                    }
                    constexpr abstract_fp2_element operator-(const abstract_fp2_element& other) {
                        return { data[0] - other.data[0], data[1] - other.data[1] };
                    }
                };

            } // namespace detail
        }    // namespace components
    }       // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ABSTRACT_FP2_HPP
