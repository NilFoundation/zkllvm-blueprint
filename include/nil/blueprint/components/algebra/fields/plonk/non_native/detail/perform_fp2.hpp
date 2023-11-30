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
// @file Declaration of template functions for F_p^2 field operations.
// with F_p^2 = F_p[u]/(u^2 - (-1)). They are intended for constraint generation.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERFORM_FP2_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERFORM_FP2_HPP

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                // actually compute bilinear forms that represent multiplication in F_p^2
                template<typename T>
                std::array<T,2> perform_fp2_mult(std::array<T,2> a, std::array<T,2> b) {
                    std::array<T,2> c = {a[0]*b[0] - a[1]*b[1], a[0]*b[1] + a[1]*b[0]};
                    return c;
                }

                template<typename T>
                std::array<T,2> perform_fp2_add(std::array<T,2> a, std::array<T,2> b) {
                    std::array<T,2> c = {a[0] + b[0], a[1] + b[1]};
                    return c;
                }

                template<typename T>
                std::array<T,2> perform_fp2_sub(std::array<T,2> a, std::array<T,2> b) {
                    std::array<T,2> c = {a[0] - b[0], a[1] - b[1]};
                    return c;
                }

                template<typename T>
                std::array<T,2> perform_fp2_scale(std::array<T,2> a, int x) {
                    std::array<T,2> c = {a[0]*x, a[1]*x};
                    return c;
                }
            } // namespace detail
        }    // namespace components
    }       // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERFORM_FP2_HPP
