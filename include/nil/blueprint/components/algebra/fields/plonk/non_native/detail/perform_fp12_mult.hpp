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
// @file Declaration of template function for F_p^{12} field multiplication.
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERFORM_FP12_MULT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERFORM_FP12_MULT_HPP

/*
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
*/

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                // actually compute all bilinear forms that represent multiplication in F_p^12
                template<typename T>
                std::array<T,12> perform_fp12_mult(std::array<T,12> a, std::array<T,12> b) {
                    std::array<T,12> c;

                    for(std::size_t i = 0; i < 12; i++) {
                        c[i] = a[0] - a[0]; // hack because we can't actually write c[i] = 0: type T might have casting problems
                    }

                    for(std::size_t i = 0; i < 12; i++) {
                        for(std::size_t j = 0; j < 12; j++) {
                            std::size_t dw = i/6 + j/6;
                            std::size_t dv = (i % 6)/2 + (j % 6)/2;
                            std::size_t du = (i % 2) + (j % 2);

                            if (dw == 2) {
                                // reduction according to w^2 = v
                                dw = 0; dv++;
                            }
                            // possible change of sign according to u^2 = -1
                            // NB: the only reason for having this "if" (and the one several lines below)
                            // instead of possibly multiplying  the product a[i]*b[j] by (-1), is to
                            // have constraints that are written shorter, as opposed to the ones that contain -1.
                            // Because -1 is a number with a lot of digits in F_p.
                            if (du > 1) {
                                c[6*dw + 2*(dv % 3) + (du % 2)] -= a[i] * b[j];
                            } else {
                                c[6*dw + 2*(dv % 3) + (du % 2)] += a[i] * b[j];
                            }
                            if (dv > 2) {
                                // reduction according to v^3 = u + 1
                                dv -= 3; du++;
                                // account for u in the reduction v^3 = u + 1
                                if (du > 1) {
                                    c[6*dw + 2*dv + (du % 2)] -= a[i] * b[j];
                                } else {
                                    c[6*dw + 2*dv + (du % 2)] += a[i] * b[j];
                                }
                            }
                        }
                    }
                    return c;
                }
            } // namespace detail
        }    // namespace components
    }       // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERFORM_FP12_MULT_HPP
