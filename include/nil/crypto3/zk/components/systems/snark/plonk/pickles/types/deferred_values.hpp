//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_DEFERRED_VALUES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_DEFERRED_VALUES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/branch_data.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/composition_types/composition_types.ml#L206-L233
                template<typename FieldType>
                struct deffered_values {
                    using var = snark::plonk_variable<FieldType>;

                    // { plonk : 'plonk
                    // ; combined_inner_product : 'fp
                    //     (** combined_inner_product = sum_{i < num_evaluation_points} sum_{j < num_polys} r^i xi^j f_j(pt_i) *)
                    // ; b : 'fp
                    //     (** b = challenge_poly plonk.zeta + r * challenge_poly (domain_generrator * plonk.zeta)
                    //     where challenge_poly(x) = \prod_i (1 + bulletproof_challenges.(i) * x^{2^{k - 1 - i}})
                    // *)
                    // ; xi : 'scalar_challenge
                    //     (** The challenge used for combining polynomials *)
                    // ; bulletproof_challenges : 'bulletproof_challenges
                    //     (** The challenges from the inner-product argument that was partially verified. *)
                    // ; branch_data : 'branch_data
                    //     (** Data specific to which step branch of the proof-system was verified *)
                    // }

                    pickles_plonk<FieldType> plonk;
                    var combined_inner_product;
                    var b;
                    var xi;
                    std::vector<var> bulletproof_challenges;
                    branch_data<FieldType> branch_data;
                };
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_DEFERRED_VALUES_HPP