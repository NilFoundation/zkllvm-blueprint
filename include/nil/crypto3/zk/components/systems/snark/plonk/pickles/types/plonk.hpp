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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PLONK_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/composition_types/composition_types.ml#L34-L65
                template<typename FieldType>
                struct pickles_plonk_min {
                    using var = snark::plonk_variable<FieldType>;

                    // { alpha : 'scalar_challenge
                    // ; beta : 'challenge
                    // ; gamma : 'challenge
                    // ; zeta : 'scalar_challenge
                    // ; joint_combiner : 'scalar_challenge option
                    // }

                    var alpha;
                    var beta;
                    var gamma;
                    var zeta;
                    var joint_combiner;
                };

                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/composition_types/composition_types.ml#L100-L124
                template<typename FieldType>
                struct pickles_plonk_circuit {
                    using var = snark::plonk_variable<FieldType>;

                    // { alpha : 'scalar_challenge
                    // ; beta : 'challenge
                    // ; gamma : 'challenge
                    // ; zeta : 'scalar_challenge
                    //     (* TODO: zeta_to_srs_length is kind of unnecessary.
                    //         Try to get rid of it when you can.
                    //     *)
                    // ; zeta_to_srs_length : 'fp
                    // ; zeta_to_domain_size : 'fp
                    // ; poseidon_selector : 'fp
                    //     (** scalar used on the poseidon selector *)
                    // ; vbmul : 'fp  (** scalar used on the vbmul selector *)
                    // ; complete_add : 'fp
                    //     (** scalar used on the complete_add selector *)
                    // ; endomul : 'fp  (** scalar used on the endomul selector *)
                    // ; endomul_scalar : 'fp
                    //     (** scalar used on the endomul_scalar selector *)
                    // ; perm : 'fp
                    //     (** scalar used on one of the permutation polynomial commitments. *)
                    // ; generic : 'fp Generic_coeffs_vec.t
                    //     (** scalars used on the coefficient column commitments. *)
                    // ; lookup : 'lookup_opt
                    // }
                    var alpha;
                    var beta;
                    var gamma;
                    var zeta;
                    
                    var zeta_to_srs_length;
                    var zeta_to_domain_size;
                    var poseidon_selector;
                    var vbmul;
                    var complete_add;
                    var endomul;
                    var endomul_scalar;
                    var perm;
                    var generic;
                    struct lookup {
                        var joint_combiner;
                        var lookup_gate;
                    } lookup;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PLONK_HPP