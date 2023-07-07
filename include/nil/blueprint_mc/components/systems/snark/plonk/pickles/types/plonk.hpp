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

#ifndef BLUEPRINT_MC_PLONK_PICKLES_TYPES_PLONK_HPP
#define BLUEPRINT_MC_PLONK_PICKLES_TYPES_PLONK_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/component.hpp>

namespace nil {
    namespace blueprint_mc {
        namespace components {

            // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/composition_types/composition_types.ml#L34-L65
            template<typename FieldType>
            struct pickles_plonk {
                using var = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

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
        }    // namespace components
    }            // namespace blueprint_mc
}    // namespace nil

#endif    // BLUEPRINT_MC_PLONK_PICKLES_TYPES_PLONK_HPP