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

#ifndef BLUEPRINT_MC_PLONK_KIMCHI_TYPES_EVALUATION_PROOF_HPP
#define BLUEPRINT_MC_PLONK_KIMCHI_TYPES_EVALUATION_PROOF_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/component.hpp>

namespace nil {
    namespace blueprint_mc {
        namespace components {

            template<typename FieldType, typename KimchiParamsType>
            struct kimchi_lookup_evaluations {
                using var = nil::crypto3::zk::snark::plonk_variable<FieldType>;

                std::array<var, KimchiParamsType::circuit_params::lookup_columns> sorted;

                var aggreg;
                var table;

                var runtime;

                kimchi_lookup_evaluations() {
                }
            };

            template<typename FieldType, typename KimchiParamsType>
            struct kimchi_proof_evaluations {
                using var = nil::crypto3::zk::snark::plonk_variable<FieldType>;
                // witness polynomials
                std::array<var, KimchiParamsType::witness_columns> w;
                // permutation polynomial
                var z;
                // permutation polynomials
                // (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
                std::array<var, KimchiParamsType::permut_size - 1> s;
                // /// lookup-related evaluations
                kimchi_lookup_evaluations<FieldType, KimchiParamsType> lookup;
                // /// evaluation of the generic selector polynomial
                var generic_selector;
                // /// evaluation of the poseidon selector polynomial
                var poseidon_selector;

                kimchi_proof_evaluations() {
                }
            };
        }    // namespace components
    }            // namespace blueprin_mc
}    // namespace nil

#endif    // BLUEPRINT_MC_PLONK_KIMCHI_TYPES_EVALUATION_PROOF_HPP