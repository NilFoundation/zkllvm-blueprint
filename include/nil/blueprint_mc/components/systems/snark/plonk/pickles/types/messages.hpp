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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_MESSAGES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_MESSAGES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/component.hpp>

#include <nil/blueprint_mc/components/systems/snark/plonk/pickles/types/app_state.hpp>

namespace nil {
    namespace blueprint_mc {
        namespace components {

            // TODO: link
            template<typename FieldType>
            struct messages_for_next_step_proof_type {
                using var = nil::crypto3::zk::snark::plonk_variable<FieldType>;
                using var_ec_point = typename nil::blueprint_mc::components::var_ec_point<FieldType>;

                app_state_type<FieldType> app_state;
                std::vector<var> old_bulletproof_challenges; 
                std::vector<var_ec_point> challenge_polynomial_commitments;         
            };

            // TODO: link
            template<typename FieldType>
            struct messages_for_next_wrap_proof_type {
                using var = nil::crypto3::zk::snark::plonk_variable<FieldType>;
                using var_ec_point = typename nil::blueprint_mc::components::var_ec_point<FieldType>;

                std::vector<var_ec_point> challenge_polynomial_commitment;
                std::vector<var> old_bulletproof_challenges; 
            };
        }    // namespace components
    }            // namespace blueprint_mc
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_MESSAGES_HPP