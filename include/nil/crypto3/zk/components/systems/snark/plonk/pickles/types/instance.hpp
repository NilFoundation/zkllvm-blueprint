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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_INSTANCE_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_INSTANCE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/statement.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/app_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // TODO: link
                template<typename BlueprintFieldType, typename CurveType, typename KimchiParamsType>
                struct instance_type {
                    private:
                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;
                    using proof_type = kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType>;

                    public:

                    proof_type kimchi_proof;
                    verifier_index_type verifier_index;
                    app_state_type<BlueprintFieldType> app_state;
                    statement_type<BlueprintFieldType> statement;

                    std::vector<var_ec_point> comms;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_INSTANCE_HPP