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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>


#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/batch_dlog_accumulator_check_base.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/hash_messages_for_next_wrap_proof.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/instance.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/urs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // base field part of verify_generogenous
                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/verify.ml#L30
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                    std::size_t BatchSize, std::size_t CommsLen, std::size_t UrsSize, std::size_t StateSize,
                    std::size_t WrapChalLen, std::size_t... WireIndexes>
                class verify_heterogenous_base;

                template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,
                         std::size_t BatchSize, std::size_t CommsLen, std::size_t UrsSize, std::size_t StateSize,
                         std::size_t WrapChalLen, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class verify_heterogenous_base<
                    snark::plonk_constraint_system<typename CurveType::base_field_type, ArithmetizationParams>,
                    CurveType, KimchiParamsType, BatchSize, CommsLen, UrsSize, StateSize, WrapChalLen,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::base_field_type;

                    using ArithmetizationType = snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                    using KimchiCommitmentParamsType = typename KimchiParamsType::commitment_params_type;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    using urs_type = typename types::var_urs<BlueprintFieldType, UrsSize>;

                    using batch_dlog_accumulator_check_component =
                        zk::components::batch_dlog_accumulator_check_base<ArithmetizationType, CurveType, KimchiParamsType,
                                                                          CommsLen, UrsSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using kimchi_verify_component = zk::components::base_field<ArithmetizationType,
                        CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize,
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using proof_binding =
                        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;
                    using proof_type = kimchi_proof_base<BlueprintFieldType, KimchiParamsType>;
                    using pickles_instance_type = instance_type_t<BlueprintFieldType, KimchiParamsType, StateSize>;
                    using endo_scalar_component =
                        zk::components::endo_scalar<ArithmetizationType, CurveType, KimchiParamsType::scalar_challenge_size,
                                                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using hash_messages_for_next_wrap_proof_component =
                        hash_messages_for_next_wrap_proof<
                            snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                            KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += batch_dlog_accumulator_check_component::rows_amount;

                        row += kimchi_verify_component::rows_amount;

                        row += BatchSize * WrapChalLen * endo_scalar_component::rows_amount;

                        row += BatchSize * hash_messages_for_next_wrap_proof_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<pickles_instance_type, BatchSize> ts;

                        typename proof_binding::template fr_data<var, BatchSize> fr_data;
                        typename proof_binding::template fq_data<var> fq_data;

                        std::array<var, UrsSize + CommsLen> scalars;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        std::array<var_ec_point, BatchSize> comms;
                        for (std::size_t i = 0; i < BatchSize; ++i) {
                            comms[i] = params.ts[i].proof.statement.proof_state.messages_for_next_wrap_proof
                                             .challenge_polynomial_commitment;
                        }
                        urs_type urs = batch_dlog_accumulator_check_component::generate_circuit(bp, assignment,
                            {comms, params.scalars}, row).output.urs;
                        row += batch_dlog_accumulator_check_component::rows_amount;

                        std::array<std::vector<std::array<var, 15>>, BatchSize>
                            computed_chals_for_next_wrap_proof;

                        for (std::size_t i = 0; i < BatchSize; i++) {
                            assert(params.ts[i].proof.statement.proof_state.messages_for_next_wrap_proof
                                         .old_bulletproof_challenges.size() == WrapChalLen);
                            computed_chals_for_next_wrap_proof[i].resize(WrapChalLen);
                            for (std::size_t j = 0; j < computed_chals_for_next_wrap_proof[0].size(); j++) {
                                for (std::size_t k = 0; k < 15; k++) {
                                    computed_chals_for_next_wrap_proof[i][j][k] =
                                        endo_scalar_component::generate_circuit(
                                            bp, assignment,
                                            {params.ts[i].proof.statement.proof_state.messages_for_next_wrap_proof
                                                   .old_bulletproof_challenges[j][k]},
                                            row)
                                            .output;
                                    row += endo_scalar_component::rows_amount;
                                }
                            }
                        }

                        std::array<var, BatchSize> messages_for_next_wrap_proof;
                        for (std::size_t i = 0; i < BatchSize; i++) {
                            messages_for_next_wrap_proof[i] =
                                hash_messages_for_next_wrap_proof_component::generate_circuit(
                                    bp, assignment,
                                    {WrapChalLen, computed_chals_for_next_wrap_proof[i],
                                     params.ts[i].proof.statement.proof_state
                                           .messages_for_next_wrap_proof.challenge_polynomial_commitment}, row
                                ).output;
                            row += hash_messages_for_next_wrap_proof_component::rows_amount;
                        }

                        /*kimchi_verify_component::generate_circuit(bp, assignment,
                            {proofs, params.ts[0].verifier_index, params.fr_data, params.fq_data}, row);
                        row += kimchi_verify_component::rows_amount;*/

                        assert(row == start_row_index + rows_amount);
                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var_ec_point, BatchSize> comms;
                        for (std::size_t i = 0; i < BatchSize; ++i) {
                            comms[i] = params.ts[i].proof.statement.proof_state.messages_for_next_wrap_proof
                                             .challenge_polynomial_commitment;
                        }
                        urs_type urs = batch_dlog_accumulator_check_component::generate_assignments(assignment,
                            {comms, params.scalars}, row).output.urs;
                        row += batch_dlog_accumulator_check_component::rows_amount;

                        std::array<std::vector<std::array<var, 15>>, BatchSize>
                            computed_chals_for_next_wrap_proof;

                        for (std::size_t i = 0; i < BatchSize; i++) {
                            assert(params.ts[i].proof.statement.proof_state.messages_for_next_wrap_proof
                                         .old_bulletproof_challenges.size() == WrapChalLen);
                            computed_chals_for_next_wrap_proof[i].resize(WrapChalLen);
                            for (std::size_t j = 0; j < computed_chals_for_next_wrap_proof[0].size(); j++) {
                                for (std::size_t k = 0; k < 15; k++) {
                                    computed_chals_for_next_wrap_proof[i][j][k] =
                                        endo_scalar_component::generate_assignments(
                                            assignment,
                                            {params.ts[i].proof.statement.proof_state.messages_for_next_wrap_proof
                                                   .old_bulletproof_challenges[j][k]},
                                            row)
                                            .output;
                                    row += endo_scalar_component::rows_amount;
                                }
                            }
                        }

                        std::array<var, BatchSize> messages_for_next_wrap_proof;
                        for (std::size_t i = 0; i < BatchSize; i++) {
                            messages_for_next_wrap_proof[i] =
                                hash_messages_for_next_wrap_proof_component::generate_assignments(
                                    assignment,
                                    {WrapChalLen, computed_chals_for_next_wrap_proof[i],
                                     params.ts[i].proof.statement.proof_state
                                           .messages_for_next_wrap_proof.challenge_polynomial_commitment}, row
                                ).output;
                            row += hash_messages_for_next_wrap_proof_component::rows_amount;
                        }

                        /*kimchi_verify_component::generate_assignments(assignment,
                            {proofs, params.ts[0].verifier_index, params.fr_data, params.fq_data}, row);
                        row += kimchi_verify_component::rows_amount;*/

                        assert(row == start_row_index + rows_amount);
                        return result_type();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP