//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_HASH_MESSAGES_FOR_NEXT_STEP_PROOF_HPP
#define CRYPTO3_ZK_BLUEPRINT_HASH_MESSAGES_FOR_NEXT_STEP_PROOF_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/app_state.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/verification_key.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>

#include <algorithm>
#include <iostream>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType, std::size_t StateSize,
                         std::size_t ChalLen, std::size_t... WireIndexes>
                class hash_messages_for_next_step_proof;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         typename KimchiParamsType, std::size_t StateSize, std::size_t ChalLen, std::size_t W0,
                         std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13,
                         std::size_t W14>
                class hash_messages_for_next_step_proof<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                                                   KimchiParamsType, StateSize, ChalLen,
                                                   W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using messages_type = typename zk::components::proof_type<
                            BlueprintFieldType, KimchiParamsType>::statement_type::messages_step_type;
                    using app_state_type = zk::components::app_state_bounded_type<BlueprintFieldType,
                                                                                  StateSize>;
                    using commitments_type = typename zk::components::verification_key_type<
                        BlueprintFieldType, KimchiParamsType>::commitments_type;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    // both fr and fq transcript types are parametrised with curve type
                    // the sponge is also parametrised with curve type
                    // we use interface in transcript_fq part
                    // but the component is actually run with fr field logic
                    using transcript_type =
                        kimchi_transcript_fq<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                             W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += transcript_type::init_rows;
                        row += KimchiParamsType::permut_size * transcript_type::absorb_group_rows;
                        row += KimchiParamsType::witness_columns * transcript_type::absorb_group_rows;
                        row += 6 * transcript_type::absorb_group_rows;
                        row += StateSize * transcript_type::absorb_fr_rows;
                        row += ChalLen * (transcript_type::absorb_group_rows + 16 * transcript_type::absorb_fr_rows);
                        row += transcript_type::digest_rows;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        // this component combines hash_messages_for_next_step_proof and a call to
                        // Reduced_messages_for_next_proof_over_same_field.Step.prepare

                        // we use only commitment from this one, prepared challenges are right below
                        messages_type messages;
                        std::vector<std::array<var, 16>> prepared_challenges  =
                            std::vector<std::array<var, 16>>(ChalLen);
                        // app_state has to be passed already transformed to field elements
                        app_state_type app_state;
                        // key.commitments
                        commitments_type commitments;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                            // we rely on curve being vesta here
                            row += rows_amount - mul_component::rows_amount;
                            output = typename mul_component::result_type(row).output;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);
                        std::size_t row = start_row_index;
                        var zero = var(0, row, false, var::column_type::constant);
                        assert(params.prepared_challenges.size() == ChalLen);
                        assert(params.messages.challenge_polynomial_commitments.size() == ChalLen);

                        transcript_type messages_transcript;
                        messages_transcript.init_circuit(bp, assignment, zero, row);
                        // key.commitments
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            messages_transcript.absorb_g_circuit(bp, assignment,
                                params.commitments.sigma[i], row);
                            row += transcript_type::absorb_group_rows;
                        }

                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            messages_transcript.absorb_g_circuit(bp, assignment,
                                params.commitments.coefficient[i], row);
                            row += transcript_type::absorb_group_rows;
                        }

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitments.generic, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitments.psm, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitments.complete_add, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitments.var_base_mul, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitments.endo_mul, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitments.endo_mul_scalar, row);
                        row += transcript_type::absorb_group_rows;
                        // app_state
                        for (std::size_t i = 0; i < StateSize; i++) {
                            messages_transcript.absorb_fr_circuit(bp, assignment, {params.app_state.zkapp_state[i]}, row);
                            row += transcript_type::absorb_fr_rows;
                        }
                        // messages (prepared) challenges and commitments
                        for (std::size_t i = 0; i < params.prepared_challenges.size(); i++) {
                            messages_transcript.absorb_g_circuit(bp, assignment,
                                params.messages.challenge_polynomial_commitments[i], row);
                            row += transcript_type::absorb_group_rows;

                            for (std::size_t j = 0; j < 16; j++) {
                                messages_transcript.absorb_fr_circuit(bp, assignment,
                                    {params.prepared_challenges[i][j]}, row);
                                row += transcript_type::absorb_fr_rows;
                            }
                        }

                        messages_transcript.digest_circuit(bp, assignment, row);
                        row += transcript_type::digest_rows;

                        assert(row == start_row_index + rows_amount);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        var zero = var(0, row, false, var::column_type::constant);
                        assert(params.prepared_challenges.size() == ChalLen);
                        assert(params.messages.challenge_polynomial_commitments.size() == ChalLen);

                        transcript_type messages_transcript;
                        messages_transcript.init_assignment(assignment, zero, row);

                        // key.commitments
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            messages_transcript.absorb_g_assignment(
                                assignment, params.commitments.sigma[i], row);
                            row += transcript_type::absorb_group_rows;
                        }

                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            messages_transcript.absorb_g_assignment(
                                assignment, params.commitments.coefficient[i], row);
                            row += transcript_type::absorb_group_rows;
                        }

                        messages_transcript.absorb_g_assignment(assignment, params.commitments.generic, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_assignment(assignment, params.commitments.psm, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_assignment(assignment, params.commitments.complete_add, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_assignment(assignment, params.commitments.var_base_mul, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_assignment(assignment, params.commitments.endo_mul, row);
                        row += transcript_type::absorb_group_rows;

                        messages_transcript.absorb_g_assignment(assignment, params.commitments.endo_mul_scalar, row);
                        row += transcript_type::absorb_group_rows;
                        // app_state
                        for (std::size_t i = 0; i < StateSize; i++) {
                            messages_transcript.absorb_fr_assignment(assignment, {params.app_state.zkapp_state[i]}, row);
                            row += transcript_type::absorb_fr_rows;
                        }
                        // messages (prepared) challenges and commitments
                        for (std::size_t i = 0; i < params.prepared_challenges.size(); i++) {
                            messages_transcript.absorb_g_assignment(assignment,
                                params.messages.challenge_polynomial_commitments[i], row);
                            row += transcript_type::absorb_group_rows;

                            for (std::size_t j = 0; j < 16; j++) {
                                messages_transcript.absorb_fr_assignment(assignment,
                                    {params.prepared_challenges[i][j]}, row);
                                row += transcript_type::absorb_fr_rows;
                            }
                        }

                        messages_transcript.digest_assignment(assignment, row);
                        row += transcript_type::digest_rows;

                        assert(row == start_row_index + rows_amount);
                        return result_type(start_row_index);
                    }

                private:

                    static void generate_assignments_constant(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row++] = 0;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_HASH_MESSAGES_FOR_NEXT_STEP_PROOF_HPP