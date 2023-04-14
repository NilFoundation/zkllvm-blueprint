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

#ifndef CRYPTO3_ZK_BLUEPRINT_HASH_MESSAGES_FOR_NEXT_WRAP_PROOF_HPP
#define CRYPTO3_ZK_BLUEPRINT_HASH_MESSAGES_FOR_NEXT_WRAP_PROOF_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/app_state.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/verification_key.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/details/dummy_generator.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <algorithm>
#include <iostream>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                         std::size_t... WireIndexes>
                class hash_messages_for_next_wrap_proof;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         typename KimchiParamsType, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class hash_messages_for_next_wrap_proof<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, KimchiParamsType,
                                                   W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    using messages_type = typename zk::components::proof_type<
                            BlueprintFieldType, KimchiParamsType>::statement_type::messages_step_type;
                    using commitments_type = typename zk::components::verification_key_type<
                        BlueprintFieldType, KimchiParamsType>::commitments_type;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    using transcript_type =
                        zk::components::kimchi_transcript_fq<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                             W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using dummy_type = zk::components::dummy_generator<CurveType>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += transcript_type::init_rows;
                        row += 2 * 15 * transcript_type::absorb_fr_rows;
                        row += transcript_type::absorb_group_rows;
                        row += transcript_type::digest_rows;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        // because the padding is static and the padded size is constant
                        // we are able treat the actual amount of passed challenges as a circuit parameter
                        std::size_t chal_len;
                        std::vector<std::array<var, 15>> prepared_challenges;
                        var_ec_point commitment;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);
                        assert(params.chal_len <= 2);
                        assert(params.prepared_challenges.size() == params.chal_len);

                        std::size_t row = start_row_index;
                        var zero = var(0, row, false, var::column_type::constant);
                        result_type result;

                        std::array<std::array<var, 15>, 2> padded_challenges;
                        std::size_t padding_size = 2 - params.chal_len;
                        std::array<var, 15> padding;
                        for (std::size_t i = 0; i < 15; i++) {
                            padding[i] = var(0, row + i, false, var::column_type::constant);
                        }

                        for (std::size_t i = 0; i < padding_size; i++) {
                            std::copy(padding.begin(),
                                      padding.end(),
                                      padded_challenges[i].begin());
                        }
                        for (std::size_t i = padding_size; i < 2; i++) {
                            std::copy(params.prepared_challenges[i - padding_size].begin(),
                                      params.prepared_challenges[i - padding_size].end(),
                                      padded_challenges[i].begin());
                        }

                        transcript_type messages_transcript;
                        messages_transcript.init_circuit(bp, assignment, zero, row);
                        row += transcript_type::init_rows;

                        for (std::size_t i = 0; i < 2; i++) {
                            for (std::size_t j = 0; j < 15; j++) {
                                messages_transcript.absorb_fr_circuit(bp, assignment,
                                    {padded_challenges[i][j]}, row);
                                row += transcript_type::absorb_fr_rows;
                            }
                        }

                        messages_transcript.absorb_g_circuit(bp, assignment, params.commitment, row);
                        row += transcript_type::absorb_group_rows;

                        result.output = messages_transcript.digest_circuit(bp, assignment, row);
                        row += transcript_type::digest_rows;

                        assert(row == start_row_index + rows_amount);
                        return result;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        assert(params.chal_len <= 2);
                        assert(params.prepared_challenges.size() == params.chal_len);

                        std::size_t row = start_row_index;
                        var zero = var(0, row, false, var::column_type::constant);
                        result_type result;

                        std::array<std::array<var, 15>, 2> padded_challenges;
                        std::size_t padding_size = 2 - params.chal_len;
                        std::array<var, 15> padding;
                        for (std::size_t i = 0; i < 15; i++) {
                            padding[i] = var(0, row + i, false, var::column_type::constant);
                        }

                        for (std::size_t i = 0; i < padding_size; i++) {
                            std::copy(padding.begin(),
                                      padding.end(),
                                      padded_challenges[i].begin());
                        }
                        for (std::size_t i = padding_size; i < 2; i++) {
                            std::copy(params.prepared_challenges[i - padding_size].begin(),
                                      params.prepared_challenges[i - padding_size].end(),
                                      padded_challenges[i].begin());
                        }

                        transcript_type messages_transcript;
                        messages_transcript.init_assignment(assignment, zero, row);
                        row += transcript_type::init_rows;

                        for (std::size_t i = 0; i < 2; i++) {
                            for (std::size_t j = 0; j < 15; j++) {
                                messages_transcript.absorb_fr_assignment(assignment,
                                    {padded_challenges[i][j]}, row);
                                row += transcript_type::absorb_fr_rows;
                            }
                        }

                        messages_transcript.absorb_g_assignment(assignment, params.commitment, row);
                        row += transcript_type::absorb_group_rows;

                        result.output =  messages_transcript.digest_assignment(assignment, row);
                        row += transcript_type::digest_rows;

                        assert(row == start_row_index + rows_amount);
                        return result;
                    }

                private:

                    static void generate_assignments_constant(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row++] = 0;

                        dummy_type dummy;
                        for (std::size_t i = 0; i < 15; i++) {
                            assignment.constant(0)[row++] = dummy.computed_challenges[i];
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_HASH_MESSAGES_FOR_NEXT_WRAP_PROOF_HPP