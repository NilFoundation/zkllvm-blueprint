//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_BASE_DETAILS_BATCH_DGLOG_ACCUMULATOR_CHECK_BASE_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_BASE_DETAILS_BATCH_DGLOG_ACCUMULATOR_CHECK_BASE_HPP

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/assignment/plonk.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/types/commitment.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/detail/to_group.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint_mc/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint_mc/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/blueprint_mc/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>

namespace nil {
    namespace blueprint_mc {
        namespace components {

            // https://github.com/MinaProtocol/mina/blob/f01d3925a273ded939a80e1de9afcd9f913a7c17/src/lib/crypto/kimchi_bindings/stubs/src/urs_utils.rs#L10
            template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                        std::size_t CommSize, std::size_t UrsSize, std::size_t... WireIndexes>
            class batch_dlog_accumulator_check_base; // TODO: move UrsSize, CommSize to KimchiParamsType

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                        typename KimchiParamsType, std::size_t CommSize, std::size_t UrsSize,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                        std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                        std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
            class batch_dlog_accumulator_check_base<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                            CurveType, KimchiParamsType, CommSize, UrsSize, W0,
                                            W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                typedef nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
                using sub_component = components::subtraction<ArithmetizationType, W0, W1, W2>;

                using kimchi_constants = components::kimchi_inner_constants<KimchiParamsType>;
                using KimchiCommitmentParamsType = typename KimchiParamsType::commitment_params_type;

                constexpr static const std::size_t final_msm_size = UrsSize + CommSize;

                using msm_component =
                    components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType, final_msm_size, W0,
                                                                W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                                                W13, W14>;

                using to_group_component = components::to_group<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                    W7, W8, W9, W10, W11, W12, W13, W14>;

                using var_ec_point = typename components::var_ec_point<BlueprintFieldType>;

                using opening_proof_type =
                    typename components::kimchi_opening_proof_base<BlueprintFieldType,
                                                                        KimchiCommitmentParamsType::eval_rounds>;

                using batch_proof_type = typename components::batch_evaluation_proof_base<
                    BlueprintFieldType, ArithmetizationType, KimchiParamsType, KimchiCommitmentParamsType>;

                using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;

                using proof_binding =
                    typename components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5,
                                                                W6, W7, W8, W9, W10, W11, W12, W13, W14>;

            public:
                constexpr static const std::size_t rows_amount = msm_component::rows_amount;

                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    std::vector<var_ec_point> comms;
                    std::vector<var> scalars;
                    std::vector<var_ec_point> urs;
                };

                struct result_type {

                    result_type(std::size_t start_row_index) {
                    }
                };

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t start_row_index) {
                    std::size_t row = start_row_index;

                    assert(params.comms.size() == CommSize);
                    assert(params.urs.size() == UrsSize);

                    std::vector<var_ec_point> bases(final_msm_size);

                    std::size_t bases_idx = 0;

                    for (std::size_t i = 0; i < params.urs.size(); i++) {
                        bases[bases_idx++] = params.urs[i];
                    }

                    for (std::size_t i = 0; i < params.comms.size(); i++) {
                        bases[bases_idx++] = params.comms[i];
                    }

                    assert(bases_idx == final_msm_size);

                    auto res =
                        msm_component::generate_assignments(assignment, {params.scalars, bases}, row)
                            .output;
                    row += msm_component::rows_amount;

                    assert(row == start_row_index + rows_amount);
                    return result_type(start_row_index);
                }

                static result_type
                    generate_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &params,
                                        const std::size_t start_row_index) {
                    std::size_t row = start_row_index;

                    assert(params.comms.size() == CommSize);
                    assert(params.urs.size() == UrsSize);

                    std::vector<var_ec_point> bases(final_msm_size);

                    std::size_t bases_idx = 0;

                    for (std::size_t i = 0; i < params.urs.size(); i++) {
                        bases[bases_idx++] = params.urs[i];
                    }

                    for (std::size_t i = 0; i < params.comms.size(); i++) {
                        bases[bases_idx++] = params.comms[i];
                    }

                    assert(bases_idx == final_msm_size);

                    auto res =
                        msm_component::generate_circuit(bp, assignment, {params.scalars, bases}, row)
                            .output;
                    row += msm_component::rows_amount;

                    assert(row == start_row_index + rows_amount);
                    return result_type(start_row_index);
                }
            };

        }    // namespace components
    }            // namespace blueprint_mc
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_BASE_DETAILS_BATCH_DGLOG_ACCUMULATOR_CHECK_BASE_HPP