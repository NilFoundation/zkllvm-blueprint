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

#ifndef BLUEPRINT_MC_PLONK_KIMCHI_DETAIL_TABLE_COMMITMENT_HPP
#define BLUEPRINT_MC_PLONK_KIMCHI_DETAIL_TABLE_COMMITMENT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/component.hpp>

#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/types/commitment.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint_mc/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>

#include <nil/blueprint_mc/algorithms/generate_circuit.hpp>

namespace nil {
    namespace blueprint_mc {
        namespace components {

            // Compute Lookup Table commitment
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L830
            // Input: 
            // Output: 
            template<typename ArithmetizationType, 
                typename KimchiParamsType, typename CurveType,
                std::size_t... WireIndexes>
            class table_commitment;

            template<typename BlueprintFieldType,
                        typename ArithmetizationParams,
                        typename KimchiParamsType,
                        typename CurveType,
                        std::size_t W0,
                        std::size_t W1,
                        std::size_t W2,
                        std::size_t W3,
                        std::size_t W4,
                        std::size_t W5,
                        std::size_t W6,
                        std::size_t W7,
                        std::size_t W8,
                        std::size_t W9,
                        std::size_t W10,
                        std::size_t W11,
                        std::size_t W12,
                        std::size_t W13,
                        std::size_t W14>
            class table_commitment<
                nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                KimchiParamsType,
                CurveType,
                W0,
                W1,
                W2,
                W3,
                W4,
                W5,
                W6,
                W7,
                W8,
                W9,
                W10,
                W11,
                W12,
                W13,
                W14> {

                typedef nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
                using var_ec_point = typename components::var_ec_point<BlueprintFieldType>;

                constexpr static const std::size_t lookup_columns = KimchiParamsType::circuit_params::lookup_columns;

                constexpr static const std::size_t use_lookup_runtime = KimchiParamsType::circuit_params::lookup_runtime ? 1 : 0; 

                constexpr static const std::size_t split_size = KimchiParamsType::commitment_params_type::shifted_commitment_split;

                constexpr static const std::size_t msm_size = (lookup_columns + use_lookup_runtime) * split_size; 

                using commitment_type = typename 
                    components::kimchi_commitment_type<BlueprintFieldType, split_size>;
                using msm_component = components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType,  
                    msm_size,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

            public:
                constexpr static const std::size_t rows_amount = msm_component::rows_amount;
                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    std::vector<commitment_type> table;
                    std::array<var, lookup_columns> joint_combiner;
                    commitment_type runtime;
                };

                struct result_type {
                    var_ec_point output;

                    result_type(std::size_t start_row_index) {
                        assert (msm_size > 1); // output of add_component. For msm_size = 1 change to output of mul_component 
                        output.X = var(W4, start_row_index + rows_amount - 1, false, var::column_type::witness);
                        output.Y = var(W5, start_row_index + rows_amount - 1, false, var::column_type::witness);
                    }
                };

                static result_type
                    generate_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &params,
                                        const std::size_t start_row_index) {

                    generate_assignments_constants(bp, assignment, params, start_row_index);

                    std::size_t row = start_row_index;
                    std::array<var_ec_point, msm_size> commitments;
                    std::array<var, msm_size> scalars;
                    std::size_t j = 0;
                    for(std::size_t i = j; i < lookup_columns; i++) {
                        for (std::size_t k = 0; k < split_size; k++) {
                            commitments[i*split_size + k] = params.table[i].parts[k];
                            scalars[i*split_size + k] = params.joint_combiner[i];
                            j++;
                        }
                    }
                    if (KimchiParamsType::circuit_params::lookup_runtime) {
                        for (std::size_t k = 0; k < split_size; k++) {
                            commitments[j] = params.runtime.parts[k];
                            scalars[j] = params.joint_combiner[1];
                            j++;
                        }       
                    }
                    std::vector<var> scalars_vec = std::vector<var>(scalars.begin(), scalars.end());
                    std::vector<var_ec_point> commitments_vec = std::vector<var_ec_point>(commitments.begin(), commitments.end());
                    msm_component::generate_circuit(bp, assignment, {scalars_vec, commitments_vec}, row);
                    return result_type(row);
                }

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t start_row_index) {

                    std::size_t row = start_row_index;
                    std::array<var_ec_point, msm_size> commitments;
                    std::array<var, msm_size> scalars;
                    std::size_t j = 0;
                    for(std::size_t i = j; i < lookup_columns; i++) {
                        for (std::size_t k = 0; k < split_size; k++) {
                            commitments[i*split_size + k] = params.table[i].parts[k];
                            scalars[i*split_size + k] = params.joint_combiner[i];
                            j++;
                        }
                    }
                    if (KimchiParamsType::circuit_params::lookup_runtime) {
                        for (std::size_t k = 0; k < split_size; k++) {
                            commitments[j] = params.runtime.parts[k];
                            scalars[j] = params.joint_combiner[1];
                            j++;
                        }       
                    }
                    std::vector<var> scalars_vec = std::vector<var>(scalars.begin(), scalars.end());
                    std::vector<var_ec_point> commitments_vec = std::vector<var_ec_point>(commitments.begin(), commitments.end());
                    msm_component::generate_assignments(assignment, {scalars_vec, commitments_vec}, row);
                    return result_type(row);
                }

            private:
                static void generate_gates(blueprint<ArithmetizationType> &bp,
                                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                            const params_type &params,
                                            const std::size_t first_selector_index) {
                }

                static void
                    generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                const params_type &params,
                                                const std::size_t start_row_index) {
                }

                static void generate_assignments_constants(
                    blueprint<ArithmetizationType> &bp,
                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                    const params_type &params,
                    const std::size_t start_row_index) {
                    std::size_t row = start_row_index;
                }
            };
        }    // namespace components
    }    // namespace blueprint_mc
}    // namespace nil

#endif    // BLUEPRINT_MC_PLONK_KIMCHI_DETAIL_TABLE_COMMITMENT_HPP