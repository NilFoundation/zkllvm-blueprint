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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_COMBINE_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_COMBINE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/environment.hpp>

#include <limits>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename ArithmetizationType, typename CurveType, std::size_t ChalAmount,
                         typename KimchiParamsType, std::size_t... WireIndexes>
                class combine;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t ChalAmount, typename KimchiParamsType, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class combine<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                                                             ChalAmount, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using kimchi_proof_evaluations = zk::components::kimchi_proof_evaluations<BlueprintFieldType,
                                                                                              KimchiParamsType>;
                    using environment_type = zk::components::kimchi_environment<BlueprintFieldType, KimchiParamsType>;
                    using plonk_type = pickles_plonk_min<ArithmetizationType>;

                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using b_poly_component = zk::components::b_poly<ArithmetizationType, 16,
                                                                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using evals_type = typename zk::components::proof_type<BlueprintFieldType, KimchiParamsType>
                                                              ::prev_evals_type::evals_type;
                    using proof_evals_type = zk::components::kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;

                        row += ChalAmount * b_poly_component::rows_amount;
                        row += (items_size - 1) * (mul_component::rows_amount + add_component::rows_amount);

                        return row;
                    }

                    constexpr static const std::size_t items_amount() {
                        std::size_t res = 0;
                        std::size_t split_size = KimchiParamsType::split_size;
                        // challenges
                        res += ChalAmount;
                        // public_input
                        res += 1;
                        // ft
                        res += 1;
                        // z
                        res += split_size;
                        // generic_selector
                        res += split_size;
                        // poseidon_selector
                        res += split_size;
                        // w
                        res += split_size * KimchiParamsType::witness_columns;
                        // s
                        res += split_size * (KimchiParamsType::permut_size - 1);
                        // lookup
                        if (KimchiParamsType::use_lookup) {
                            // sorted
                            res += split_size * KimchiParamsType::circuit_params::lookup_columns;
                            // aggreg
                            res += split_size;
                            // table
                            res += split_size;
                            // runtime
                            if (KimchiParamsType::lookup_runtime) {
                                res += split_size;
                            }
                        }

                        return res;
                    }

                public:
                    constexpr static const std::size_t items_size = items_amount();

                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::vector<std::array<var, 16>> old_bulletproof_challenges =
                            std::vector<std::array<var, 16>>(ChalAmount);
                        evals_type prev_evals;
                        std::size_t eval_idx;
                        var ft;
                        var pt;
                        var xi;
                    };

                    struct result_type {
                        var output;

                        result_type(const std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            row += rows_amount;
                            output = typename add_component::result_type(
                                row - add_component::rows_amount).output;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        assert(params.eval_idx == 0 || params.eval_idx == 1);
                        generate_assignments_constant(assignment, params, start_row_index);
                        var one = var(0, row, false, var::column_type::constant);

                        std::array<var, items_size> items;
                        std::size_t idx = 0;
                        for (std::size_t i = 0; i < ChalAmount; i++) {
                            assert(params.old_bulletproof_challenges.size() == ChalAmount);
                            items[idx] = b_poly_component::generate_circuit(
                                bp, assignment,
                                {
                                    const_cast<std::array<var, 16>&>(params.old_bulletproof_challenges[i]),
                                    params.pt,
                                    one
                                }, row).output;
                            row += b_poly_component::rows_amount;
                            idx++;
                        }
                        items[idx] = params.prev_evals.public_input[params.eval_idx];
                        idx++;
                        items[idx] = params.ft;
                        idx++;
                        std::array<proof_evals_type, KimchiParamsType::split_size> eval =
                            params.prev_evals.evals[params.eval_idx];
                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = eval[j].z;
                            idx++;
                        }

                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = eval[j].generic_selector;
                            idx++;
                        }

                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = eval[j].poseidon_selector;
                            idx++;
                        }

                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].w[i];
                                idx++;
                            }
                        }

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].s[i];
                                idx++;
                            }
                        }

                        if (KimchiParamsType::use_lookup) {
                            for (size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                                for (size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                    items[idx] = eval[j].lookup.sorted[i];
                                    idx++;
                                }
                            }

                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].lookup.aggreg;
                                idx++;
                            }
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].lookup.table;
                                idx++;
                            }

                            if (KimchiParamsType::lookup_runtime) {
                                for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                    items[idx] = eval[j].lookup.runtime;
                                    idx++;
                                }
                            }
                        }
                        assert(idx == items_size);

                        var acc = items.back();
                        for (size_t i = items_size - 2; i != std::numeric_limits<size_t>::max(); i--) {
                            acc = zk::components::generate_circuit<mul_component>(
                                bp, assignment, {params.xi, acc}, row).output;
                            row += mul_component::rows_amount;
                            acc = zk::components::generate_circuit<add_component>(
                                bp, assignment, {items[i], acc}, row).output;
                            row += add_component::rows_amount;
                        }

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        assert(params.eval_idx == 0 || params.eval_idx == 1);
                        var one = var(0, row, false, var::column_type::constant);

                        std::array<var, items_size> items;
                        std::size_t idx = 0;
                        for (std::size_t i = 0; i < ChalAmount; i++) {
                            assert(params.old_bulletproof_challenges.size() == ChalAmount);
                            items[idx] = b_poly_component::generate_assignments(
                                assignment,
                                {
                                    const_cast<std::array<var, 16>&>(params.old_bulletproof_challenges[i]),
                                    params.pt,
                                    one
                                }, row).output;
                            row += b_poly_component::rows_amount;
                            idx++;
                        }
                        items[idx] = params.prev_evals.public_input[params.eval_idx];
                        idx++;
                        items[idx] = params.ft;
                        idx++;
                        std::array<proof_evals_type, KimchiParamsType::split_size> eval =
                            params.prev_evals.evals[params.eval_idx];
                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = eval[j].z;
                            idx++;
                        }

                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = eval[j].generic_selector;
                            idx++;
                        }

                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = eval[j].poseidon_selector;
                            idx++;
                        }

                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].w[i];
                                idx++;
                            }
                        }

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].s[i];
                                idx++;
                            }
                        }

                        if (KimchiParamsType::use_lookup) {
                            for (size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                                for (size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                    items[idx] = eval[j].lookup.sorted[i];
                                    idx++;
                                }
                            }

                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].lookup.aggreg;
                                idx++;
                            }
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = eval[j].lookup.table;
                                idx++;
                            }

                            if (KimchiParamsType::lookup_runtime) {
                                for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                    items[idx] = eval[j].lookup.runtime;
                                    idx++;
                                }
                            }
                        }
                        assert(idx == items_size);

                        var acc = items.back();
                        for (size_t i = items_size - 2; i != std::numeric_limits<size_t>::max(); i--) {
                            acc = mul_component::generate_assignments(
                                assignment, {params.xi, acc}, row).output;
                            row += mul_component::rows_amount;
                            acc = add_component::generate_assignments(
                                assignment, {items[i], acc}, row).output;
                            row += add_component::rows_amount;
                        }

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    private:

                    static void generate_assignments_constant(
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        size_t row = component_start_row;
                        assignment.constant(0)[row] = 1;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_COMBINE_HPP
