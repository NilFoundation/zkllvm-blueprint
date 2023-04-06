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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/force_equality.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/urs_generator.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/urs.hpp>

#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace zk {
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
                class batch_dlog_accumulator_check_base<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                              CurveType, KimchiParamsType, CommSize, UrsSize, W0,
                                              W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t final_msm_size = UrsSize + CommSize;

                    using msm_component =
                        zk::components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType, final_msm_size, W0,
                                                                    W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                                                    W13, W14>;

                    using internal_scalar_mul_component =
                        zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;

                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
                    using urs_value_type = typename zk::components::urs<CurveType, UrsSize>;
                    using urs_var_type = typename zk::components::var_urs<BlueprintFieldType, UrsSize>;

                    using force_equality_component = zk::components::force_equality<ArithmetizationType>;

                    constexpr static std::size_t msm_internal_rows =
                        internal_scalar_mul_component::rows_amount + add_component::rows_amount;

                    constexpr static inline bool check_offset(std::size_t start_row_index, std::size_t offset) {
                        const std::size_t bad_offset = (start_row_index + 1) % msm_internal_rows;
                        return (bad_offset != offset % msm_internal_rows);
                    }

                    static var_ec_point load_g_point(std::size_t start_row_index, std::size_t index) {
                        // skipping 1 for the first zero and 2 for h
                        std::size_t first_g_row = start_row_index + 3;
                        std::size_t points_to_skip = (index + 2) / msm_internal_rows;
                        std::size_t row = first_g_row + points_to_skip * msm_internal_rows;

                        var x = var(0, row++, false, var::column_type::constant);
                        row += !check_offset(start_row_index, row);
                        var y = var(0, row++, false, var::column_type::constant);
                        return var_ec_point({x, y});
                    }

                    static var_ec_point load_h_point(std::size_t start_row_index) {
                        std::size_t row = start_row_index + 1;

                        var x = var(0, row++, false, var::column_type::constant);
                        row += !check_offset(start_row_index, row);
                        var y = var(0, row++, false, var::column_type::constant);
                        return var_ec_point({x, y});
                    }

                public:
                    constexpr static const std::size_t rows_amount = msm_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<var_ec_point, CommSize> comms;
                        std::array<var, final_msm_size> scalars;
                    };

                    struct result_type {
                        urs_var_type urs;
                        var_ec_point _debug_msm_result;
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        result_type result;

                        std::vector<var_ec_point> bases(final_msm_size);
                        std::size_t bases_idx = 0;

                        for (std::size_t i = 0; i < UrsSize; i++) {
                            result.urs.g[i] = bases[bases_idx++] = load_g_point(start_row_index, i);
                        }
                        result.urs.h = load_h_point(start_row_index);

                        for (std::size_t i = 0; i < params.comms.size(); i++) {
                            bases[bases_idx++] = params.comms[i];
                        }

                        assert(bases_idx == final_msm_size);

                        std::vector<var> msm_params_scalar;
                        msm_params_scalar.reserve(params.scalars.size());
                        std::copy(params.scalars.begin(), params.scalars.end(), std::back_inserter(msm_params_scalar));
                        auto res =
                            msm_component::generate_assignments(assignment, {msm_params_scalar, bases}, row)
                                .output;
                        row += msm_component::rows_amount;
                        result._debug_msm_result = res;

                        force_equality_component::generate_assignments(assignment, {res.X, zero}, row);
                        force_equality_component::generate_assignments(assignment, {res.Y, zero}, row);

                        assert(row == start_row_index + rows_amount);
                        return result;
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        result_type result;

                        std::vector<var_ec_point> bases(final_msm_size);
                        std::size_t bases_idx = 0;

                        for (std::size_t i = 0; i < UrsSize; i++) {
                            result.urs.g[i] = bases[bases_idx++] = load_g_point(start_row_index, i);
                        }
                        result.urs.h = load_h_point(start_row_index);

                        for (std::size_t i = 0; i < params.comms.size(); i++) {
                            bases[bases_idx++] = params.comms[i];
                        }

                        assert(bases_idx == final_msm_size);

                        std::vector<var> msm_params_scalar;
                        msm_params_scalar.reserve(params.scalars.size());
                        std::copy(params.scalars.begin(), params.scalars.end(), std::back_inserter(msm_params_scalar));
                        auto res =
                            msm_component::generate_circuit(bp, assignment, {msm_params_scalar, bases}, row)
                                .output;
                        row += msm_component::rows_amount;
                        result._debug_msm_result = res;

                        force_equality_component::generate_circuit(bp, assignment, {res.X, zero}, row);
                        force_equality_component::generate_circuit(bp, assignment, {res.Y, zero}, row);

                        assert(row == start_row_index + rows_amount);
                        return result;
                    }

                    static void generate_assignments_constant(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        // urs_value_type is constant, but might be big
                        // we need to carefully place it in order to dodge msm constants
                        // this is done manually and is going to break if msm_component is changed
                        urs_value_type urs = urs_value_type::generate_mina_urs();
                        // this zero overlaps with a zero in msm
                        assignment.constant(0)[row++] = 0;
                        auto save_point = [component_start_row, &assignment]
                                            (const typename CurveType::template
                                                g1_type<algebra::curves::coordinates::affine>::value_type&p,
                                            std::size_t &row) {
                            // branchless wherever possible: this code is hot
                            row += !check_offset(component_start_row, row);
                            assignment.constant(0)[row++] = p.X;
                            row += !check_offset(component_start_row, row);
                            assignment.constant(0)[row++] = p.Y;
                        };
                        save_point(urs.h, row);
                        for (std::size_t i = 0; i < UrsSize; i++) {
                            save_point(urs.g[i], row);
                        }
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_BASE_DETAILS_BATCH_DGLOG_ACCUMULATOR_CHECK_BASE_HPP