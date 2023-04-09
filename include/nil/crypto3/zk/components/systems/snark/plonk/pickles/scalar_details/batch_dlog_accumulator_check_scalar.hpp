//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the BATCH_VERIFY_SCALAR_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_BATCH_DLOG_ACCUMULATOR_CHECK_SCALAR_HPP
#define CRYPTO3_ZK_BLUEPRINT_BATCH_DLOG_ACCUMULATOR_CHECK_SCALAR_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/combined_inner_product.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/random.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly_coefficients.hpp>

#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/f01d3925a273ded939a80e1de9afcd9f913a7c17/src/lib/crypto/kimchi_bindings/stubs/src/urs_utils.rs#L10
                template<typename ArithmetizationType, typename CurveType,
                        std::size_t CommsLen, std::size_t EvalRounds,
                         std::size_t... WireIndexes>
                class batch_dlog_accumulator_check_scalar;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t CommsLen, std::size_t EvalRounds,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class batch_dlog_accumulator_check_scalar<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                    CommsLen, EvalRounds, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2, W3>;

                    constexpr static const std::size_t challenges_len = CommsLen * EvalRounds;
                    constexpr static const std::size_t urs_size = 1 << EvalRounds;
                    constexpr static const std::size_t scalars_len() {
                        return CommsLen + urs_size;
                    }

                    using b_poly_coeff_component =
                        zk::components::b_poly_coefficients<ArithmetizationType,
                                                            EvalRounds, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using prepare_scalars_component =
                        zk::components::prepare_scalars<ArithmetizationType, CurveType, scalars_len(), W0, W1, W2, W3, W4,
                                                        W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += (CommsLen - 1) * mul_component::rows_amount;

                        row += CommsLen * EvalRounds * div_component::rows_amount;

                        row += CommsLen * b_poly_coeff_component::rows_amount;
                        row += (CommsLen - 1) * b_poly_coeff_component::polynomial_len * mul_component::rows_amount;

                        row += CommsLen * urs_size * sub_component::rows_amount;

                        row += prepare_scalars_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t output_len = scalars_len();

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<std::array<var, EvalRounds>, CommsLen> challenges;
                        var rand_base;
                    };

                    struct result_type {
                        std::array<var, output_len> output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                            row += rows_amount - prepare_scalars_component::rows_amount;
                            std::vector<var> output_vec = typename prepare_scalars_component::result_type(row).output;
                            assert(output_vec.size() == output_len);
                            std::copy(output_vec.begin(), output_vec.end(), output.begin());
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);
                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::vector<var> scalars;
                        scalars.resize(output_len);

                        for (std::size_t i = 0; i < urs_size; i++) {
                            scalars[i] = zero;
                        }
                        std::size_t scalar_idx = urs_size;

                        var rand_base = params.rand_base,
                            rand_base_i = params.rand_base;
                        std::array<var, CommsLen> rs;
                        rs[0] = one;
                        scalars[scalar_idx++] = one;
                        for (std::size_t i = 1; i < CommsLen; i++) {
                            rs[i] = scalars[scalar_idx++] = rand_base_i;

                            rand_base_i =
                                zk::components::generate_circuit<mul_component>(
                                    bp, assignment, {rand_base_i, rand_base}, row).output;
                            row += mul_component::rows_amount;
                        }
                        assert(scalar_idx == output_len);

                        std::array<std::array<var, EvalRounds>, CommsLen> challenges_inv;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            for (std::size_t j = 0; j < EvalRounds; j++) {
                                challenges_inv[i][j] = zk::components::generate_circuit<div_component>(
                                    bp, assignment, {one, params.challenges[i][j]}, row)
                                    .output;
                                row += div_component::rows_amount;
                            }
                        }

                        std::array<std::array<var, urs_size>, CommsLen> termss;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            auto s = b_poly_coeff_component::generate_circuit(
                                bp, assignment,
                                {const_cast<std::array<var, EvalRounds>&>
                                 (challenges_inv[i]), one}, row)
                                .output;
                            row += b_poly_coeff_component::rows_amount;

                            for (std::size_t j = 0; j < s.size(); j++) {
                                // in Mina urs_size is 2^16, we save 2^16 multiplications
                                // by skipping multiplication when rs[0] = 1
                                if (i != 0) {
                                    s[j] = zk::components::generate_circuit<mul_component>(
                                        bp, assignment, {s[j], rs[i]}, row)
                                        .output;
                                    row += mul_component::rows_amount;
                                }
                                termss[i][j] = s[j];
                            }
                        }

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            for (std::size_t j = 0; j < urs_size; j++) {
                                scalars[j] = zk::components::generate_circuit<sub_component>(
                                    bp, assignment, {scalars[j], termss[i][j]}, row).output;
                                row += sub_component::rows_amount;
                            }
                        }
                        // output
                        prepare_scalars_component::generate_circuit(
                            bp, assignment, {scalars}, row);
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::vector<var> scalars;
                        scalars.resize(output_len);

                        for (std::size_t i = 0; i < urs_size; i++) {
                            scalars[i] = zero;
                        }
                        std::size_t scalar_idx = urs_size;

                        var rand_base = params.rand_base,
                            rand_base_i = params.rand_base;
                        std::array<var, CommsLen> rs;
                        rs[0] = one;
                        scalars[scalar_idx++] = one;
                        for (std::size_t i = 1; i < CommsLen; i++) {
                            scalars[scalar_idx++] = rs[i] = rand_base_i;

                            rand_base_i = mul_component::generate_assignments(
                                assignment, {rand_base_i, rand_base}, row).output;
                            row += mul_component::rows_amount;
                        }
                        assert(scalar_idx == output_len);

                        std::array<std::array<var, EvalRounds>, CommsLen> challenges_inv;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            for (std::size_t j = 0; j < EvalRounds; j++) {
                                challenges_inv[i][j] = div_component::generate_assignments(
                                    assignment, {one, params.challenges[i][j]}, row)
                                    .output;
                                row += div_component::rows_amount;
                            }
                        }

                        std::array<std::array<var, urs_size>, CommsLen> termss;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            auto s = b_poly_coeff_component::generate_assignments(
                                assignment,
                                {const_cast<std::array<var, EvalRounds>&>
                                 (challenges_inv[i]), one}, row)
                                .output;
                            row += b_poly_coeff_component::rows_amount;

                            for (std::size_t j = 0; j < s.size(); j++) {
                                // in Mina urs_size is 2^16, we save 2^16 multiplications
                                // by skipping multiplication when rs[0] = 1
                                if (i != 0) {
                                    s[j] = mul_component::generate_assignments(
                                        assignment, {s[j], rs[i]}, row)
                                        .output;
                                    row += mul_component::rows_amount;
                                }
                                termss[i][j] = s[j];
                            }
                        }

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            for (std::size_t j = 0; j < urs_size; j++) {
                                scalars[j] = sub_component::generate_assignments(
                                    assignment, {scalars[j], termss[i][j]}, row).output;
                                row += sub_component::rows_amount;
                            }
                        }
                        // output
                        prepare_scalars_component::generate_assignments(
                            assignment, {scalars}, row);
                        row += prepare_scalars_component::rows_amount;

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
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_BATCH_DLOG_ACCUMULATOR_CHECK_SCALAR_HPP