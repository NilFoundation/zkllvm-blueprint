//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_ALGEBRA_FIELDS_ELEMENT_POWERS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_ALGEBRA_FIELDS_ELEMENT_POWERS_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // for (base, n) calculates [base^0, base^1, ..., base^n]
                template<typename ArithmetizationParams, typename BlueprintFieldType, std::size_t n, std::size_t... WireIndexes>
                class element_powers;

                template<typename ArithmetizationParams,
                         typename BlueprintFieldType,
                         std::size_t n,
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
                class element_powers<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType,
                    n,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0fff;

                public:
                    // we take at least one row for constant (1)
                    constexpr static const std::size_t rows_amount = (n <= 1) ? 1 : (n - 1) * mul_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var base;
                    };

                    struct result_type {
                        std::vector<var> output;

                        result_type(const params_type &params,
                                    const std::size_t start_row_index) {
                            size_t row = start_row_index;
                            output.resize(n);
                            if (n > 0) {
                                output[0] = var(0, start_row_index, false, var::column_type::constant);
                            }
                            if (n > 1) {
                                output[1] = params.base;
                            }
                            for (std::size_t i = 2; i < n; i++) {
                                output[i] = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var base = params.base;
                        var last_result = params.base;

                        for (std::size_t i = 2; i < n; i++) {
                            last_result =
                                zk::components::generate_circuit<mul_component>(
                                    bp, assignment, {base, last_result}, row
                                ).output;
                            row += mul_component::rows_amount;
                        }

                        generate_assignments_constant(assignment, params, start_row_index);

                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var base = params.base;
                        var last_result = params.base;

                        for (std::size_t i = 2; i < n; i++) {
                            last_result =
                                mul_component::generate_assignments(assignment, {base, last_result}, row).output;
                            row += mul_component::rows_amount;
                        }

                        return result_type(params, start_row_index);
                    }

                private:
                    static void generate_assignments_constant(
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 1;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_ALGEBRA_FIELDS_ELEMENT_POWERS_HPP