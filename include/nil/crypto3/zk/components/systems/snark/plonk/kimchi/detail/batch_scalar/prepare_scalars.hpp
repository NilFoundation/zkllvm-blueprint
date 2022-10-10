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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_PREPARE_SCALARS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_PREPARE_SCALARS_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

// #include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // shift scalars for scalar multiplication input
                // f(X) = X -> (X - 2^255 - 1) / 2  if base field > scalar field
                // if scalar field > base field, then different formula for X = 1,0,-1: 
                // f(X) = X -> (X - 2^255)
                // 
                // TODO: "larger scalar field is depricated case"
                // Input: [x_0, ..., x_InputSize]
                // Output: [f(x_0), ..., f(x_InputSize)]
                
                template<typename ArithmetizationType, typename CurveType, std::size_t InputSize, std::size_t... WireIndexes>
                class prepare_scalars;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t InputSize, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8,
                         std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13,
                         std::size_t W14>
                class prepare_scalars<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                      CurveType, InputSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using div_or_zero_component = zk::components::division_or_zero<ArithmetizationType, W0, W1, W2, W3, W4>;

                    constexpr static const std::size_t selector_seed = 0x0f2C;

                    constexpr static bool scalar_larger() {
                        using ScalarField = typename CurveType::scalar_field_type;
                        using BaseField = typename CurveType::base_field_type;

                        auto n1 = ScalarField::modulus;
                        auto n2 = BaseField::modulus;

                        return n1 > n2;
                    }

                public:
                    constexpr static const std::size_t rows_amount_if_InputSize_is_1 = add_component::rows_amount * 6 + mul_component::rows_amount * 9  + sub_component::rows_amount * 4 +  div_or_zero_component::rows_amount * 3;
                    constexpr static const std::size_t rows_amount = InputSize * rows_amount_if_InputSize_is_1;


                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<var, InputSize> scalars;
                    };

                    struct result_type {
                        std::array<var, InputSize> output;

                        result_type (std::size_t row) {
                            for (std::size_t i = row; i < InputSize; i++) {
                                output[i] = var(W2, (rows_amount_if_InputSize_is_1 - 1) + i * rows_amount_if_InputSize_is_1);
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constants(bp, assignment, params, start_row_index);


                        var shift_curve_dependent = var(0, start_row_index, false, var::column_type::constant);
                        var coef_curve_dependent = var(0, start_row_index + 1, false, var::column_type::constant);
                        var shift_pallas = var(0, start_row_index + 2, false, var::column_type::constant);
                        var coef_pallas = var(0, start_row_index + 3, false, var::column_type::constant);
                        var one = var(0, start_row_index + 4, false, var::column_type::constant);


                        std::size_t row = start_row_index;

                        for (std::size_t i = 0; i < InputSize; ++i) {

                           var b_shift_curve_dependent_interm = zk::components::generate_circuit<add_component>(bp, assignment, {params.scalars[i], shift_curve_dependent}, row).output;
                            row += add_component::rows_amount;
                            var b_shift_curve_dependent        = zk::components::generate_circuit<mul_component>(bp, assignment, {b_shift_curve_dependent_interm, coef_curve_dependent}, row).output;
                            row += mul_component::rows_amount;

                            var b_shift_pallas_interm = zk::components::generate_circuit<add_component>(bp, assignment, {params.scalars[i], shift_pallas}, row).output;
                            row += add_component::rows_amount;
                            var b_shift_pallas        = zk::components::generate_circuit<mul_component>(bp, assignment, {b_shift_pallas_interm, coef_pallas}, row).output;
                            row += mul_component::rows_amount;

                            var b_minus_1 = zk::components::generate_circuit<sub_component>(bp, assignment, {params.scalars[i], one}, row).output;
                            row += sub_component::rows_amount;
                            var b_minus_1_inversed = zk::components::generate_circuit<div_or_zero_component>(bp, assignment, {one, b_minus_1}, row).output;
                            row += div_or_zero_component::rows_amount;
                            var true_if_not_1 = zk::components::generate_circuit<mul_component>(bp, assignment, {b_minus_1, b_minus_1_inversed}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_1 = zk::components::generate_circuit<sub_component>(bp, assignment, {one, true_if_not_1}, row).output;
                            row += sub_component::rows_amount;
                            
                            var b_minus_0 = params.scalars[i];
                            var b_minus_0_inversed = zk::components::generate_circuit<div_or_zero_component>(bp, assignment, {one, b_minus_0}, row).output;
                            row += div_or_zero_component::rows_amount;
                            var true_if_not_0 = zk::components::generate_circuit<mul_component>(bp, assignment, {b_minus_0, b_minus_0_inversed}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_0 = zk::components::generate_circuit<sub_component>(bp, assignment, {one, true_if_not_0}, row).output;
                            row += sub_component::rows_amount;
                            

                            var b_minus_neg1 = zk::components::generate_circuit<add_component>(bp, assignment, {params.scalars[i], one}, row).output;
                            row += add_component::rows_amount;
                            var b_minus_neg1_inversed = zk::components::generate_circuit<div_or_zero_component>(bp, assignment, {one, b_minus_neg1}, row).output;
                            row += div_or_zero_component::rows_amount;
                            var true_if_not_neg1 = zk::components::generate_circuit<mul_component>(bp, assignment, {b_minus_neg1, b_minus_neg1_inversed}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_neg1 = zk::components::generate_circuit<sub_component>(bp, assignment, {one, true_if_not_neg1}, row).output;
                            row += sub_component::rows_amount;
                            
                            var true_if_1_or_0 = zk::components::generate_circuit<add_component>(bp, assignment, {true_if_0, true_if_1}, row).output;
                            row += add_component::rows_amount;
                            var true_if_1_or_0_or_neg1 = zk::components::generate_circuit<add_component>(bp, assignment, {true_if_1_or_0, true_if_neg1}, row).output;
                            row += add_component::rows_amount;
                            var case_of_1_or_0_or_neg1 = zk::components::generate_circuit<mul_component>(bp, assignment, {true_if_1_or_0_or_neg1, b_shift_curve_dependent}, row).output;
                            row += mul_component::rows_amount;

                            var true_if_not_1_not_0 = zk::components::generate_circuit<mul_component>(bp, assignment, {true_if_not_1, true_if_not_0}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_not_1_not_0_not_neg1 = zk::components::generate_circuit<mul_component>(bp, assignment, {true_if_not_1_not_0, true_if_not_neg1}, row).output;
                            row += mul_component::rows_amount;
                            var case_of_not_1_not_0_not_neg1 = zk::components::generate_circuit<mul_component>(bp, assignment, {true_if_not_1_not_0_not_neg1, b_shift_pallas}, row).output;
                            row += mul_component::rows_amount;

                            var b_shifted = zk::components::generate_circuit<add_component>(bp, assignment, {case_of_1_or_0_or_neg1, case_of_not_1_not_0_not_neg1}, row).output;
                            row += add_component::rows_amount;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        var shift_curve_dependent = var(0, start_row_index, false, var::column_type::constant);
                        var coef_curve_dependent = var(0, start_row_index + 1, false, var::column_type::constant);
                        var shift_pallas = var(0, start_row_index + 2, false, var::column_type::constant);
                        var coef_pallas = var(0, start_row_index + 3, false, var::column_type::constant);
                        var one = var(0, start_row_index + 4, false, var::column_type::constant);
                        

                        std::size_t row = start_row_index;


                        for (std::size_t i = 0; i < InputSize; ++i) {
                            
                            var b_shift_curve_dependent_interm = add_component::generate_assignments(assignment, {params.scalars[i], shift_curve_dependent}, row).output;
                            row += add_component::rows_amount;
                            var b_shift_curve_dependent        = mul_component::generate_assignments(assignment, {b_shift_curve_dependent_interm, coef_curve_dependent}, row).output;
                            row += mul_component::rows_amount;

                            var b_shift_pallas_interm = add_component::generate_assignments(assignment, {params.scalars[i], shift_pallas}, row).output;
                            row += add_component::rows_amount;
                            var b_shift_pallas        = mul_component::generate_assignments(assignment, {b_shift_pallas_interm, coef_pallas}, row).output;
                            row += mul_component::rows_amount;

                            var b_minus_1 = sub_component::generate_assignments(assignment, {params.scalars[i], one}, row).output;
                            row += sub_component::rows_amount;
                            var b_minus_1_inversed = div_or_zero_component::generate_assignments(assignment, {one, b_minus_1}, row).output;
                            row += div_or_zero_component::rows_amount;
                            var true_if_not_1 = mul_component::generate_assignments(assignment, {b_minus_1, b_minus_1_inversed}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_1 = sub_component::generate_assignments(assignment, {one, true_if_not_1}, row).output;
                            row += sub_component::rows_amount;
                            
                            var b_minus_0 = params.scalars[i];
                            var b_minus_0_inversed = div_or_zero_component::generate_assignments(assignment, {one, b_minus_0}, row).output;
                            row += div_or_zero_component::rows_amount;
                            var true_if_not_0 = mul_component::generate_assignments(assignment, {b_minus_0, b_minus_0_inversed}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_0 = sub_component::generate_assignments(assignment, {one, true_if_not_0}, row).output;
                            row += sub_component::rows_amount;
                            
                            var b_minus_neg1 = add_component::generate_assignments(assignment, {params.scalars[i], one}, row).output;
                            row += add_component::rows_amount;
                            var b_minus_neg1_inversed = div_or_zero_component::generate_assignments(assignment, {one, b_minus_neg1}, row).output;
                            row += div_or_zero_component::rows_amount;
                            var true_if_not_neg1 = mul_component::generate_assignments(assignment, {b_minus_neg1, b_minus_neg1_inversed}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_neg1 = sub_component::generate_assignments(assignment, {one, true_if_not_neg1}, row).output;
                            row += sub_component::rows_amount;
                            std::cout << "neg1: " << assignment.var_value(true_if_neg1).data << " " << assignment.var_value(true_if_not_neg1).data << std::endl;

                            var true_if_1_or_0 = add_component::generate_assignments(assignment, {true_if_0, true_if_1}, row).output;
                            row += add_component::rows_amount;
                            var true_if_1_or_0_or_neg1 = add_component::generate_assignments(assignment, {true_if_1_or_0, true_if_neg1}, row).output;
                            row += add_component::rows_amount;
                            var case_of_1_or_0_or_neg1 = mul_component::generate_assignments(assignment, {true_if_1_or_0_or_neg1, b_shift_curve_dependent}, row).output;
                            row += mul_component::rows_amount;

                            var true_if_not_1_not_0 = mul_component::generate_assignments(assignment, {true_if_not_1, true_if_not_0}, row).output;
                            row += mul_component::rows_amount;
                            var true_if_not_1_not_0_not_neg1 = mul_component::generate_assignments(assignment, {true_if_not_1_not_0, true_if_not_neg1}, row).output;
                            row += mul_component::rows_amount;
                            var case_of_not_1_not_0_not_neg1 = mul_component::generate_assignments(assignment, {true_if_not_1_not_0_not_neg1, b_shift_pallas}, row).output;
                            row += mul_component::rows_amount;

                            var b_shifted = add_component::generate_assignments(assignment, {case_of_1_or_0_or_neg1, case_of_not_1_not_0_not_neg1}, row).output;
                            row += add_component::rows_amount;
                        }

                        return result_type(start_row_index);
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
                        typename BlueprintFieldType::value_type base = 2;
                        if (scalar_larger()) {
                            assignment.constant(0)[row] = -base.pow(255) - 1;
                            row++;
                            assignment.constant(0)[row] = 1 / base;
                            row++;
                        } else {
                            assignment.constant(0)[row] = -base.pow(255);
                            row++;
                            assignment.constant(0)[row] = 1;
                            row++;
                        }
                        assignment.constant(0)[row] = -base.pow(255) - 1;
                        row++;
                        assignment.constant(0)[row] = 1 / base;
                        row++;
                        assignment.constant(0)[row] = 1;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_PREPARE_SCALARS_HPP