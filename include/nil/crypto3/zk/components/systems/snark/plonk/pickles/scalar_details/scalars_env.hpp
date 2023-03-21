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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_SCALARS_ENV_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_SCALARS_ENV_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/environment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/zkpm_evaluate.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/element_powers.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/plonk_checks/plonk_checks.ml#L90-L212
                // This one only partially implements the original function, as we don't need some parts
                template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
                class scalars_env;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename KimchiParamsType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11,
                         std::size_t W12, std::size_t W13, std::size_t W14>
                class scalars_env<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                    KimchiParamsType,
                                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    
                    using environment = zk::components::kimchi_environment<BlueprintFieldType, KimchiParamsType>;
                    using plonk_min = zk::components::pickles_plonk_min<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using exponentiation_component = zk::components::exponentiation<ArithmetizationType, 128, W0, W1,
                                                                                    W2, W3, W4, W5, W6, W7, W8, W9,
                                                                                    W10, W11, W12, W13, W14>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    using alpha_powers_component = zk::components::element_powers<
                        ArithmetizationType, BlueprintFieldType, KimchiParamsType::alpha_powers_n,
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using zkpm_evaluate_component = zkpm_evaluate<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7,
                                                                  W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0x0f1a;

                    constexpr static const std::size_t rows() {
                        size_t rows = 0;

                        rows += alpha_powers_component::rows_amount;
                        rows += exponentiation_component::rows_amount;
                        rows += sub_component::rows_amount;
                        rows += zkpm_evaluate_component::rows_amount;

                        return rows;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        plonk_min plonk;
                        var srs_length_log2;

                        var group_gen;
                        std::size_t domain_size_log2;
                    };

                    struct result_type {
                        environment output;

                        result_type(const params_type &params,
                                    const std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                            output.domain_generator = params.group_gen;
                            output.domain_size_log2 = params.domain_size_log2;
                            output.domain_size = 1 << params.domain_size_log2;
                            output.srs_length_log2 = params.srs_length_log2;

                            output.alphas = typename alpha_powers_component::result_type({params.plonk.alpha}, row).output;
                            row += alpha_powers_component::rows_amount;

                            row += exponentiation_component::rows_amount;
                            output.zeta_to_n_minus_1 = typename sub_component::result_type(row).output;
                            row += sub_component::rows_amount;

                            output.zk_polynomial = typename zkpm_evaluate_component::result_type(row).output;
                            row += zkpm_evaluate_component::rows_amount;

                            assert(row == start_row_index + rows_amount);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        generate_assignments_constants(bp, assignment, params, start_row_index);

                        std::size_t row = start_row_index;
                        var one = var(0, start_row_index, false, var::column_type::constant);
                        var two = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        size_t domain_size_t = 1 << params.domain_size_log2;
                        // alphas
                        alpha_powers_component::generate_circuit(
                            bp, assignment, {params.plonk.alpha}, row);
                        row += alpha_powers_component::rows_amount;

                        var zeta_to_n = exponentiation_component::generate_circuit(
                            bp, assignment, {params.plonk.zeta, domain_size}, row)
                            .output;
                        row += exponentiation_component::rows_amount;
                        // zeta_to_n_minus_1
                        zk::components::generate_circuit<sub_component>(
                            bp, assignment, {zeta_to_n, one}, row);
                        row += sub_component::rows_amount;

                        var zk_polynomial = zkpm_evaluate_component::generate_circuit(
                            bp, assignment, 
                            {params.group_gen, domain_size_t, params.plonk.zeta}, row)
                            .output;
                        row += zkpm_evaluate_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        var one = var(0, start_row_index, false, var::column_type::constant);
                        var two = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        size_t domain_size_t = 1 << params.domain_size_log2;
                        // alphas
                        alpha_powers_component::generate_assignments(
                            assignment, {params.plonk.alpha}, row);
                        row += alpha_powers_component::rows_amount;

                        var zeta_to_n = exponentiation_component::generate_assignments(
                            assignment, {params.plonk.zeta, domain_size}, row)
                            .output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_n_minus_1
                        sub_component::generate_assignments(
                            assignment, {zeta_to_n, one}, row);
                        row += sub_component::rows_amount;

                        var zk_polynomial = zkpm_evaluate_component::generate_assignments(
                            assignment, {params.group_gen, domain_size_t, params.plonk.zeta}, row)
                            .output;
                        row += zkpm_evaluate_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(params, start_row_index);
                    }

                private:
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
                        assignment.constant(0)[row] = 1;
                        row++;
                        assignment.constant(0)[row] = 2;
                        row++;
                        assignment.constant(0)[row] = 1 << params.domain_size_log2;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_SCALARS_ENV_HPP
