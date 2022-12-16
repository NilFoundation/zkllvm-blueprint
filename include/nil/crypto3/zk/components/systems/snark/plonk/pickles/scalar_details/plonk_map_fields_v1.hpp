//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Abdel Ali Harchaoui <harchaoui@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_PLONK_MAP_FIELDS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_PLONK_MAP_FIELDS_HPP

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/generic_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>

#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/plonk_checks/plonk_checks.ml#L409
                // template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class plonk_map_fields;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
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
                class plonk_map_fields<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    // (zeta_to_srs_length) : is just to points zeta^max_poly_size and (zeta*omega)^max_poly_size
                    constexpr static const std::size_t eval_points_amount = 2;
                    using exponentiation_component = zk::components::exponentiation<ArithmetizationType,
                                                                                    256,
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
                                                                                    W14>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    // using generic_scalars_component = generic_scalars<ArithmetizationType,
                    //                                                   KimchiParamsType,
                    //                                                   W0,
                    //                                                   W1,
                    //                                                   W2,
                    //                                                   W3,
                    //                                                   W4,
                    //                                                   W5,
                    //                                                   W6,
                    //                                                   W7,
                    //                                                   W8,
                    //                                                   W9,
                    //                                                   W10,
                    //                                                   W11,
                    //                                                   W12,
                    //                                                   W13,
                    //                                                   W14>;
                    // using proof_binding =
                    //     typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    // vbmul = Lazy.force (Hashtbl.find_exn index_terms (Index VarBaseMul))
                    // using vbmul_component = zk::components::element_g1_multi_scalar_mul<ArithmetizationType,
                    //                                                                     CurveType,
                    //                                                                     f_comm_base_size,
                    //                                                                     W0,
                    //                                                                     W1,
                    //                                                                     W2,
                    //                                                                     W3,
                    //                                                                     W4,
                    //                                                                     W5,
                    //                                                                     W6,
                    //                                                                     W7,
                    //                                                                     W8,
                    //                                                                     W9,
                    //                                                                     W10,
                    //                                                                     W11,
                    //                                                                     W12,
                    //                                                                     W13,
                    //                                                                     W14>;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;
                        row += exponentiation_component::rows_amount;
                        row += exponentiation_component::rows_amount;
                        // row += generic_scalars_component::rows_amount;
                        // row += vbmul_component::rows_amount;
                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var alpha;
                        var beta;
                        var gamma;
                        var zeta;           // kind of constat
                        var domain_size;    // kind of constant
                        var one;
                        var zero;
                        var joint_combiner;
                        var max_poly_size;
                        zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
                    };

                    struct result_type {
                        var zeta_to_domain_size;
                        var zeta_to_srs_len;
                        // result_type(std::size_t component_start_row) {
                        //     std::size_t row = component_start_row;
                        // }

                        // var output;

                        // result_type(std::size_t component_start_row) {
                        //     std::size_t row = component_start_row;

                        // }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        var zero = var(0, 0, false, var::column_type::constant);
                        var one = var(0, 1, false, var::column_type::constant);
                        var domain_size = var(0, 2, false, var::column_type::public_input);
                        var max_poly_size = var(0, row + 3, false, var::column_type::public_input);
                        var zeta = params.zeta;

                        // zeta_pow_n = zeta**n
                        var zeta_pow_n = exponentiation_component::generate_circuit(
                                             bp, assignment, {params.zeta, params.domain_size}, row)
                                             .output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_srs_length = zeta^max_poly_size
                        var zeta_to_srs_len = exponentiation_component::generate_circuit(
                                                  bp, assignment, {params.zeta, params.max_poly_size}, row)
                                                  .output;
                        row += exponentiation_component::rows_amount;
                        // row += sub_component::rows_amount;

                        std::cout << "Plonk.hpp rows= [ " << row << " ] " << std::endl;
                        std::cout << "Plonk.hpp rows_amount= [ " << rows_amount << " ] " << std::endl;

                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.zeta_to_domain_size = zeta_pow_n;
                        res.zeta_to_srs_len = zeta_to_srs_len;

                        return res;
                        // return result_type({zeta_pow_n, zeta_to_srs_len});
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        var zero = var(0, 0, false, var::column_type::constant);
                        var one = var(0, 1, false, var::column_type::constant);
                        var domain_size = var(0, 2, false, var::column_type::public_input);
                        var max_poly_size = var(0, start_row_index + 3, false, var::column_type::public_input);
                        var zeta = params.zeta;

                        // zeta_pow_n = zeta**n
                        var zeta_pow_n = exponentiation_component::generate_assignments(
                                             assignment, {params.zeta, params.domain_size}, row)
                                             .output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_srs_length = zeta^max_poly_size
                        var zeta_to_srs_len = exponentiation_component::generate_assignments(
                                                  assignment, {params.zeta, params.max_poly_size}, row)
                                                  .output;
                        row += exponentiation_component::rows_amount;

                        std::cout << "alpha_var = " << assignment.var_value(params.max_poly_size).data << " data"
                                  << std::endl;

                        std::cout << " res.zeta_to_domain_size = [ " << assignment.var_value(zeta_pow_n).data << " ] "
                                  << std::endl;

                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.zeta_to_domain_size = zeta_pow_n;
                        res.zeta_to_srs_len = zeta_to_srs_len;
                        
                        std::cout << " res.zeta_to_srs_len = [ " << assignment.var_value(res.zeta_to_srs_len).data << " ] "
                                  << std::endl;


                        return res;

                        // return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row = 0) {
                    }

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {

                        // assignment.constant(0)[row] = ArithmetizationType::field_type::value_type::zero();
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;

                        // assignment.constant(0)[row] = params.verifier_index.domain_size;
                        // row++;
                        // assignment.constant(0)[row] = KimchiCommitmentParamsType::max_poly_size;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP
