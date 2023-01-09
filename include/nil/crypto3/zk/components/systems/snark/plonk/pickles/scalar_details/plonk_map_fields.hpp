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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/generic_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/plonk_checks/plonk_checks.ml#L409
                template<typename ArithmetizationType,
                         typename CurveType,
                         typename KimchiParamsType,
                         std::size_t... WireIndexes>
                class plonk_map_fields;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename KimchiParamsType,
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
                                       CurveType,
                                       KimchiParamsType,
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
                    // constexpr static const std::size_t eval_points_amount = 2;

                    // ; zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
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
                    using add_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    //    index_terms_scalars
                    using index_terms_scalars_component = zk::components::index_terms_scalars<ArithmetizationType,
                                                                                              KimchiParamsType,
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
                    using evaluations_type =
                        typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;

                    // constexpr std::size_t InputSize = 2;
                    // [TODO] get InputSize from result_type struct / Any other method ?
                    constexpr static std::size_t InputSize() {
                        // 19 kimchi scalars - 15 we don't need + 2 (zeta2domain, zeta2srs_len)
                        return KimchiParamsType::index_term_size() - 15 + 2;
                    }
                    using prepare_scalars_component = zk::components::prepare_scalars<ArithmetizationType,
                                                                                      CurveType,
                                                                                      InputSize(),
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

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;
                        row += exponentiation_component::rows_amount;
                        row += sub_component::rows_amount;
                        row += add_component::rows_amount;
                        row += exponentiation_component::rows_amount;
                        row += index_terms_scalars_component::rows_amount;
                        row += prepare_scalars_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var alpha;
                        var beta;
                        var gamma;
                        var zeta;     // eval_point
                        var omega;    // group_gen
                        // [TODO] create var domain_size from size_t using constant columns
                        var domain_expo_var;    // creates problem/error in index_terms_scalars_component... (must be
                                                // field element)
                        std::size_t domain_size_scalars_sizet;    // try to use domain size as var
                        var joint_combiner;
                        var max_poly_size;
                        std::array<evaluations_type, KimchiParamsType::eval_points_amount> evaluations;

                        var one;     // could be optional here
                        var zero;    // the same for this
                    };

                    struct result_type {
                        std::vector<var> output = std::vector<var>(InputSize());
                        result_type(std::size_t start_row_index) {
                        }

                        result_type() {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        // zeta_to_n  = zeta**n
                        auto zeta_to_n = exponentiation_component::generate_circuit(
                                             bp, assignment, {params.zeta, params.domain_expo_var}, row)
                                             .output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_n_minus_1
                        auto zeta_to_n_minus_1 = zk::components::generate_circuit<sub_component>(
                                                     bp, assignment, {zeta_to_n, params.one}, row)
                                                     .output;
                        row += sub_component::rows_amount;

                        // ; zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
                        auto zeta_to_domain_size = zk::components::generate_circuit<add_component>(
                                                       bp, assignment, {zeta_to_n_minus_1, params.one}, row)
                                                       .output;
                        row += add_component::rows_amount;

                        // zeta_to_srs_length = zeta^max_poly_size
                        auto zeta_to_srs_len = exponentiation_component::generate_circuit(
                                                   bp, assignment, {params.zeta, params.max_poly_size}, row)
                                                   .output;
                        row += exponentiation_component::rows_amount;

                        auto index_terms_scalars =
                            index_terms_scalars_component::generate_circuit(
                                bp,
                                assignment,
                                {params.zeta, params.alpha, params.beta, params.gamma, params.joint_combiner,
                                 params.evaluations, params.omega, params.domain_size_scalars_sizet},
                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        // prepare scalars for multiplication
                        // [TODO] : use domain_size as var
                        // [TODO] get the size of the input params -> result of index_terms_scalars size
                        std::vector<var> index_scalars_unprepared;
                        index_scalars_unprepared.push_back(zeta_to_domain_size);
                        index_scalars_unprepared.push_back(zeta_to_srs_len);
                        for (size_t i = 15; i < index_terms_scalars.size(); i++) {
                            index_scalars_unprepared.push_back(index_terms_scalars[i]);
                        }

                        auto prepared_scalars =
                            prepare_scalars_component::generate_circuit(bp, assignment, {index_scalars_unprepared}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.output = prepared_scalars;
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        // zeta_pow_n = zeta**n
                        var zeta_to_n = exponentiation_component::generate_assignments(
                                            assignment, {params.zeta, params.domain_expo_var}, row)
                                            .output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_n_minus_1
                        var zeta_to_n_minus_1 =
                            sub_component::generate_assignments(assignment, {zeta_to_n, params.one}, row).output;
                        row += sub_component::rows_amount;

                        // ; zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
                        var zeta_to_domain_size =
                            add_component::generate_assignments(assignment, {zeta_to_n_minus_1, params.one}, row)
                                .output;
                        row += add_component::rows_amount;

                        // zeta_to_srs_length = zeta^max_poly_size
                        var zeta_to_srs_len = exponentiation_component::generate_assignments(
                                                  assignment, {params.zeta, params.max_poly_size}, row)
                                                  .output;
                        row += exponentiation_component::rows_amount;

                        auto index_terms_scalars =
                            index_terms_scalars_component::generate_assignments(
                                assignment,
                                {params.zeta, params.alpha, params.beta, params.gamma, params.joint_combiner,
                                 params.evaluations, params.omega, params.domain_size_scalars_sizet},
                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        // prepare scalars for multiplication
                        std::vector<var> index_scalars_unprepared;
                        index_scalars_unprepared.push_back(zeta_to_domain_size);
                        index_scalars_unprepared.push_back(zeta_to_srs_len);

                        for (size_t i = 15; i < index_terms_scalars.size(); i++) {
                            index_scalars_unprepared.push_back(index_terms_scalars[i]);
                        }

                        // for (size_t i = 0; i < index_scalars_unprepared.size(); i++) {
                        //     std::cout << "index_scalars_unprepared [ " << i
                        //               << "]=" << assignment.var_value(index_scalars_unprepared[i]).data << std::endl;
                        //     // index_scalars_unprepared.push_back(index_terms_scalars[i]);
                        // }

                        auto prepared_scalars =
                            prepare_scalars_component::generate_assignments(assignment, {index_scalars_unprepared}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.output = prepared_scalars;
                        return res;
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    // static void
                    //     generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                    //                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                    //                               const params_type &params,
                    //                               std::size_t component_start_row = 0) {
                    // }

                    // static void generate_assignments_constant(
                    //     blueprint<ArithmetizationType> &bp,
                    //     blueprint_public_assignment_table<ArithmetizationType> &assignment,
                    //     const params_type &params,
                    //     std::size_t component_start_row) {

                    //     // assignment.constant(0)[row] = ArithmetizationType::field_type::value_type::zero();
                    //     std::size_t row = component_start_row;
                    //     assignment.constant(0)[row] = 0;
                    //     row++;
                    //     assignment.constant(0)[row] = 1;
                    //     row++;

                    //     // assignment.constant(0)[row] = params.verifier_index.domain_size;
                    //     // row++;
                    //     // assignment.constant(0)[row] = KimchiCommitmentParamsType::max_poly_size;
                    // }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP
