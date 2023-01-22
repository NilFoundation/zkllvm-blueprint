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
                         typename KimchiParamsType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class plonk_map_fields;

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
                class plonk_map_fields<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    // constexpr static const std::size_t eval_points_amount = 2;

                    // constexpr std::size_t InputSize = 2;
                    // [TODO] get InputSize from result_type struct / Any other method ?
                    constexpr static std::size_t InputSize() {
                        // 19 kimchi scalars - 15 we don't need + 3 (zeta2domain, zeta2srs_len,permutation_scalar_inv)
                        // return KimchiParamsType::index_term_size() - 15 + 3;
                        return 7;
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
                    // using proof_binding =
                    //     typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    // using mul_by_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;
                    // using add_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;

                        // row += 2 * exponentiation_component::rows_amount;
                        // row += add_component::rows_amount;
                        row += prepare_scalars_component::rows_amount;
                        // row += mul_by_const_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    // constexpr static const std::size_t gates_amount = 0;
                    // constexpr static const std::size_t BatchSize = 1;

                    struct params_type {
                        var alpha;
                        var beta;
                        var gamma;
                        var zeta;    // eval_point

                        var zeta_to_domain_size;
                        var zeta_to_srs_len;

                        //
                        // std::vector<var> index_terms_scalars;
                        std::array<var, 4> index_terms_scalars;
                        var permutation_scalars;
                        // // var generic
                    };

                    struct result_type {
                        std::vector<var> output;
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
                        // generate_assignments_constant(bp, assignment, params, start_row_index);
                        // var one = var(0, start_row_index, false, var::column_type::constant);
                        // var one = var(0, start_row_index, false, var::column_type::public_input);
                        // typename BlueprintFieldType::value_type one = 1;

                        // zeta_to_domain_size_minus_1 + F.one
                        // var zeta_to_domain_size = zk::components::generate_circuit<add_component>(
                        //                               bp, assignment, {params.zeta_to_domain_size, one}, row)
                        //                               .output;
                        // row += add_component::rows_amount;

                        std::vector<var> index_scalars_unprepared;

                        result_type res;
                        // res.output;

                        res.output.push_back(params.alpha);
                        res.output.push_back(params.beta);
                        res.output.push_back(params.gamma);
                        res.output.push_back(params.zeta);

                        // prepare for multiplication
                        index_scalars_unprepared.push_back(params.zeta_to_domain_size);
                        index_scalars_unprepared.push_back(params.zeta_to_srs_len);

                        for (size_t i = 0; i < params.index_terms_scalars.size(); i++) {
                            index_scalars_unprepared.push_back(params.index_terms_scalars[i]);
                        }

                        index_scalars_unprepared.push_back(params.permutation_scalars);

                        auto to_field =
                            prepare_scalars_component::generate_circuit(bp, assignment, {index_scalars_unprepared}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        for (size_t i = 4; i < params.index_terms_scalars.size(); i++) {
                            res.output.push_back(to_field[i]);
                        }

                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        // var one = var(0, start_row_index, false, var::column_type::public_input);
                        // typename BlueprintFieldType::value_type one = 1;
                        // zeta_pow_n = zeta**n
                        // var zeta_to_domain_size =
                        //     add_component::generate_assignments(
                        //         assignment, {params.fr_data.zeta_to_domain_size_minus_1, one}, row)
                        //         .output;
                        // row += add_component::rows_amount;

                        std::vector<var> index_scalars_unprepared;

                        result_type res;
                        // res.output;

                        res.output.push_back(params.alpha);
                        res.output.push_back(params.beta);
                        res.output.push_back(params.gamma);
                        res.output.push_back(params.zeta);

                        // prepare for multiplication
                        index_scalars_unprepared.push_back(params.zeta_to_domain_size);
                        index_scalars_unprepared.push_back(params.zeta_to_srs_len);

                        for (size_t i = 0; i < params.index_terms_scalars.size(); i++) {
                            index_scalars_unprepared.push_back(params.index_terms_scalars[i]);
                            // std::cout << " params.index_terms_scalars[i] "
                            //           << assignment.var_value(params.index_terms_scalars[i]).data << " " << std::endl;
                        }

                        index_scalars_unprepared.push_back(params.permutation_scalars);

                        auto to_field =
                            prepare_scalars_component::generate_assignments(assignment, {index_scalars_unprepared}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        for (size_t i = 4; i < params.index_terms_scalars.size(); i++) {
                            res.output.push_back(to_field[i]);
                        }

                        return res;
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }
                    // static void generate_assignments_constant(
                    //     blueprint<ArithmetizationType> &bp,
                    //     blueprint_public_assignment_table<ArithmetizationType> &assignment,
                    //     const params_type &params,
                    //     std::size_t component_start_row) {
                    //     // std::size_t row = component_start_row;
                    //     //// one
                    //     // assignment.constant(0)[row] = 1;
                    //     // row++;
                    //     // assignment.constant(0)[row] = params.verifier_index.domain_size;
                    //     // // assignment.constant(0)[row] = KimchiCommitmentParamsType::max_poly_size;
                    // }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP
