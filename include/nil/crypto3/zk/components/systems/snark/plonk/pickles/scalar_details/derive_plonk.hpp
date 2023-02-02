//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_DERIVE_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_DERIVE_PLONK_HPP

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/zkpm_evaluate.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_scalars.hpp>
// #include <nil/crypto3/zk/components/algebra/fields/plonk/element_powers.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/perm_scalars.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/plonk_map_fields.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/plonk_checks/plonk_checks.ml#L409
                template<typename ArithmetizationType, typename KimchiParamsType, typename CurveType,
                         std::size_t... WireIndexes>
                class derive_plonk;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         typename CurveType, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class derive_plonk<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                   KimchiParamsType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                   W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    //   let zkp = env.zk_polynomial in
                    using zkpm_evaluate_component = zkpm_evaluate<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7,
                                                                  W8, W9, W10, W11, W12, W13, W14>;
                    //   let index_terms = Sc.index_terms env in
                    using index_terms_scalars_component =
                        zk::components::index_terms_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    //   let alpha_pow = env.alpha_pow in
                    // [TODO] implement element_powers component
                    // using alpha_powers_component =
                    //     zk::components::element_powers<ArithmetizationType, KimchiParamsType::alpha_powers_n, W0, W1,
                    //                                    W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using perm_scalars_component = perm_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3,
                                                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using mul_by_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;

                    using evaluations_type =
                        typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;

                    using verifier_index_type = kimchi_verifier_index_scalar<BlueprintFieldType>;
                    using index_terms_list = typename KimchiParamsType::circuit_params::index_terms_list;
                    using plonk_map_fields_component_type =
                        zk::components::plonk_map_fields<ArithmetizationType, KimchiParamsType, CurveType, W0, W1, W2,
                                                         W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;
                        row += zkpm_evaluate_component::rows_amount;
                        row += index_terms_scalars_component::rows_amount;
                        row += perm_scalars_component::rows_amount;
                        row += mul_by_const_component::rows_amount;
                        row += plonk_map_fields_component_type::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;
                    constexpr static const std::size_t permScalarsInputSize = 11;

                    //   let e1 field = snd (field e) in
                    //   let w0 = Vector.map e.w ~f:fst in
                    struct params_type {
                        verifier_index_type verifier_index;
                        var zeta;
                        var alpha;
                        var beta;
                        var gamma;

                        var zeta_to_domain_size;
                        var zeta_to_srs_len;

                        var joint_combiner;
                        std::array<var, KimchiParamsType::alpha_powers_n> alphas;

                        std::array<evaluations_type, KimchiParamsType::eval_points_amount>
                            combined_evals;    // evaluations
                    };

                    struct result_type {
                        std::vector<var> output = std::vector<var>(permScalarsInputSize);

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

                        var zkp = zkpm_evaluate_component::generate_circuit(bp, assignment,
                                                                            {
                                                                                params.verifier_index.omega,
                                                                                params.verifier_index.domain_size,
                                                                                params.zeta,
                                                                            },
                                                                            row)
                                      .output;

                        row += zkpm_evaluate_component::rows_amount;

                        auto index_scalars =
                            index_terms_scalars_component::generate_circuit(bp,
                                                                            assignment,
                                                                            {
                                                                                params.zeta,
                                                                                params.alpha,
                                                                                params.beta,
                                                                                params.gamma,
                                                                                params.joint_combiner,
                                                                                params.combined_evals,
                                                                                params.verifier_index.omega,
                                                                                params.verifier_index.domain_size,
                                                                            },
                                                                            row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        // take 4 last rows , varBaseMul , endoMul , endoMulScalar , completeAdd
                        std::array<var, 4> index_scalars_4_last;
                        for (size_t i = 15; i < index_scalars.size(); i++) {
                            index_scalars_4_last[i - 15] = index_scalars[i];
                        }

                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);

                        var perm_scalar = perm_scalars_component::generate_circuit(bp,
                                                                                   assignment,
                                                                                   {
                                                                                       params.combined_evals,
                                                                                       params.alphas,
                                                                                       alpha_idxs.first,
                                                                                       params.beta,
                                                                                       params.gamma,
                                                                                       zkp,
                                                                                   },
                                                                                   row)
                                              .output;
                        row += perm_scalars_component::rows_amount;

                        typename BlueprintFieldType::value_type minus_1 = -1;
                        var perm_scalar_inv = zk::components::generate_circuit<mul_by_const_component>(
                                                  bp, assignment, {perm_scalar, minus_1}, row)
                                                  .output;

                        row += mul_by_const_component::rows_amount;

                        auto to_fields =
                            plonk_map_fields_component_type::generate_circuit(bp,
                                                                              assignment,
                                                                              {
                                                                                  params.zeta,
                                                                                  params.alpha,
                                                                                  params.beta,
                                                                                  params.gamma,
                                                                                  params.zeta_to_domain_size,
                                                                                  params.zeta_to_srs_len,
                                                                                  index_scalars_4_last,
                                                                                  perm_scalar_inv,
                                                                              },
                                                                              row)
                                .output;
                        row += plonk_map_fields_component_type::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        assert(permScalarsInputSize == to_fields.size());

                        result_type res;
                        for (size_t i = 0; i < to_fields.size(); i++) {
                            res.output[i] = to_fields[i];
                        }

                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zkp = zkpm_evaluate_component::generate_assignments(assignment,
                                                                                {
                                                                                    params.verifier_index.omega,
                                                                                    params.verifier_index.domain_size,
                                                                                    params.zeta,
                                                                                },
                                                                                row)
                                      .output;
                        row += zkpm_evaluate_component::rows_amount;

                        auto index_scalars =
                            index_terms_scalars_component::generate_assignments(assignment,
                                                                                {
                                                                                    params.zeta,
                                                                                    params.alpha,
                                                                                    params.beta,
                                                                                    params.gamma,
                                                                                    params.joint_combiner,
                                                                                    params.combined_evals,
                                                                                    params.verifier_index.omega,
                                                                                    params.verifier_index.domain_size,
                                                                                },
                                                                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        // take 4 last rows , varBaseMul , endoMul , endoMulScalar , completeAdd
                        std::array<var, 4> index_scalars_4_last;
                        for (size_t i = 15; i < index_scalars.size(); i++) {
                            index_scalars_4_last[i - 15] = index_scalars[i];
                        }

                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);

                        var perm_scalar = perm_scalars_component::generate_assignments(assignment,
                                                                                       {
                                                                                           params.combined_evals,
                                                                                           params.alphas,
                                                                                           alpha_idxs.first,
                                                                                           params.beta,
                                                                                           params.gamma,
                                                                                           zkp,
                                                                                       },
                                                                                       row)
                                              .output;
                        row += perm_scalars_component::rows_amount;

                        typename BlueprintFieldType::value_type minus_1 = -1;
                        var perm_scalar_inv =
                            mul_by_const_component::generate_assignments(assignment, {perm_scalar, minus_1}, row)
                                .output;
                        row += mul_by_const_component::rows_amount;

                        auto to_fields =
                            plonk_map_fields_component_type::generate_assignments(assignment,
                                                                                  {
                                                                                      params.alpha,
                                                                                      params.beta,
                                                                                      params.gamma,
                                                                                      params.zeta,
                                                                                      params.zeta_to_domain_size,
                                                                                      params.zeta_to_srs_len,
                                                                                      index_scalars_4_last,
                                                                                      perm_scalar_inv,
                                                                                  },
                                                                                  row)
                                .output;
                        row += plonk_map_fields_component_type::rows_amount;
                        assert(row == start_row_index + rows_amount);
                        assert(permScalarsInputSize == to_fields.size());

                        result_type res;
                        for (size_t i = 0; i < to_fields.size(); i++) {
                            res.output[i] = to_fields[i];
                        }

                        return res;
                    }

                private:
                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {

                        // std::size_t row = component_start_row;
                        // one var
                        // assignment.constant(0)[row] = 1;
                        // row++;
                        // assignment.constant(0)[row] = params.verifier_index.domain_size;
                        // // assignment.constant(0)[row] = KimchiCommitmentParamsType::max_poly_size;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_DERIVE_PLONK_HPP
