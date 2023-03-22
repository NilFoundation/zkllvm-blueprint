//---------------------------------------------------------------------------//
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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/element_powers.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/perm_scalars.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/environment.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>

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

                    constexpr static const std::size_t prep_scalars_input_size =
                        KimchiParamsType::circuit_params::use_lookup 
                            ? (KimchiParamsType::circuit_params::lookup_runtime 
                              ? 23
                              : 22)
                            : 21;

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using pickles_plonk_min = nil::crypto3::zk::components::pickles_plonk_min<BlueprintFieldType>;
                    using pickles_plonk_circuit = nil::crypto3::zk::components::pickles_plonk_circuit<BlueprintFieldType>;

                    //   let index_terms = Sc.index_terms env in
                    using index_terms_scalars_component =
                        zk::components::index_terms_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using perm_scalars_component = perm_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3,
                                                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    //using mul_by_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;
                    using prepare_scalars_component = zk::components::prepare_scalars<ArithmetizationType,
                                      CurveType, prep_scalars_input_size, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    using exponentiation_component =
                        zk::components::exponentiation<ArithmetizationType, 255, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                                       W10, W11, W12, W13, W14>;

                    using evaluations_type =
                        typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;
                    using environment_type = typename
                        zk::components::kimchi_environment<BlueprintFieldType, KimchiParamsType>;
                    using plonk_circuit = typename
                        zk::components::pickles_plonk_circuit<BlueprintFieldType>;

                    using index_terms_list = typename KimchiParamsType::circuit_params::index_terms_list;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;

                        row += perm_scalars_component::rows_amount;
                        row += index_terms_scalars_component::rows_amount;
                        row += add_component::rows_amount;
                        row += exponentiation_component::rows_amount;
                        row += 2 * mul_component::rows_amount;
                        row += prepare_scalars_component::rows_amount;

                        return row;
                    }
                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        pickles_plonk_min plonk;
                        environment_type env;

                        std::array<evaluations_type, KimchiParamsType::eval_points_amount>
                            combined_evals;    // evaluations
                    };

                    struct result_type {
                        plonk_circuit output;

                        result_type(const std::size_t start_row_index) {
                            std::size_t row = start_row_index;

                            row += perm_scalars_component::rows_amount;
                            row += index_terms_scalars_component::rows_amount;
                            row += add_component::rows_amount;
                            row += exponentiation_component::rows_amount;
                            row += 2 * mul_component::rows_amount;

                            std::vector<var> prepared_scalars = typename prepare_scalars_component::result_type(row).output;
                            size_t idx = 0;
                            output.alpha = prepared_scalars[idx];
                            idx++;
                            output.beta = prepared_scalars[idx];
                            idx++;
                            output.gamma = prepared_scalars[idx];
                            idx++;
                            output.zeta = prepared_scalars[idx];
                            idx++;
                            output.zeta_to_domain_size = prepared_scalars[idx];
                            idx++;
                            output.zeta_to_srs_length = prepared_scalars[idx];
                            idx++;
                            output.poseidon_selector = prepared_scalars[idx];
                            idx++;
                            output.vbmul = prepared_scalars[idx];
                            idx++;
                            output.endomul = prepared_scalars[idx];
                            idx++;
                            output.endomul_scalar = prepared_scalars[idx];
                            idx++;
                            output.complete_add = prepared_scalars[idx];
                            idx++;
                            output.perm = prepared_scalars[idx];
                            idx++;
                            for (std::size_t i = 0; i < 9; ++i) {
                                output.generic[i] = prepared_scalars[idx];
                                idx++;
                            }
                            if (KimchiParamsType::circuit_params::use_lookup) {
                                output.lookup.joint_combiner = prepared_scalars[idx];
                                idx++;
                                if (KimchiParamsType::circuit_params::lookup_runtime) {
                                    output.lookup.lookup_gate = prepared_scalars[idx];
                                    idx++;
                                }
                            }
                            assert(idx == prep_scalars_input_size);

                            row += prepare_scalars_component::rows_amount;
                            assert(row == start_row_index + rows_amount);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        var one = var(0, start_row_index, false, var::column_type::constant);
                        var two = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        // ordering this before index scalars saves 2 rows (otherwise constants overlap)
                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);

                        var perm_scalar = perm_scalars_component::generate_circuit(
                            bp, assignment,
                            {
                                params.combined_evals,
                                params.env.alphas,
                                alpha_idxs.first,
                                params.plonk.beta,
                                params.plonk.gamma,
                                params.env.zk_polynomial,
                            },
                            row)
                            .output;
                        row += perm_scalars_component::rows_amount;

                        auto index_scalars =
                            index_terms_scalars_component::generate_circuit(
                                bp, assignment,
                                {
                                    params.plonk.zeta,
                                    params.plonk.alpha,
                                    params.plonk.beta,
                                    params.plonk.gamma,
                                    params.plonk.joint_combiner,
                                    params.combined_evals,
                                    params.env.domain_generator,
                                    params.env.domain_size
                                },
                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        // take 4 or 5 last rows: varBaseMul, endoMul, endoMulScalar, completeAdd
                        // if lookup is enabled, the 5th row is lookupKindIndex
                        std::vector<var> index_scalars_extracted;
                        std::copy(index_scalars.begin() + 15, index_scalars.end(), 
                                  std::back_inserter(index_scalars_extracted));

                        var zeta_to_domain_size = zk::components::generate_circuit<add_component>(
                            bp, assignment, {params.env.zeta_to_n_minus_1, one}, row)
                            .output;
                        row += add_component::rows_amount;

                        var zeta_to_srs_len = exponentiation_component::generate_circuit(
                            bp, assignment, {params.plonk.zeta, domain_size}, row)
                            .output;
                        row += exponentiation_component::rows_amount;

                        std::array<var, KimchiParamsType::witness_columns> w0 = params.combined_evals[0].w;
                        var m1 = zk::components::generate_circuit<mul_component>(
                            bp, assignment, {w0[0], w0[1]}, row
                            ).output;
                        row += mul_component::rows_amount;

                        var m2 = zk::components::generate_circuit<mul_component>(
                            bp, assignment, {w0[3], w0[4]}, row
                            ).output;
                        row += mul_component::rows_amount;

                        std::array<var, 9> generic = {
                            params.combined_evals[0].generic_selector,
                            w0[0], w0[1], w0[2], m1,
                            w0[3], w0[4], w0[5], m2
                        };

                        std::vector<var> prepare_scalars_params = {
                            params.plonk.alpha,
                            params.plonk.beta,
                            params.plonk.gamma,
                            params.plonk.zeta,
                            zeta_to_domain_size,
                            zeta_to_srs_len,
                            params.combined_evals[0].poseidon_selector
                        };
                        auto last_index_scalars_it = KimchiParamsType::circuit_params::lookup_columns > 0
                            ? index_scalars_extracted.end() - 1
                            : index_scalars_extracted.end();
                        std::copy(index_scalars_extracted.begin(), last_index_scalars_it,
                                  std::back_inserter(prepare_scalars_params));

                        prepare_scalars_params.push_back(perm_scalar);

                        std::copy(generic.begin(), generic.end(), 
                                  std::back_inserter(prepare_scalars_params));

                        if (KimchiParamsType::use_lookup) {
                            prepare_scalars_params.push_back(params.plonk.joint_combiner);
                            prepare_scalars_params.push_back(*index_scalars_extracted.rbegin());
                        }
                        auto to_fields =
                            prepare_scalars_component::generate_circuit(
                                bp, assignment, {prepare_scalars_params}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        assert(prep_scalars_input_size == to_fields.size());

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var one = var(0, start_row_index, false, var::column_type::constant);
                        var two = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        // ordering this before index scalars saves 2 rows (otherwise constants overlap)
                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);

                        var perm_scalar = perm_scalars_component::generate_assignments(
                            assignment,
                            {
                                params.combined_evals,
                                params.env.alphas,
                                alpha_idxs.first,
                                params.plonk.beta,
                                params.plonk.gamma,
                                params.env.zk_polynomial,
                            },
                            row)
                            .output;
                        row += perm_scalars_component::rows_amount;

                        auto index_scalars =
                            index_terms_scalars_component::generate_assignments(
                                assignment,
                                {
                                    params.plonk.zeta,
                                    params.plonk.alpha,
                                    params.plonk.beta,
                                    params.plonk.gamma,
                                    params.plonk.joint_combiner,
                                    params.combined_evals,
                                    params.env.domain_generator,
                                    params.env.domain_size
                                },
                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        // take 4 or 5 last rows: varBaseMul, endoMul, endoMulScalar, completeAdd
                        // if lookup is enabled, the 5th row is lookupKindIndex
                        std::vector<var> index_scalars_extracted;
                        std::copy(index_scalars.begin() + 15, index_scalars.end(), 
                                  std::back_inserter(index_scalars_extracted));

                        var zeta_to_domain_size = add_component::generate_assignments(
                            assignment, {params.env.zeta_to_n_minus_1, one}, row)
                            .output;
                        row += add_component::rows_amount;

                        var zeta_to_srs_len = exponentiation_component::generate_assignments(
                            assignment, {params.plonk.zeta, domain_size}, row)
                            .output;
                        row += exponentiation_component::rows_amount;

                        std::array<var, KimchiParamsType::witness_columns> w0 = params.combined_evals[0].w;
                        var m1 = mul_component::generate_assignments(
                            assignment, {w0[0], w0[1]}, row
                            ).output;
                        row += mul_component::rows_amount;

                        var m2 = mul_component::generate_assignments(
                            assignment, {w0[3], w0[4]}, row
                            ).output;
                        row += mul_component::rows_amount;

                        std::array<var, 9> generic = {
                            params.combined_evals[0].generic_selector,
                            w0[0], w0[1], w0[2], m1,
                            w0[3], w0[4], w0[5], m2
                        };

                        std::vector<var> prepare_scalars_params = {
                            params.plonk.alpha,
                            params.plonk.beta,
                            params.plonk.gamma,
                            params.plonk.zeta,
                            zeta_to_domain_size,
                            zeta_to_srs_len,
                            params.combined_evals[0].poseidon_selector
                        };
                        auto last_index_scalars_it = KimchiParamsType::circuit_params::lookup_columns > 0
                            ? index_scalars_extracted.end() - 1
                            : index_scalars_extracted.end();
                        std::copy(index_scalars_extracted.begin(), last_index_scalars_it,
                                  std::back_inserter(prepare_scalars_params));

                        prepare_scalars_params.push_back(perm_scalar);

                        std::copy(generic.begin(), generic.end(), 
                                  std::back_inserter(prepare_scalars_params));

                        if (KimchiParamsType::use_lookup) {
                            prepare_scalars_params.push_back(params.plonk.joint_combiner);
                            prepare_scalars_params.push_back(*index_scalars_extracted.rbegin());
                        }

                        auto to_fields =
                            prepare_scalars_component::generate_assignments(
                                assignment, {prepare_scalars_params}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        assert(prep_scalars_input_size == to_fields.size());

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {

                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 1;
                        row++;
                        assignment.constant(0)[row] = 2;
                        row++;
                        assignment.constant(0)[row] = params.env.domain_size;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_DERIVE_PLONK_HPP
