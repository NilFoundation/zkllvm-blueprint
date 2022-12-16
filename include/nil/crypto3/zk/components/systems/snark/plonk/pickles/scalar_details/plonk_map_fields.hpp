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
namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/plonk_checks/plonk_checks.ml#L409
                template<typename ArithmetizationType,
                         typename CurveType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType,
                         std::size_t... WireIndexes>
                class plonk_map_fields;

                template<typename ArithmetizationParams,
                         typename CurveType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType,
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
                class plonk_map_fields<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType,
                    KimchiParamsType,
                    KimchiCommitmentParamsType,
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

                    // typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    //     ArithmetizationType;
                    using BlueprintFieldType = typename CurveType::scalar_field_type;

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
                    using generic_scalars_component = generic_scalars<ArithmetizationType,
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
                    using proof_binding =
                        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;
                        row += exponentiation_component::rows_amount;
                        row += sub_component::rows_amount;
                        row += generic_scalars_component::rows_amount;
                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var zeta;
                        var alpha;
                        var beta;
                        var gamma;
                        var zeta;
                        var joint_combiner;
                        std::array<var, KimchiParamsType::index_term_size()> index_terms;
                        var perm;
                        std::array<var, generic_scalars_component::output_size> generic;
                        // kimchi_verifier_index_scalar<BlueprintFieldType> &_verifier_index;
                        zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
                        // verifier_index
                        // params_type(kimchi_proof_scalar<BlueprintFieldType,
                        //                                 KimchiParamsType,
                        //                                 KimchiCommitmentParamsType::eval_rounds> &_proof,
                        //             typename proof_binding::fq_sponge_output &_fq_output) :
                        // verifier_index(_verifier_index),
                        //     proof(_proof), fq_output(_fq_output) {
                        // }
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;

                            
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(assignment, params, start_row_index);

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        var max_poly_size = var(0, start_row_index + 3, false, var::column_type::constant);
                        var zeta = params.zeta;

                        // zeta_pow_n = zeta**n
                        var zeta_pow_n =
                            exponentiation_component::generate_circuit(bp, assignment, {zeta, domain_size}, row).output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
                        var zeta1m1 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {zeta_pow_n, one}, row)
                                .output;
                        row += sub_component::rows_amount;

                        // zeta_to_srs_length = zeta^max_poly_size
                        var zeta_to_srs_len =
                            exponentiation_component::generate_circuit(bp, assignment, {zeta, max_poly_size}, row)
                                .output;
                        row += exponentiation_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        return result_type({zeta1m1, zeta_to_srs_len});
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        var max_poly_size = var(0, start_row_index + 3, false, var::column_type::constant);
                        var zeta = params.zeta;

                        // zeta_pow_n = zeta**n
                        var zeta_pow_n =
                            exponentiation_component::generate_assignments(assignment, {zeta, domain_size}, row).output;
                        row += exponentiation_component::rows_amount;

                        // zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
                        var zeta1m1 = sub_component::generate_assignments(assignment, {zeta_pow_n, one}, row).output;
                        row += sub_component::rows_amount;

                        // zeta_to_srs_length = zeta^max_poly_size
                        var zeta_to_srs_len =
                            exponentiation_component::generate_assignments(assignment, {zeta, max_poly_size}, row)
                                .output;
                        row += exponentiation_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP