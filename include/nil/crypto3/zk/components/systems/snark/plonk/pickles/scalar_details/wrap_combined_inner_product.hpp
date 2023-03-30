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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_COMBINED_INNER_PRODUCT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_COMBINED_INNER_PRODUCT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/environment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/ft_eval.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename ArithmetizationType, typename KimchiParamsType, typename CurveType,
                         std::size_t... WireIndexes>
                class wrap_combined_inner_product;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         typename CurveType, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class wrap_combined_inner_product<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                  KimchiParamsType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using exponentiation_component =
                        zk::components::exponentiation<ArithmetizationType, 255, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                                       W10, W11, W12, W13, W14>;
                    /*using combined_proof_evals_component =
                        zk::components::combine_proof_evals<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;*/
                    using ft_eval_component = zk::components::ft_eval<ArithmetizationType, CurveType, KimchiParamsType,
                                                                      W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                                                      W10, W11, W12, W13, W14>;

                    using kimchi_proof_evaluations = zk::components::kimchi_proof_evaluations<BlueprintFieldType,
                                                                                              KimchiParamsType>;
                    using environment_type = zk::components::kimchi_environment<BlueprintFieldType, KimchiParamsType>;
                    using plonk_type = pickles_plonk_min<BlueprintFieldType>;

                    using evals_type = typename zk::components::proof_type<BlueprintFieldType, KimchiParamsType>
                                                              ::prev_evals_type::evals_type;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;

                        row += add_component::rows_amount;
                        row += ft_eval_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        // this is output of evals_of_split_evals component
                        // it's recalculated inside derive_plonk, but we can avoid that by just passing it in
                        std::array<kimchi_proof_evaluations, KimchiParamsType::eval_points_amount> combined_evals;
                        evals_type evals;
                        environment_type env;
                        plonk_type plonk;
                        var ft_eval1;
                        var zeta;
                        var zetaw;
                        var r;
                        var xi;
                        std::vector<std::array<var, 16>> old_bulletproof_challenges;
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

                        std::size_t row = start_row_index;
                        var one = var(0, start_row_index, false, var::column_type::constant);
                        // we reuse ft_eval component from kimchi
                        typename ft_eval_component::params_type ft_eval_params;
                        ft_eval_params.gamma = params.plonk.gamma;
                        ft_eval_params.beta = params.plonk.beta;
                        ft_eval_params.zeta = params.plonk.zeta;
                        ft_eval_params.combined_evals = params.combined_evals;
                        ft_eval_params.alpha_powers = params.env.alphas;
                        ft_eval_params.verifier_index.omega = params.env.domain_generator;
                        ft_eval_params.verifier_index.domain_size = params.env.domain_size_log2;
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            ft_eval_params.verifier_index.shift[i] =
                                var(0, start_row_index + 1 + i, false, var::column_type::constant);
                        }
                        ft_eval_params.zeta_pow_n = zk::components::generate_circuit<add_component>(
                            bp, assignment, {params.env.zeta_to_n_minus_1, one}, row).output;
                        ft_eval_params.public_eval[0] = params.evals.public_input[0];
                        // joint_combiner technically should not be used, so is not set
                        row += add_component::rows_amount;
                        // dodging constants of ft_eval_component
                        row += 6;
                        var ft_eval0 = ft_eval_component::generate_circuit(bp, assignment, ft_eval_params, row).output;

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    private:

                    static void generate_assignments_constant(
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        size_t row = component_start_row;

                        assignment.constant(0)[row] = 1;
                        row++;
                        // these are constant shifts; they are taken from tests
                        // should be correct
                        assignment.constant(0)[row] =
                            0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;
                        row++;
                        assignment.constant(0)[row] =
                            0x00B9CDC8FD0BD4B27E2A74AF7AEBD5734D52D75BDF85EBF1CAD03413E914A2E3_cppui256;
                        row++;
                        assignment.constant(0)[row] =
                            0x0033BFCF8112720332825BD83D44D92CADC0C30466E8102C419C30FA2665695A_cppui256;
                        row++;
                        assignment.constant(0)[row] =
                            0x0087F4BB29954E16960F2DE3A1FA5AC7B62146DB348C7C9F0E8BF10B2C8E8411_cppui256;
                        row++;
                        assignment.constant(0)[row] =
                            0x00EC71373B9F6CF15ED1949647365DB60B2E26C3A8ABBA5BB06BF23E9DBE5893_cppui256;
                        row++;
                        assignment.constant(0)[row] =
                            0x00F39197CC4C55084C68D31F64F1A172406B585CB86445F00C248C721C496D10_cppui256;
                        row++;
                        assignment.constant(0)[row] =
                            0x00B8DD039799DBEE12D2E6A4299A83E067353C0143C5DFD203190C239159EEA3_cppui256;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_COMBINED_INNER_PRODUCT_HPP
