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

                    // [TODO] get InputSize from result_type
                    constexpr static std::size_t InputSize() {
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

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;
                        row += prepare_scalars_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();

                    struct params_type {
                        var alpha;
                        var beta;
                        var gamma;
                        var zeta;    // eval_point

                        var zeta_to_domain_size;
                        var zeta_to_srs_len;

                        std::array<var, 4> index_terms_scalars;
                        var permutation_scalars;
                        // var generic; //[TODO]
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

                        std::vector<var> index_scalars_unprepared = std::vector<var>(7);

                        index_scalars_unprepared[0] = params.zeta_to_domain_size;
                        index_scalars_unprepared[1] = params.zeta_to_srs_len;

                        for (size_t i = 2; i < params.index_terms_scalars.size(); i++) {
                            index_scalars_unprepared[i] = params.index_terms_scalars[i - 2];
                        }
                        index_scalars_unprepared[6] = params.permutation_scalars;

                        auto to_field =
                            prepare_scalars_component::generate_circuit(bp, assignment, {index_scalars_unprepared}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        result_type res;

                        res.output[0] = params.alpha;
                        res.output[1] = params.beta;
                        res.output[2] = params.gamma;
                        res.output[3] = params.zeta;
                        for (size_t i = 4; i < to_field.size(); i++) {
                            res.output[i] = to_field[i - 4];
                        }
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::vector<var> index_scalars_unprepared = std::vector<var>(7);

                        index_scalars_unprepared[0] = params.zeta_to_domain_size;
                        index_scalars_unprepared[1] = params.zeta_to_srs_len;

                        for (size_t i = 2; i < params.index_terms_scalars.size(); i++) {
                            index_scalars_unprepared[i] = params.index_terms_scalars[i - 2];
                        }
                        index_scalars_unprepared[6] = params.permutation_scalars;

                        auto to_field =
                            prepare_scalars_component::generate_assignments(assignment, {index_scalars_unprepared}, row)
                                .output;
                        row += prepare_scalars_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        result_type res;

                        res.output[0] = params.alpha;
                        res.output[1] = params.beta;
                        res.output[2] = params.gamma;
                        res.output[3] = params.zeta;

                        for (size_t i = 4; i < to_field.size(); i++) {
                            res.output[i] = to_field[i - 4];
                        }

                        return res;
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_PLONK_MAP_FIELDS_HPP
