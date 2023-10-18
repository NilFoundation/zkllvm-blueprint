//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_AUXILIARY_SPONGE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_AUXILIARY_SPONGE_HPP

#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/sponge.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<size_t num_squeezes,
                        typename ArithmetizationType,
                        typename CurveType>
            class aux;

            template<typename BlueprintFieldType,
                        size_t num_squeezes,
                        typename ArithmetizationParams,
                        typename CurveType>
            class aux<
                num_squeezes,
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType> {

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using sponge_type =
                    nil::blueprint::components::kimchi_sponge<ArithmetizationType, CurveType>;

            public:
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return aux::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3)),
                        true
                    );
                    return manifest;
                }

                constexpr static const std::size_t rows_amount =
                    sponge_type::init_rows + sponge_type::absorb_rows * num_squeezes +
                    sponge_type::squeeze_rows * num_squeezes;
                constexpr static const std::size_t gates_amount = 0;


                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return rows_amount;
                }

                struct params_type {
                    std::vector<var> input;
                    var zero;
                };

                struct result_type {
                    var squeezed = var(0, 0, false);
                    result_type(var &input) : squeezed(input) {}
                    result_type(const params_type &params, const std::size_t &start_row_index) {
                        // TODO: fix the six! need to actually procure this var from output
                        squeezed = var(6, start_row_index + rows_amount - 1, false, var::column_type::witness);
                    }
                };

                static result_type generate_circuit(
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const params_type &params,
                    const std::size_t start_row_index) {

                    std::size_t row = start_row_index;
                    sponge_type sponge;
                    sponge.init_circuit(bp, assignment, params.zero, row);
                    row += sponge_type::init_rows;
                    for (std::size_t i = 0; i < params.input.size(); ++i) {
                        sponge.absorb_circuit(bp, assignment, params.input[i], row);
                        row += sponge_type::absorb_rows;
                    }
                    var sq;
                    for (size_t i = 0; i < num_squeezes; ++i) {
                        sq = sponge.squeeze_circuit(bp, assignment, row);
                        row += sponge_type::squeeze_rows;
                    }
                    return {sq};
                }

                static result_type generate_assignments(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                    const params_type &params,
                    const std::size_t start_row_index) {

                    std::size_t row = start_row_index;

                    sponge_type sponge;
                    sponge.init_assignment(assignment, params.zero, row);
                    row += sponge_type::init_rows;
                    for (std::size_t i = 0; i < params.input.size(); ++i) {
                        sponge.absorb_assignment(assignment, params.input[i], row);
                        row += sponge_type::absorb_rows;
                    }
                    var sq;
                    for (size_t i = 0; i < num_squeezes; ++i) {
                        sq = sponge.squeeze_assignment(assignment, row);
                        row += sponge_type::squeeze_rows;
                    }
                    return {sq};
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP
