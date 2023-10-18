//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_SPONGE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_SPONGE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Poseidon sponge construction
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/poseidon.rs#L64
            template<typename ArithmetizationType, typename CurveType>
            class kimchi_sponge;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            class kimchi_sponge<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType> {

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using poseidon_component =
                    nil::blueprint::components::poseidon<ArithmetizationType, BlueprintFieldType>;
                using add_component =
                    nil::blueprint::components::addition<ArithmetizationType, BlueprintFieldType,
                        nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;
                std::size_t state_count = 0;
                bool state_absorbed = true;

                std::array<var, poseidon_component::state_size> state;

                void permute_assignment(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::uint32_t start_row_index) {

                    typename poseidon_component::result_type poseidon_res =
                        poseidon_component::generate_assignments(assignment, {state}, start_row_index);

                    for (std::size_t i = 0; i < poseidon_component::state_size; i++) {
                        state[i] = poseidon_res.output_state[i];
                    }
                }

                void add_input_assignment(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const var &input, std::size_t state_index,
                    const std::size_t start_row_index) {

                    auto addition_result = add_component::generate_assignments(
                        assignment, {input, state[state_index]}, start_row_index);

                    state[state_index] = addition_result.output;
                }

                void permute_circuit(
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {

                    typename poseidon_component::result_type poseidon_res =
                        poseidon_component::generate_circuit(bp, assignment, {state}, start_row_index);

                    for (std::size_t i = 0; i < poseidon_component::state_size; i++) {
                        state[i] = poseidon_res.output_state[i];
                    }
                }

                void add_input_circuit(
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const var &input, std::size_t state_index,
                    const std::size_t start_row_index) {

                    auto addition_result = add_component::generate_circuit(
                        bp, assignment, {input, state[state_index]}, start_row_index);
                    state[state_index] = addition_result.output;
                }

                constexpr static const std::size_t permute_rows = poseidon_component::rows_amount;
                constexpr static const std::size_t add_input_rows = add_component::rows_amount;

            public:
                constexpr static const std::size_t init_rows = 0;
                constexpr static const std::size_t absorb_rows = permute_rows + add_input_rows;
                constexpr static const std::size_t squeeze_rows = permute_rows;
                constexpr static const std::size_t gates_amount = 0;

                constexpr static const std::size_t state_size = poseidon_component::state_size;

                std::array<var, state_size> _inner_state() {
                    return state;
                }

                void init_assignment(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::array<var, 3> &start_state,
                    const std::size_t start_row_index) {

                    state = start_state;
                }

                void init_circuit(
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::array<var, 3> &start_state,
                    const std::size_t start_row_index) {

                    state = start_state;
                }

                void absorb_assignment(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const var &absorbing_value,
                    const std::size_t start_row_index) {

                    std::size_t row = start_row_index;

                    if (this->state_absorbed) {
                        if (this->state_count == poseidon_component::rate) {
                            permute_assignment(assignment, row);
                            row += permute_rows;

                            add_input_assignment(assignment, absorbing_value, 0, row);

                            this->state_count = 1;
                        } else {
                            add_input_assignment(assignment, absorbing_value, this->state_count,
                                                    row);

                            this->state_count++;
                        }
                    } else {
                        add_input_assignment(assignment, absorbing_value, 0, row);

                        this->state_absorbed = true;
                        this->state_count = 1;
                    }
                }

                void absorb_circuit(
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const var &absorbing_value,
                    const std::size_t component_start_row) {

                    std::size_t row = component_start_row;

                    if (this->state_absorbed) {
                        if (this->state_count == poseidon_component::rate) {
                            permute_circuit(bp, assignment, row);

                            row += permute_rows;

                            add_input_circuit(bp, assignment, absorbing_value, 0, row);

                            this->state_count = 1;
                        } else {
                            add_input_circuit(bp, assignment, absorbing_value, this->state_count, row);

                            this->state_count++;
                        }
                    } else {
                        add_input_circuit(bp, assignment, absorbing_value, 0, component_start_row);

                        this->state_absorbed = true;
                        this->state_count = 1;
                    }
                }

                var squeeze_assignment(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {

                    if (!this->state_absorbed) {    // state = squeezed
                        if (this->state_count == poseidon_component::rate) {
                            permute_assignment(assignment, start_row_index);
                            this->state_count = 1;
                            return this->state[0];
                        } else {
                            return this->state[this->state_count++];
                        }
                    } else {
                        permute_assignment(assignment, start_row_index);

                        this->state_absorbed = false;
                        this->state_count = 1;

                        return this->state[0];
                    }
                }

                var squeeze_circuit(
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {

                    if (!this->state_absorbed) {    // state = squeezed
                        if (this->state_count == poseidon_component::rate) {
                            permute_circuit(bp, assignment, start_row_index);
                            this->state_count = 1;
                            return this->state[0];
                        } else {
                            return this->state[this->state_count++];
                        }
                    } else {
                        permute_circuit(bp, assignment, start_row_index);

                        this->state_absorbed = false;
                        this->state_count = 1;

                        return this->state[0];
                    }
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_SPONGE_HPP
