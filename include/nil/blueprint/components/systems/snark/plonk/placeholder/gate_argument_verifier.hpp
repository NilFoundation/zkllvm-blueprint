//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the GATE_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/gate_component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, std::uint32_t WitnessAmount>
            class basic_constraints_verifier;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            class basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount, 0, 1> {

                // constexpr static const std::uint32_t WitnessAmount = WitnessAmount;
                constexpr static const std::uint32_t ConstantsAmount = 0;

                constexpr static const std::size_t
                    rows_amount_internal(std::size_t witness_amount, const std::vector<std::size_t> gate_sizes) {

                    std::size_t r = 0;
                    for (std::size_t i = 0; i < gate_sizes.size(); i++) {
                        r += gate_component::get_rows_amount(witness_amount, gate_sizes[i] - 1);
                    }
                    r += std::ceil(gate_sizes.size() * 1.0 / (witness_amount - 1));
                    return r;
                }

                constexpr static const std::size_t
                    gates_amount_internal(std::size_t witness_amount, const std::vector<std::size_t> gate_sizes) {
                    if( gate_sizes.size() < witness_amount ){
                        return 1;
                    }
                    return 3;
                }

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount, ConstantsAmount, 1>;

            public:
                using var = typename component_type::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType, WitnessAmount>;

                const std::size_t N_sl;
                const std::vector<std::size_t> gate_sizes;
                const std::size_t rows_amount = rows_amount_internal(WitnessAmount, gate_sizes);
                const std::size_t gates_amount = gates_amount_internal(WitnessAmount, gate_sizes);;

                struct input_type {
                    var theta;
                    std::vector<std::vector<var>> gates;
                    std::vector<var> selectors;
                };

                struct result_type {
                    var output;

                    result_type(const basic_constraints_verifier &component, std::uint32_t start_row_index) {
                        output =
                            var(component.W(WitnessAmount - 1), start_row_index + component.rows_amount - 1, false);
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessAmount << "_" << N_sl;
                    return ss.str();
                }

                template<typename ContainerType>
                basic_constraints_verifier(ContainerType witness, std::size_t N_sl_,
                                           std::vector<std::size_t> &gate_sizes_) :
                    component_type(witness, {}, {}),
                    N_sl(N_sl_), gate_sizes(gate_sizes_) {
                                     // rows_amount = 2 * N_sl / (WitnessAmount - 1) + 1;
                                 };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                basic_constraints_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                           PublicInputContainerType public_input, std::size_t N_sl_,
                                           std::vector<std::size_t> &gate_sizes_) :
                    component_type(witness, constant, public_input),
                    N_sl(N_sl_), gate_sizes(gate_sizes_) {
                                     // rows_amount = 2 * N_sl / (WitnessAmount - 1) + 1;
                                 };

                basic_constraints_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t N_sl_, std::vector<std::size_t> &gate_sizes_) :
                    component_type(witnesses, constants, public_inputs),
                    N_sl(N_sl_), gate_sizes(gate_sizes_) {
                                     // rows_amount = 2 * N_sl / (WitnessAmount - 1) + 1;
                                 };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            using plonk_basic_constraints_verifier = basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::result_type
                generate_assignments(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                    WitnessAmount>::input_type instance_input,
                    const std::size_t start_row_index) {

                assert(component.N_sl == instance_input.gates.size());
                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessAmount>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType, WitnessAmount>;

                std::size_t row = start_row_index;
                std::vector<var> G;
                std::array<std::uint32_t, WitnessAmount> witnesses;
                for (std::uint32_t i = 0; i < WitnessAmount; i++) {
                    witnesses[i] = component.W(i);
                }
                for (std::size_t i = 0; i < component.N_sl; i++) {
                    assert(instance_input.gates[i].size() == component.gate_sizes[i]);

                    std::size_t c_size = instance_input.gates[i].size();
                    gate_component gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                                  std::array<std::uint32_t, 1>(), c_size - 1);

                    typename gate_component::input_type gate_input = {instance_input.theta, instance_input.gates[i],
                                                                      instance_input.selectors[i]};

                    typename gate_component::result_type gate_i_result =
                        generate_assignments(gate_instance, assignment, gate_input, row);

                    G.push_back(gate_i_result.output);
                    row += gate_instance.rows_amount;
                }

                std::size_t r = 0, j = 0;
                for (std::size_t i = 0; i < G.size(); i++) {
                    r = i / (WitnessAmount - 1);
                    j = i % (WitnessAmount - 1);
                    assignment.witness(component.W(j), row + r) = var_value(assignment, G[i]);
                }
                
                std::size_t k = WitnessAmount - 1;
                typename BlueprintFieldType::value_type sum = 0;
                for (std::size_t rr = 0; rr <= r; rr++) {
                    for (std::size_t i = 0; i < k; i++) {
                        if (k * rr + i >= G.size()) {
                            break;
                        }
                        sum += var_value(assignment, G[k * rr + i]);
                    }
                    assignment.witness(component.W(WitnessAmount - 1), row + r) = sum;
                }
                row += r;

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessAmount>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            void generate_gates(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessAmount>::input_type instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessAmount>::var;

                using term = typename crypto3::zk::snark::plonk_constraint<BlueprintFieldType>::base_type;

                std::size_t last_pos = component.N_sl % WitnessAmount;

                if (component.N_sl <= WitnessAmount - 1) {
                    term constraint_1 = var(component.W(WitnessAmount - 1), 0);
                    for (std::size_t j = 0; j < last_pos; j++) {
                        constraint_1 = constraint_1 - var(component.W(j), 0);
                    }
                    bp.add_gate(first_selector_index, {bp.add_constraint(constraint_1)});
                } else {
                    term constraint_1 = var(component.W(WitnessAmount - 1), 0);
                    for (std::size_t j = 0; j < WitnessAmount - 1; j++) {
                        constraint_1 = constraint_1 - var(component.W(j), 0);
                    }
                    bp.add_gate(first_selector_index, {bp.add_constraint(constraint_1)});

                    term constraint_2 =
                        var(component.W(WitnessAmount - 1), 0) - var(component.W(WitnessAmount - 1), -1);
                    for (std::size_t j = 0; j < WitnessAmount - 1; j++) {
                        constraint_2 = constraint_2 - var(component.W(j), 0);
                    }
                    bp.add_gate(first_selector_index + 1, {bp.add_constraint(constraint_2)});

                    term constraint_3 =
                        var(component.W(WitnessAmount - 1), 0) - var(component.W(WitnessAmount - 1), -1);
                    for (std::size_t j = 0; j < last_pos; j++) {
                        constraint_3 = constraint_3 - var(component.W(j), 0);
                    }
                    bp.add_gate(first_selector_index + 2, {bp.add_constraint(constraint_3)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            void generate_copy_constraints(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessAmount>::input_type instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessAmount>::var;
                std::size_t row = start_row_index;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using gate_component = detail::gate_component<ArithmetizationType, WitnessAmount>;

                std::vector<std::size_t> row_positions;
                for (std::size_t i = 0; i < component.N_sl; i++) {
                    std::size_t r = gate_component::get_rows_amount(WitnessAmount, component.gate_sizes[i] - 1);
                    row += r;
                    row_positions.push_back(row);
                }
                assert(row_positions.size() == component.N_sl);

                for (std::size_t i = 0; i < component.N_sl; i++) {
                    std::size_t j = i % WitnessAmount;
                    std::size_t r = i / (WitnessAmount - 1);

                    bp.add_copy_constraint({var(component.W(j), row + r, false),
                                            var(component.W(WitnessAmount - 1), row_positions[i] - 1, false)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::result_type
                generate_circuit(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                    WitnessAmount>::input_type instance_input,
                    const std::size_t start_row_index) {

                assert(component.N_sl == instance_input.gates.size());
                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessAmount>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType, WitnessAmount>;

                std::size_t row = start_row_index;

                std::vector<typename BlueprintFieldType::value_type> G;
                std::array<std::uint32_t, WitnessAmount> witnesses;
                for (std::uint32_t i = 0; i < WitnessAmount; i++) {
                    witnesses[i] = component.W(i);
                }
                for (std::size_t i = 0; i < component.N_sl; i++) {
                    assert(instance_input.gates[i].size() == component.gate_sizes[i]);
                    gate_component gate_instance =
                        gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                       instance_input.gates[i].size() - 1);
                    typename gate_component::input_type gate_input = {instance_input.theta, instance_input.gates[i],
                                                                      instance_input.selectors[i]};

                    typename gate_component::result_type gate_i_result =
                        generate_circuit(gate_instance, bp, assignment, gate_input, row);
                    row += gate_instance.rows_amount;
                }

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, row);

                if (component.N_sl >= WitnessAmount) {
                    row++;
                    std::size_t n = component.N_sl / WitnessAmount;
                    while (n--) {
                        assignment.enable_selector(first_selector_index + 1, row);
                        row++;
                    }
                    assignment.enable_selector(first_selector_index + 2, row);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessAmount>::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP