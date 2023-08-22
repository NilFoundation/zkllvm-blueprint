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
// @file Declaration of interfaces for auxiliary components for the GATE_COMPONENT component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
                class gate_component;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                class gate_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    WitnessesAmount>
                    : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0> {

                    constexpr static const std::uint32_t WitnessesAmount = WitnessesAmount;
                    constexpr static const std::uint32_t ConstantsAmount = 0;

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 0>;

                public:
                    using var = typename component_type::var;

                    std::size_t rows_amount;
                    std::size_t gates_amount = 2 * WitnessesAmount + 1;
                    const std::size_t N_cr;

                    struct input_type {
                        var theta;
                        std::vector<var> constraints;    // new type ?
                        var selector;
                    };

                    struct result_type {
                        var output;

                        result_type(const gate_component &component, std::uint32_t start_row_index) {
                            output = var(component.W(WitnessesAmount - 1), start_row_index + component.rows_amount - 1,
                                         false);
                        }
                    };

                    nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                        std::stringstream ss;
                        ss << "_" << WitnessesAmount << "_" << N_cr;
                        return ss.str();
                    }

                    template<typename ContainerType>
                    gate_component(ContainerType witness, std::size_t N_cr_) :
                        component_type(witness, {}, {}), N_cr(N_cr_) {
                        rows_amount = 3 * N_cr / (WitnessesAmount - 1) + 1;
                    };

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    gate_component(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input, std::size_t N_cr_) :
                        component_type(witness, constant, public_input),
                        N_cr(N_cr_) {
                        rows_amount = 3 * N_cr / (WitnessesAmount - 1) + 1;
                    };

                    gate_component(
                        std::initializer_list<typename component_type::witness_container_type::value_type>
                            witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        std::size_t N_cr_) :
                        component_type(witnesses, constants, public_inputs),
                        N_cr(N_cr_) {
                        rows_amount = 3 * N_cr / (WitnessesAmount - 1) + 1;
                    };
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
                using plonk_gate_component = gate_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    WitnessAmount>;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                    generate_assignments(
                        const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>> &assignment,
                        const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                            WitnessAmount>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                    std::size_t row = start_row_index;
                    using var =
                        typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                    var q = var_value(assignment, instance_input.selector);
                    var theta = var_value(assignment, instance_input.theta);
                    var theta_acc = theta;
                    std::vector<var> assignments;
                    var G = var::value_type::zero();

                    var tmp;
                    for (std::size_t i = 1; i < component.N_cr - 1; i++) {
                        assignments.push_back(theta_acc);
                        tmp = var_value(assignment, instance_input.constraints[i]);
                        assignments.push_back(tmp);
                        G = G + theta_acc * tmp;
                        assignments.push_back(G);
                        theta_acc *= theta;
                    }
                    G = q * (G + var_value(assignment, instance_input.constraints[0]));

                    std::size_t r, j;
                    for (std::size_t i = 0; i < assignemnts.size(); i++) {
                        r = i / WitnessAmount;
                        j = i % WitnessAmount;
                        assignment.witness(component.W(j), row + r) = assignments[i];
                    }
                    row += r;
                    if (j >= WitnessAmount - 3) {
                        j = 0;
                        row++;
                    }
                    assignment.witness(component.W(j), row) = var_value(assignment, instance_input.constraints[0]);
                    assignment.witness(component.W(j + 1), row) = q;
                    assignment.witness(component.W(WitnessAmount - 1), row) = G;

                    return typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams,
                                                               WitnessAmount>::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                void generate_gates(
                    const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessAmount>::input_type instance_input,
                    const std::uint32_t first_selector_index) {

                    using var =
                        typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                    auto constraint_1 = bp.add_constraint(
                        var(component.W(2), 0) - var(component.W(1), 0) * var(component.W(0), 0));    // G = theta * C_1
                    bp.add_gate(first_selector_index, {constraint_1});

                    auto constraint_2 = bp.add_constraint(var(component.W(0), 0) -
                                                          var(component.W(WitnessAmount - 2), -1) *
                                                              var(component.W(WitnessAmount - 1), -1) -
                                                          var(component.W(WitnessAmount - 3), -1));
                    bp.add_gate(first_selector_index + 1, {constraint_2});

                    auto constraint_3 = bp.add_constraint(
                        var(component.W(1), 0) - var(component.W(0), 0) * var(component.W(WitnessAmount - 1), -1) -
                        var(component.W(WitnessAmount - 2), -1));
                    bp.add_gate(first_selector_index + 2, {constraint_3});

                    auto constraint_4 =
                        bp.add_constraint(var(component.W(2), 0) - var(component.W(1), 0) * var(component.W(0), 0) -
                                          var(component.W(WitnessAmount - 1), -1));
                    bp.add_gate(first_selector_index + 3, {constraint_4});

                    for (std::size_t i = 3; i < WitnessAmount; i++) {
                        auto constraint_i = bp.add_constraint(var(component.W(i), 0) -
                                                              var(component.W(i - 1), 0) * var(component.W(i - 2), 0) -
                                                              var(component.W(i - 3), 0));
                        bp.add_gate(first_selector_index + i + 1, {constraint_4});
                    }

                    auto constraint_5 = bp.add_constraint(
                        var(component.W(WitnessAmount - 1), 0) -
                        var(component.W(1), 0) * (var(component.W(0), 0) + var(component.W(WitnessAmount - 3), -1)));
                    bp.add_gate(first_selector_index + WitnessAmount + 1, {constraint_5});

                    auto constraint_6 = bp.add_constraint(
                        var(component.W(WitnessAmount - 1), 0) -
                        var(component.W(1), 0) * (var(component.W(0), 0) + var(component.W(WitnessAmount - 2), -1)));
                    bp.add_gate(first_selector_index + WitnessAmount + 2, {constraint_6});

                    auto constraint_7 = bp.add_constraint(
                        var(component.W(WitnessAmount - 1), 0) -
                        var(component.W(1), 0) * (var(component.W(0), 0) + var(component.W(WitnessAmount - 1), -1)));
                    bp.add_gate(first_selector_index + WitnessAmount + 3, {constraint_7});

                    for (std::size_t i = 2; i < WitnessAmount - 1; i++) {
                        auto constraint_i = bp.add_constraint(
                            var(component.W(WitnessAmount - 1), 0) -
                            var(component.W(i), 0) * (var(component.W(i - 1), 0) + var(component.W(i - 2), 0)));
                        bp.add_gate(first_selector_index + WitnessAmount + i + 2, {constraint_i});
                    }
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                void generate_copy_constraints(
                    const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessAmount>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using var =
                        typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                    std::size_t row = start_row_index;

                    bp.add_copy_constraint({var(component.W(0), row, false), instance_input.theta});

                    std::size_t r, j;
                    for (std::size_t i = 0; i < component.N_cr - 1; i++) {
                        r = (3 * i + 1) / WitnessAmount;
                        j = (3 * i + 1) % WitnessAmount;
                        bp.add_copy_constraint(
                            {var(component.W(j), row + r, false), instance_input.constraints[i + 1]});
                    }
                    row += r;
                    if (j >= WitnessAmount - 3) {
                        j = 0;
                        row++;
                    }
                    bp.add_copy_constraint({var(component.W(j), row, false), instance_input.constraints[0]});
                    bp.add_copy_constraint({var(component.W(j + 1), row, false), instance_input.selector});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                    generate_circuit(
                        const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>> &assignment,
                        const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                            WitnessAmount>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                    std::size_t row = start_row_index;

                    using var =
                        typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;
                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;

                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }

                    assignment.enable_selector(first_selector_index, row);

                    // first row gates
                    for (std::size_t i = 6; i <= WitnessAmount; i = i + 3) {
                        assignment.enable_selector(first_selector_index + i, row);
                    }

                    // middle row gates
                    for (std::size_t r = 1; r < component.rows_amount - 1; r++) {
                        auto tmp = 3 - (r % 3) * (WitnessAmount % 3);
                        if (tmp < 0) {
                            tmp += 3;
                        }
                        for (std::size_t i = tmp; i <= WitnessAmount; i = i + 3) {
                            assignment.enable_selector(first_selector_index + i, row + r);
                        }
                    }

                    // last row gates

                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                    return typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessAmount>::result_type(component, start_row_index);
                }
            }    // namespace detail
        }        // namespace components
    }            // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP