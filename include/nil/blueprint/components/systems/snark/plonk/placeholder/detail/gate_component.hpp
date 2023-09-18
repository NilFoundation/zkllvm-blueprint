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
                    : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 1> {

                    // constexpr static const std::uint32_t WitnessesAmount = WitnessesAmount;
                    constexpr static const std::uint32_t ConstantsAmount = 0;

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 1>;


                    constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t degree){
                        
                        if (degree == 0) {
                            return 1;
                        } else {
                            std::size_t r = std::ceil(2.0 * degree / (witness_amount - 1));
                            if ((2 * degree - 1) % (witness_amount - 1) + 1 >= witness_amount - 3) {
                                r += 1;
                                // need_extra_row = true;
                            }
                            return r;
                        }
                    }

                public:
                    using var = typename component_type::var;

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t degree){
                        return rows_amount_internal(witness_amount, degree);
                    }

                    constexpr static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t degree){
                        return (degree == 0 ? 1 : 2 * witness_amount + 1);
                    }

                    const std::size_t _d;
                    bool need_extra_row = false;

                    const std::size_t rows_amount = get_rows_amount(WitnessesAmount, _d);
                    const std::size_t gates_amount = get_gates_amount(WitnessesAmount, _d);


                    struct input_type {
                        var theta;
                        std::vector<var> constraints;  
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
                        ss << "_" << WitnessesAmount << "_" << gates_amount;
                        return ss.str();
                    }

                    template<typename ContainerType>
                    gate_component(ContainerType witness, std::size_t _d_) : component_type(witness, {}, {}), _d(_d_) {
                        if ( (_d >= 0)  && ((2 * _d - 1) % (WitnessesAmount - 1) + 1 >= WitnessesAmount - 3)) {
                            need_extra_row = true;
                        }
                    };

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    gate_component(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input, std::size_t _d_) :
                        component_type(witness, constant, public_input),
                        _d(_d_) {
                        if ( (_d >= 0)  && ((2 * _d - 1) % (WitnessesAmount - 1) + 1 >= WitnessesAmount - 3)) {
                            need_extra_row = true;
                        }
                    };

                    gate_component(
                        std::initializer_list<typename component_type::witness_container_type::value_type>
                            witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        std::size_t _d_) :
                        component_type(witnesses, constants, public_inputs),
                        _d(_d_) {
                        if ( (_d >= 0)  && ((2 * _d - 1) % (WitnessesAmount - 1) + 1 >= WitnessesAmount - 3)) {
                            need_extra_row = true;
                        }
                    };
                };

            }    // namespace detail

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            using plonk_gate_component = detail::gate_component<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_assignments(
                    const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessAmount>::input_type instance_input,
                    const std::size_t start_row_index) {

                std::size_t row = start_row_index;
                using var =
                    typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                typename BlueprintFieldType::value_type q = var_value(assignment, instance_input.selector);
                typename BlueprintFieldType::value_type theta = var_value(assignment, instance_input.theta);
                
                std::vector<typename BlueprintFieldType::value_type> assignments;
                typename BlueprintFieldType::value_type G = BlueprintFieldType::value_type::zero();

                typename BlueprintFieldType::value_type tmp;

                for (std::size_t i = 1; i <= component._d; i++) {
                    tmp = var_value(assignment, instance_input.constraints[component._d - i + 1]);
                    assignments.push_back(tmp);
                    G = theta * (G + tmp);
                    assignments.push_back(G);
                }
                G = q * (G + var_value(assignment, instance_input.constraints[0]));

                std::size_t r = 0, j = 0, i = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / (WitnessAmount - 1);
                    j = i % (WitnessAmount - 1) + 1;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r;
                if (component._d > 0) {
                    for (r = start_row_index; r <= row; r++) {
                        assignment.witness(component.W(0), r) = theta;
                    }
                    j = (assignments.size() % (WitnessAmount - 1)) + 1;
                    if (component.need_extra_row) {
                        j = 0;
                        row++;
                    }
                }

                assignment.witness(component.W(j), row) = var_value(assignment, instance_input.constraints[0]);
                assignment.witness(component.W(j + 1), row) = q;
                assignment.witness(component.W(WitnessAmount - 1), row) = G;

                // std::cout << "W(" << j << "," << row << "): " << var_value(assignment, instance_input.constraints[0]).data << "\n";
                // std::cout << "W(" << j+1 << "," << row << "): " << q.data << "\n";
                // std::cout << "W(" << WitnessAmount - 1 << "," << row << "): " << G.data << "\n";

                return typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessAmount>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            void generate_gates(
                const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                    WitnessAmount>::input_type instance_input,
                const std::size_t first_selector_index) {

                using var =
                    typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                if (component._d == 0) {
                    auto constraint_ =
                        bp.add_constraint(var(component.W(WitnessAmount - 1), 0) -
                                          var(component.W(1), 0) * var(component.W(0), 0));    // G = q * C_0
                    bp.add_gate(first_selector_index, {constraint_});
                } else {
                    auto constraint_1 = bp.add_constraint(
                        var(component.W(2), 0) - var(component.W(1), 0) * var(component.W(0), 0));    // G = theta * C_d
                    bp.add_gate(first_selector_index, {constraint_1});

                    auto constraint_2 = bp.add_constraint(
                        var(component.W(1), 0) - var(component.W(0), 0) * (var(component.W(WitnessAmount - 1), -1) +
                                                                           var(component.W(WitnessAmount - 2), -1)));
                    bp.add_gate(first_selector_index + 1, {constraint_2});

                    auto constraint_3 = bp.add_constraint(
                        var(component.W(2), 0) -
                        var(component.W(0), 0) * (var(component.W(1), 0) + var(component.W(WitnessAmount - 1), -1)));
                    bp.add_gate(first_selector_index + 2, {constraint_3});

                    for (std::size_t i = 3; i <= WitnessAmount; i++) {
                        auto constraint_i = bp.add_constraint(
                            var(component.W(i), 0) -
                            var(component.W(0), 0) * (var(component.W(i - 1), 0) + var(component.W(i - 2), 0)));
                        bp.add_gate(first_selector_index + i, {constraint_i});
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
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            void generate_copy_constraints(
                const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                    WitnessAmount>::input_type instance_input,
                const std::size_t start_row_index) {

                using var =
                    typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                std::size_t row = start_row_index;

                std::size_t r = 0, j = 0;
                if (component._d > 0) {
                    for (std::size_t i = start_row_index; i < component.rows_amount - 1; i++) {
                        bp.add_copy_constraint({var(component.W(0), row + i, false), instance_input.theta});
                    }
                    if (!component.need_extra_row) {
                        bp.add_copy_constraint(
                            {var(component.W(0), row + component.rows_amount - 1, false), instance_input.theta});
                    }

                    for (std::size_t i = 0; i < component._d; i++) {
                        r = (2 * i) / (WitnessAmount - 1);
                        j = (2 * i) % (WitnessAmount - 1) + 1;
                        bp.add_copy_constraint(
                            {var(component.W(j), row + r, false), instance_input.constraints[component._d - i]});
                    }
                    row = start_row_index + component.rows_amount - 1;
                    j = 2 * component._d % (WitnessAmount - 1) + 1;
                    if (component.need_extra_row) {
                        j = 0;
                    }
                }
                bp.add_copy_constraint({var(component.W(j), row, false), instance_input.constraints[0]});
                bp.add_copy_constraint({var(component.W(j + 1), row, false), instance_input.selector});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 3, bool> = true>
            typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_circuit(
                    const plonk_gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessAmount>::input_type instance_input,
                    const std::size_t start_row_index) {

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

                if (component._d > 0) {
                    // first row gates
                    std::size_t last_gate = (2 * component._d - 1) % (WitnessAmount - 1) + 1;
                    std::size_t first_row_last_gate = WitnessAmount - 1;

                    if (component.rows_amount == 1 || (component.rows_amount == 2 && component.need_extra_row)) {
                        first_row_last_gate = last_gate;
                    }

                    for (std::size_t i = 4; i <= first_row_last_gate; i = i + 2) {
                        assignment.enable_selector(first_selector_index + i, row);
                    }

                    if (component.rows_amount > 1) {
                        // middle row gates
                        std::size_t r;
                        std::size_t tmp = 2;
                        for (r = 1; r < component.rows_amount - 2; r++) {
                            tmp = 2 - ((WitnessAmount - 1) % 2) * (r % 2);
                            for (std::size_t i = tmp; i <= WitnessAmount; i = i + 2) {
                                assignment.enable_selector(first_selector_index + i, row + r);
                            }
                        }

                        tmp = 2 - ((WitnessAmount - 1) % 2) * (r % 2);
                        if (component.need_extra_row && r == component.rows_amount - 2) {
                            for (std::size_t i = tmp; i <= last_gate; i = i + 2) {
                                assignment.enable_selector(first_selector_index + i, row + r);
                            }
                            r++;
                        }

                        // last row gates
                        tmp = 2 - (r % 2) * ((WitnessAmount - 1) % 2);
                        if (component.need_extra_row) {
                            assignment.enable_selector(first_selector_index + last_gate + 4, row + r);
                        } else {
                            for (std::size_t i = tmp; i <= last_gate; i = i + 2) {
                                assignment.enable_selector(first_selector_index + i, row + r);
                            }
                            assignment.enable_selector(first_selector_index + WitnessAmount + last_gate + 4, row + r);
                        }
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_gate_component<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessAmount>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP