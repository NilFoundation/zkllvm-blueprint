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
// @file Declaration of interfaces for auxiliary components for the LOOKUP_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_F3_LOOP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_F3_LOOP_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
                class f3_loop;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                class f3_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              WitnessesAmount>
                    : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 1> {

                    constexpr static const std::uint32_t ConstantsAmount = 0;

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 1>;

                    constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t n) {

                        std::size_t r = std::ceil(4.0 * n / witness_amount);
                        return r;
                    }

                public:
                    using var = typename component_type::var;

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t m) {
                        return rows_amount_internal(witness_amount, m);
                    }

                    constexpr static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t degree) {
                        if (witness_amount % 4 == 0) {
                            return witness_amount / 4 + 1;
                        }
                        if (witness_amount % 4 == 2) {
                            return witness_amount / 2 + 1;
                        }
                        return witness_amount + 1;
                    }

                    const std::size_t m;

                    const std::size_t rows_amount = get_rows_amount(WitnessesAmount, m);
                    const std::size_t gates_amount = get_gates_amount(WitnessesAmount, m);

                    struct input_type {
                        std::vector<var> alphas;
                        std::vector<var> s;
                        std::vector<var> t;
                    };

                    struct result_type {
                        var output;

                        result_type(const f3_loop &component, std::uint32_t start_row_index) {
                            std::size_t l = 4 * component.m % WitnessesAmount;
                            if (l == 0) {
                                l = WitnessesAmount;
                            }
                            output = var(component.W(l - 1), start_row_index + component.rows_amount - 1, false);
                        }
                    };

                    nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                        std::stringstream ss;
                        ss << "_" << WitnessesAmount << "_" << m;
                        return ss.str();
                    }

                    template<typename ContainerType>
                    f3_loop(ContainerType witness, std::size_t m_) : component_type(witness, {}, {}), m(m_) {};

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    f3_loop(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input, std::size_t m_) :
                        component_type(witness, constant, public_input),
                        m(m_) {};

                    f3_loop(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs,
                            std::size_t m_) :
                        component_type(witnesses, constants, public_inputs),
                        m(m_) {};
                };
            }    // namespace detail

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            using plonk_f3_loop =
                detail::f3_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 4, bool> = true>
            typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_assignments(
                    const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                assert(instance_input.s.size() == instance_input.t.size());
                assert(instance_input.s.size() == instance_input.alphas.size());
                assert(instance_input.s.size() == component.m);

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                typename BlueprintFieldType::value_type f3 = BlueprintFieldType::value_type::zero();
                std::vector<typename BlueprintFieldType::value_type> assignments;
                for (std::size_t i = 0; i < component.m; i++) {
                    typename BlueprintFieldType::value_type s_i = var_value(assignment, instance_input.s[i]);
                    typename BlueprintFieldType::value_type t_i = var_value(assignment, instance_input.t[i]);
                    typename BlueprintFieldType::value_type alpha_i = var_value(assignment, instance_input.alphas[i]);
                    f3 = f3 + (s_i - t_i) * alpha_i;
                    assignments.push_back(alpha_i);
                    assignments.push_back(s_i);
                    assignments.push_back(t_i);
                    assignments.push_back(f3);
                }

                std::size_t r = 0, j = 0, i = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / (WitnessAmount);
                    j = i % WitnessAmount;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r;

                return typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 4, bool> = true>
            void generate_gates(
                const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::input_type
                    instance_input,
                const std::uint32_t first_selector_index) {

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                std::size_t ctr = 0;

                auto constraint_1 =
                    bp.add_constraint(var(component.W(3), 0) -
                                      (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0));
                bp.add_gate(first_selector_index + ctr, {constraint_1});
                ctr++;

                if (WitnessAmount % 4 == 0) {
                    auto constraint_2 =
                        bp.add_constraint(var(component.W(3), 0) - var(component.W(WitnessAmount - 1), -1) -
                                          (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0));
                    bp.add_gate(first_selector_index + ctr, {constraint_2});
                    ctr++;

                    for (std::size_t j = 7; j < WitnessAmount; j = j + 4) {
                        auto constraint_ = bp.add_constraint(var(component.W(j), 0) - var(component.W(j - 4), 0) -
                                                             (var(component.W(j - 2), 0) - var(component.W(j - 1), 0)) *
                                                                 var(component.W(j - 3), 0));
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }
                } else if (WitnessAmount % 4 == 2) {
                    auto constraint_2 =
                        bp.add_constraint(var(component.W(1), 0) - var(component.W(WitnessAmount - 3), -1) -
                                          (var(component.W(WitnessAmount - 1), -1) - var(component.W(0), 0)) *
                                              var(component.W(WitnessAmount - 2), -1));
                    bp.add_gate(first_selector_index + ctr, {constraint_2});
                    ctr++;

                    auto constraint_3 =
                        bp.add_constraint(var(component.W(3), 0) - var(component.W(WitnessAmount - 1), -1) -
                                          (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0));
                    bp.add_gate(first_selector_index + ctr, {constraint_3});
                    ctr++;

                    for (std::size_t j = 5; j < WitnessAmount; j = j + 2) {
                        auto constraint_ = bp.add_constraint(var(component.W(j), 0) - var(component.W(j - 4), 0) -
                                                             (var(component.W(j - 2), 0) - var(component.W(j - 1), 0)) *
                                                                 var(component.W(j - 3), 0));
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                } else {
                    auto constraint_2 = bp.add_constraint(
                        var(component.W(0), 0) - var(component.W(WitnessAmount - 4), -1) -
                        (var(component.W(WitnessAmount - 2), -1) - var(component.W(WitnessAmount - 1), -1)) *
                            var(component.W(WitnessAmount - 3), -1));
                    bp.add_gate(first_selector_index + ctr, {constraint_2});
                    ctr++;

                    auto constraint_3 =
                        bp.add_constraint(var(component.W(1), 0) - var(component.W(WitnessAmount - 3), -1) -
                                          (var(component.W(WitnessAmount - 1), -1) - var(component.W(0), 0)) *
                                              var(component.W(WitnessAmount - 2), -1));
                    bp.add_gate(first_selector_index + ctr, {constraint_3});
                    ctr++;

                    auto constraint_4 = bp.add_constraint(
                        var(component.W(2), 0) - var(component.W(WitnessAmount - 2), -1) -
                        (var(component.W(0), 0) - var(component.W(1), 0)) * var(component.W(WitnessAmount - 1), -1));
                    bp.add_gate(first_selector_index + ctr, {constraint_4});
                    ctr++;

                    auto constraint_5 =
                        bp.add_constraint(var(component.W(3), 0) - var(component.W(WitnessAmount - 1), -1) -
                                          (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0));
                    bp.add_gate(first_selector_index + ctr, {constraint_5});
                    ctr++;

                    for (std::size_t j = 4; j < WitnessAmount; j++) {
                        auto constraint_ = bp.add_constraint(var(component.W(j), 0) - var(component.W(j - 4), 0) -
                                                             (var(component.W(j - 2), 0) - var(component.W(j - 1), 0)) *
                                                                 var(component.W(j - 3), 0));
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 4, bool> = true>
            void generate_copy_constraints(
                const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;
                std::size_t row = start_row_index;

                std::size_t tmp;
                for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                    for (std::size_t j = 0; j < WitnessAmount; j++) {
                        tmp = r * WitnessAmount + j;
                        if (tmp % 4 == 0) {
                            bp.add_copy_constraint(
                                {var(component.W(j), row + r, false), instance_input.alphas[tmp / 4]});
                        } else if (tmp % 4 == 1) {
                            bp.add_copy_constraint({var(component.W(j), row + r, false), instance_input.s[tmp / 4]});
                        } else if (tmp % 4 == 2) {
                            bp.add_copy_constraint({var(component.W(j), row + r, false), instance_input.t[tmp / 4]});
                        }
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
                     std::enable_if_t<WitnessAmount >= 4, bool> = true>
            typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_circuit(
                    const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                assert(instance_input.s.size() == instance_input.t.size());
                assert(instance_input.s.size() == component.m);

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;
                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, row);

                if (WitnessAmount % 4 == 0) {
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        for (std::size_t j = 3; j < WitnessAmount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(first_selector_index + (j / 4 + 1), row + r);
                        }
                    }
                } else if (WitnessAmount % 4 == 2) {
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        for (std::size_t j = 3 - 2 * (r % 2); j < WitnessAmount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(first_selector_index + (j / 2 + 1), row + r);
                        }
                    }
                } else if (WitnessAmount % 4 == 3) {
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        std::size_t tmp = r % 4 - 1;
                        if (tmp < 0) {
                            tmp += 4;
                        }
                        for (std::size_t j = tmp; j < WitnessAmount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(first_selector_index + j + 1, row + r);
                        }
                    }
                } else {
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        std::size_t tmp = 3 - r % 4;

                        for (std::size_t j = tmp; j < WitnessAmount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(first_selector_index + j + 1, row + r);
                        }
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_F3_LOOP_HPP