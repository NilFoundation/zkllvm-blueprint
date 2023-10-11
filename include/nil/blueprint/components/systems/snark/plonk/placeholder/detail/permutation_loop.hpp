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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
                class permutation_loop;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                class permutation_loop<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    WitnessesAmount>
                    : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 1> {

                    constexpr static const std::uint32_t ConstantsAmount = 0;

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 1>;

                    constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t n) {

                        std::size_t r = std::ceil(3.0 * n / (witness_amount - 1));
                        if (r < 2)
                            return 2;
                        return r;
                    }

                public:
                    using var = typename component_type::var;

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t m) {
                        return rows_amount_internal(witness_amount, m);
                    }

                    constexpr static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t degree) {
                        return witness_amount + 2;
                    }

                    const std::size_t m;

                    const std::size_t rows_amount = get_rows_amount(WitnessesAmount, m);
                    const std::size_t gates_amount = get_gates_amount(WitnessesAmount, m);

                    struct input_type {
                        var beta;
                        var gamma;
                        std::vector<var> s;
                        std::vector<var> t;
                    };

                    struct result_type {
                        var output;

                        result_type(const permutation_loop &component, std::uint32_t start_row_index) {
                            std::size_t j = (3 * component.m) % (WitnessesAmount - 1);
                            if(j == 0){
                                j = WitnessesAmount - 1;
                            }
                            
                            output = var(component.W(j), start_row_index + component.rows_amount - 1,
                                         false);
                        }
                    };

                    nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                        std::stringstream ss;
                        ss << "_" << WitnessesAmount << "_" << m;
                        return ss.str();
                    }

                    template<typename ContainerType>
                    permutation_loop(ContainerType witness, std::size_t m_) : component_type(witness, {}, {}), m(m_) {};

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    permutation_loop(WitnessContainerType witness, ConstantContainerType constant,
                                     PublicInputContainerType public_input, std::size_t m_) :
                        component_type(witness, constant, public_input),
                        m(m_) {};

                    permutation_loop(
                        std::initializer_list<typename component_type::witness_container_type::value_type>
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
            using plonk_permutation_loop = detail::permutation_loop<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_assignments(
                    const plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessAmount>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                assert(instance_input.s.size() == instance_input.t.size());
                assert(instance_input.s.size() == component.m);

                using var =
                    typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                typename BlueprintFieldType::value_type beta = var_value(assignment, instance_input.beta);
                typename BlueprintFieldType::value_type gamma = var_value(assignment, instance_input.gamma);

                typename BlueprintFieldType::value_type delta = (BlueprintFieldType::value_type::one() + beta) * gamma;

                typename BlueprintFieldType::value_type h = BlueprintFieldType::value_type::one();
                std::vector<typename BlueprintFieldType::value_type> assignments;
                for (std::size_t i = 0; i < component.m; i++) {
                    typename BlueprintFieldType::value_type s_i = var_value(assignment, instance_input.s[i]);
                    typename BlueprintFieldType::value_type t_i = var_value(assignment, instance_input.t[i]);
                    h = h * (delta + s_i + beta * t_i);
                    assignments.push_back(s_i);
                    assignments.push_back(t_i);
                    assignments.push_back(h);
                }

                std::size_t r = 0, j = 0, i = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / (WitnessAmount - 1);
                    j = i % (WitnessAmount - 1) + 1;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r;
                for (r = start_row_index; r <= row; r++) {
                    if (WitnessAmount % 3 == 1) {
                        if ((r - start_row_index) % 2 == 0) {
                            assignment.witness(component.W(0), r) = beta;
                        } else {
                            assignment.witness(component.W(0), r) = gamma;
                        }
                    } else {
                        if ((r - start_row_index) % 3 != 1) {
                            assignment.witness(component.W(0), r) = beta;
                        } else {
                            assignment.witness(component.W(0), r) = gamma;
                        }
                    }
                }

                if (j != WitnessAmount - 1) {
                    assignment.witness(component.W(WitnessAmount - 1), row) = h;
                }

                return typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessAmount>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            void generate_gates(
                const plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::input_type instance_input,
                const std::uint32_t first_selector_index) {

                using var =
                    typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                std::size_t ctr = 0;

                auto constraint_1 = bp.add_constraint(
                    var(component.W(3), 0) -
                    ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(1), 0) +
                     var(component.W(0), 0) * var(component.W(2), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                bp.add_gate(first_selector_index + ctr, {constraint_1});
                ctr++;

                if (WitnessAmount % 3 == 1) {

                    auto constraint_2 = bp.add_constraint(
                        var(component.W(3), 0) -
                        var(component.W(WitnessAmount - 1), -1) *
                            ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(1), 0) +
                             var(component.W(0), 0) * var(component.W(2), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_2});
                    ctr++;

                    for (std::size_t j = 6; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(j - 2), 0) +
                                 var(component.W(0), 0) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                    auto constraint_3 = bp.add_constraint(
                        var(component.W(3), 0) -
                        var(component.W(WitnessAmount - 1), -1) *
                            ((1 + var(component.W(0), -1)) * var(component.W(0), 0) + var(component.W(1), 0) +
                             var(component.W(0), -1) *
                                 var(component.W(2), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_3});
                    ctr++;

                    for (std::size_t j = 6; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), -1)) * var(component.W(0), 0) + var(component.W(j - 2), 0) +
                                 var(component.W(0), -1) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }
                } else if (WitnessAmount % 3 == 2) {

                    auto constraint_2 = bp.add_constraint(
                        var(component.W(3), 0) -
                        var(component.W(WitnessAmount - 1), -1) *
                            ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(1), 0) +
                             var(component.W(0), 0) * var(component.W(2), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_2});
                    ctr++;

                    for (std::size_t j = 6; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(j - 2), 0) +
                                 var(component.W(0), 0) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                    auto constraint_3 =
                        bp.add_constraint(var(component.W(2), 0) -
                                          var(component.W(WitnessAmount - 2), -1) *
                                              ((1 + var(component.W(0), -1)) * var(component.W(0), 0) +
                                               var(component.W(WitnessAmount - 1), -1) +
                                               var(component.W(0), -1) *
                                                   var(component.W(1), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_3});
                    ctr++;

                    for (std::size_t j = 5; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), -1)) * var(component.W(0), 0) + var(component.W(j - 2), 0) +
                                 var(component.W(0), -1) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                    auto constraint_4 = bp.add_constraint(
                        var(component.W(1), 0) -
                        var(component.W(WitnessAmount - 3), -1) *
                            ((1 + var(component.W(0), 0)) * var(component.W(0), -1) +
                             var(component.W(WitnessAmount - 2), -1) +
                             var(component.W(0), 0) *
                                 var(component.W(WitnessAmount - 1), -1)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_4});
                    ctr++;

                    for (std::size_t j = 4; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), 0)) * var(component.W(0), -1) + var(component.W(j - 2), 0) +
                                 var(component.W(0), 0) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                } else {

                    auto constraint_2 = bp.add_constraint(
                        var(component.W(3), 0) -
                        var(component.W(WitnessAmount - 1), -1) *
                            ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(1), 0) +
                             var(component.W(0), 0) * var(component.W(2), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_2});
                    ctr++;

                    for (std::size_t j = 6; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), 0)) * var(component.W(0), +1) + var(component.W(j - 2), 0) +
                                 var(component.W(0), 0) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                    auto constraint_3 =
                        bp.add_constraint(var(component.W(1), 0) -
                                          var(component.W(WitnessAmount - 3), -1) *
                                              ((1 + var(component.W(0), -1)) * var(component.W(0), 0) +
                                               var(component.W(WitnessAmount - 2), -1) +
                                               var(component.W(0), -1) *
                                                   var(component.W(WitnessAmount - 1), -1)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_3});
                    ctr++;

                    for (std::size_t j = 4; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), -1)) * var(component.W(0), 0) + var(component.W(j - 2), 0) +
                                 var(component.W(0), -1) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                    auto constraint_4 = bp.add_constraint(
                        var(component.W(2), 0) -
                        var(component.W(WitnessAmount - 2), -1) *
                            ((1 + var(component.W(0), 0)) * var(component.W(0), -1) +
                             var(component.W(WitnessAmount - 1), -1) +
                             var(component.W(0), 0) *
                                 var(component.W(1), 0)));    // h = (1+beta)gamma + s_0 + beta t_0
                    bp.add_gate(first_selector_index + ctr, {constraint_4});
                    ctr++;

                    for (std::size_t j = 5; j < WitnessAmount; j = j + 3) {
                        auto constraint_ = bp.add_constraint(
                            var(component.W(j), 0) -
                            var(component.W(j - 3), 0) *
                                ((1 + var(component.W(0), 0)) * var(component.W(0), -1) + var(component.W(j - 2), 0) +
                                 var(component.W(0), 0) *
                                     var(component.W(j - 1),
                                         0)));    // h_new = h_old * ((1+beta)gamma + s_0 + beta t_0)
                        bp.add_gate(first_selector_index + ctr, {constraint_});
                        ctr++;
                    }

                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            void generate_copy_constraints(
                const plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::input_type instance_input,
                const std::uint32_t start_row_index) {

                using var =
                    typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;
                std::size_t row = start_row_index;

                for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                    if (WitnessAmount % 3 == 1) {
                        if (r % 2 == 0) {
                            bp.add_copy_constraint({var(component.W(0), row + r, false), instance_input.beta});
                        } else {
                            bp.add_copy_constraint({var(component.W(0), row + r, false), instance_input.gamma});
                        }
                    } else {
                        if (r % 3 != 1) {
                            bp.add_copy_constraint({var(component.W(0), row + r, false), instance_input.beta});
                        } else {
                            bp.add_copy_constraint({var(component.W(0), row + r, false), instance_input.gamma});
                        }
                    }

                    for (std::size_t j = 1; j < WitnessAmount; j++) {
                        auto tmp = (r * (WitnessAmount - 1) + j);
                        if (tmp % 3 == 1) {
                            bp.add_copy_constraint({var(component.W(j), row + r, false), instance_input.s[tmp / 3]});
                        } else if (tmp % 3 == 2) {
                            bp.add_copy_constraint({var(component.W(j), row + r, false), instance_input.t[tmp / 3]});
                        } else {
                            continue;
                        }
                    }
                }

            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
            typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_circuit(
                    const plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessAmount>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                assert(instance_input.s.size() == instance_input.t.size());
                assert(instance_input.s.size() == component.m);

                using var =
                    typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;
                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, row);

                if (WitnessAmount % 3 == 1) {
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        if (r & 1) {
                            for (std::size_t j = 3; j < WitnessAmount; j = j + 3) {
                                assignment.enable_selector(first_selector_index + (WitnessAmount / 3) + (j / 3),
                                                           row + r);
                            }
                        } else {
                            for (std::size_t j = 3; j < WitnessAmount; j = j + 3) {
                                if (r == 0 && j == 3)
                                    continue;
                                assignment.enable_selector(first_selector_index + (j / 3), row + r);
                            }
                        }
                    }
                } else if (WitnessAmount % 3 == 2) {
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        if (r % 3 == 1) {
                            for (std::size_t j = 2; j < WitnessAmount; j = j + 3) {
                                assignment.enable_selector(first_selector_index + (WitnessAmount / 3) + ((j + 1) / 3),
                                                           row + r);
                            }
                        } else if (r % 3 == 0) {
                            for (std::size_t j = 3; j < WitnessAmount; j = j + 3) {
                                if (r == 0 && j == 3)
                                    continue;
                                assignment.enable_selector(first_selector_index + (j / 3), row + r);
                            }
                        } else {
                            for (std::size_t j = 1; j < WitnessAmount; j = j + 3) {
                                assignment.enable_selector(
                                    first_selector_index + 2 * (WitnessAmount / 3) + ((j + 2) / 3), row + r);
                            }
                        }
                    }
                }else{
                    for (std::size_t r = 0; r < component.rows_amount - 1; r++) {
                        if (r % 3 == 1) {
                            for (std::size_t j = 1; j < WitnessAmount; j = j + 3) {
                                assignment.enable_selector(first_selector_index + (WitnessAmount / 3) + ((j + 1) / 3),
                                                           row + r);
                            }
                        } else if (r % 3 == 0) {
                            for (std::size_t j = 3; j < WitnessAmount; j = j + 3) {
                                if (r == 0 && j == 3)
                                    continue;
                                assignment.enable_selector(first_selector_index + (j / 3), row + r);
                            }
                        } else {
                            for (std::size_t j = 2; j < WitnessAmount; j = j + 3) {
                                assignment.enable_selector(
                                    first_selector_index + 2 * (WitnessAmount / 3) + ((j + 2) / 3), row + r);
                            }
                        }
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_permutation_loop<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessAmount>::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP