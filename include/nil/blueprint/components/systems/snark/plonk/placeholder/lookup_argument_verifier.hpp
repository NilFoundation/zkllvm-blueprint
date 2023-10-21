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

#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/permutation_loop.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/types.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class lookup_verifier;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class lookup_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessesAmount>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 1> {

                constexpr static const std::uint32_t ConstantsAmount = 0;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 1>;

            public:
                using var = typename component_type::var;

                std::size_t rows_amount;
                std::size_t gates_amount = 4;
                const std::size_t m;

                struct input_type {
                    var theta;
                    var beta;
                    var gamma;
                    std::vector<var> alphas;
                    std::array<var, 2> V_L_values;
                    std::array<var, 2> q_last;
                    std::array<var, 2> q_blind;
                    var L0;

                    std::vector<typename lookup_gate<var>> lookup_gates;
                    std::vector<typename lookup_table<var>> lookup_tables;
                    std::vector<typename lookup_table<var>> shifted_lookup_tables;
                    std::vector<std::vector<var>> sorted;
                };

                struct result_type {
                    std::array<var, 4> output;

                    result_type(const permutation_verifier &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(4), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(4), start_row_index + component.rows_amount - 1, false),
                                  var(component.W(0), start_row_index + component.rows_amount - 1, false)};
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessesAmount << "_" << m;
                    return ss.str();
                }

                template<typename ContainerType>
                lookup_verifier(ContainerType witness, std::size_t m_) : component_type(witness, {}, {}), m(m_) {
                    rows_amount = m_ + 2;
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                lookup_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input, std::size_t m_) :
                    component_type(witness, constant, public_input),
                    m(m_) {
                    rows_amount = m_ + 2;
                };

                lookup_verifier(std::initializer_list<typename component_type::witness_container_type::value_type>
                                    witnesses,
                                std::initializer_list<typename component_type::constant_container_type::value_type>
                                    constants,
                                std::initializer_list<typename component_type::public_input_container_type::value_type>
                                    public_inputs,
                                std::size_t m_) :
                    component_type(witnesses, constants, public_inputs),
                    m(m_) {
                    rows_amount = m_ + 2;
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            using plonk_lookup_verifier =
                lookup_verifier<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_assignments(
                    const plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessAmount>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using var =
                    typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using f1_loop = detail::permutation_loop<ArithmetizationType, WitnessAmount>;
                using f3_loop = detail::f3_loop<ArithmetizationType, WitnessAmount>;

                td::array<std::uint32_t, WitnessAmount> witnesses;
                for (std::uint32_t i = 0; i < WitnessAmount; i++) {
                    witnesses[i] = component.W(i);
                }

                typename BlueprintFieldType::value_type one = typename BlueprintFieldType::value_type::one();
                typename BlueprintFieldType::value_type theta = var_value(assignment, instance_input.theta);
                typename BlueprintFieldType::value_type beta = var_value(assignment, instance_input.beta);
                typename BlueprintFieldType::value_type gamma = var_value(assignment, instance_input.gamma);
                typename BlueprintFieldType::value_type q_last = var_value(assignment, instance_input.q_last[0]);
                typename BlueprintFieldType::value_type q_last_shifted =
                    var_value(assignment, instance_input.q_last[q]);
                typename BlueprintFieldType::value_type q_blind = var_value(assignment, instance_input.q_blind[0]);
                typename BlueprintFieldType::value_type q_blind_shifted =
                    var_value(assignment, instance_input.q_blind[q]);
                typename BlueprintFieldType::value_type L0 = var_value(assignment, instance_input.L0);
                typename BlueprintFieldType::value_type V_L = var_value(assignment, instance_input.V_L_values[0]);
                typename BlueprintFieldType::value_type V_L_shifted =
                    var_value(assignment, instance_input.V_L_values[1]);

                typename BlueprintFieldType::value_type F0 = (one - V_L) * L0;
                typename BlueprintFieldType::value_type F2 = q_last * (V_L * V_L - V_L);

                std::vector<var> assignments;

                std::vector<var> lookup_values;
                std::vector<var> shifted_lookup_values;

                for (std::size_t i = 0; i < instance_input.lookup_tables.size(); i++) {
                    var selector = instance_input.lookup_tables[i].selector;
                    var shifted_selector = instance_input.lookup_tables[i].shifted_selector;
                    var t_id_inc = var(component.C(0), start_row_index + i, false, var::column_type::constant);

                    for (std::size_t j = 0; j < instance_input.lookup_tables[i].lookup_options.size(); j++) {
                        std::vector<var> gate_constraints;
                        gate_constraints.insert(gate_constraints.begin(),
                                                instance_input.lookup_tables[i].lookup_options[j].begin(),
                                                instance_input.lookup_tables[i].lookup_options[j].end());
                        gate_constraints.reverse();
                        gate_constraints.push_back(t_id_inc);
                        gate_component gate_instance =
                            gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           instance_input.lookup_tables[i].lookup_options[j].size());
                        typename gate_component::input_type gate_input = {instance_input.theta, gate_constraints,
                                                                          selector};

                        typename gate_component::result_type gate_i_result =
                            generate_assignments(gate_instance, assignment, gate_input, row);

                        lookup_values.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;

                        gate_constraints.clear();
                        gate_constraints.insert(gate_constraints.begin(),
                                                instance_input.shifted_lookup_tables[i].lookup_options[j].begin(),
                                                instance_input.shifted_lookup_tables[i].lookup_options[j].end());
                        gate_constraints.reverse();
                        gate_constraints.push_back(t_id_inc);
                        gate_instance =
                            gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           instance_input.lookup_tables[i].lookup_options[j].size());
                        gate_input = {instance_input.theta, gate_constraints, shifted_selector};

                        gate_i_result = generate_assignments(gate_instance, assignment, gate_input, row);

                        shifted_lookup_values.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;
                    }
                }

                typename BlueprintFieldType::value_type mask_value =
                    (typename BlueprintFieldType::value_type::one - (q_last + q_blind));
                typename BlueprintFieldType::value_type shifted_mask_value =
                    (typename BlueprintFieldType::value_type::one - (q_last_shifted + q_blind_shifted));

                assignments.push_back(q_last);
                assignemnts.push_back(q_blind);
                assingments.push_back(mask_value);
                assignments.push_back(q_last_shifted);
                assignemnts.push_back(q_blind_shifted);
                assingments.push_back(shifted_mask_value);

                std::size_t i, r = 0, j = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / WitnessAmount;
                    j = i % WitnessAmount;

                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r + 1;

                std::vector<var> lookup_input;
                using gate_component = detail::gate_component<ArithmetizationType, WitnessAmount>;
                for (std::size_t i = 0; i < instance_input.lookup_gates.size(); i++) {

                    var selector = instance_input.lookup_gates[i].selector;
                    for (std::size_t j = 0; j < instance_input.lookup_gates[i].constraints.size(); j++) {
                        std::vector<var> gate_constraints;
                        gate_constraints.insert(gate_constraints.begin(),
                                                instance_input.gates[i].constraints[j].lookup_input.begin(),
                                                instance_input.gates[i].constraints[j].lookup_input.end());
                        gate_constraints.reverse();
                        gate_constraints.push_back(instance_input.gates[i].constraints[j].table_id);
                        gate_component gate_instance =
                            gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           instance_input.lookup_gates[i].constraints[j].lookup_input.size());
                        typename gate_component::input_type gate_input = {instance_input.theta, gate_constraints,
                                                                          selector};

                        typename gate_component::result_type gate_i_result =
                            generate_assignments(gate_instance, assignment, gate_input, row);

                        lookup_input.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;
                    }
                }

                std::vector<var> s0, s1;
                for (std::size_t i = 0; i < instance_input.sorted.size(); i++) {
                    s0.push_back(instance_input.sorted[i][0]);
                    s1.push_back(instance_input.sorted[i][1]);
                }
                f1_loop h_loop =
                    f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), s0.size());
                typename f1_loop::input_type h_loop_input = {instance_input.beta, instance_input.gamma, s0, s1};

                typename f1_loop::result_type h_loop_result =
                    generate_assignments(h_loop, assignment, h_loop_input, row);

                typename BlueprintFieldType::value_type h = var_value(assignment, h_loop_result.output);
                rows += h_loop.rows_amount;

                f1_loop g_loop_1 = f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_input.size());

                typename f1_loop::input_type g_loop_input = {instance_input.beta, instance_input.gamma, lookup_input,
                                                             lookup_input};

                typename f1_loop::result_type g_loop_result =
                    generate_assignments(g_loop_1, assignment, g_loop_input, row);

                typename BlueprintFieldType::value_type g1 = var_value(assignment, g_loop_result.output);
                rows += g_loop_1.rows_amount;

                f1_loop g_loop_2 = f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_values.size());

                typename f1_loop::input_type g_loop_input_2 = {instance_input.beta, instance_input.gamma, lookup_values,
                                                             shifted_lookup_values};

                typename f1_loop::result_type g_loop_result_2 =
                    generate_assignments(g_loop_2, assignment, g_loop_input_2, row);

                typename BlueprintFieldType::value_type g2 = var_value(assignment, g_loop_result.output);
                rows += g_loop_2.rows_amount;

                typename BlueprintFieldType::value_type g = g1 * g2;

                s0.erase(s0.begin());
                s1.pop_back();
                f3_loop F3_loop =
                    f3_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), s0.size());
                typename f3_loop::input_type F3_loop_input = {instance_input.beta, instance_input.gamma, s0, s1};

                typename f3_loop::result_type F3_loop_result =
                    generate_assignments(F3_loop, assignment, F3_loop_input, row);

                typename BlueprintFieldType::value_type F3 = var_value(assignment, F3_loop_result.output);
                rows += F3_loop.rows_amount;

                typename BlueprintFieldType::value_type F3_final = F3 * L0;

                assignments.clear();
                assignments.push_back(V_L);
                assignments.push_back(L0);
                assingments.push_back(F0);
                assignments.push_back(q_last);
                assignments.push_back(F2);

                for (i = 0; i < assignments.size(); i++) {
                    r = i / WitnessAmount;
                    j = i % WitnessAmount;

                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r + 1;

                // assignments.clear();
                // assingments.push_back(F3);
                // assingments.push_back(L0);
                // assingments.push_back(F3_final);
                assignment.witness(component.W(0), row) = F3;
                assignment.witness(component.W(1), row) = L0;
                assignment.witness(component.W(2), row) = F3_final;

                return typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            void generate_gates(
                const plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessAmount>::input_type instance_input,
                const std::uint32_t start_row_index) {

                using var =
                    typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::var;

                std::vector < std::pair < std::size_t, std::size_t >>> locs;

                std::size_t r, j;
                for (std::size_t i = 0; i < 6; i++) {
                    r = i / WitnessAmount;
                    j = i % WitnessAmount;
                    locs.push_back(std::make_pair(j, r));
                }

                auto _q_last = var(component.W(locs[0].first), locs[0].second);
                auto _q_blind = var(component.W(locs[1].first), locs[1].second);
                auto _mask = var(component.W(locs[2].first), locs[2].second);

                auto _q_last_shifted = var(component.W(locs[3].first), locs[3].second);
                auto _q_blind_shifted = var(component.W(locs[4].first), locs[4].second);
                auto _mask_shifted = var(component.W(locs[5].first), locs[5].second);

                auto constraint_1 = bp.add_constraint(_mask - (1 - _q_last - _q_blind));
                auto constraint_2 = bp.add_constraint(_mask_shifted - (1 - _q_last_shifted - _q_blind_shifted));

                bp.add_gate(first_selector_index, {constraint_1, constraint_2});

                locs.clear();
                for (std::size_t i = 0; i < 5; i++) {
                    r = i / WitnessAmount;
                    j = i % WitnessAmount;
                    locs.push_back(std::make_pair(j, r));
                }

                auto _vl = var(component.W(locs[0].first), locs[0].second);
                auto _lo = var(component.W(locs[1].first), locs[1].second);
                auto _f0 = var(component.W(locs[2].first), locs[2].second);
                auto _q_last = var(component.W(locs[3].first), locs[3].second);
                auto _f2 = var(component.W(locs[4].first), locs[4].second);

                auto constraint_3 = bp.add_constraint(_f0 - (1 - _vl) * _l0);
                auto constraint_4 = bp.add_constraint(_f2 - _q_last * (_vl * _vl - _vl));

                bp.add_gate(first_selector_index + 1, {constraint_3, constraint_4});

                locs.clear();

                auto constraint_5 =
                    bp.add_constraint(var(component.W(2), 0) - var(component.W(1), 0) * var(component.W(0), 0));
                bp.add_gate(first_selector_index + 2, {constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            void generate_copy_constraints(
                const plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessAmount>::input_type instance_input,
                const std::uint32_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::result_type
                generate_circuit(
                    const plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessAmount>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                return typename plonk_lookup_verifier<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP