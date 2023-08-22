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

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class basic_constraints_verifier;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessesAmount>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0> {

                constexpr static const std::uint32_t WitnessesAmount = WitnessesAmount;
                constexpr static const std::uint32_t ConstantsAmount = 0;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 0>;

            public:
                using var = typename component_type::var;

                std::size_t rows_amount;
                std::size_t gates_amount = 4;
                const std::size_t N_sl;

                struct gate_constraints {
                    std::vector<var> constraints;
                    var selector;
                };

                struct input_type {
                    var theta;
                    std::vector<gate_constraints> gates;    // new type ?
                };

                struct result_type {
                    var output;

                    result_type(const permutation_verifier &component, std::uint32_t start_row_index) {
                        output = var(component.W(0), start_row_index + component.rows_amount - 1, false);
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessesAmount << "_" << N_sl;
                    return ss.str();
                }

                template<typename ContainerType>
                basic_constraints_verifier(ContainerType witness, std::size_t N_sl_) :
                    component_type(witness, {}, {}), N_sl(N_sl_) {
                    rows_amount = 2 * N_sl / (WitnessesAmount - 1) + 1;
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                basic_constraints_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                           PublicInputContainerType public_input, std::size_t N_cr_) :
                    component_type(witness, constant, public_input),
                    N_sl(N_sl_) {
                    rows_amount = 2 * N_sl / (WitnessesAmount - 1) + 1;
                };

                basic_constraints_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t N_cr_) :
                    component_type(witnesses, constants, public_inputs),
                    N_sl(N_sl_) {
                    rows_amount = 2 * N_sl / (WitnessesAmount - 1) + 1;
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            using plonk_basic_constraints_verifier = basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                     std::enable_if_t<WitnessesAmount >= 3, bool> = true>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessAmount>::result_type
                generate_assignments(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                    WitnessAmount>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                assert(component.N_sl == instance_input.gates.size());
                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessAmount>::var;

                std::size_t row = start_row_index;

                for (std::size_t i = 0; i < component.N_sl; i++) {
                    auto gate_instance = gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>(
                        component._W, {}, {}, instance_input.gates[i].constraints.size());
                    typename gate_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount>::input_type
                        gate_input = {instance_input.theta, instance_input.gates[i].constraints,
                                      instance_input.gate[i].selector};
                    auto gate_i_result = generate_assignment(gate_instance, assignment, gate_input, row);
                    row += gate_instance.rows_amount;
                }

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessAmount>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                     std::enable_if_t<WitnessesAmount >= 3, bool> = true>
            void generate_gates(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessAmount>::input_type instance_input,
                const std::uint32_t first_selector_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                     std::enable_if_t<WitnessesAmount >= 3, bool> = true>
            void generate_copy_constraints(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams, WitnessAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessAmount>::input_type instance_input,
                const std::uint32_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t WitnessAmount,
                     std::enable_if_t<WitnessesAmount >= 3, bool> = true>
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
                    const std::uint32_t start_row_index) {

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessAmount>::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP