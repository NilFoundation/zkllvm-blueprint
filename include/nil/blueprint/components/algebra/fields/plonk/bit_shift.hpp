//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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


#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_modes.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_builder_component.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>

#include <algorithm>

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_SHIFT_RIGHT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_SHIFT_RIGHT_HPP

using nil::blueprint::components::detail::bit_builder_component_constants_required;

namespace nil {
    namespace blueprint {
        namespace components {

            /*
                Input has to fit into [BlueprintFieldType::modulus_bits - 1] bits (this is checked).
                This is implemented as decomposition + composition.
            */
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount,
                     std::uint32_t Shift, bit_shift_mode Mode>
            class bit_shift;


            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t Shift, bit_shift_mode Mode>
            class bit_shift<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                            WitnessesAmount, Shift, Mode>
                                 : public plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount,
                                                          // Use constants if either compose/decompose
                                                          // requires them OR if we are shifitng left,
                                                          // as shifting left requires padding.
                                                          std::max({
                                                            bit_builder_component_constants_required(
                                                                WitnessesAmount,
                                                                BlueprintFieldType::modulus_bits - 1),
                                                            bit_builder_component_constants_required(
                                                                WitnessesAmount,
                                                                Mode == bit_shift_mode::RIGHT ?
                                                                    BlueprintFieldType::modulus_bits - 1 - Shift
                                                                  : BlueprintFieldType::modulus_bits - 1),
                                                            std::uint32_t(Mode == bit_shift_mode::LEFT ? 1 : 0)}),
                                                          0> {
                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                    std::max({
                        bit_builder_component_constants_required(
                            WitnessesAmount,
                            BlueprintFieldType::modulus_bits - 1),
                        bit_builder_component_constants_required(
                            WitnessesAmount,
                            Mode == bit_shift_mode::RIGHT ?
                                  BlueprintFieldType::modulus_bits - 1 - Shift
                                : BlueprintFieldType::modulus_bits - 1),
                        std::uint32_t(Mode == bit_shift_mode::LEFT ? 1 : 0)}), 0>;

            public:
                using var = typename component_type::var;

                using decomposition_component_type =
                    bit_decomposition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                  ArithmetizationParams>,
                                      WitnessesAmount, BlueprintFieldType::modulus_bits - 1,
                                      bit_composition_mode::MSB>;

                using composition_component_type =
                    bit_composition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                                    WitnessesAmount,
                                    Mode == bit_shift_mode::RIGHT ? BlueprintFieldType::modulus_bits - 1 - Shift
                                                                  : BlueprintFieldType::modulus_bits - 1,
                                    bit_composition_mode::MSB, false>;

                constexpr static const std::size_t rows_amount = decomposition_component_type::rows_amount +
                                                                 composition_component_type::rows_amount;

                // Technically, this component uses two gates.
                // But both of them are inside subcomponents.
                constexpr static const std::size_t gates_amount = 0;

                decomposition_component_type decomposition_subcomponent;
                composition_component_type composition_subcomponent;

                struct input_type {
                    var input;
                };

                struct result_type {
                    var output;

                    result_type(const bit_shift &component, std::uint32_t start_row_index) {
                        std::uint32_t row = start_row_index;
                        row += decomposition_component_type::rows_amount;
                        output = typename composition_component_type::result_type(
                                    component.composition_subcomponent, row).output;
                    }
                };

                template<typename ContainerType>
                bit_shift(ContainerType witness) :
                    component_type(witness, {}, {}),
                    decomposition_component_type(witness),
                    composition_component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_shift(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input) :
                                    component_type(witness, constant, public_input),
                                    decomposition_subcomponent(witness, constant, public_input),
                                    composition_component_type(witness, constant, public_input) {};

                bit_shift(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                            component_type(witnesses, constants, public_inputs),
                            decomposition_subcomponent(witnesses, constants, public_inputs),
                            composition_subcomponent(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t WitnessesAmount, std::uint32_t Shift, bit_shift_mode Mode>
            using plonk_bit_shift = bit_shift<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                WitnessesAmount, Shift, Mode>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t Shift, bit_shift_mode Mode>
            typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                     WitnessesAmount, Shift, Mode>::result_type
                generate_assignments(
                    const plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                          WitnessesAmount, Shift, Mode> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                                   WitnessesAmount, Shift, Mode>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {
                std::uint32_t row = start_row_index;

                using var = typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessesAmount, Shift, Mode>::var;
                using decomposition_component_type =
                    typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                             WitnessesAmount, Shift, Mode>::decomposition_component_type;
                using composition_component_type =
                    typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                             WitnessesAmount, Shift, Mode>::composition_component_type;

                typename decomposition_component_type::result_type decomposition =
                    generate_assignments(component.decomposition_subcomponent, assignment,
                                         {instance_input.input}, row);
                row += decomposition_component_type::rows_amount;

                typename composition_component_type::input_type composition_input;
                if (Mode == bit_shift_mode::LEFT) {
                    var zero(0, start_row_index, false, var::column_type::constant);
                    std::fill(composition_input.bits.begin(), composition_input.bits.end(), zero);

                    std::move(decomposition.output.begin() + Shift, decomposition.output.end(),
                              composition_input.bits.begin());
                } else if (Mode == bit_shift_mode::RIGHT) {
                    std::move(decomposition.output.begin(), decomposition.output.end() - Shift,
                              composition_input.bits.begin());
                }
                typename composition_component_type::result_type composition =
                    generate_assignments(component.composition_subcomponent, assignment, composition_input, row);
                row += composition_component_type::rows_amount;

                assert(row == start_row_index + component.rows_amount);
                return typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount, Shift, Mode>::result_type(
                                                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t Shift, bit_shift_mode Mode>
            typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                           WitnessesAmount, Shift, Mode>::result_type
                generate_circuit(
                    const plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                          WitnessesAmount, Shift, Mode> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                                   WitnessesAmount, Shift, Mode>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {
                std::uint32_t row = start_row_index;

                using var = typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessesAmount, Shift, Mode>::var;
                using decomposition_component_type =
                    typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                             WitnessesAmount, Shift, Mode>::decomposition_component_type;
                using composition_component_type =
                    typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                             WitnessesAmount, Shift, Mode>::composition_component_type;

                generate_assignments_constant(component, assignment, row);

                typename decomposition_component_type::result_type decomposition =
                    generate_circuit(component.decomposition_subcomponent, bp, assignment, {instance_input.input},
                                     row);
                row += decomposition_component_type::rows_amount;

                typename composition_component_type::input_type composition_input;
                if (Mode == bit_shift_mode::LEFT) {
                    var zero(0, start_row_index, false, var::column_type::constant);
                    std::fill(composition_input.bits.begin(), composition_input.bits.end(), zero);

                    std::move(decomposition.output.begin() + Shift, decomposition.output.end(),
                              composition_input.bits.begin());
                } else if (Mode == bit_shift_mode::RIGHT) {
                    std::move(decomposition.output.begin(), decomposition.output.end() - Shift,
                              composition_input.bits.begin());
                }
                generate_circuit(component.composition_subcomponent, bp, assignment, composition_input, row);
                row += composition_component_type::rows_amount;

                assert(row == start_row_index + component.rows_amount);
                return typename plonk_bit_shift<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount, Shift, Mode>::result_type(
                                                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t Shift>
            void generate_assignments_constant(
                    const plonk_bit_shift<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                          Shift, bit_shift_mode::RIGHT>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {
                // no constants in this case
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t Shift>
            void generate_assignments_constant(
                    const plonk_bit_shift<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                          Shift, bit_shift_mode::LEFT>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = 0;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif   // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_SHIFT_RIGHT_HPP
