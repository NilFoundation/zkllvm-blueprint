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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_modes.hpp>

#include <type_traits>
#include <utility>
#include <algorithm>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                /*
                    This duplicates logic in bit_builder_component's method padding_bits_amount.
                    The component requires constants only when padding is required.
                    We use this function in derived components to create the right amount of constants.
                    It's a bit janky, but I haven't found a better way.
                */
                constexpr std::uint32_t bit_builder_component_constants_required(
                        std::uint32_t WitnessesAmount, std::uint32_t BitsAmount) {
                    if (BitsAmount < 3 * WitnessesAmount) {
                        return 0;
                    }
                    std::uint32_t padding =
                        ((3 * WitnessesAmount - 2) -
                            (BitsAmount - 3 * WitnessesAmount + 1) % (3 * WitnessesAmount - 2))
                                % (3 * WitnessesAmount - 2);
                    return padding > 0;
                }
            }
            /*
                This is a component base, which is used for both bit_decomposition and
                bit_builder_component components, as they are similar.

                Only the case of BitsAmount < BlueprintFieldType::modulus_bits is supported.

                The composition part does not perfom checks that the inputs are actually bits.
                composition performs a check that the element actually fits in the field.
                Bits can be passed/saved LSB-first or MSB-first, depending on the value of
                Mode parameter.

                A schematic representation of the component. 'o' signifies an input bit.
                'x' signifies one of the sum bits.
                '0' signifies padding with zeros.
                Input bits are packed MSB first.

                For small (BitsAmount < 3 * WitnessesAmount) components, we use a single sum of bits.
                Example for BitsAmount = 16:
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- A single constraint forces 'x' to be equal to the (weighted) sum
                |o|x| | | | | | | | | | | | | | ]    of 'o' bits
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                For larger components, we repeat the following sum constraint:
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |x|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- The first 'x' is the previous sum.
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |    The second 'x' is constrained to be equal to the
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    (weighted) sum of 'o' bits and the first 'x'.
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                This requires padding up to nearest value of
                3 * WitnessesAmount - 1 + k * (3 * WitnessesAmount - 2).
                The first 'x' in the component is assinged to be the first bit (of input or padding).

                An example for BitsAmount = 64 (90 cells: 3 sum bits, 64 input bits, 23 padding bits):
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |0|0|0|0|0|0|0|0|0|0|0|0|0|0|0| ] -- Note that the first 'x' is being used as an input/padding bit.
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                |0|0|0|0|0|0|0|0|o|o|o|o|o|o|o| |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |x|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ] -- This 'x' needs to be constrained to the last 'x'
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    in the previous constraint block
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                The following is asymptotically the tightest packing I've found (in terms of rows amount).
                It would utilise constraints of the form:
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                | | | | | | | | | | | | | | |x| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- The first 'x' is the previous sum.
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |    The second 'x' is constrained to be equal to the sum of 'o' bits
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    and the first 'x'. Empty spaces are not constrained.
                |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                These constraints have the best (sum_bits / input_bits) ratio I've seen.
                It does not make sense to use for WitnessAmount = 15 as the asymptotics kick in too late.

                Lower WitnessesAmount values would result in asymptotics kicking in earlier, and
                less wasted bits in the first gate, so for them it starts being better.
                E.g. for WitnessesAmount = 9 this is better (in rows) or equal for BitsAmount = {32, 128, 255}
                and same for BitsAmount = {64}.
                This is despite 8 cells being wasted in the beginning!

                The downside is that we would use more constraints.
            */
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount, std::uint32_t ConstantsAmount,
                     std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits>
            class bit_builder_component;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            class bit_builder_component<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                            WitnessesAmount, ConstantsAmount, BitsAmount,
                                                            Mode, CheckBits>
                                 : public plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount, ConstantsAmount, 0> {

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 0>;

                constexpr static const std::size_t rows() {
                    std::size_t total_bits = BitsAmount + sum_bits_amount() + padding_bits_amount();
                    return total_bits / WitnessesAmount + (total_bits % WitnessesAmount ? 1 : 0);
                }

                constexpr static const std::size_t gates() {
                    return 1;
                }

                /*
                    Returns bit position inside the packing, if the packing were done by filling each row in order,
                    without skipping any cells.
                */
                constexpr static const std::pair<std::size_t, std::size_t> straight_bit_position(
                        std::size_t start_row_index, std::size_t bit_num) {

                    std::size_t row = start_row_index + bit_num / WitnessesAmount;
                    std::size_t col = bit_num % WitnessesAmount;

                    return std::make_pair(row, col);
                };

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t rows_amount = rows();

                constexpr static const std::size_t gates_amount = gates();

                struct input_type {
                    std::array<var, BitsAmount> bits;
                };

                struct result_type {
                    var output;
                    result_type(const bit_builder_component &component, std::uint32_t start_row_index) {
                        auto pos = sum_bit_position(start_row_index, sum_bits_amount() - 1);
                        output = var(component.W(pos.second), pos.first);
                    }
                };

                template<typename ContainerType>
                bit_builder_component(ContainerType witness) :
                    component_type(witness, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_builder_component(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                bit_builder_component(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};


                constexpr static const std::size_t padding_bits_amount() {
                    if (BitsAmount < 3 * WitnessesAmount) {
                        return 0;
                    }
                    return ((3 * WitnessesAmount - 2) -
                            (BitsAmount - 3 * WitnessesAmount + 1) % (3 * WitnessesAmount - 2))
                                % (3 * WitnessesAmount - 2);
                }

                /*
                    Returns row and column pair for each input bit.
                    Packing is done MSB first; code in generate_assignments is responsible for reversing the order if necessary.
                */
                constexpr static const std::pair<std::size_t, std::size_t> bit_position(
                        std::size_t start_row_index, std::size_t bit_num) {

                    if (BitsAmount < 3 * WitnessesAmount) {
                        return straight_bit_position(start_row_index, bit_num);
                    }

                    std::size_t sum_bits = (bit_num >= 3 * WitnessesAmount - 1) *
                                           (2 + (bit_num - 3 * WitnessesAmount + 1) / (3 * WitnessesAmount - 2) * 2);
                    return straight_bit_position(start_row_index, bit_num + sum_bits);
                }

                /*
                    Returns the amount of auxillary sum bits in the component.
                */
                constexpr static const std::size_t sum_bits_amount() {
                    if (BitsAmount < 3 * WitnessesAmount) {
                        return 1;
                    }
                    // ceil division
                    return 1 + (BitsAmount - 3 * WitnessesAmount + 3 * WitnessesAmount - 2) /
                               (3 * WitnessesAmount - 2) * 2;
                }

                /*
                    Returns row and column pair for each auxillary sum bit.
                */
                constexpr static const std::pair<std::size_t, std::size_t> sum_bit_position(
                        std::size_t start_row_index, std::size_t sum_bit_num) {
                    assert(sum_bit_num < sum_bits_amount());
                    std::size_t bit_pos = 0;

                    if (BitsAmount < 3 * WitnessesAmount) {
                        // we only have a single sum bit in this case
                        bit_pos = BitsAmount;
                    } else {
                        bit_pos = 3 * WitnessesAmount - 1 + (sum_bit_num / 2) * (3 * WitnessesAmount) +
                                  (sum_bit_num % 2);
                    }

                    return straight_bit_position(start_row_index, bit_pos);
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount,
                     std::int32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            using plonk_bit_builder = bit_builder_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                            BlueprintFieldType,
                                                                                            ArithmetizationParams>,
                                                            WitnessesAmount, ConstantsAmount, BitsAmount, Mode,
                                                            CheckBits>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount,
                     std::int32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            void generate_assignments(
                    const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                            ConstantsAmount, BitsAmount, Mode, CheckBits>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::array<bool, BitsAmount> &input_bits,
                    const std::uint32_t start_row_index) {

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, ConstantsAmount, BitsAmount, Mode,
                                                       CheckBits>::var;

                using field_value_type = typename BlueprintFieldType::value_type;

                auto bit_index = [](std::size_t i) {
                    return Mode == bit_composition_mode::MSB ? i : BitsAmount - i - 1;
                };

                std::size_t padding = 0;
                for (; padding < component.padding_bits_amount(); padding++) {
                    auto bit_pos = component.bit_position(start_row_index, padding);
                    assignment.witness(component.W(bit_pos.second), bit_pos.first) = 0;
                }

                for (std::size_t i = 0; i < BitsAmount; i++) {
                    auto bit_pos = component.bit_position(start_row_index, padding + i);
                    assignment.witness(component.W(bit_pos.second), bit_pos.first) = input_bits[bit_index(i)];
                }

                field_value_type sum = 0;
                std::size_t bit_num = 0;
                for (std::size_t i = 0; i < component.sum_bits_amount(); i += 2) {
                    auto sum_bit_pos = component.sum_bit_position(start_row_index, i);
                    std::size_t max_bit_num = BitsAmount < 3 * WitnessesAmount ?
                                               BitsAmount :
                                               3 * WitnessesAmount - padding - 1 + (i / 2) * (3 * WitnessesAmount - 2);
                    for (; bit_num < max_bit_num; bit_num++) {
                        sum = 2 * sum + input_bits[bit_index(bit_num)];
                    }

                    assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                    if (i != component.sum_bits_amount() - 1) {
                        auto sum_bit_pos = component.sum_bit_position(start_row_index, i + 1);
                        assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                    }
                }
            }

            /*
                The CheckBits component should always be true for bit_decomposition: we need to check that the output
                is actually bits.
                It is optional for bit_composition: the input might have already been checked.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            void generate_gates(
                    const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                            ConstantsAmount, BitsAmount, Mode, CheckBits>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t first_selector_index) {

                using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, ConstantsAmount, BitsAmount, Mode,
                                                       CheckBits>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                constraint_type constraint_sum;
                int row_idx = -1;
                std::size_t col_idx = 1;

                constraint_sum = var(component.W(0), -1);
                for (std::size_t bit_num = 1; bit_num < std::min(BitsAmount, 3 * WitnessesAmount - 1); bit_num++) {
                    constraint_sum = 2 * constraint_sum + var(component.W(col_idx), row_idx);
                    col_idx++;
                    if (col_idx % WitnessesAmount == 0) {
                        row_idx++;
                        col_idx = 0;
                    }
                }

                constraint_sum = constraint_sum - var(component.W(col_idx), row_idx);

                if (!CheckBits) {
                    bp.add_gate(first_selector_index, constraint_sum);
                } else {
                    int row_idx = -1;
                    std::size_t col_idx = 1;

                    std::vector<constraint_type> bit_constraints;
                    bit_constraints.resize(3 * WitnessesAmount - 2);

                    for (std::size_t bit_num = 1; bit_num < std::min(BitsAmount, 3 * WitnessesAmount - 1); bit_num++) {
                        bit_constraints[bit_num - 1] = var(component.W(col_idx), row_idx) *
                                                       (1 - var(component.W(col_idx), row_idx));

                        col_idx++;
                        if (col_idx % WitnessesAmount == 0) {
                            row_idx++;
                            col_idx = 0;
                        }
                    }

                    bit_constraints.push_back(constraint_sum);
                    crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type> gate(
                        first_selector_index, bit_constraints);
                    bp.add_gate(gate);
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            void generate_assignments_constant(
                    const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                            1, BitsAmount, Mode, CheckBits>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {

                using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, ConstantsAmount, BitsAmount, Mode,
                                                       CheckBits>::var;

                assignment.constant(component.C(0), start_row_index) = 0;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            void generate_assignments_constant(
                    const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                            0, BitsAmount, Mode, CheckBits>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {
                // no constants in this case
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t ConstantsAmount, std::uint32_t BitsAmount, bit_composition_mode Mode,
                     bool CheckBits>
            void generate_circuit(
                    const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                            ConstantsAmount, BitsAmount, Mode, CheckBits>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::size_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                   ConstantsAmount, BitsAmount, Mode, CheckBits>(
                                        component, bp, assignment, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                std::size_t end_row_index = start_row_index +
                                            (component.rows_amount > 2 ? component.rows_amount - 2 : 1);
                assignment.enable_selector(first_selector_index, start_row_index + 1, end_row_index, 3);

                // copy constraints are specific to either bit_composition or bit_decomposition
                // they are created in generate_circuit for corresponding classes
                generate_assignments_constant<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                              ConstantsAmount, BitsAmount, Mode, CheckBits>(
                                                component, assignment, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP