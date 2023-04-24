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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_COMPOSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_COMPOSITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_modes.hpp>

#include <type_traits>
#include <limits>
#include <utility>
#include <numeric>

namespace nil {
    namespace blueprint {
        namespace components {

            /*
                Makes a single field element from BitsAmount bits.
                Does not perform a check that the inputs actually belong to {0, 1}.
                In case that BitsAmount is the same as the field integer type size this performs a check that the element actually fits in the field. This case is implemented separately.
                Bits can be passed LSB-first or MSB-first, depending on the value of Mode parameter.
            */
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount,
                     bit_composition_mode Mode>
            class bit_composition;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t BitsAmount,
                     bit_composition_mode Mode>
            class bit_composition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                            15, BitsAmount, Mode>
                                 : public plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 0, 0> {

                constexpr static const std::uint32_t WitnessesAmount = 15;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;

                constexpr static const std::size_t rows() {
                    std::size_t total_bits = BitsAmount + sum_bits_amount();
                    return total_bits / WitnessesAmount + (total_bits % WitnessesAmount ? 1 : 0);
                }

                constexpr static const std::size_t gates() {
                    std::size_t total_bits = BitsAmount + sum_bits_amount();
                    if (total_bits <= 3 * WitnessesAmount - 1) {
                        return 1;
                    } else if (total_bits <= 5 * WitnessesAmount - 2) {
                        return 2;
                    } else if ((total_bits - 3 * WitnessesAmount - 1) % (2 * WitnessesAmount - 1) == 0) {
                        return 2;
                    } else {
                        return 3;
                    }
                }

                /*
                    Returns bit position inside the packing, if the packing were done by filling each row in order, without skipping any cells.
                */
                constexpr static const std::pair<std::size_t, std::size_t> straight_bit_position(
                        std::size_t start_row_index, std::size_t bit_num) {

                    std::size_t row = start_row_index + bit_num / WitnessesAmount;
                    std::size_t col = bit_num % WitnessesAmount;

                    return std::make_pair(row, col);
                };

                constexpr static const std::size_t straight_bit_position_inv(
                        std::size_t start_row_index, std::pair<std::size_t, std::size_t> pos) {

                    std::size_t unshifted_row = pos.first - start_row_index;
                    return unshifted_row * WitnessesAmount + pos.second;
                }

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t rows_amount = rows();

                constexpr static const std::size_t gates_amount = gates();

                struct input_type {
                    std::array<var, BitsAmount> bits;
                };

                struct result_type {
                    var output;
                    result_type(const bit_composition &component, std::uint32_t start_row_index) {
                        auto pos = sum_bit_position(start_row_index, sum_bits_amount() - 1);
                        output = var(component.W(pos.second), pos.first);
                    }
                };

                template<typename ContainerType>
                bit_composition(ContainerType witness) : component_type(witness, {}, {}) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_composition(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                bit_composition(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};

                /*
                    Returns row and column pair for each input bit for the BitsAmount < modulus_bits case.
                    Packing is done MSB first; code in generate_assignments is responsible for reversing the order if necessary.
                */
                template<std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
                constexpr static const std::pair<std::size_t, std::size_t> bit_position(
                        std::size_t start_row_index, std::size_t bit_num) {

                    if (bit_num < 3 * WitnessesAmount - 1) {
                        return straight_bit_position(start_row_index, bit_num);
                    }

                    std::size_t sum_bits = 1 + (bit_num - (3 * WitnessesAmount - 1)) / (2 * WitnessesAmount - 1);
                    return straight_bit_position(start_row_index, bit_num + sum_bits);
                }

                /*
                    Returns the amount of auxillary sum bits in the component for the BitsAmount < modulus_bits case.
                */
                template<std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
                constexpr static const std::size_t sum_bits_amount() {
                    if (BitsAmount < 3 * WitnessesAmount) {
                        return 1;
                    }
                    bool last_bit_sum_bit = (BitsAmount - (3 * WitnessesAmount - 1)) % (2 * WitnessesAmount - 1) == 0;

                    return 2 - last_bit_sum_bit + (BitsAmount - (3 * WitnessesAmount - 1)) / (2 * WitnessesAmount - 1);
                }

                /*
                    Returns row and column pair for each auxillary sum bit for the BitsAmount < modulus_bits case.
                */
                template<std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
                constexpr static const std::pair<std::size_t, std::size_t> sum_bit_position(
                        std::size_t start_row_index, std::size_t sum_bit_num) {
                    assert(sum_bit_num < sum_bits_amount());
                    std::size_t bit_pos = 0;

                    if (BitsAmount < 3 * WitnessesAmount - 1) {
                        // we only have a single sum bit in this case
                        bit_pos = BitsAmount;
                    } else if (sum_bit_num < sum_bits_amount() - 1) {
                        bit_pos = 3 * WitnessesAmount - 1 + sum_bit_num * 2 * WitnessesAmount;
                    } else {
                        bit_pos = BitsAmount + sum_bits_amount() - 1;
                    }

                    return straight_bit_position(start_row_index, bit_pos);
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount,
                     std::uint32_t BitsAmount, bit_composition_mode Mode>
            using plonk_bit_composition = bit_composition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                                  ArithmetizationParams>,
                                                          WitnessesAmount, BitsAmount, Mode>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t BitsAmount,
                     bit_composition_mode Mode,
                     std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
            typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams, 15, BitsAmount, Mode>::result_type
                generate_assignments(
                    const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams, 15, BitsAmount, Mode> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                         15, BitsAmount, Mode>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using var = typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                           15, BitsAmount, Mode>::var;

                using field_value_type = typename BlueprintFieldType::value_type;
                std::size_t witness_amount = 15;

                auto bit_index = [](std::size_t i) {
                    return Mode == bit_composition_mode::MSB ? i : BitsAmount - i - 1;
                };

                for (std::size_t i = 0; i < BitsAmount; i++) {
                    auto bit_pos = component.bit_position(start_row_index, i);
                    assignment.witness(component.W(bit_pos.second), bit_pos.first) =
                        var_value(assignment, instance_input.bits[bit_index(i)]);
                }

                field_value_type sum = 0;
                std::size_t bit_num = 0;
                for (std::size_t i = 0; i < component.sum_bits_amount(); i++) {
                    auto sum_bit_pos = component.sum_bit_position(start_row_index, i);
                    for (; bit_num < std::min(std::size_t(BitsAmount),
                                              3 * witness_amount - 1 + i * (2 * witness_amount - 1)); bit_num++) {
                        sum = 2 * sum + var_value(assignment, instance_input.bits[bit_index(bit_num)]);
                    }

                    assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                }

                return typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                      15, BitsAmount, Mode>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t BitsAmount,
                     bit_composition_mode Mode,
                     std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
            void generate_gates(
                const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams, 15, BitsAmount, Mode> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                     15, BitsAmount, Mode>::input_type &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                           15, BitsAmount, Mode>::var;

                std::size_t witness_amount = 15;

                std::size_t used_selectors = 1;

                std::size_t bit_num = 1;
                int row_idx = -1;
                std::size_t col_idx = 1;
                crypto3::zk::snark::plonk_constraint<BlueprintFieldType> constraint_prologue = var(component.W(0), -1);
                for (; bit_num < std::min(std::size_t(BitsAmount), 3 * witness_amount - 1); bit_num++) {
                    constraint_prologue = 2 * constraint_prologue + var(component.W(col_idx), row_idx);
                    col_idx++;
                    if (col_idx % witness_amount == 0) {
                        row_idx++;
                        col_idx = 0;
                    }
                }

                constraint_prologue = constraint_prologue - var(component.W(col_idx), row_idx);
                bp.add_gate(first_selector_index, constraint_prologue);

                if (bit_num == BitsAmount) {
                    return;
                }
                // We have two types of gates to add
                // 1) (second+) gate for fully filled rows
                // 2) incomplete final gate.
                // Either of the types can be absent.
                if (BitsAmount - bit_num >= 2 * witness_amount - 1) {
                    // Gate for fully filled rows
                    crypto3::zk::snark::plonk_constraint<BlueprintFieldType> constraint_middle =
                        var(component.W(witness_amount - 1), -1);
                    row_idx = 0;
                    col_idx = 0;
                    for (std::size_t i = 0; i < 2 * witness_amount - 1; i++) {
                        constraint_middle = 2 * constraint_middle + var(component.W(col_idx), row_idx);
                        col_idx++;
                        if (col_idx % witness_amount == 0) {
                            row_idx++;
                            col_idx = 0;
                        }
                    }

                    constraint_middle = constraint_middle - var(component.W(col_idx), row_idx);
                    bp.add_gate(first_selector_index + used_selectors, constraint_middle);
                    used_selectors++;
                }

                std::size_t bits_remaining = (BitsAmount - bit_num) % (2 * witness_amount - 1);
                if (bits_remaining > 0) {
                    // Gate for incompletely filled last rows
                    crypto3::zk::snark::plonk_constraint<BlueprintFieldType> constraint_epilogue =
                        var(component.W(witness_amount - 1), -1);
                    row_idx = 0;
                    col_idx = 0;
                    for (std::size_t i = 0; i < bits_remaining; i++) {
                        constraint_epilogue = 2 * constraint_epilogue + var(component.W(col_idx), row_idx);
                        col_idx++;
                        if (col_idx % witness_amount == 0) {
                            row_idx++;
                            col_idx = 0;
                        }
                    }
                    constraint_epilogue = constraint_epilogue - var(component.W(col_idx), row_idx);
                    bp.add_gate(first_selector_index + used_selectors, constraint_epilogue);
                    used_selectors++;
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t BitsAmount,
                     bit_composition_mode Mode,
                     std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
            void generate_copy_constraints(
                const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams, 15, BitsAmount, Mode> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                     15, BitsAmount, Mode>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                           15, BitsAmount, Mode>::var;

                std::size_t row = start_row_index;

                auto bit_index = [](std::size_t i) {
                    return Mode == bit_composition_mode::MSB ? i : BitsAmount - i - 1;
                };

                for (std::size_t i = 0; i < BitsAmount; i++) {
                    auto bit_pos = component.bit_position(start_row_index, i);
                    bp.add_copy_constraint({instance_input.bits[bit_index(i)],
                                            var(component.W(bit_pos.second), (std::int32_t)(bit_pos.first))});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t BitsAmount,
                     bit_composition_mode Mode,
                     std::enable_if_t<BitsAmount < BlueprintFieldType::modulus_bits, bool> = true>
            typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams, 15, BitsAmount, Mode>::result_type
                generate_circuit(
                    const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams, 15, BitsAmount, Mode> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                         15, BitsAmount, Mode>::input_type &instance_input,
                    const std::size_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                std::size_t row = start_row_index + 1;
                std::size_t witness_amount = 15;
                std::size_t used_selectors = 1;
                assignment.enable_selector(first_selector_index, row);

                std::size_t bits_remaining = BitsAmount > 3 * witness_amount + 1 ?
                                                BitsAmount - 3 * witness_amount - 1 :
                                                0;
                if (bits_remaining >= 2 * witness_amount - 1) {
                    for (; bits_remaining >= 2 * witness_amount - 1;
                           bits_remaining -= 2 * witness_amount - 1) {
                        row += 2;
                        assignment.enable_selector(first_selector_index + used_selectors, row);
                    }
                    used_selectors++;
                }
                if (bits_remaining > 0) {
                    row += 2;
                    assignment.enable_selector(first_selector_index + used_selectors, row);
                    used_selectors++;
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams,
                                                      15, BitsAmount, Mode>::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_COMPOSITION_HPP