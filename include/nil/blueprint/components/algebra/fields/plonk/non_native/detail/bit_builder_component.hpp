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
                enum bit_builder_component_implementation {
                    SMALL,
                    J3,
                    J2,
                    A2
                };

                /*
                    This function is responsible for deciding, which of the implementations (described below)
                    gets picked for a given WitnessesAmount/BitsAmount.
                    The implementation with the least amount of rows gets selected, with priority
                    going to implementations with less constraints.
                    The SMALL implementation gets picked iff BitsAmount < 3 * WitnessesAmount.

                    This function should *NOT* be called from outside bit_builder_component_constants_required
                    if possible.
                    Use bit_builder_component::implementation_variant method instead.
                */
                constexpr bit_builder_component_implementation bit_builder_component_implementation_picker(
                        std::uint32_t WitnessesAmount, std::uint32_t BitsAmount) {
                    if (BitsAmount < 3 * WitnessesAmount) {
                        return bit_builder_component_implementation::SMALL;
                    }
                    const std::uint32_t B = BitsAmount;
                    const std::uint32_t W = WitnessesAmount;
                    // 3 * ceil((B - 1) / (3W - 2))
                    std::uint32_t j3 = 3 * ((B - 1 + 3 * W - 2 - 1) / (3 * W - 2));
                    // 2 * ceil((B - 1) / (2W - 2))
                    std::uint32_t j2 = 2 * ((B - 1 + 2 * W - 2 - 1) / (2 * W - 2));
                    // 1 + 2 * ceil((B - 1) / (2W - 1))
                    std::uint32_t a2 = 1 + 2 * ((B - 1 + 2 * W - 1 - 1) / (2 * W - 1));

                    std::array<std::pair<bit_builder_component_implementation, std::uint32_t>, 1> variants = {
                        std::pair(bit_builder_component_implementation::J3, j3),
                        /*{bit_builder_component_implementation::J2, j2},
                        {bit_builder_component_implementation::A2, a2}*/
                    };

                    return std::min_element(variants.begin(), variants.end(),
                                            [](const auto &a, const auto &b) {
                                                return a.second < b.second;
                                            })->first;
                }
                /*
                    The component requires constants only when padding is required.
                    We use this function to avoid requiring constant columns when possible.
                    It's a bit janky -- this duplicates padding calculations -- but I haven't found a better way.

                    This function should *NOT* be called from outside this file if possible.
                */
                constexpr std::uint32_t bit_builder_component_constants_required(
                        std::uint32_t WitnessesAmount, std::uint32_t BitsAmount) {
                    bit_builder_component_implementation variant =
                        bit_builder_component_implementation_picker(WitnessesAmount, BitsAmount);
                    std::uint32_t padding = 0;
                    switch (variant) {
                    case bit_builder_component_implementation::SMALL:
                        return 0;
                    case bit_builder_component_implementation::J3:
                        padding = ((3 * WitnessesAmount - 2) -
                                   (BitsAmount - 3 * WitnessesAmount + 1) % (3 * WitnessesAmount - 2))
                                        % (3 * WitnessesAmount - 2);
                        return padding > 0;
                    default:
                        throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
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

                    There are four different component implementations.
                    The 'best' implementation gets chosen depending on BitsAmount and WitnessesAmount.

                    A schematic representation of the component. 'o' signifies an input bit.
                    'x' signifies one of the sum bits.
                    '0' signifies padding with zeros.
                    Input bits are packed MSB first.

                    For small (BitsAmount < 3 * WitnessesAmount) components, we use a single sum of bits.
                    Example for BitsAmount = 16:

                    SMALL
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- A single constraint forces 'x' to be equal to the (weighted)
                    |o|x| | | | | | | | | | | | | | ]    sum of 'o' bits
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                    J3
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
                    Similar padding is done for other variants.

                    An example for BitsAmount = 80 (90 cells: 3 sum bits, 80 input bits, 7 padding bits):
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |0|0|0|0|0|0|0|o|o|o|o|o|o|o|o| ] -- Note that the first 'x' is being used as an input/padding bit.
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |x|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ] -- The top lrft 'x' needs to be constrained to be equal to
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    the bottom right 'x' in the previous constraint block.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    J2
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |x|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- The first 'x' is the previous sum.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]    The second 'x' is constrained to be equal to the (weighted)
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      sum of 'o' bits and the previous sum.


                    A2
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    | | | | | | | | | | | | | | |x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- The first 'x' is the previous sum.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |    The second 'x' is constrained to be equal to the sum of 'o'
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    bits and the first 'x'. Empty spaces are not constrained.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    A2 is especially good at low WitnessesAmount, as it has the least asymptotic cell overhead, and
                    less cells are wasted at the start of the component.

                    A1 was considered for implementation, but found to be never better than one of {SMALL, J3, J2, A2}.

                    A1 (*NOT* implemented)
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    | | | | | | | | | | | | | | |x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- The first 'x' is the previous sum.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]    The second 'x' is constrained to be equal to the (weighted)
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      sum of 'o' bits and the first 'x'. Empty spaces are not
                                                        constrained.

                    J1 is a possible candidate for implementation, but it rarely provides benefits over
                    one of {SMALL, J3, J2, A2}.

                    J1 (*NOT* implemented)
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |x|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ] -- The left 'x' is the previous sum, the right 'x' is constrained
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      to be equal to the (weighted) sum of 'o' bits
                                                         and the left 'x'.
                */
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits>
                class bit_builder_component;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode,
                        bool CheckBits>
                class bit_builder_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                                WitnessesAmount, BitsAmount,
                                                                Mode, CheckBits>
                                    : public plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                            WitnessesAmount,
                                                            bit_builder_component_constants_required(
                                                                    WitnessesAmount, BitsAmount),
                                                            0> {

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                        bit_builder_component_constants_required(WitnessesAmount, BitsAmount), 0>;

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

                    constexpr static const bit_builder_component_implementation implementation_variant() {
                        return bit_builder_component_implementation_picker(WitnessesAmount, BitsAmount);
                    }

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
                        bit_builder_component_implementation variant =
                            bit_builder_component_implementation_picker(WitnessesAmount, BitsAmount);
                        switch (variant) {
                        case bit_builder_component_implementation::SMALL:
                            return 0;
                        case bit_builder_component_implementation::J3:
                            return ((3 * WitnessesAmount - 2) -
                                    (BitsAmount - 3 * WitnessesAmount + 1) % (3 * WitnessesAmount - 2))
                                        % (3 * WitnessesAmount - 2);
                        default:
                            throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                        }
                    }

                    /*
                        Returns row and column pair for each input bit.
                        Packing is done MSB first; code in generate_assignments is responsible for reversing the order if necessary.
                    */
                    constexpr static const std::pair<std::size_t, std::size_t> bit_position(
                            std::size_t start_row_index, std::size_t bit_num) {
                        bit_builder_component_implementation variant =
                            bit_builder_component_implementation_picker(WitnessesAmount, BitsAmount);
                        std::size_t sum_bits = 0;

                        switch (variant) {
                        case bit_builder_component_implementation::SMALL:
                            return straight_bit_position(start_row_index, bit_num);
                        case bit_builder_component_implementation::J3:
                            sum_bits = (bit_num >= 3 * WitnessesAmount - 1) *
                                        (2 + (bit_num - 3 * WitnessesAmount + 1) / (3 * WitnessesAmount - 2) * 2);
                            return straight_bit_position(start_row_index, bit_num + sum_bits);
                        default:
                            throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                        }
                    }

                    /*
                        Returns the amount of auxillary sum bits in the component.
                    */
                    constexpr static const std::size_t sum_bits_amount() {
                        bit_builder_component_implementation variant =
                            bit_builder_component_implementation_picker(WitnessesAmount, BitsAmount);
                        switch (variant) {
                        case bit_builder_component_implementation::SMALL:
                            return 1;
                        case bit_builder_component_implementation::J3:
                            // ceil division
                            return 1 + (BitsAmount - 3 * WitnessesAmount + 3 * WitnessesAmount - 2) /
                                    (3 * WitnessesAmount - 2) * 2;
                        default:
                            throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                        }
                    }

                    /*
                        Returns row and column pair for each auxillary sum bit.
                    */
                    constexpr static const std::pair<std::size_t, std::size_t> sum_bit_position(
                            std::size_t start_row_index, std::size_t sum_bit_num) {
                        assert(sum_bit_num < sum_bits_amount());
                        std::size_t bit_pos = 0;

                        bit_builder_component_implementation variant =
                            bit_builder_component_implementation_picker(WitnessesAmount, BitsAmount);
                        switch (variant) {
                        case bit_builder_component_implementation::SMALL:
                            bit_pos = BitsAmount;
                            break;
                        case bit_builder_component_implementation::J3:
                            bit_pos = 3 * WitnessesAmount - 1 + (sum_bit_num / 2) * (3 * WitnessesAmount) +
                                    (sum_bit_num % 2);
                            break;
                        default:
                            throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                        }

                        return straight_bit_position(start_row_index, bit_pos);
                    }
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits>
                using plonk_bit_builder = bit_builder_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                                WitnessesAmount, BitsAmount, Mode, CheckBits>;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits>
                void generate_assignments(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                                BitsAmount, Mode, CheckBits>
                            &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::array<bool, BitsAmount> &input_bits,
                        const std::uint32_t start_row_index) {

                    using ArithmetizationType =
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                    using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, BitsAmount, Mode, CheckBits>::var;

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
                    // In J3/J2 and SMALL type implementations we have to 'double up' the sum bits.
                    // In A2 implementation all the sum bits are unique.
                    switch (component.implementation_variant()) {
                    case bit_builder_component_implementation::SMALL: // expected fallthrough
                    case bit_builder_component_implementation::J3:
                        for (std::size_t i = 0; i < component.sum_bits_amount(); i += 2) {
                            auto sum_bit_pos = component.sum_bit_position(start_row_index, i);
                            std::size_t max_bit_num = BitsAmount < 3 * WitnessesAmount ?
                                                    BitsAmount :
                                                    3 * WitnessesAmount - padding - 1 +
                                                    (i / 2) * (3 * WitnessesAmount - 2);
                            for (; bit_num < max_bit_num; bit_num++) {
                                sum = 2 * sum + input_bits[bit_index(bit_num)];
                            }

                            assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                            if (i != component.sum_bits_amount() - 1) {
                                auto sum_bit_pos = component.sum_bit_position(start_row_index, i + 1);
                                assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                            }
                        }
                        break;
                    default:
                        throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                    }
                }

                /*
                    The CheckBits component should always be true for bit_decomposition: we need to check that the output
                    is actually bits.
                    It is optional for bit_composition: the input might have already been checked.
                */
                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits>
                void generate_gates(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                                BitsAmount, Mode, CheckBits>
                            &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::size_t first_selector_index) {

                    using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, BitsAmount, Mode, CheckBits>::var;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                    constraint_type constraint_sum;
                    int row_idx = -1;
                    std::size_t col_idx = 1;
                    std::vector<constraint_type> bit_constraints;

                    switch (component.implementation_variant()) {
                        case bit_builder_component_implementation::SMALL: // expected fallthrough
                        case bit_builder_component_implementation::J3:
                            constraint_sum = var(component.W(0), -1);
                            for (std::size_t bit_num = 1; bit_num < std::min(BitsAmount, 3 * WitnessesAmount - 1);
                                bit_num++) {

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
                                row_idx = -1;
                                col_idx = 1;

                                bit_constraints.resize(3 * WitnessesAmount - 2);

                                for (std::size_t bit_num = 1; bit_num < std::min(BitsAmount, 3 * WitnessesAmount - 1);
                                    bit_num++) {

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
                            break;
                        default:
                            throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                    }
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits,
                        std::enable_if_t<bit_builder_component_constants_required(WitnessesAmount, BitsAmount) == 1,
                                        bool> = true>
                void generate_assignments_constant(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                                BitsAmount, Mode, CheckBits>
                            &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::size_t start_row_index) {

                    using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, BitsAmount, Mode, CheckBits>::var;

                    assignment.constant(component.C(0), start_row_index) = 0;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits,
                        std::enable_if_t<bit_builder_component_constants_required(WitnessesAmount, BitsAmount) == 0,
                                        bool> = true>
                void generate_assignments_constant(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                                BitsAmount, Mode, CheckBits>
                            &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::size_t start_row_index) {
                    // no constants in this case
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                        std::uint32_t BitsAmount, bit_composition_mode Mode, bool CheckBits>
                void generate_circuit(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                                BitsAmount, Mode, CheckBits>
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
                                    BitsAmount, Mode, CheckBits>(
                                            component, bp, assignment, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }

                    std::size_t end_row_index, row_offset;

                    switch (component.implementation_variant()) {
                    case bit_builder_component_implementation::SMALL: // expected fallthrough
                    case bit_builder_component_implementation::J3:
                        end_row_index = start_row_index +
                                        (component.rows_amount > 2 ? component.rows_amount - 2 : 1);
                        row_offset = 3;
                        break;
                    default:
                        throw std::runtime_error("UNIMPLEMENTED BIT_BUILDER_COMPONENT VARIANT");
                    }

                    assignment.enable_selector(first_selector_index, start_row_index + 1, end_row_index, row_offset);

                    // copy constraints are specific to either bit_composition or bit_decomposition
                    // they are created in generate_circuit for corresponding classes
                    generate_assignments_constant<BlueprintFieldType, ArithmetizationParams, WitnessesAmount,
                                                BitsAmount, Mode, CheckBits>(
                                                    component, assignment, start_row_index);
                }
            }   // namespace detail
        }       // namespace components
    }           // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP