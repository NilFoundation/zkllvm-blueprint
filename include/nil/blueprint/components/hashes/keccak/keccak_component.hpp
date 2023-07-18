//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class keccak;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class keccak<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                                     WitnessesAmount> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;

                std::size_t calculate_normalize_chunk_size(std::size_t num_rows, std::size_t i) {
                    std::size_t res = 0;
                    std::size_t power = i;
                    while (power < num_rows) {
                        ++res;
                        power *= i;
                    }
                    return res;
                }

                std::size_t rows() const {
                    return 0;
                }

            public:
                using var = typename component_type::var;

                using round_component_type = keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>,
                                            WitnessesAmount>;
                std::array<round_component_type, 17> rounds;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;
                const std::size_t normalize3_chunk_size;
                const std::size_t normalize4_chunk_size;
                const std::size_t normalize6_chunk_size;

                constexpr static const bool needs_bonus_row = WitnessesAmount < 5;
                const std::size_t rows_amount;
                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    std::array<var, 25> inner_state;
                    std::array<var, 17> padded_message_chunk;
                    var round_constant;
                };

                struct result_type {
                    std::array<var, 25> final_inner_state;

                    result_type(const keccak &component, std::size_t start_row_index) {
                        std::pair<std::size_t, std::size_t>
                            r_address = component.get_var_address(var_address::R_, start_row_index),
                            q_address = component.get_var_address(var_address::Q, start_row_index);

                        quotient = var(component.W(q_address.second), q_address.first);
                        remainder = var(component.W(r_address.second), r_address.first);
                    }
                };

                #define __keccak_init_macro(witness, constant, public_input, \
                                                        lookup_rows_, lookup_columns_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    normalize3_chunk_size(calculate_normalize_chunk_size(lookup_rows_, 3)), \
                    normalize4_chunk_size(calculate_normalize_chunk_size(lookup_rows_, 4)), \
                    normalize6_chunk_size(calculate_normalize_chunk_size(lookup_rows_, 6)), \
                    range_checks(range_check_amount, \
                                 range_check_component_type(witness, constant, public_input, bits_amount_)), \
                    rows_amount(rows())

                template<typename ContainerType>
                division_remainder(ContainerType witness, std::size_t bits_amount_, bool check_inputs_) :
                    component_type(witness, {}, {}),
                    __division_remainder_init_macro(witness, {}, {}, bits_amount_, check_inputs_) {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                division_remainder(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t bits_amount_, bool check_inputs_):
                    component_type(witness, constant, public_input),
                    __division_remainder_init_macro(witness, constant, public_input, bits_amount_, check_inputs_) {};

                division_remainder(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t bits_amount_, bool check_inputs_) :
                        component_type(witnesses, constants, public_inputs),
                        __division_remainder_init_macro(witnesses, constants, public_inputs,
                                                        bits_amount_, check_inputs_)
                {};

                #undef __keccak_init_macro
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            using keccak_component =
                keccak<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>,
                                   WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_gates(
                const keccak_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {
                    
                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_copy_constraints(
                const keccak_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                std::uint32_t row = start_row_index;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            typename keccak_component<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount>::result_type
            generate_circuit(
                const keccak_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                std::size_t row = start_row_index;

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            typename keccak_component<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount>::result_type
            generate_assignments(
                const keccak_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;


                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP