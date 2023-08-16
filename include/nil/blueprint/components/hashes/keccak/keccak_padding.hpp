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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PER_CHUNK_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PER_CHUNK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class keccak_per_chunk;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class keccak_per_chunk<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                                     WitnessesAmount> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;

                std::size_t rows() const {
                    return 0;
                } 

            public:
                using var = typename component_type::var;

                const std::size_t rows_amount;
                constexpr static const std::size_t gates_amount;
                
                const std::size_t num_blocks;
                const std::size_t num_bits_first;
                const std::size_t bits_per_block = 255;
                std::vector<std::size_t> shifts;

                struct input_type {
                    std::vector<var> message;
                };

                struct result_type {
                    std::vector<var> padded_message;

                    result_type(const keccak_per_chunk &component, std::size_t start_row_index) {
                        
                    }
                };

                configuration configure_batching(std::size_t row, std::size_t column,
                                                std::size_t prev_bits, std::size_t &next_bits,
                                                std::size_t total_bits = bits_per_block) {
                    if (prev_bits > 64) {
                        next_bits = prev_bits - 64;
                    } else {
                        next_bits = bits_per_block - 64 + prev_bits;
                    }

                    std::size_t num_chunks = total_bits / 64 + bool(total_bits % 64);


                    // return configuration({last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                }

                configuration configure_padding(std::size_t row, std::size_t column,
                                                std::size_t prev_bits = 0) {
                    if (prev_bits == 0) {
                        // costraint with 0
                        auto last_column = column + 1;
                        auto last_row = row + (last_column / WitnessesAmount);
                        last_column %= WitnessesAmount;
                        return configuration({last_row, last_column}, {{row, column}}, {}, {}, {row, column});
                    }
                    auto other_column = column + 1;
                    auto other_row = row + (other_column / WitnessesAmount);
                    other_column %= WitnessesAmount;
                    auto last_column = column + 2;
                    auto last_row = row + (last_column / WitnessesAmount);
                    last_column %= WitnessesAmount;
                    
                    return configuration({last_row, last_column}, {{row, column}}, {{{other_row, other_column}, {row, column}}}, {{other_row, other_column}}, {other_row, other_column});
                }

                std::vector<configuration> configure_all() {
                    std::vector<configuration> result;
                    std::size_t row = 0,
                                column = 0;
                    std::size_t next_bits = 0;

                    //batching
                    result.push_back(configure_batching(row, column, 0, next_bits, num_bits_first));
                    row = result.back().last_row;
                    column = result.back().last_column;
                    for (std::size_t i = 1; i < num_blocks; ++i) {
                        result.push_back(configure_batching(row, column, next_bits, next_bits));
                        row = result[i].last_row;
                        column = result[i].last_column;
                    }

                    //counting number of chunks
                    std::size_t total_bits = num_bits_first + (num_blocks - 1) * bits_per_block;
                    std::size_t padding_bits = 1088 - (total_bits % 1088);
                    std::size_t padding_chunks = (total_bits + padding_bits) / 64 - total_bits / 64;

                    //padding with zeros
                    result.push_back(configure_padding(row, column, next_bits));
                    row = result.back().last_row;
                    column = result.back().last_column;
                    for (std::size_t i = 1; i < padding_chunks; ++i) {
                        result.push_back(configure_padding(row, column));
                        row = result.back().last_row;
                        column = result.back().last_column;
                    }

                    return result;
                }

                #define __keccak_padding_init_macro(lookup_rows_, lookup_columns_, num_blocks_, num_bits_first_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    num_blocks(num_blocks_), \
                    num_bits_first(num_bits_first_), \
                    full_configuration(configure_all()), \
                    rows_amount(rows()), \
                    gates_amount(gates())

                template<typename ContainerType>
                keccak_per_chunk(ContainerType witness, std::size_t lookup_rows_, std::size_t lookup_columns_, std::size_t num_blocks_) :
                    component_type(witness, {}, {}),
                    __keccak_per_chunk_init_macro(lookup_rows_, lookup_columns_, num_blocks_) {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_per_chunk(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_, std::size_t lookup_columns_, std::size_t num_blocks_):
                    component_type(witness, constant, public_input),
                    __keccak_per_chunk_init_macro(lookup_rows_, lookup_columns_, num_blocks_) {};

                keccak_per_chunk(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t lookup_rows_, std::size_t lookup_columns_, std::size_t num_blocks_) :
                        component_type(witnesses, constants, public_inputs),
                        __keccak_per_chunk_init_macro(lookup_rows_, lookup_columns_, num_blocks_)
                {};

                #undef __keccak_padding_init_macro
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            using keccak_pad_component =
                keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>,
                                   WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_gates(
                const keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {
                    
                using component_type = keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
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
                const keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                std::uint32_t row = start_row_index;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount>::result_type
            generate_circuit(
                const keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                std::size_t row = start_row_index;

                using component_type = keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constants(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount>::result_type
            generate_assignments(
                const keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                std::size_t config_index = 0;

                // batching
                value_type relay_chunk = 0;
                std::size_t relay_bits = 0;
                for (std::size_t index = 0; index < component.num_blocks; ++index) {
                    value_type chunk = var_value(assignment, instance_input.message[index]);
                    std::size_t bit_size = index == 0 ? component.num_bits_first : component.bits_per_block;
                    std::size_t shift = component.shifts[index];
                    std::vector<value_type> chunk_parts;
                    while (chunk > 0) {
                        integral_type mask = (integral_type(1) << shift) - 1;
                        chunk_parts.push_back(chunk & mask);
                        chunk >>= shift;
                        shift = 64;
                    }
                    value_type first_chunk = (relay_chunk << relay_bits) + chunk_parts.back();
                }

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_assignments_constant(
                const keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_pad_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;

                assignment.constant(component.C(0), start_row_index) = 0;
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PER_CHUNK_HPP