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
                const std::size_t num_bits;
                const std::size_t bits_per_block = 64;
                std::size_t shift;

                const std::size_t limit_permutation_column = 7;

                struct input_type {
                    // initial message = message[0] * 2^(64 * (num_blocks - 1)) + ... + message[num_blocks - 2] * 2^64 + message[num_blocks - 1]
                    // all message[i] are 64-bit for i > 0
                    // message[0] is <= 64-bit
                    std::vector<var> message;
                };

                struct result_type {
                    std::vector<var> padded_message;

                    result_type(const keccak_per_chunk &component, std::size_t start_row_index) {
                        
                    }
                };

                std::size_t get_shift() {
                    return num_blocks * 64 - num_bits;
                }

                configuration configure_batching(std::size_t row, std::size_t column,
                                                std::size_t prev_bits, std::size_t &next_bits,
                                                std::size_t total_bits = bits_per_block) {
                    if (prev_bits > 64) {
                        next_bits = prev_bits - 64;
                    } else {
                        next_bits = bits_per_block - 64 + prev_bits;
                    }

                    std::size_t num_chunks = total_bits / 64 + bool(total_bits % 64);

                    std::size_t last_row = row,
                                last_column = column;
                                
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;

                    if (num_args + column > limit_permutation_column) {
                        for (int i = 0; i < num_args; ++i) {
                            copy_to.push_back({last_row + 1, i});
                        }
                    } else {
                        for (int i = 0; i < num_args; ++i) {
                            copy_to.push_back({last_row + (last_column / WitnessesAmount),
                                                            (last_column++) % WitnessesAmount});
                        }
                    }
                    
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    std::size_t final_row = (column + num_cells - 1) / WitnessesAmount + row;
                    if (final_row == copy_to[0].first) {
                        cell_copy_from = {final_row, copy_to.back().second + 1};
                    } else {
                        cell_copy_from = {final_row, 0};
                    }
                    
                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (num_args + column > limit_permutation_column) {
                        for (int i = column; i < WitnessesAmount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - WitnessesAmount + column;
                        std::size_t cur_row = row + 1,
                                    cur_column = num_args;
                        while (cur_column < cells_left) {
                            if (cur_column % WitnessesAmount == cell_copy_from.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_from.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + num_args;
                        while (cur_column - column < num_cells) {
                            if (cur_column % WitnessesAmount == cell_copy_from.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_from.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    }
                    std::size_t cell_index = 0;
                    
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    constraints.push_back({cells[cell_index++]});
                    for (int i = 0; i < num_args; ++i) {
                        constraints[0].push_back(copy_to[i]);
                    }

                    constraints.push_back({constraints[0][0]});
                    constraints.push_back({cell_copy_from});
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(num_chunks, std::vector<std::pair<std::size_t, std::size_t>>());
                    for (std::size_t i = 1; i < 3; ++i) {
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            constraints[i].push_back(cells[cell_index++]);
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    last_column = cells.back().second + 1;
                    last_row = cells.back().first + (last_column >= WitnessesAmount);
                    last_column %= WitnessesAmount;

                    // return configuration({last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                }

                configuration configure_padding(std::size_t row, std::size_t column,
                                                std::size_t prev_bits = 0) {
                    if (prev_bits == 0) {
                        // costraint with 0
                        if (column >= limit_permutation_column) {
                            row = row + 1;
                            column = 0;
                            return configuration({row + 1, 1}, {{row + 1, 0}}, {}, {}, {row + 1, 0});
                        }
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

                #define __keccak_padding_init_macro(lookup_rows_, lookup_columns_, num_blocks_, num_bits_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    num_blocks(num_blocks_), \
                    num_bits(num_bits_), \
                    shift(get_shift()), \
                    full_configuration(configure_all()), \
                    rows_amount(rows()), \
                    gates_amount(gates())

                template<typename ContainerType>
                keccak_per_chunk(ContainerType witness, std::size_t lookup_rows_, std::size_t lookup_columns_,
                                                        std::size_t num_blocks_, std::size_t num_bits_) :
                    component_type(witness, {}, {}),
                    __keccak_per_chunk_init_macro(lookup_rows_, lookup_columns_, num_blocks_, num_bits_) {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_per_chunk(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_, std::size_t lookup_columns_,
                                   std::size_t num_blocks_ std::size_t num_bits_):
                    component_type(witness, constant, public_input),
                    __keccak_per_chunk_init_macro(lookup_rows_, lookup_columns_, num_blocks_, num_bits_) {};

                keccak_per_chunk(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t lookup_rows_, std::size_t lookup_columns_,
                    std::size_t num_blocks_, std::size_t num_bits_) :
                        component_type(witnesses, constants, public_inputs),
                        __keccak_per_chunk_init_macro(lookup_rows_, lookup_columns_, num_blocks_, num_bits_)
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
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                
                auto config = component.full_configuration;
                auto gate_config = component.gates_configuration;
                // auto lookup_gate_config = component.lookup_gates_configuration;
                std::size_t config_index = 0;
                std::size_t gate_index = 0;
                // std::size_t lookup_gate_index = 0;

                std::vector<constraint_type> constraints;
                // std::vector<lookup_constraint_type> lookup_constraints;

                // batching
                if (component.shift > 0) {
                    for (int i = 0; i < component.num_block; ++i) {
                        auto cur_config = config[config_index];
                        constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])
                                                              - var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index]) * (integral_type(1) << component.shift)
                                                              - var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index])));
                        gate_index++;
                        constraints.push_back(bp.add_constraint(var(cur_config.constraints[1][1].column, cur_config.constraints[1][1].row - gate_config[gate_index])
                                                            - (integral_type(1) << (64 - component.shift))
                                                            + (integral_type(1) << 64)
                                                            - var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index])));
                        gate_index++;
                        if (i > 0) {
                            constraints.push_back(bp.add_constraint(var(cur_config.constraints[2][1].column, cur_config.constraints[2][1].row - gate_config[gate_index])
                                                                + var(cur_config.constraints[2][2].column, cur_config.constraints[2][2].row - gate_config[gate_index]) 
                                                                - var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index])));
                            gate_index++;
                        }
                        config_index++;
                    }
                    
                    // padding
                    {
                        auto cur_config = config[config_index];
                        constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])
                                                              - var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index]) * (integral_type(1) << component.shift)));
                    }
                }
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

                std::size_t config_index = 0;
                if (component.shift > 0) {
                    config_index += component.num_blocks + 1;
                }

                while (congif_index < component.full_configuration.size()) {
                    bp.add_copy_constraint({component.C(0), var(component.W(config[i].copy_to[0].row), config[i].copy_to[0].column, false)});
                    config_index++;
                }
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
                if (component.shift != 0) {
                    // TODO where to put first relay chunk?
                    value_type relay_chunk = var_value(assignment, instance_input.message[0]);
                    for (std::size_t index = 1; index < component.num_blocks; ++index) {
                        value_type chunk = var_value(assignment, instance_input.message[index]);
                        integral_type integral_chunk = integral_type(chunk);
                        integral_type mask = (integral_type(1) << component.shift) - 1;
                        std::array<value_type, 2> chunk_parts = {value_type(integral_chunk >> component.shift), value_type(integral_chunk & mask)};
                        value_type first_chunk = (relay_chunk << (64 - component.shift)) + chunk_parts[0];
                        value_type relay_range_check = chunk_parts[1] - (1 << component.shift) + (1 << 64);

                        auto cur_config = component.full_configuration[config_index];
                        assignment.witness(component.W(cur_config.constraints[0][0].row), cur_config.constraints[0][0].column) = chunk;
                        for (int j = 1; j < 3; ++j) {
                            assignment.witness(component.W(cur_config.constraints[0][j].row), cur_config.constraints[0][j].column) = value_type(chunk_parts[j - 1]);
                        }
                        assignment.witness(component.W(cur_config.constraints[1][0].row), cur_config.constraints[1][0].column) = relay_range_check;
                        assignment.witness(component.W(cur_config.constraints[2][0].row), cur_config.constraints[2][0].column) = first_chunk;
                        
                        relay_chunk = chunk_parts[1];
                        config_index++;
                    }
                    // padding
                    {
                        value_type last_chunk = relay_chunk << (64 - component.shift);

                        auto cur_config = component.full_configuration[config_index];
                        assignment.witness(component.W(cur_config.copy_to[0].row), cur_config.copy_to[0].column) = relay_chunk;
                        assignment.witness(component.W(cur_config.constraints[0][0].row), cur_config.constraints[0][0].column) = last_chunk;
                        config_index++;
                    }
                }
                
                while (congif_index < component.full_configuration.size()) {
                    auto cur_config = component.full_configuration[config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].row), cur_config.copy_to[0].column) = component.C(0);
                    config_index++;
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