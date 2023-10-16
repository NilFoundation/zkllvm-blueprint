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
#include <nil/blueprint/components/hashes/keccak/keccak_padding.hpp>

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
                using integral_type = typename BlueprintFieldType::integral_type;

                // TODO check if it is correct
                std::size_t calculate_chunk_size(std::size_t lookup_rows) const {
                    std::size_t chunk_size = 0;
                    while ((1 << chunk_size) < lookup_rows) {
                        chunk_size++;
                    }
                    return 0;//chunk_size;
                }
                std::size_t calculate_num_chunks() const {
                    return 0;//(num_bits + pack_chunk_size - 1) / pack_chunk_size;
                }
                std::size_t calculate_num_cells() const {
                    return 0;//(num_bits + pack_chunk_size * WitnessesAmount - 1) / (pack_chunk_size * WitnessesAmount);
                }
                std::size_t calculate_buff() const {
                    return 0;//(num_bits + pack_chunk_size * WitnessesAmount - 1) / pack_chunk_size;
                }

                std::size_t calculate_num_round_calls(std::size_t num_blocks) const {
                    return (num_blocks + (17 - num_blocks % 17)) / 17;
                }

                std::size_t rows() const {
                    return 0;
                }

            public:
                using var = typename component_type::var;

                using round_component_type = keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>, WitnessesAmount>;
                round_component_type round_true_true;
                std::vector<round_component_type> rounds_true_false;
                std::vector<round_component_type> rounds_false_false;
                std::vector<round_component_type> rounds;

                // using padding_component_type = keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                //                                                             ArithmetizationParams>, WitnessesAmount>;
                // padding_component_type padding;

                using configuration = typename round_component_type::configuration;
                std::vector<configuration> full_configuration;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;
                
                const std::size_t num_blocks;
                const std::size_t num_bits;
                const std::size_t limit_permutation_column;

                const std::size_t num_round_calls;
                const std::size_t num_configs;

                const std::size_t pack_chunk_size;
                const std::size_t pack_num_chunks;
                const std::size_t pack_cells;
                const std::size_t pack_buff;

                const std::size_t rows_amount;
                constexpr static const std::size_t gates_amount = 1;

                const std::size_t round_constant[24] = {1, 0x8082, 0x800000000000808a, 0x8000000080008000,
                                                        0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
                                                        0x8a, 0x88, 0x80008009, 0x8000000a,
                                                        0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                                                        0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a,
                                                        0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008};

                struct input_type {
                    std::vector<var> message;
                };

                struct result_type {
                    std::array<var, 5> final_inner_state;

                    result_type(const keccak &component, std::size_t start_row_index) {
                        for (std::size_t i = 0; i < 5; ++i) {
                            final_inner_state[i] = var(component.W(component.full_configuration[component.num_configs - 5 + i].copy_from.column),
                                                        start_row_index + component.full_configuration[component.num_configs - 5 + i].copy_from.row, false);
                        }
                    }
                };

                std::vector<round_component_type> create_rounds() {
                    std::vector<round_component_type> rounds;
                    rounds.push_back(round_true_true);
                    rounds.insert(rounds.end(), rounds_false_false.begin(), rounds_false_false.begin() + 23);
                    for (std::size_t i = 1; i < num_round_calls; ++i) {
                        rounds.push_back(rounds_true_false[i - 1]);
                        rounds.insert(rounds.end(), rounds_false_false.begin() + i * 23, rounds_false_false.begin() + (i + 1) * 23);
                    }
                    return rounds;
                }

                integral_type pack(const integral_type& const_input) const {
                    integral_type input = const_input;
                    integral_type sparse_res = 0;
                    integral_type power = 1;
                    while (input > 0) {
                        auto bit = input % 2;
                        sparse_res += bit * power;
                        power *= 8;
                        input /= 2;
                    }
                    return sparse_res;
                }

                integral_type unpack(const integral_type& const_sparse_input) const {
                    integral_type sparse_input = const_sparse_input;
                    integral_type res = 0;
                    integral_type power = 1;
                    while (sparse_input > 0) {
                        auto bit = sparse_input % 8;
                        BOOST_ASSERT(bit * (1 - bit) == 0);
                        res += bit * power;
                        power *= 2;
                        sparse_input /= 8;
                    }
                    return res;
                }

                configuration configure_pack_unpack(std::size_t row, std::size_t column) {
                    // regular constraints:
                    // input = input0 + input1 * 2^chunk_size + ... + inputk * 2^(k*chunk_size)
                    // output = output0 + output1 * 2^chunk_size + ... + outputk * 2^(k*chunk_size)
                    
                    std::size_t last_row = row,
                                last_column = column;
                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};
                                
                    std::vector<std::pair<std::size_t, std::size_t>> copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    
                    if (1 + column > limit_permutation_column) {
                        copy_from.push_back({last_row + 1, 0});
                    } else {
                        copy_from.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                    }
                                    
                    std::pair<std::size_t, std::size_t> cell_copy_to;
                    std::size_t final_row = (column + pack_cells - 1) / WitnessesAmount + row;
                    if (final_row == copy_from[0].first) {
                        cell_copy_to = {final_row, copy_from.back().second + 1};
                    } else {
                        cell_copy_to = {final_row, 0};
                    }
                    
                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (1 + column > limit_permutation_column) {
                        for (int i = column; i < WitnessesAmount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = pack_cells - WitnessesAmount + column;
                        std::size_t cur_row = row + 1,
                                    cur_column = 1;
                        while (cur_column < cells_left) {
                            if (cur_column % WitnessesAmount == cell_copy_to.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + 1;
                        while (cur_column - column < pack_cells) {
                            if (cur_column % WitnessesAmount == cell_copy_to.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    }                
                    std::size_t cell_index = 0;
                    
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> 
                                lookups(pack_num_chunks, std::vector<std::pair<std::size_t, std::size_t>>());
                        
                    constraints.push_back({copy_from[0]});
                    constraints.push_back({cell_copy_to});
                    for (std::size_t i = 0; i < 2; ++i) {
                        for (std::size_t j = 0; j < pack_num_chunks; ++j) {
                            constraints[i].push_back(cells[cell_index++]);
                            lookups[j].push_back(constraints[i].back());
                        }
                    }
                    
                    last_column = cells.back().second + 1;
                    last_row = cells.back().first + (last_column / WitnessesAmount);
                    last_column %= WitnessesAmount;
                    
                    return configuration(first_coordinate, {last_row, last_column}, copy_from, constraints, lookups, cell_copy_to);
                }

                std::vector<configuration> configure_all(const std::size_t num_configs,
                                                         const std::size_t num_round_calls) {
                    std::vector<configuration> result;

                    std::size_t row = 0,
                                column = 0;
                    // padding
                    // row += padding_component.rows_amount;

                    //rounds
                    for (std::size_t index = 0; index < num_round_calls; ++index) {
                        // to sparse representation
                        for (std::size_t i = 0; i < 17; ++i) {
                            result.push_back(configure_pack_unpack(row, column));
                            row = result[i].last_coordinate.row;
                            column = result[i].last_coordinate.column;
                        }
                        // round
                        if (column > 0) {
                            column = 0;
                            row++;
                        }
                        for (std::size_t i = 0; i < 24; ++i) {
                            row += rounds[index * 24 + i].rows_amount;
                        }
                    }

                    // from sparse representation
                    for (std::size_t i = 0; i < 5; ++i) {
                        result.push_back(configure_pack_unpack(row, column));
                        row = result[i].last_coordinate.row;
                        column = result[i].last_coordinate.column;
                    }

                    return result;
                }

                #define __keccak_init_macro(witness, constant, public_input, \
                                            lookup_rows_, lookup_columns_, num_blocks_, num_bits_, lpc_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    pack_chunk_size(calculate_chunk_size(lookup_rows_)), \
                    pack_num_chunks(calculate_num_chunks()), \
                    pack_cells(calculate_num_cells()), \
                    pack_buff(calculate_buff()), \
                    num_blocks(num_blocks_), \
                    num_bits(num_bits_), \
                    limit_permutation_column(lpc_), \
                    num_round_calls(calculate_num_round_calls(num_blocks_)), \
                    round_true_true(round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, true, true, lpc_)), \
                    rounds_true_false(num_round_calls - 1, \
                            round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, true, false, lpc_)), \
                    rounds_false_false(num_round_calls * 23, \
                            round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, false, false, lpc_)), \
                    rounds(create_rounds()), \
                    num_configs(), \
                    full_configuration(configure_all(num_configs, num_round_calls)), \
                    rows_amount(rows())

                template<typename ContainerType>
                keccak(ContainerType witness, std::size_t lookup_rows_,
                        std::size_t lookup_columns_, std::size_t num_blocks_, std::size_t num_bits_, std::size_t lpc_ = 7) :
                    component_type(witness, {}, {}),
                    __keccak_init_macro(witness, {}, {}, lookup_rows_, lookup_columns_, num_blocks_, num_bits_, lpc_) {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_,
                                   std::size_t lookup_columns_,
                                   std::size_t num_blocks_,
                                   std::size_t num_bits_,
                                   std::size_t lpc_ = 7) :
                    component_type(witness, constant, public_input),
                    __keccak_init_macro(witness, constant, public_input, lookup_rows_, lookup_columns_, num_blocks_, num_bits_, lpc_) {};

                keccak(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs,
                        std::size_t lookup_rows_, std::size_t lookup_columns_, std::size_t num_blocks_, std::size_t num_bits_, std::size_t lpc_ = 7) :
                        component_type(witnesses, constants, public_inputs),
                        __keccak_init_macro(witnesses, constants, public_inputs,
                                            lookup_rows_, lookup_columns_, num_blocks_, num_bits_, lpc_) {};

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

                // std::vector<std::vector<var>> padded_message = generate_assignments(component.padding, assignment,
                //                                                                     {instance_input.message}, row).output;
                // row += component.padding.rows_amount;

                std::array<var, 25> inner_state;
                for (std::size_t i = 0; i < component.num_round_calls; ++i) {
                    for (std::size_t j = 0; j < 24; ++j) {
                        auto round_input = typename component_type::round_component_type::input_type();
                        round_input.padded_message_chunk;// = instance_input.message;
                        round_input.inner_state = inner_state;
                        round_input.round_constant = var(component.C(0), row + i, false, var::column_type::constant);
                        inner_state = generate_assignments(component.rounds[i * 24 + j], assignment, round_input, row).inner_state;
                        row += component.rounds[i * 24 + j].rows_amount;
                    }
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_assignments_constant(
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

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::size_t row = start_row_index;
                for (std::size_t i = 0; i < 24; ++i) {
                    assignment.constant(component.C(0), row + i) = component.round_constant[i];
                }
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP