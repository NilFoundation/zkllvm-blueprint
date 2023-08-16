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

#include <<nil/blueprint/components/hashes/keccak/keccak_round.hpp>
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

                std::size_t rows() const {
                    return 0;
                }

            public:
                using var = typename component_type::var;

                using round_component_type = keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>, WitnessesAmount>;
                std::vector<round_component_type> rounds;

                using padding_component_type = keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>, WitnessesAmount>;
                padding_component_type padding;

                using configuration = round_component_type::configuration;
                std::vector<configuration> full_configuration;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;
                
                const std::size_t num_blocks;
                const std::size_t num_round_calls;
                const std::size_t num_configs;

                const std::size_t pack_chunk_size;
                const std::size_t pack_num_chunks;
                const std::size_t pack_num_cells;

                const std::size_t rows_amount;
                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    std::vector<var> message;
                };

                struct result_type {
                    std::array<var, 25> final_inner_state;

                    result_type(const keccak &component, std::size_t start_row_index) {
                        
                    }
                };

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
                                
                    std::vector<std::pair<std::size_t, std::size_t>> copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    
                    if (1 + column > limit) {
                        copy_from.push_back({last_row + 1, 0});
                    } else {
                        copy_from.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                    }
                                    
                    std::pair<std::size_t, std::size_t> cell_copy_to;
                    std::size_t final_row = (column + num_cells - 1) / WitnessesAmount + row;
                    if (final_row == copy_from[0].first) {
                        cell_copy_to = {final_row, copy_from.back().second + 1};
                    } else {
                        cell_copy_to = {final_row, 0};
                    }
                    
                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (1 + column > limit) {
                        for (int i = column; i < WitnessesAmount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - WitnessesAmount + column;
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
                        while (cur_column - column < num_cells) {
                            if (cur_column % WitnessesAmount == cell_copy_to.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    }                
                    std::size_t cell_index = 0;
                    
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(num_chunks, std::vector<std::pair<std::size_t, std::size_t>>());
                        
                    constraints.push_back({copy_from[0]});
                    constraints.push_back({cell_copy_to});
                    for (std::size_t i = 0; i < 2; ++i) {
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            constraints[i].push_back(cells[cell_index++]);
                            lookups[j].push_back(constraints[i].back());
                        }
                    }
                    
                    last_column = cells.back().second + 1;
                    last_row = cells.back().first + (last_column / WitnessesAmount);
                    last_column %= WitnessesAmount;
                    
                    
                    return configuration({last_row, last_column}, copy_from, constraints, lookups, cell_copy_to);
                }

                std::vector<configuration> configure_all(const std::size_t num_configs,
                                                         const std::size_t num_round_calls) {
                    std::vector<configuration> result;
                    std::size_t round_rows = round_component_type::rows_amount;
                    std::size_t padding_rows = padding_component_type::rows_amount;

                    std::size_t row = 0,
                                column = 0;
                    // padding
                    row += padding_rows;

                    //rounds
                    for (std::size_t index = 0; index < num_round_calls; ++index) {
                        // to sparse representation
                        for (std::size_t i = 0; i < 17; ++i) {
                            result.push_back(configure_pack_unpack(row, column));
                            row = result[i].last_row;
                            column = result[i].last_column;
                        }
                        // round
                        if (column > 0) {
                            column = 0;
                            row += 1 + 24 * round_rows;
                        } else {
                            row += 24 * round_rows;
                        }
                    }

                    // from sparse representation
                    for (std::size_t i = 0; i < 5; ++i) {
                        result.push_back(configure_pack_unpack(row, column));
                        row = result[i].last_row;
                        column = result[i].last_column;
                    }

                    return result;
                }

                #define __keccak_init_macro(witness, constant, public_input, \
                                                        lookup_rows_, lookup_columns_, num_blocks_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    num_blocks(num_blocks_), \
                    num_round_calls(), \
                    rounds(num_round_calls * 24, \
                            round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_)), \
                    padding(padding_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_)), \
                    num_configs(), \
                    full_configuration(configure_all(num_configs, num_round_calls)), \
                    rows_amount(rows())

                template<typename ContainerType>
                keccak(ContainerType witness, std::size_t lookup_rows_,
                        std::size_t lookup_columns_, std::size_t num_blocks_) :
                    component_type(witness, {}, {}),
                    __keccak_init_macro(witness, {}, {}, lookup_rows_, lookup_columns_, num_blocks_) {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_,
                                   std::size_t lookup_columns_,
                                   std::size_t num_blocks_):
                    component_type(witness, constant, public_input),
                    __keccak_init_macro(witness, constant, public_input, lookup_rows_, lookup_columns_, num_blocks_) {};

                keccak(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                        std::size_t lookup_rows_, std::size_t lookup_columns_, std::size_t num_blocks_) :
                        component_type(witnesses, constants, public_inputs),
                        __keccak_init_macro(witnesses, constants, public_inputs,
                                            lookup_rows_, lookup_columns_, num_blocks_)
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

                std::vector<std::vector<var>> padded_message = generate_assignments(component.padding, assignment,
                                                                                    {instance_input.message}, row).output;
                row += component.padding.rows_amount;

                

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP