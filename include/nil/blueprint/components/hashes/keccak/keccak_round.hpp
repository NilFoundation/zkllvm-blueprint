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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <vector>
#include <array>
#include <queue>


namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class keccak_round;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                                     WitnessesAmount> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::size_t calculate_normalize_chunk_size(std::size_t num_rows, std::size_t base) {
                    std::size_t chunk_size = 0;
                    std::size_t power = base;
                    while (power < num_rows) {
                        ++chunk_size;
                        power *= base;
                    }
                    return chunk_size * 3;
                }
                std::size_t calculate_chi_chunk_size(std::size_t num_rows) {
                    std::size_t chunk_size = 0;
                    std::size_t power = 2;
                    while (power < num_rows) {
                        ++chunk_size;
                        power *= 2;
                    }
                    return chunk_size * 3;
                }
                std::size_t calculate_num_chunks(std::size_t chunk_size) {
                    return word_size / chunk_size + bool(word_size % chunk_size);
                }

                std::size_t rows() const {
                    std::size_t num_cells = 17 * xor2_cells +           // inner_state ^ chunk
                                            5 * xor5_cells +            // theta
                                            5 * rot_cells +             // theta
                                            25 * xor3_cells +           // theta
                                            24 * rot_cells +            // rho/phi
                                            25 * chi_cells +            // chi
                                            xor2_cells;                 // iota
                    return num_cells / WitnessesAmount + bool(num_cells % WitnessesAmount);
                }
                std::size_t gates() const {
                    // TODO: need to find the exact answer
                    return rows() / 3 + bool(rows() % 3);
                }

            public:
                using var = typename component_type::var;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;

                const std::size_t normalize3_chunk_size;
                const std::size_t normalize4_chunk_size;
                const std::size_t normalize6_chunk_size;
                const std::size_t chi_chunk_size;
                const std::size_t rotate_chunk_size = 24;

                const std::size_t normalize3_num_chunks;
                const std::size_t normalize4_num_chunks;
                const std::size_t normalize6_num_chunks;
                const std::size_t chi_num_chunks;
                const std::size_t rotate_num_chunks = 8;

                const std::size_t xor2_cells;
                const std::size_t xor3_cells;
                const std::size_t xor5_cells;
                const std::size_t rot_cells = 22;
                const std::size_t chi_cells;

                constexpr static const int r[5][5] = {{0, 3, 186, 84, 81},
                                                    {108, 132, 18, 165, 60},
                                                    {9, 30, 129, 75, 117},
                                                    {123, 135, 45, 63, 24},
                                                    {54, 6, 183, 168, 42}};

                // all words in sparse form
                const std::size_t word_size = 192;
                const value_type sparse_3 = 0x6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB_cppui192;

                const std::size_t limit_permutation_column = 7;

                constexpr static const std::array<std::size_t, 25>
                    r_constants = {0, 36, 3, 41, 18, 
                                    1, 44, 10, 45, 2, 
                                    62, 6, 43, 15, 61, 
                                    28, 55, 25, 21, 56, 
                                    27, 20, 39, 8, 14};

                // full configuration is precalculated, then used in other functions
                std::array<configuration, 102> full_configuration;

                const std::size_t rows_amount;
                const std::size_t gates_amount = 1;

                struct input_type {
                    std::array<var, 25> inner_state;
                    std::array<var, 17> padded_message_chunk;
                    var round_constant;
                };

                struct result_type {
                    std::array<var, 25> inner_state;

                    result_type(const keccak_round &component, std::size_t start_row_index) {
                        std::size_t num_config = 102;
                        std::size_t ind = 25;
                        inner_state[0] = var(component.W(component.full_configuration[num_config].copy_to[0].row),
                                                         component.full_configuration[num_config].copy_to[0].column);
                        for (int i = 1; i < 25; ++i) {
                            inner_state[ind - i] = var(component.W(component.full_configuration[num_config - i].copy_to[0].row),
                                                                   component.full_configuration[num_config - i].copy_to[0].column);
                        }
                    }
                };

                integral_type normalize(const integral_type& integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    for (std::size_t i = 0; i < 64; ++i) {
                        result += (value & 1) * power;
                        power *= 8;
                        value >>= 3;
                    }
                    return result;
                }

                integral_type chi(const integral_type& integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    integral_type mask = 7;
                    int table[5] = {0, 1, 1, 0, 0};
                    for (std::size_t i = 0; i < 64; ++i) {
                        int bit = table[int(value & mask)];
                        result += bit * power;
                        power *= 8;
                        value >>= 8;
                    }
                    return result;
                }

                struct configuration {
                    struct coordinates {
                        std::size_t row;
                        std::size_t column;

                        coordinates() = default;
                        coordinates(std::size_t row_, std::size_t column_) : row(row_), column(column_) {};
                        coordinates(std::pair<std::size_t, std::size_t> pair) : row(pair.first), column(pair.second) {};
                    };
                    
                    // In constraints we use such notation: constr[0] - result,
                    // constr[1]... - arguments for lookup, linear elements for regular constraints in correct order.
                    coordinates last_coordinate;
                    std::vector<coordinates> copy_from;
                    std::vector<std::vector<coordinates>> constraints;
                    std::vector<std::vector<coordinates>> lookups;
                    coordinates copy_to;

                    configuration() = default;
                    configuration(std::pair<std::size_t, std::size_t> last_coordinate_,
                                  std::vector<std::pair<std::size_t, std::size_t>> copy_from_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups_,
                                  std::pair<std::size_t, std::size_t> copy_to_) {
                            last_coordinate = coordinates(last_coordinate_);
                            for (std::size_t i = 0; i < copy_from_.size(); ++i) {
                                copy_from[i] = coordinates(copy_from_[i]);
                            }
                            for (std::size_t i = 0; i < constraints_.size(); ++i) {
                                for (std::size_t j = 0; j < constraints[i].size(); ++j) {
                                    constraints[i][j] = coordinates(constraints_[i][j]);
                                }
                            }
                            for (std::size_t i = 0; i < lookups_.size(); ++i) {
                                for (std::size_t j = 0; j < lookups[i].size(); ++j) {
                                    lookups[i][j] = coordinates(lookups_[i][j]);
                                }
                            }
                            copy_to = coordinates(copy_to_);
                        };
                };

                configuration configure_inner(std::size_t row, std::size_t column, std::size_t num_args,
                                            std::size_t num_chunks, std::size_t num_cells) {

                    std::size_t last_row = row,
                                last_column = column;
                                
                    std::vector<std::pair<std::size_t, std::size_t>> copy_from;

                    if (num_args + column > limit_permutation_column) {
                        for (int i = 0; i < num_args; ++i) {
                            copy_from.push_back({last_row + 1, i});
                        }
                    } else {
                        for (int i = 0; i < num_args; ++i) {
                            copy_from.push_back({last_row + (last_column / WitnessesAmount),
                                                            (last_column++) % WitnessesAmount});
                        }
                    }
                    
                    std::pair<std::size_t, std::size_t> cell_copy_to;
                    std::size_t final_row = (column + num_cells - 1) / WitnessesAmount + row;
                    if (final_row == copy_from[0].first) {
                        cell_copy_to = {final_row, copy_from.back().second + 1};
                    } else {
                        cell_copy_to = {final_row, 0};
                    }
                    
                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    std::pair<std::size_t, std::size_t> cell_copy_to;
                    if (num_args + column > limit_permutation_column) {
                        for (int i = column; i < WitnessesAmount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - WitnessesAmount + column;
                        std::size_t cur_row = row + 1,
                                    cur_column = num_args;
                        while (cur_column < cells_left) {
                            if (cur_column % WitnessesAmount == cell_copy_to.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + num_args;
                        while (cur_column - column < num_cells) {
                            if (cur_column % WitnessesAmount == cell_copy_to.second && (cur_row + (cur_column / WitnessesAmount) == cell_copy_to.first)) {
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
                        constraints[0].push_back(copy_from[i]);
                    }

                    constraints.push_back({constraints[0][0]});
                    constraints.push_back({cell_copy_to});
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(num_chunks, std::vector<std::pair<std::size_t, std::size_t>>());
                    for (std::size_t i = 1; i < 3; ++i) {
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            constraints[i].push_back(cells[cell_index++]);
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    last_column = cells.back().second + 1;
                    last_row = cells.back().first + (last_column > WitnessesAmount);
                    last_column %= WitnessesAmount;
                    return configuration({last_row, last_column}, copy_from, constraints, lookups, cell_copy_to);
                }

                configuration configure_xor(std::size_t row, std::size_t column, int num_args) {
                    // regular constraints:
                    // sum = arg1 + arg2 + ... + argn
                    // sum = sum_chunk0 + sum_chunk1 * 2^chunk_size + ... + sum_chunkk * 2^(k*chunk_size)
                    // norm_sum = norm_sum_chunk0 + norm_sum_chunk1 * 2^chunk_size + ... + norm_sum_chunkk * 2^(k*chunk_size)

                    std::size_t num_chunks = num_args == 2 ? normalize3_num_chunks
                                            : num_args == 3 ? normalize4_num_chunks
                                            : normalize6_num_chunks;
                    std::size_t num_cells = num_chunks * 2 + num_args + 2;

                    return configure_inner(row, column, num_args, num_chunks, num_cells);
                }

                configuration configure_chi(std::size_t row, std::size_t column) {
                    // regular constraints:
                    // sum = sparse_3 - 2 * a + b - c;
                    // sum = sum_chunk0 + sum_chunk1 * 2^chunk_size + ... + sum_chunkk * 2^(k*chunk_size)
                    // chi_sum = chi_sum_chunk0 + chi_sum_chunk1 * 2^chunk_size + ... + chi_sum_chunkk * 2^(k*chunk_size)

                    std::size_t num_args = 3;
                    std::size_t num_cells = num_chunks * 2 + num_args + 2;

                    return configure_inner(row, column, num_args, chi_num_chunks, num_cells);
                }

                configuration configure_rot(std::size_t row, std::size_t column) {
                    // regular constraints:
                    // a = big_part << r + small_part;
                    // a_rot = small_part << (192 - r) + big_part;
                    // bound_big = big_part - (1 << (192 - r)) + (1 << 192);
                    // bound_small = small_part - (1 << r) + (1 << 192);
                    // bound_big = big_chunk0 + big_chunk1 * 2^chunk_size + ... + big_chunkk * 2^(k*chunk_size)
                    // bound_small = small_chunk0 + small_chunk1 * 2^chunk_size + ... + small_chunkk * 2^(k*chunk_size)

                    std::size_t last_row = row,
                                last_column = column;
                
                    std::vector<std::pair<std::size_t, std::size_t>> copy_from;
                    std::pair<std::size_t, std::size_t> cell_copy_to;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    
                    if (2 + column > limit_permutation_column) {
                        copy_from.push_back({last_row + 1, 0});
                        cell_copy_to = {last_row + 1, 1};
                    } else {
                        copy_from.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                        cell_copy_to = {last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount};
                    }
                    
                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (2 + column > limit_permutation_column) {
                        for (int i = column; i < WitnessesAmount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - WitnessesAmount + column;
                        std::size_t cur_row = row + 1,
                                    cur_column = 2;
                        while (cur_column < cells_left) {
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + 2;
                        while (cur_column - column < num_cells) {
                            cells.push_back({cur_row + (cur_column / WitnessesAmount), (cur_column++) % WitnessesAmount});
                        }
                    }                    
                    std::size_t cell_index = 0;
                    
                    constraints.push_back({copy_from[0]});
                    constraints[0].push_back(cells[cell_index++]);
                    constraints[0].push_back(cells[cell_index++]);
                    
                    constraints.push_back({cell_copy_to});
                    constraints[1].push_back(constraints[0][2]);
                    constraints[1].push_back(constraints[0][1]);
                    
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(2, std::vector<std::pair<std::size_t, std::size_t>>());
                        
                    constraints.push_back({cells[cell_index++]});
                    constraints[2].push_back(constraints[0][1]);
                    constraints.push_back({constraints[2][0]});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[3].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[3].back());
                    }
                    
                    constraints.push_back({cells[cell_index++]});
                    constraints[4].push_back(constraints[0][2]);
                    constraints.push_back({constraints[4][0]});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[5].push_back(cells[cell_index++]);
                        lookups[1].push_back(constraints[5].back());
                    }
                    
                    last_column = cells.back().second + 1;
                    last_row = cells.back().first + (last_column / WitnessesAmount);
                    last_column %= WitnessesAmount;
                    
                    return configuration({last_row, last_column}, copy_from, constraints, lookups, cell_copy_to);
                }

                std::array<configuration, 102> configure_all() {
                    std::array<configuration, 102> result;
                    std::size_t row = 0,
                                column = 0;

                    // inner_state ^ chunk
                    for (int i = 0; i < 17; ++i) {
                        result[i] = configure_xor(row, column, 2);
                        row = result[i].last_coordinate.row;
                        column = result[i].last_coordinate.column;
                    }
                    // theta
                    for (int i = 0; i < 5; ++i) {
                        result[17 + i] = configure_xor(row, column, 5);
                        row = result[17 + i].last_coordinate.row;
                        column = result[17 + i].last_coordinate.column;
                    }
                    for (int i = 0; i < 5; ++i) {
                        result[22 + i] = configure_rot(row, column);
                        row = result[22 + i].last_coordinate.row;
                        column = result[22 + i].last_coordinate.column;
                    }
                    for (int i = 0; i < 25; ++i) {
                        result[27 + i] = configure_xor(row, column, 3);
                        row = result[27 + i].last_coordinate.row;
                        column = result[27 + i].last_coordinate.column;
                    }
                    // rho/phi
                    for (int i = 0; i < 24; ++i) {
                        result[52 + i] = configure_rot(row, column);
                        row = result[52 + i].last_coordinate.row;
                        column = result[52 + i].last_coordinate.column;
                    }
                    // chi
                    for (int i = 0; i < 25; ++i) {
                        result[76 + i] = configure_chi(row, column);
                        row = result[76 + i].last_coordinate.row;
                        column = result[76 + i].last_coordinate.column;
                    }
                    // iota
                    result[101] = configure_xor(row, column, 2);

                    return result;
                }

                #define __keccak_round_init_macro(lookup_rows_, lookup_columns_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    normalize3_chunk_size(calculate_normalize_chunk_size(lookup_rows_, 3)), \
                    normalize4_chunk_size(calculate_normalize_chunk_size(lookup_rows_, 4)), \
                    normalize6_chunk_size(calculate_normalize_chunk_size(lookup_rows_, 6)), \
                    chi_chunk_size(calculate_chi_chunk_size(lookup_rows_)), \
                    normalize3_num_chunks(calculate_num_chunks(normalize3_chunk_size)), \
                    normalize4_num_chunks(calculate_num_chunks(normalize4_chunk_size)), \
                    normalize6_num_chunks(calculate_num_chunks(normalize6_chunk_size)), \
                    chi_num_chunks(calculate_num_chunks(chi_chunk_size)), \
                    xor2_cells(normalize3_num_chunks * 2 + 2 + 2), \
                    xor3_cells(normalize4_num_chunks * 2 + 3 + 2), \
                    xor5_cells(normalize6_num_chunks * 2 + 5 + 2), \
                    chi_cells(chi_num_chunks * 2 + 5), \
                    full_configuration(configure_all()), \
                    rows_amount(rows()), \
                    gates_amount(gates())

                template<typename ContainerType>
                keccak_round(ContainerType witness, std::size_t lookup_rows_, std::size_t lookup_columns_) :
                    component_type(witness, {}, {}),
                    __keccak_round_init_macro(lookup_rows_, lookup_columns_) {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_round(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_, std::size_t lookup_columns_):
                    component_type(witness, constant, public_input),
                    __keccak_round_init_macro(lookup_rows_, lookup_columns_) {};

                keccak_round(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t lookup_rows_, std::size_t lookup_columns_) :
                        component_type(witnesses, constants, public_inputs),
                        __keccak_round_init_macro(lookup_rows_, lookup_columns_)
                {};

                #undef __keccak_round_init_macro
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            using keccak_round_component =
                keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>,
                                   WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_gates(
                const keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {
                    
                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_copy_constraints(
                const keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;

                std::size_t config_index = 0;
                auto config = component.full_configuration;

                // TODO: finish copy_constraints
                for (int i = 0; i < 17; ++i) {
                    bp.add_copy_constraint({instance_input.inner_state[i], var(component.W(config[i].copy_from[0].row), config[i].copy_from[0].column, false)});
                    bp.add_copy_constraint({instance_input.padded_message_chunk[i], var(component.W(config[i].copy_from[1].row), config[i].copy_from[1].column, false)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            void generate_assignments_constant(
                const keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                // TODO: need to find the exact answer
                std::size_t row = start_row_index + 242 + 3;
                for (std::size_t i = 0; i < 25; i++) {
                    assignment.constant(component.C(0), row + i * 8) = component_type::r_constants[i];
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount>::result_type
            generate_circuit(
                const keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                std::size_t row = start_row_index;

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using var = typename component_type::var;
                

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount>::result_type
            generate_assignments(
                const keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;
                std::size_t word_size = component.word_size;

                int config_index = 0;

                // inner_state ^ chunk
                std::array<value_type, 25> A_1;
                for (int index = 0; index < 17; ++index) {
                    value_type state = var_value(assignment, instance_input.inner_state[index]);
                    value_type message = var_value(assignment, instance_input.padded_message_chunk[index]);
                    value_type sum = state + message;
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize3_chunk_size;
                    auto num_chunks = component.normalize3_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (1 << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power *= chunk_size;
                    }
                    A_1[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = state;
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = message;
                    assignment.witness(component.W(cur_config.constraints[1][0].row), cur_config.constraints[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].row), cur_config.constraints[2][0].column) = value_type(integral_normalized_sum);
                    for (int j = 1; j < num_chunks; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].row), cur_config.constraints[1][j].column) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].row), cur_config.constraints[2][j].column) = value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                for (int i = 17; i < 25; ++i) {
                    A_1[i] = var_value(assignment, instance_input.inner_state[i]);
                }
                config_index += 17;

                // theta
                std::array<value_type, 5> C;
                for (int index = 0; index < 5; ++index) {
                    value_type sum = 0;
                    for (int j = 0; j < 5; ++j) {
                        sum += A_1[5 * index + j];
                    }
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize6_chunk_size;
                    auto num_chunks = component.normalize6_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (1 << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power *= chunk_size;
                    }
                    C[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_1[index];
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = A_1[index + 1];
                    assignment.witness(component.W(cur_config.copy_from[2].row), cur_config.copy_from[2].column) = A_1[index + 2];
                    assignment.witness(component.W(cur_config.copy_from[3].row), cur_config.copy_from[3].column) = A_1[index + 3];
                    assignment.witness(component.W(cur_config.copy_from[4].row), cur_config.copy_from[4].column) = A_1[index + 4];
                    assignment.witness(component.W(cur_config.constraints[1][0].row), cur_config.constraints[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].row), cur_config.constraints[2][0].column) = value_type(integral_normalized_sum);
                    for (int j = 1; j < num_chunks; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].row), cur_config.constraints[1][j].column) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].row), cur_config.constraints[2][j].column) = value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                config_index += 5;

                std::array<value_type, 5> C_rot;
                for (int index = 0; index < 5; ++index) {
                    integral_type integral_C = integral_type(C[index].data);
                    integral_type smaller_part = integral_C & ((1 << 3) - 1);
                    integral_type bigger_part = integral_C >> 3;
                    integral_type integral_C_rot = (smaller_part << 189) + bigger_part;
                    C_rot[index] = value_type(integral_C_rot);
                    integral_type bound_smaller = smaller_part - (1 << 3) + (integral_type(1) << 192);
                    integral_type bound_bigger = bigger_part - (integral_type(1) << 189) + (integral_type(1) << 192);
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (1 << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(bound_smaller & mask);
                        bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(bound_bigger & mask);
                        bound_bigger >>= chunk_size;
                    }

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = C[index];
                    assignment.witness(component.W(cur_config.copy_to.row), cur_config.copy_to.column) = C_rot[index];
                    assignment.witness(component.W(cur_config.constraints[0][1].row), cur_config.constraints[0][1].column) = value_type(smaller_part);
                    assignment.witness(component.W(cur_config.constraints[0][2].row), cur_config.constraints[0][2].column) = value_type(bigger_part);
                    assignment.witness(component.W(cur_config.constraints[3][0].row), cur_config.constraints[3][0].column) = value_type(bound_smaller);
                    assignment.witness(component.W(cur_config.constraints[5][0].row), cur_config.constraints[5][0].column) = value_type(bound_bigger);
                    for (int j = 1; j < num_chunks; ++j) {
                        assignment.witness(component.W(cur_config.constraints[3][j].row), cur_config.constraints[3][j].column) = value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[5][j].row), cur_config.constraints[5][j].column) = value_type(integral_big_chunks[j - 1]);
                    }
                }
                config_index += 5;

                std::array<value_type, 25> A_2;
                for (int index = 0; index < 25; ++index) {
                    value_type sum = A_1[index] + C_rot[(index + 1) % 5] + C[(index - 1) % 5];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize4_chunk_size;
                    auto num_chunks = component.normalize4_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (1 << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power *= chunk_size;
                    }
                    A_2[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_1[index];
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = C_rot[(index + 1) % 5];
                    assignment.witness(component.W(cur_config.copy_from[2].row), cur_config.copy_from[2].column) = C[(index - 1) % 5];
                    assignment.witness(component.W(cur_config.constraints[1][0].row), cur_config.constraints[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].row), cur_config.constraints[2][0].column) = value_type(integral_normalized_sum);
                    for (int j = 1; j < num_chunks; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].row), cur_config.constraints[1][j].column) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].row), cur_config.constraints[2][j].column) = value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                config_index += 25;

                // rho/phi
                std::array<std::array<value_type, 5>, 5> B;
                B[0][0] = A_2[0];
                for (int index = 1; index < 25; ++index) {
                    int x = index / 5;
                    int y = index % 5;
                    int r = r_constants[x][y];
                    int minus_r = 192 - r_constants[x][y];
                    integral_type integral_A = integral_type(A_2[index].data);
                    integral_type smaller_part = integral_A & ((1 << r) - 1);
                    integral_type bigger_part = integral_A >> r;
                    integral_type integral_A_rot = (smaller_part << minus_r) + bigger_part;
                    B[y][2*x + 3*y] = value_type(integral_A_rot);

                    integral_type bound_smaller = smaller_part - (1 << r) + (integral_type(1) << 192);
                    integral_type bound_bigger = bigger_part - (integral_type(1) << minus_r) + (integral_type(1) << 192);
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (1 << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(bound_smaller & mask);
                        bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(bound_bigger & mask);
                        bound_bigger >>= chunk_size;
                    }

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_2[index];
                    assignment.witness(component.W(cur_config.copy_to.row), cur_config.copy_to.column) = B[y][2*x + 3*y];
                    assignment.witness(component.W(cur_config.constraints[0][1].row), cur_config.constraints[0][1].column) = value_type(smaller_part);
                    assignment.witness(component.W(cur_config.constraints[0][2].row), cur_config.constraints[0][2].column) = value_type(bigger_part);
                    assignment.witness(component.W(cur_config.constraints[3][0].row), cur_config.constraints[3][0].column) = value_type(bound_smaller);
                    assignment.witness(component.W(cur_config.constraints[5][0].row), cur_config.constraints[5][0].column) = value_type(bound_bigger);
                    for (int j = 1; j < num_chunks; ++j) {
                        assignment.witness(component.W(cur_config.constraints[3][j].row), cur_config.constraints[3][j].column) = value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[5][j].row), cur_config.constraints[5][j].column) = value_type(integral_big_chunks[j - 1]);
                    }
                }
                config_index += 24;

                // chi
                std::array<value_type, 25> A_3;
                for (int index = 0; index < 25; ++index) {
                    int x = index / 5;
                    int y = index % 5;
                    value_type sum = component.sparse_3 - 2 * B[x][y] + B[(x+1)%5][y] - B[(x+2)%5][y];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.chi_chunk_size;
                    auto num_chunks = component.chi_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_chi_chunks;
                    integral_type mask = (1 << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_chi_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_chi_chunks.push_back(component.chi(integral_chunks.back()));
                        integral_chi_sum += integral_chi_chunks.back() * power;
                        power *= chunk_size;
                    }
                    A_3[index] = value_type(integral_chi_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = B[x][y];
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = B[(x+1)%5][y];
                    assignment.witness(component.W(cur_config.copy_from[2].row), cur_config.copy_from[2].column) = B[(x+2)%5][y];
                    assignment.witness(component.W(cur_config.constraints[1][0].row), cur_config.constraints[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].row), cur_config.constraints[2][0].column) = value_type(integral_chi_sum);
                    for (int j = 1; j < num_chunks; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].row), cur_config.constraints[1][j].column) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].row), cur_config.constraints[2][j].column) = value_type(integral_chi_chunks[j - 1]);
                    }
                }
                config_index += 25;

                // iota
                value_type round_constant = var_value(assignment, instance_input.round_constant);
                value_type sum = A_3[0] + round_constant;
                integral_type integral_sum = integral_type(sum.data);
                auto chunk_size = component.normalize3_chunk_size;
                auto num_chunks = component.normalize3_num_chunks;
                std::vector<integral_type> integral_chunks;
                std::vector<integral_type> integral_normalized_chunks;
                integral_type mask = (1 << chunk_size) - 1;
                integral_type power = 1;
                integral_type integral_normalized_sum = 0;
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    integral_chunks.push_back(integral_sum & mask);
                    integral_sum >>= chunk_size;
                    integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                    integral_normalized_sum += integral_normalized_chunks.back() * power;
                    power *= chunk_size;
                }
                value_type A_4 = value_type(integral_normalized_sum);
                
                auto cur_config = component.full_configuration[config_index];
                assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_3[0];
                assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = round_constant;
                assignment.witness(component.W(cur_config.constraints[1][0].row), cur_config.constraints[1][0].column) = sum;
                assignment.witness(component.W(cur_config.constraints[2][0].row), cur_config.constraints[2][0].column) = value_type(integral_normalized_sum);
                for (int j = 1; j < num_chunks; ++j) {
                    assignment.witness(component.W(cur_config.constraints[1][j].row), cur_config.constraints[1][j].column) = value_type(integral_chunks[j - 1]);
                    assignment.witness(component.W(cur_config.constraints[2][j].row), cur_config.constraints[2][j].column) = value_type(integral_normalized_chunks[j - 1]);
                }

                return typename component_type::result_type(component, start_row_index);
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP