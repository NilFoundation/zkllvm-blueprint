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
#include <map>
#include <iostream>


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

                std::size_t calculate_chunk_size(std::size_t num_rows, std::size_t base) {
                    std::size_t chunk_size = 0;
                    std::size_t power = base;
                    while (power < num_rows) {
                        ++chunk_size;
                        power *= base;
                    }
                    return chunk_size * 3;
                }
                std::size_t calculate_num_chunks(std::size_t base = 0) {
                    std::size_t chunk_size = base == 3 ? normalize3_chunk_size
                                            : base == 4 ? normalize4_chunk_size
                                            : base == 6 ? normalize6_chunk_size
                                            : chi_chunk_size;
                    std::size_t res = 192 / chunk_size + bool(192 % chunk_size);
                    return res;
                }
                std::size_t calculate_num_cells(std::size_t base = 0) {
                    std::size_t res = base == 3 ? normalize3_num_chunks * 2 + 2 + 2
                                    : base == 4 ? normalize4_num_chunks * 2 + 3 + 2
                                    : base == 6 ? normalize6_num_chunks * 2 + 5 + 2
                                    : chi_num_chunks * 2 + 5;
                    return res;
                }
                std::size_t calculate_buff(std::size_t base = 0) {
                    std::size_t buff = 0;
                    std::size_t cells = base == 3 ? xor2_cells
                                    : base == 4 ? xor3_cells
                                    : base == 6 ? xor5_cells
                                    : base == 7 ? chi_cells
                                    : rotate_cells;
                    if (base == 6) {
                        return WitnessesAmount * ((cells - 1) / WitnessesAmount + 1) - cells;
                    }
                    if (WitnessesAmount % 9 == 0) {
                        while (cells % 3 != 0) {
                            cells++;
                            buff++;
                        }
                    } else if (WitnessesAmount % 15 == 0) {
                        while (cells % 5 != 0) {
                            cells++;
                            buff++;
                        }
                    }
                    return buff;
                }

                std::size_t calculate_rows() const {
                    std::size_t num_cells = (xor3_cells + xor3_buff) * last_round_call
                                             * xor_with_mes +                       // xor with last message chunk
                                            ((17 - last_round_call) * (xor2_cells + xor2_buff))
                                             * xor_with_mes +                       // inner_state ^ chunk
                                            5 * (xor5_cells + xor5_buff) +                        // theta
                                            5 * (rotate_cells + rotate_buff) +                      // theta
                                            25 * (xor3_cells + xor3_buff) +                       // theta
                                            24 * (rotate_cells + rotate_buff) +                     // rho/phi
                                            25 * (chi_cells + chi_buff) +                        // chi
                                            xor2_cells;                             // iota
                    std::size_t num_cells_before = (xor3_cells) * last_round_call
                                             * xor_with_mes +                       // xor with last message chunk
                                            ((17 - last_round_call) * (xor2_cells))
                                             * xor_with_mes +                       // inner_state ^ chunk
                                            5 * (xor5_cells) +                        // theta
                                            5 * (rotate_cells) +                      // theta
                                            25 * (xor3_cells) +                       // theta
                                            24 * (rotate_cells) +                     // rho/phi
                                            25 * (chi_cells) +                        // chi
                                            xor2_cells;                             // iota
                    std::size_t num_cells_buff = (0 + xor3_buff) * last_round_call
                                             * xor_with_mes +                       // xor with last message chunk
                                            ((17 - last_round_call) * (0 + xor2_buff))
                                             * xor_with_mes +                       // inner_state ^ chunk
                                            5 * (0 + xor5_buff) +                        // theta
                                            5 * (0 + rotate_buff) +                      // theta
                                            25 * (0 + xor3_buff) +                       // theta
                                            24 * (0 + rotate_buff) +                     // rho/phi
                                            25 * (0 + chi_buff) +                        // chi
                                            xor2_cells;                             // iota
                    std::cout << "rows: " << num_cells / WitnessesAmount + bool(num_cells % WitnessesAmount) << std::endl;
                    std::cout << "rows before: " << num_cells_before / WitnessesAmount + bool(num_cells_before % WitnessesAmount) << std::endl;
                    std::cout << "empty cells: " << num_cells_buff + num_cells % WitnessesAmount << std::endl;
                    std::cout << "empty cells before: " << num_cells_before % WitnessesAmount << std::endl;
                    return num_cells / WitnessesAmount + bool(num_cells % WitnessesAmount);
                }
                // std::vector<std::size_t> calculate_gates_rows() const {
                //     std::vector<std::size_t> res;
                //     auto cur_selector = gates_configuration[0];
                //     res.push_back(cur_selector);
                //     for (std::size_t i = 1; i < gates_configuration.size(); ++i) {
                //         if (gates_configuration[i] != cur_selector) {
                //             cur_selector = gates_configuration[i];
                //             res.push_back(cur_selector);
                //         }
                //     }
                //     // for (int i = 0; i < res.size(); ++i) {
                //     //     std::cout << res[i] << " ";
                //     // }
                //     return res;
                // }
                std::size_t calculate_last_round_call_row() const {
                    if (!last_round_call) {
                        return 0;
                    }
                    std::size_t res = 0;
                    for (auto g : gates_configuration_map) {
                        if (g.first.first == 3) {
                            res = g.second[0];
                        }
                    }
                    return res;
                }
                std::size_t gates() const {
                    std::size_t res = 0;
                    for (std::size_t i = 1; i < gates_configuration.size(); ++i) {
                        res += gates_configuration[i].size();
                    }
                    std::cout << "gates num: " << res << std::endl;
                    return res;
                }

            public:

                struct configuration {
                    struct coordinates {
                        std::size_t row;
                        std::size_t column;

                        coordinates() = default;
                        coordinates(std::size_t row_, std::size_t column_) : row(row_), column(column_) {};
                        coordinates(std::pair<std::size_t, std::size_t> pair) : row(pair.first), column(pair.second) {};
                        bool operator== (const coordinates& other) const {
                            return row == other.row && column == other.column;
                        }
                        bool operator< (const coordinates& other) const {
                            return row < other.row || (row == other.row && column < other.column);
                        }
                    };
                    
                    // In constraints we use such notation: constr[0] - result,
                    // constr[1]... - arguments for lookup, linear elements for regular constraints in correct order.
                    coordinates first_coordinate;
                    coordinates last_coordinate;
                    std::vector<coordinates> copy_to;
                    std::vector<std::vector<coordinates>> constraints;
                    std::vector<std::vector<coordinates>> lookups;
                    coordinates copy_from;

                    configuration() = default;
                    configuration(std::pair<std::size_t, std::size_t> first_coordinate_,
                                  std::pair<std::size_t, std::size_t> last_coordinate_,
                                  std::vector<std::pair<std::size_t, std::size_t>> copy_to_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups_,
                                  std::pair<std::size_t, std::size_t> copy_from_) {
                            first_coordinate = coordinates(first_coordinate_);
                            last_coordinate = coordinates(last_coordinate_);
                            for (std::size_t i = 0; i < copy_to_.size(); ++i) {
                                copy_to.push_back(coordinates(copy_to_[i]));
                            }
                            for (std::size_t i = 0; i < constraints_.size(); ++i) {
                                std::vector<coordinates> constr;
                                for (std::size_t j = 0; j < constraints_[i].size(); ++j) {
                                    constr.push_back(coordinates(constraints_[i][j]));
                                }
                                constraints.push_back(constr);
                            }
                            for (std::size_t i = 0; i < lookups_.size(); ++i) {
                                std::vector<coordinates> lookup;
                                for (std::size_t j = 0; j < lookups_[i].size(); ++j) {
                                    lookup.push_back(coordinates(lookups_[i][j]));
                                }
                                lookups.push_back(lookup);
                            }
                            copy_from = coordinates(copy_from_);
                        };
                    bool operator== (const configuration& other) const {
                        return first_coordinate == other.first_coordinate &&
                               last_coordinate == other.last_coordinate &&
                               copy_to == other.copy_to &&
                               constraints == other.constraints &&
                               lookups == other.lookups &&
                               copy_from == other.copy_from;
                    }
                    bool operator< (const configuration& other) const {
                        return first_coordinate < other.first_coordinate ||
                                (first_coordinate == other.first_coordinate && last_coordinate < other.last_coordinate);
                    }
                };

                using var = typename component_type::var;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;

                // need to xor inner state with message only on the first round
                const bool xor_with_mes;
                // need to xor last message chunk with 0x80 or 1 only on the last round
                const bool last_round_call;
                // change permutation on rho/phi step
                const bool eth_perm;

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
                const std::size_t rotate_cells = 22;
                const std::size_t chi_cells;

                const std::size_t xor2_buff;
                const std::size_t xor3_buff;
                const std::size_t xor5_buff;
                const std::size_t rotate_buff;
                const std::size_t chi_buff;

                const std::size_t rows_amount;

                // full configuration is precalculated, then used in other functions
                const std::size_t full_configuration_size = 17 * xor_with_mes + 85;
                std::vector<configuration> full_configuration = std::vector<configuration>(full_configuration_size);
                // number represents relative selector index for each constraint
                std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> gates_configuration_map;
                std::vector<std::vector<configuration>> gates_configuration;
                std::vector<std::size_t> lookup_gates_configuration;
                std::vector<std::size_t> gates_rows;

                const std::size_t last_round_call_row;
                const std::size_t gates_amount;

                // all words in sparse form
                const std::size_t word_size = 192;
                const value_type sparse_3 = 0x6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB_cppui255;

                const std::size_t limit_permutation_column = 7;

                constexpr static const std::array<std::size_t, 25>
                    rho_offsets = {0, 36, 3, 41, 18, 
                                    1, 44, 10, 45, 2, 
                                    62, 6, 43, 15, 61, 
                                    28, 55, 25, 21, 56, 
                                    27, 20, 39, 8, 14};

                struct input_type {
                    std::array<var, 25> inner_state;
                    std::array<var, 17> padded_message_chunk;
                    var round_constant;
                };

                struct result_type {
                    std::array<var, 25> inner_state;

                    result_type(const keccak_round &component, std::size_t start_row_index) {
                        std::size_t num_config = component.full_configuration.size() - 1;
                        inner_state[0] = var(component.W(component.full_configuration[num_config].copy_from.column),
                                                         component.full_configuration[num_config].copy_from.row);
                        for (int i = 1; i < 25; ++i) {
                            inner_state[25 - i] = var(component.W(component.full_configuration[num_config - i].copy_from.column),
                                                                   component.full_configuration[num_config - i].copy_from.row);
                        }
                    }
                };

                integral_type normalize(const integral_type& integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    while (value > 0) {
                        result += (value & 1) * power;
                        power <<= 3;
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
                    while (value > 0) {
                        int bit = table[int(value & mask)];
                        result += bit * power;
                        power <<= 3;
                        value >>= 3;
                    }
                    return result;
                }

                configuration configure_inner(std::size_t row, std::size_t column, std::size_t num_args,
                                            std::size_t num_chunks, std::size_t num_cells, std::size_t buff = 0) {

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

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

                    if (cell_copy_from.first > cells.back().first) {
                        cells.back() = cell_copy_from;
                    }

                    last_column = cells.back().second + 1 + buff;
                    last_row = cells.back().first + (last_column >= WitnessesAmount);
                    last_column %= WitnessesAmount;

                    // std::cout << "normalize " << num_args << ": " << row << ' ' << column << std::endl;
                    // std::cout << "last coordinate: " << last_row << " " << last_column << std::endl;
                    // std::cout << "copy from: " << cell_copy_from.first << " " << cell_copy_from.second << std::endl;
                    // std::cout << "copy to:\n";
                    // for (auto cell : copy_to) {
                    //     std::cout << cell.first << " " << cell.second << "\n";
                    // }
                    // std::cout << "constraints:\n";
                    // for (auto constr : constraints) {
                    //     std::cout << "constraint:\n";
                    //     for (auto cell : constr) {
                    //         std::cout << cell.first << " " << cell.second << "\n";
                    //     }
                    // }

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
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
                    std::size_t buff = num_args == 2 ? xor2_buff
                                        : num_args == 3 ? xor3_buff
                                        : xor5_buff;

                    return configure_inner(row, column, num_args, num_chunks, num_cells, buff);
                }

                configuration configure_chi(std::size_t row, std::size_t column) {
                    // regular constraints:
                    // sum = sparse_3 - 2 * a + b - c;
                    // sum = sum_chunk0 + sum_chunk1 * 2^chunk_size + ... + sum_chunkk * 2^(k*chunk_size)
                    // chi_sum = chi_sum_chunk0 + chi_sum_chunk1 * 2^chunk_size + ... + chi_sum_chunkk * 2^(k*chunk_size)

                    std::size_t num_args = 3;
                    std::size_t num_cells = chi_num_chunks * 2 + num_args + 2;

                    return configure_inner(row, column, num_args, chi_num_chunks, num_cells, chi_buff);
                }

                configuration configure_rot(std::size_t row, std::size_t column) {
                    // regular constraints:
                    // a = small_part << (192 - r) + big_part;
                    // a_rot = big_part << r + small_part;
                    // bound_small = small_part - (1 << r) + (1 << 192);
                    // bound_small = small_chunk0 + small_chunk1 * 2^chunk_size + ... + small_chunkk * 2^(k*chunk_size)
                    // bound_big = big_part - (1 << (192 - r)) + (1 << 192);
                    // bound_big = big_chunk0 + big_chunk1 * 2^chunk_size + ... + big_chunkk * 2^(k*chunk_size)

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row,
                                last_column = column;
                    std::size_t num_chunks = rotate_num_chunks;
                    std::size_t num_cells = rotate_cells;
                
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    
                    if (2 + column > limit_permutation_column) {
                        copy_to.push_back({last_row + 1, 0});
                        cell_copy_from = {last_row + 1, 1};
                    } else {
                        copy_to.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                        cell_copy_from = {last_row + (last_column / WitnessesAmount),
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
                    
                    constraints.push_back({copy_to[0]});
                    constraints[0].push_back(cells[cell_index++]);
                    constraints[0].push_back(cells[cell_index++]);
                    
                    constraints.push_back({cell_copy_from});
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
                    
                    last_column = cells.back().second + 1 + rotate_buff;
                    last_row = cells.back().first + (last_column / WitnessesAmount);
                    last_column %= WitnessesAmount;

                    // std::cout << "ROT: " << row << ' ' << column << std::endl;
                    // std::cout << "last coordinate: " << last_row << " " << last_column << std::endl;
                    // std::cout << "copy from: " << cell_copy_from.first << " " << cell_copy_from.second << std::endl;
                    // std::cout << "copy to:\n";
                    // for (auto cell : copy_to) {
                    //     std::cout << cell.first << " " << cell.second << "\n";
                    // }
                    // std::cout << "constraints:\n";
                    // for (auto constr : constraints) {
                    //     std::cout << "constraint:\n";
                    //     for (auto cell : constr) {
                    //         std::cout << cell.first << " " << cell.second << "\n";
                    //     }
                    // }
                    
                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                }

                std::vector<configuration> configure_all() {
                    auto result = std::vector<configuration>(full_configuration_size);
                    std::size_t row = 0,
                                column = 0;
                    std::size_t cur_config = 0;

                    // inner_state ^ chunk
                    if (xor_with_mes) {
                        for (int i = 0; i < 17 - last_round_call; ++i) {
                            result[i] = configure_xor(row, column, 2);
                            row = result[i].last_coordinate.row;
                            column = result[i].last_coordinate.column;
                            cur_config++;
                        }
                        // xor with last message chunk
                        if (last_round_call) {
                            result[cur_config] = configure_xor(row, column, 3);
                            row = result[cur_config].last_coordinate.row;
                            column = result[cur_config].last_coordinate.column;
                            cur_config++;
                        }
                    }
                    // theta
                    for (int i = 0; i < 5; ++i) {
                        result[cur_config] = configure_xor(row, column, 5);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    for (int i = 0; i < 5; ++i) {
                        result[cur_config] = configure_rot(row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    for (int i = 0; i < 25; ++i) {
                        result[cur_config] = configure_xor(row, column, 3);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    // rho/phi
                    for (int i = 0; i < 24; ++i) {
                        result[cur_config] = configure_rot(row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    // chi
                    for (int i = 0; i < 25; ++i) {
                        result[cur_config] = configure_chi(row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    // iota
                    result[cur_config] = configure_xor(row, column, 2);

                    // for (int i = 0; i < 50; ++i) {
                    //     std::cout << "configuration " << i << std::endl;
                    //     std::cout << "last coordinate: " << result[i].last_coordinate.row << " " << result[i].last_coordinate.column << std::endl;
                    //     std::cout << "copy from: " << result[i].copy_from.row << " " << result[i].copy_from.column << std::endl;
                    //     std::cout << "copy to:\n";
                    //     for (auto cell : result[i].copy_to) {
                    //         std::cout << cell.row << " " << cell.column << "\n";
                    //     }
                    //     std::cout << "constraints:\n";
                    //     for (auto constr : result[i].constraints) {
                    //         std::cout << "constraint:\n";
                    //         for (auto cell : constr) {
                    //             std::cout << cell.row << " " << cell.column << "\n";
                    //         }
                    //     }
                    // }
                    return result;
                }

                std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> configure_map() {
                    auto config = full_configuration;
                    std::size_t row = 0,
                                column = 0;
                    std::size_t cur_config = 0;

                    std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> config_map;

                    // inner_state ^ chunk
                    if (xor_with_mes) {
                        for (int i = 0; i < 17 - last_round_call; ++i) {
                            row = config[cur_config].first_coordinate.row;
                            column = config[cur_config].first_coordinate.column;
                            std::pair<std::size_t, std::size_t> zero_config = {2, column};
                            if (config_map.find(zero_config) != config_map.end()) {
                                config_map[zero_config].push_back(row);
                            } else {
                                config_map[zero_config] = {row};
                            }
                            cur_config++;
                        }
                        // xor with last message chunk
                        if (last_round_call) {
                            row = config[cur_config].first_coordinate.row;
                            column = config[cur_config].first_coordinate.column;
                            std::pair<std::size_t, std::size_t> zero_config = {3, column};
                            if (config_map.find(zero_config) != config_map.end()) {
                                config_map[zero_config].push_back(row);
                            } else {
                                config_map[zero_config] = {row};
                            }
                            cur_config++;
                        }
                    }
                    // theta
                    for (int i = 0; i < 5; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {5, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    for (int i = 0; i < 5; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {7, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    for (int i = 0; i < 25; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {3, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    // rho/phi
                    for (int i = 0; i < 24; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {7, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    // chi
                    for (int i = 0; i < 25; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {0, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    // iota
                    row = config[cur_config].first_coordinate.row;
                    column = config[cur_config].first_coordinate.column;
                    std::pair<std::size_t, std::size_t> zero_config = {2, column};
                    if (config_map.find(zero_config) != config_map.end()) {
                        config_map[zero_config].push_back(row);
                    } else {
                        config_map[zero_config] = {row};
                    }

                    // for (auto config : config_map) {
                    //     std::cout << "config: " << config.first.first << ' ' << config.first.second << ": ";
                    //     for (auto c : config.second) {
                    //         std::cout << c << ' ';
                    //     }
                    //     std::cout << std::endl;
                    // }
                    return config_map;
                }

                std::vector<std::size_t> configure_gates_before() {
                    std::vector<std::pair<std::size_t, std::size_t>> pairs;
                    for (std::size_t i = 0; i < full_configuration_size; ++i) {
                        for (auto constr : full_configuration[i].constraints) {
                            std::size_t min = constr[0].row;
                            std::size_t max = constr.back().row;
                            for (std::size_t j = 0; j < constr.size(); ++j) {
                                min = std::min(min, constr[j].row);
                                max = std::max(max, constr[j].row);
                            }
                            BOOST_ASSERT(max - min <= 2);
                            pairs.push_back({min, max});
                        }
                    }
                    std::vector<std::size_t> result;
                    std::size_t cur_row = 0;
                    std::size_t cur_constr = 0;
                    while (cur_row < rows_amount) {
                        while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 && pairs[cur_constr].first >= cur_row) {
                            result.push_back(cur_row + 1);
                            ++cur_constr;
                        }
                        if (cur_constr == pairs.size()) {
                            break;
                        }
                        cur_row = pairs[cur_constr].first;
                    }
                    return result;
                }

                std::vector<std::vector<configuration>> configure_gates() {

                    auto gates_before = configure_gates_before();
                    std::size_t num_before = 1;
                    std::size_t cur_before = gates_before[0];
                    for (int i = 1; i < gates_before.size(); ++i) {
                        if (gates_before[i] != cur_before) {
                            cur_before = gates_before[i];
                            num_before++;
                        }
                    }
                    std::cout << "gates num before: " << num_before << std::endl;

                    std::vector<std::vector<configuration>> result;
                    for (auto config: gates_configuration_map) {
                        configuration cur_config;
                        switch (config.first.first) {
                            case 2:
                                cur_config = configure_xor(0, config.first.second, 2);
                                break;
                            case 3:
                                cur_config = configure_xor(0, config.first.second, 3);
                                break;
                            case 5:
                                cur_config = configure_xor(0, config.first.second, 5);
                                break;
                            case 7:
                                cur_config = configure_rot(0, config.first.second);
                                break;
                            case 0:
                                cur_config = configure_chi(0, config.first.second);
                                break;
                        }
                    
                        std::vector<std::pair<std::size_t, std::size_t>> pairs;
                        for (auto constr : cur_config.constraints) {
                            std::size_t min = constr[0].row;
                            std::size_t max = constr.back().row;
                            for (std::size_t j = 0; j < constr.size(); ++j) {
                                min = std::min(min, constr[j].row);
                                max = std::max(max, constr[j].row);
                            }
                            BOOST_ASSERT(max - min <= 2);
                            pairs.push_back({min, max});
                        }
                        std::vector<configuration> cur_result;
                        std::size_t cur_row = 0;
                        std::size_t cur_constr = 0;
                        while (cur_constr < pairs.size()) {
                            configuration c;
                            while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 && pairs[cur_constr].first >= cur_row) {
                                c.constraints.push_back(cur_config.constraints[cur_constr]);
                                c.first_coordinate = {cur_row, 0};
                                ++cur_constr;
                            }
                            cur_row = pairs[cur_constr].first;
                            cur_result.push_back(c);
                        }
                        result.push_back(cur_result);
                    }
                    
                    // for (int i = 0; i < result.size(); ++i) {
                    //     std::cout << "gate " << i << std::endl;
                    //     for (int j = 0; j < result[i].size(); ++j) {
                    //         std::cout << "configuration " << j << std::endl;
                    //         std::cout << "type: " << " " << result[i][j].first_coordinate.column << std::endl;
                    //         std::cout << "constraints:\n";
                    //         for (auto constr : result[i][j].constraints) {
                    //             std::cout << "constraint:\n";
                    //             for (auto cell : constr) {
                    //                 std::cout << cell.row << " " << cell.column << "\n";
                    //             }
                    //         }
                    //     }
                    // }
                    return result;
                }

                std::vector<std::size_t> configure_lookup_gates() {
                    std::vector<std::pair<std::size_t, std::size_t>> pairs;
                    for (std::size_t i = 0; i < full_configuration_size; ++i) {
                        for (auto constr : full_configuration[i].lookups) {
                            std::size_t min = constr[0].row;
                            std::size_t max = constr.back().row;
                            for (std::size_t j = 0; j < constr.size(); ++j) {
                                min = std::min(min, constr[j].row);
                                max = std::max(max, constr[j].row);
                            }
                            BOOST_ASSERT(max - min <= 2);
                            pairs.push_back({min, max});
                        }
                    }
                    std::vector<std::size_t> result;
                    std::size_t cur_row = 0;
                    std::size_t cur_constr = 0;
                    while (cur_row < rows_amount) {
                        while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 && pairs[cur_constr].first >= cur_row) {
                            result.push_back(cur_row + 1);
                            ++cur_constr;
                        }
                        if (cur_constr == pairs.size()) {
                            break;
                        }
                        cur_row = pairs[cur_constr].first;
                    }
                    return result;
                }

                #define __keccak_round_init_macro(lookup_rows_, lookup_columns_, xor_with_mes_, last_round_call_, eth_perm_) \
                    lookup_rows(lookup_rows_), \
                    lookup_columns(lookup_columns_), \
                    xor_with_mes(xor_with_mes_), \
                    last_round_call(last_round_call_),\
                    eth_perm(eth_perm_), \
                    normalize3_chunk_size(calculate_chunk_size(lookup_rows_, 3)), \
                    normalize4_chunk_size(calculate_chunk_size(lookup_rows_, 4)), \
                    normalize6_chunk_size(calculate_chunk_size(lookup_rows_, 6)), \
                    chi_chunk_size(calculate_chunk_size(lookup_rows_, 2)), \
                    word_size(192), \
                    normalize3_num_chunks(calculate_num_chunks(3)), \
                    normalize4_num_chunks(calculate_num_chunks(4)), \
                    normalize6_num_chunks(calculate_num_chunks(6)), \
                    chi_num_chunks(calculate_num_chunks()), \
                    xor2_cells(calculate_num_cells(3)), \
                    xor3_cells(calculate_num_cells(4)), \
                    xor5_cells(calculate_num_cells(6)), \
                    chi_cells(calculate_num_cells()), \
                    xor2_buff(calculate_buff(3)), \
                    xor3_buff(calculate_buff(4)), \
                    xor5_buff(calculate_buff(6)), \
                    chi_buff(calculate_buff(7)), \
                    rotate_buff(calculate_buff()), \
                    rows_amount(calculate_rows()), \
                    full_configuration(configure_all()), \
                    gates_configuration_map(configure_map()), \
                    gates_configuration(configure_gates()), \
                    lookup_gates_configuration(configure_lookup_gates()), \
                    last_round_call_row(calculate_last_round_call_row()), \
                    gates_amount(gates())

                template<typename ContainerType>
                keccak_round(ContainerType witness, std::size_t lookup_rows_, std::size_t lookup_columns_,
                                                    bool xor_with_mes_ = false,
                                                    bool last_round_call_ = false,
                                                    bool eth_perm_ = false) :
                    component_type(witness, {}, {}),
                    __keccak_round_init_macro(lookup_rows_, lookup_columns_, xor_with_mes_, last_round_call_, eth_perm_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_round(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_, std::size_t lookup_columns_,
                                   bool xor_with_mes_ = false,
                                   bool last_round_call_ = false,
                                   bool eth_perm_ = false) :
                    component_type(witness, constant, public_input),
                    __keccak_round_init_macro(lookup_rows_, lookup_columns_, xor_with_mes_, last_round_call_, eth_perm_) {};

                keccak_round(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t lookup_rows_, std::size_t lookup_columns_,
                                   bool xor_with_mes_ = false,
                                   bool last_round_call_ = false,
                                   bool eth_perm_ = false) :
                        component_type(witnesses, constants, public_inputs),
                        __keccak_round_init_macro(lookup_rows_, lookup_columns_, xor_with_mes_, last_round_call_, eth_perm_) {};

                #undef __keccak_round_init_macro
            };

            // template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            // using keccak_round_component =
            //     keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
            //                                                                    ArithmetizationParams>,
            //                        WitnessesAmount>;

            // template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
            //          std::enable_if_t<WitnessesAmount >= 9, bool> = true>
            // void generate_gates(
            //     const keccak_round_component<BlueprintFieldType, ArithmetizationParams,
            //                                    WitnessesAmount>
            //         &component,
            //     circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
            //                                                         ArithmetizationParams>>
            //         &bp,
            //     assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
            //                                                            ArithmetizationParams>>
            //         &assignment,
            //     const typename keccak_round_component<BlueprintFieldType, ArithmetizationParams,
            //                                             WitnessesAmount>::input_type
            //         &instance_input,
            //     const std::size_t first_selector_index) {
                    
            //     using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
            //                                                     WitnessesAmount>;
            //     using var = typename component_type::var;
            //     using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            //     using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
            //     // using lookup_constraint_type = typename crypto3::zk::snark::lookup_constraint<BlueprintFieldType>;
            //     // using lookup_gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, lookup_constraint_type>;
            //     using value_type = typename BlueprintFieldType::value_type;
            //     using integral_type = typename BlueprintFieldType::integral_type;

            //     auto config = component.full_configuration;
            //     auto gate_config = component.gates_configuration;
            //     // auto lookup_gate_config = component.lookup_gates_configuration;
            //     std::size_t config_index = 0;
            //     std::size_t gate_index = 0;
            //     // std::size_t lookup_gate_index = 0;

            //     std::vector<constraint_type> constraints;
            //     // std::vector<lookup_constraint_type> lookup_constraints;

            //     // inner_state ^ chunk
            //     if (component.xor_with_mes) {
            //         for (int i = 0; i < 17 - component.last_round_call; ++i) {
            //             auto cur_config = config[config_index];
            //             constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index])
            //                                                 + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                                 - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //             gate_index++;
            //             constraint_type constraint_1 = var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index]);
            //             for (int j = 0; j < component.normalize3_num_chunks; ++j) {
            //                 constraint_1 -= var(cur_config.constraints[1][j + 1].column, cur_config.constraints[1][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.normalize3_chunk_size));
            //             } 
            //             constraints.push_back(bp.add_constraint(constraint_1));
            //             gate_index++;
            //             constraint_type constraint_2 = var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]);
            //             for (int j = 0; j < component.normalize3_num_chunks; ++j) {
            //                 constraint_2 -= var(cur_config.constraints[2][j + 1].column, cur_config.constraints[2][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.normalize3_chunk_size));
            //             }
            //             constraints.push_back(bp.add_constraint(constraint_2));
            //             gate_index++;
            //             config_index++;
            //         }
            //         if (component.last_round_call) {
            //             auto cur_config = config[config_index];
            //             constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index])
            //                                                 + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                                 + var(cur_config.constraints[0][3].column, cur_config.constraints[0][3].row - gate_config[gate_index])
            //                                                 - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //             gate_index++;
            //             constraint_type constraint_1 = var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index]);
            //             for (int j = 0; j < component.normalize4_num_chunks; ++j) {
            //                 constraint_1 -= var(cur_config.constraints[1][j + 1].column, cur_config.constraints[1][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.normalize4_chunk_size));
            //             } 
            //             constraints.push_back(bp.add_constraint(constraint_1));
            //             gate_index++;
            //             constraint_type constraint_2 = var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]);
            //             for (int j = 0; j < component.normalize4_num_chunks; ++j) {
            //                 constraint_2 -= var(cur_config.constraints[2][j + 1].column, cur_config.constraints[2][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.normalize4_chunk_size));
            //             }
            //             constraints.push_back(bp.add_constraint(constraint_2));
            //             gate_index++;
            //             config_index++;
            //         }
            //     }

            //     // theta
            //     for (int i = 0; i < 5; ++i) {
            //         auto cur_config = config[config_index];
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index])
            //                                               + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                               + var(cur_config.constraints[0][3].column, cur_config.constraints[0][3].row - gate_config[gate_index])
            //                                               + var(cur_config.constraints[0][4].column, cur_config.constraints[0][4].row - gate_config[gate_index])
            //                                               + var(cur_config.constraints[0][5].column, cur_config.constraints[0][5].row - gate_config[gate_index])
            //                                               - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraint_type constraint_1 = var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.normalize6_num_chunks; ++j) {
            //             constraint_1 -= var(cur_config.constraints[1][j + 1].column, cur_config.constraints[1][j + 1].row - gate_config[gate_index])
            //                                                                                         * (integral_type(1) << (j * component.normalize6_chunk_size));
            //         } 
            //         constraints.push_back(bp.add_constraint(constraint_1));
            //         gate_index++;
            //         constraint_type constraint_2 = var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.normalize6_num_chunks; ++j) {
            //             constraint_2 -= var(cur_config.constraints[2][j + 1].column, cur_config.constraints[2][j + 1].row - gate_config[gate_index])
            //                                                                                         * (integral_type(1) << (j * component.normalize6_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_2));
            //         gate_index++;
            //         config_index++;
            //     }

            //     for (int i = 0; i < 5; ++i) {
            //         auto cur_config = config[config_index];
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index]) * (integral_type(1) << 189)
            //                                               + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[1][1].column, cur_config.constraints[1][1].row - gate_config[gate_index]) * (integral_type(1) << 3)
            //                                               + var(cur_config.constraints[1][2].column, cur_config.constraints[1][2].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[2][1].column, cur_config.constraints[2][1].row - gate_config[gate_index])
            //                                               - (integral_type(1) << 3)
            //                                               + (integral_type(1) << 192)));
            //         gate_index++;
            //         constraint_type constraint_1 = var(cur_config.constraints[3][0].column, cur_config.constraints[3][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.rotate_num_chunks; ++j) {
            //             constraint_1 -= var(cur_config.constraints[3][j + 1].column, cur_config.constraints[3][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.rotate_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_1));
            //         gate_index++;
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[4][0].column, cur_config.constraints[4][0].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[4][1].column, cur_config.constraints[4][1].row - gate_config[gate_index])
            //                                               - (integral_type(1) << 189)
            //                                               + (integral_type(1) << 192)));
            //         gate_index++;
            //         constraint_type constraint_2 = var(cur_config.constraints[5][0].column, cur_config.constraints[5][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.rotate_num_chunks; ++j) {
            //             constraint_2 -= var(cur_config.constraints[5][j + 1].column, cur_config.constraints[5][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.rotate_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_2));
            //         gate_index++;
            //         config_index++;
            //     }

            //     for (int i = 0; i < 25; ++i) {
            //         auto cur_config = config[config_index];
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index])
            //                                               + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                               + var(cur_config.constraints[0][3].column, cur_config.constraints[0][3].row - gate_config[gate_index])
            //                                               - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraint_type constraint_1 = var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.normalize4_num_chunks; ++j) {
            //             constraint_1 -= var(cur_config.constraints[1][j + 1].column, cur_config.constraints[1][j + 1].row - gate_config[gate_index])
            //                                                                                         * (integral_type(1) << (j * component.normalize4_chunk_size));
            //         } 
            //         constraints.push_back(bp.add_constraint(constraint_1));
            //         gate_index++;
            //         constraint_type constraint_2 = var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.normalize4_num_chunks; ++j) {
            //             constraint_2 -= var(cur_config.constraints[2][j + 1].column, cur_config.constraints[2][j + 1].row - gate_config[gate_index])
            //                                                                                         * (integral_type(1) << (j * component.normalize4_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_2));
            //         gate_index++;
            //         config_index++;
            //     }

            //     // rho/phi
            //     for (int i = 1; i < 25; ++i) {
            //         auto r = 3 * component.rho_offsets[i];

            //         auto cur_config = config[config_index];
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index]) * (integral_type(1) << (192 - r))
            //                                               + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[1][1].column, cur_config.constraints[1][1].row - gate_config[gate_index]) * (integral_type(1) << r)
            //                                               + var(cur_config.constraints[1][2].column, cur_config.constraints[1][2].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[2][1].column, cur_config.constraints[2][1].row - gate_config[gate_index])
            //                                               - (integral_type(1) << r)
            //                                               + (integral_type(1) << 192)));
            //         gate_index++;
            //         constraint_type constraint_1 = var(cur_config.constraints[3][0].column, cur_config.constraints[3][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.rotate_num_chunks; ++j) {
            //             constraint_1 -= var(cur_config.constraints[3][j + 1].column, cur_config.constraints[3][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.rotate_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_1));
            //         gate_index++;
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[4][0].column, cur_config.constraints[4][0].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[4][1].column, cur_config.constraints[4][1].row - gate_config[gate_index])
            //                                               - (integral_type(1) << (192 - r))
            //                                               + (integral_type(1) << 192)));
            //         gate_index++;
            //         constraint_type constraint_2 = var(cur_config.constraints[5][0].column, cur_config.constraints[5][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.rotate_num_chunks; ++j) {
            //             constraint_2 -= var(cur_config.constraints[5][j + 1].column, cur_config.constraints[5][j + 1].row - gate_config[gate_index])
            //                                                                                             * (integral_type(1) << (j * component.rotate_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_2));
            //         gate_index++;
            //         config_index++;
            //     }

            //     // chi
            //     for (int i = 0; i < 25; ++i) {
            //         auto cur_config = config[config_index];
            //         constraints.push_back(bp.add_constraint(component.sparse_3
            //                                               - var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index]) * 2
            //                                               + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                               - var(cur_config.constraints[0][3].column, cur_config.constraints[0][3].row - gate_config[gate_index])
            //                                               - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraint_type constraint_1 = var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.chi_num_chunks; ++j) {
            //             constraint_1 -= var(cur_config.constraints[1][j + 1].column, cur_config.constraints[1][j + 1].row - gate_config[gate_index])
            //                                                                                                 * (integral_type(1) << (j * component.chi_chunk_size));
            //         } 
            //         constraints.push_back(bp.add_constraint(constraint_1));
            //         gate_index++;
            //         constraint_type constraint_2 = var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.chi_num_chunks; ++j) {
            //             constraint_2 -= var(cur_config.constraints[2][j + 1].column, cur_config.constraints[2][j + 1].row - gate_config[gate_index])
            //                                                                                                 * (integral_type(1) << (j * component.chi_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_2));
            //         gate_index++;
            //         config_index++;
            //     }

            //     // iota
            //     {
            //         auto cur_config = config[config_index];
            //         constraints.push_back(bp.add_constraint(var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row - gate_config[gate_index])
            //                                             + var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row - gate_config[gate_index]) 
            //                                             - var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row - gate_config[gate_index])));
            //         gate_index++;
            //         constraint_type constraint_1 = var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.normalize3_num_chunks; ++j) {
            //             constraint_1 -= var(cur_config.constraints[1][j + 1].column, cur_config.constraints[1][j + 1].row - gate_config[gate_index])
            //                                                                                         * (integral_type(1) << (j * component.normalize3_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_1));
            //         gate_index++;
            //         constraint_type constraint_2 = var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row - gate_config[gate_index]);
            //         for (int j = 0; j < component.normalize3_num_chunks; ++j) {
            //             constraint_2 -= var(cur_config.constraints[2][j + 1].column, cur_config.constraints[2][j + 1].row - gate_config[gate_index])
            //                                                                                         * (integral_type(1) << (j * component.normalize3_chunk_size));
            //         }
            //         constraints.push_back(bp.add_constraint(constraint_2));
            //         gate_index++;
            //         config_index++;
            //     }

            //     BOOST_ASSERT(config_index == component.full_configuration_size);
            //     // BOOST_ASSERT(constraints.size() == gate_config.size());

            //     std::size_t prev_selector = gate_config[0];
            //     std::vector<constraint_type> cur_constraints = {constraints[0]};
            //     gate_index = 1;
            //     while (gate_index < gate_config.size()) {
            //         while (gate_index < gate_config.size() && gate_config[gate_index] == prev_selector) {
            //             cur_constraints.push_back(constraints[gate_index]);
            //             ++gate_index;
            //         }
            //         if (gate_index == gate_config.size()) {
            //             break;
            //         }
            //         gate_type gate(first_selector_index + prev_selector, cur_constraints);
            //         bp.add_gate(gate);
            //         cur_constraints.clear();
            //         prev_selector = gate_config[gate_index];
            //     }
            //     if (!cur_constraints.empty()) {
            //         gate_type gate(first_selector_index + prev_selector, cur_constraints);
            //         bp.add_gate(gate);
            //     }
            // }

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
                // using lookup_constraint_type = typename crypto3::zk::snark::lookup_constraint<BlueprintFieldType>;
                // using lookup_gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, lookup_constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using configuration = typename component_type::configuration;

                auto gate_config = component.gates_configuration;
                auto gate_map = component.gates_configuration_map;
                // auto lookup_gate_config = component.lookup_gates_configuration;
                std::size_t gate_index = 0;
                // std::size_t lookup_gate_index = 0;

                std::vector<constraint_type> constraints;
                // std::vector<lookup_constraint_type> lookup_constraints;

                std::size_t index = 0;
                std::size_t selector_index = first_selector_index;
                for (auto gm: gate_map) {
                    std::vector<configuration> cur_config_vec = gate_config[index];
                    std::size_t i = 0, j = 0, cur_len = 0;
                    std::vector<constraint_type> cur_constraints;
                    switch (gm.first.first) {
                        case 2: 
                        {
                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                + var(cur_config_vec[i].constraints[j][2].column, cur_config_vec[i].constraints[j][2].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.normalize3_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.normalize3_chunk_size));
                            } 
                            cur_constraints.push_back(bp.add_constraint(constraint_1));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.normalize3_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.normalize3_chunk_size));
                            }
                            cur_constraints.push_back(bp.add_constraint(constraint_2));
                            
                            gate_type gate(selector_index++, cur_constraints);
                            bp.add_gate(gate);

                            break;
                        }
                        case 3:
                        {
                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                + var(cur_config_vec[i].constraints[j][2].column, cur_config_vec[i].constraints[j][2].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                + var(cur_config_vec[i].constraints[j][3].column, cur_config_vec[i].constraints[j][3].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.normalize4_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.normalize4_chunk_size));
                            } 
                            cur_constraints.push_back(bp.add_constraint(constraint_1));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.normalize4_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.normalize4_chunk_size));
                            }
                            cur_constraints.push_back(bp.add_constraint(constraint_2));
                            
                            gate_type gate(selector_index++, cur_constraints);
                            bp.add_gate(gate);

                            break;
                        }
                        case 5:
                        {
                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                + var(cur_config_vec[i].constraints[j][2].column, cur_config_vec[i].constraints[j][2].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                + var(cur_config_vec[i].constraints[j][3].column, cur_config_vec[i].constraints[j][3].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                + var(cur_config_vec[i].constraints[j][4].column, cur_config_vec[i].constraints[j][4].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                + var(cur_config_vec[i].constraints[j][5].column, cur_config_vec[i].constraints[j][5].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.normalize6_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.normalize6_chunk_size));
                            } 
                            cur_constraints.push_back(bp.add_constraint(constraint_1));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.normalize6_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.normalize6_chunk_size));
                            }
                            cur_constraints.push_back(bp.add_constraint(constraint_2));
                            
                            gate_type gate(selector_index++, cur_constraints);
                            bp.add_gate(gate);

                            break;
                        }
                        case 7:
                        {
                            auto r = var(component.C(0), -1, true, var::column_type::constant);
                            auto minus_r = var(component.C(0), 0, true, var::column_type::constant);

                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1) * minus_r
                                                                + var(cur_config_vec[i].constraints[j][2].column, cur_config_vec[i].constraints[j][2].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[1][1].column, cur_config_vec[i].constraints[1][1].row - cur_config_vec[i].first_coordinate.row - 1) * r
                                                                + var(cur_config_vec[i].constraints[1][2].column, cur_config_vec[i].constraints[1][2].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[1][0].column, cur_config_vec[i].constraints[1][0].row - cur_config_vec[i].first_coordinate.row - 1)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                + r
                                                                - (integral_type(1) << 192)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.rotate_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                                * (integral_type(1) << (k * component.rotate_chunk_size));
                            }
                            cur_constraints.push_back(bp.add_constraint(constraint_1));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(bp.add_constraint(var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                + minus_r
                                                                - (integral_type(1) << 192)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.rotate_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                                * (integral_type(1) << (k * component.rotate_chunk_size));
                            }
                            cur_constraints.push_back(bp.add_constraint(constraint_2));

                            gate_type gate(selector_index++, cur_constraints);
                            bp.add_gate(gate);

                            break;
                        }
                        case 0:
                        {
                            cur_constraints.push_back(bp.add_constraint(component.sparse_3
                                                                - var(cur_config_vec[i].constraints[j][1].column, cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row - 1) * 2
                                                                + var(cur_config_vec[i].constraints[j][2].column, cur_config_vec[i].constraints[j][2].row - cur_config_vec[i].first_coordinate.row - 1) 
                                                                - var(cur_config_vec[i].constraints[j][3].column, cur_config_vec[i].constraints[j][3].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                - var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1)));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.chi_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.chi_chunk_size));
                            } 
                            cur_constraints.push_back(bp.add_constraint(constraint_1));
                            
                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column, cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row - 1);
                            for (int k = 0; k < component.chi_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column, cur_config_vec[i].constraints[j][k + 1].row - cur_config_vec[i].first_coordinate.row - 1)
                                                                                                            * (integral_type(1) << (k * component.chi_chunk_size));
                            }
                            cur_constraints.push_back(bp.add_constraint(constraint_2));
                            
                            {
                                gate_type gate(selector_index++, cur_constraints);
                                bp.add_gate(gate);
                            }

                            break;
                        }
                    }
                    index++;
                }
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
                std::size_t prev_index = 0;
                auto config = component.full_configuration;

                if (component.xor_with_mes) {
                    // inner_state ^ chunk
                    for (int i = 0; i < 17 - component.last_round_call; ++i) {
                        bp.add_copy_constraint({instance_input.inner_state[i], var(component.W(config[i].copy_to[0].column), config[i].copy_to[0].row + start_row_index, false)});
                        bp.add_copy_constraint({instance_input.padded_message_chunk[i], var(component.W(config[i].copy_to[1].column), config[i].copy_to[1].row + start_row_index, false)});
                    }
                    config_index += 16;
                    if (component.last_round_call) {
                        bp.add_copy_constraint({instance_input.inner_state[config_index], var(component.W(config[config_index].copy_to[0].column), config[config_index].copy_to[0].row + start_row_index, false)});
                        bp.add_copy_constraint({instance_input.padded_message_chunk[config_index], var(component.W(config[config_index].copy_to[1].column), config[config_index].copy_to[1].row + start_row_index, false)});
                        bp.add_copy_constraint({var(component.C(0), component.last_round_call_row + start_row_index), var(component.W(config[config_index].copy_to[2].column), config[config_index].copy_to[2].row + start_row_index, false)});
                    }
                    config_index += 1;

                    // theta
                    for (int i = 0; i < 17; ++i) {
                        bp.add_copy_constraint({{component.W(config[prev_index + i].copy_from.column), static_cast<int>(config[prev_index + i].copy_from.row + start_row_index), false}, 
                                                {component.W(config[config_index + i / 5].copy_to[i % 5].column), static_cast<int>(config[config_index + i / 5].copy_to[i % 5].row + start_row_index), false}});
                    }
                    for (int i = 17; i < 25; ++i) {
                        bp.add_copy_constraint({instance_input.inner_state[i],
                                                {component.W(config[config_index + i / 5].copy_to[i % 5].column), static_cast<int>(config[config_index + i / 5].copy_to[i % 5].row + start_row_index), false}});
                    }
                    config_index += 5;
                    prev_index += 17;
                } else {
                    for (int i = 0; i < 25; ++i) {
                        bp.add_copy_constraint({instance_input.inner_state[i],
                                                {component.W(config[config_index + i / 5].copy_to[i % 5].column), static_cast<int>(config[config_index + i / 5].copy_to[i % 5].row + start_row_index), false}});
                    }
                    config_index += 5;
                }
                for (int i = 0; i < 5; ++i) {
                    bp.add_copy_constraint({{component.W(config[prev_index + i].copy_from.column), static_cast<int>(config[prev_index + i].copy_from.row + start_row_index), false},
                                            {component.W(config[config_index + i].copy_to[0].column), static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                }
                config_index += 5;
                prev_index += 5;

                for (int i = 0; i < 25; ++i) {
                    bp.add_copy_constraint({{component.W(config[prev_index - 5 + i / 5].copy_to[i % 5].column), static_cast<int>(config[prev_index - 5 + i / 5].copy_to[i % 5].row + start_row_index), false},
                                            {component.W(config[config_index + i].copy_to[0].column), static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                    bp.add_copy_constraint({{component.W(config[prev_index + (i + 1) % 5].copy_from.column), static_cast<int>(config[prev_index + (i + 1) % 5].copy_from.row + start_row_index), false},
                                            {component.W(config[config_index + i].copy_to[1].column), static_cast<int>(config[config_index + i].copy_to[1].row + start_row_index), false}});
                    bp.add_copy_constraint({{component.W(config[prev_index + (i + 4) % 5].copy_to[0].column), static_cast<int>(config[prev_index + (i + 4) % 5].copy_to[0].row + start_row_index), false},
                                            {component.W(config[config_index + i].copy_to[2].column), static_cast<int>(config[config_index + i].copy_to[2].row + start_row_index), false}});
                }
                config_index += 25;
                prev_index += 5;

                // rho/phi
                for (int i = 0; i < 24; ++i) {
                    bp.add_copy_constraint({{component.W(config[prev_index + i + 1].copy_from.column), static_cast<int>(config[prev_index + i + 1].copy_from.row + start_row_index), false},
                                            {component.W(config[config_index + i].copy_to[0].column), static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                }

                // chi
                std::vector<int> perm_index = {14,4,19,9, 5,20,10,0,15, 11,1,16,6,21, 17,7,22,12,2, 23,13,3,18,8};
                std::vector<var> B = {{component.W(config[prev_index].copy_from.column), static_cast<int>(config[prev_index].copy_from.row + start_row_index), false}};
                for (auto i : perm_index) {
                    B.push_back({component.W(config[config_index + i].copy_from.column), static_cast<int>(config[config_index + i].copy_from.row + start_row_index), false});
                }
                config_index += 24;
                prev_index += 25;
                for (int i = 0; i < 25; ++i) {
                    int x = i / 5;
                    int y = i % 5;
                    bp.add_copy_constraint({B[x * 5 + y],
                                            {component.W(config[config_index + i].copy_to[0].column), static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                    bp.add_copy_constraint({B[((x + 1) % 5) * 5 + y],
                                            {component.W(config[config_index + i].copy_to[1].column), static_cast<int>(config[config_index + i].copy_to[1].row + start_row_index), false}});
                    bp.add_copy_constraint({B[((x + 2) % 5) * 5 + y],
                                            {component.W(config[config_index + i].copy_to[2].column), static_cast<int>(config[config_index + i].copy_to[2].row + start_row_index), false}});
                }
                config_index += 25;
                prev_index += 24;

                // iota
                bp.add_copy_constraint({{component.W(config[prev_index].copy_from.column), static_cast<int>(config[prev_index].copy_from.row + start_row_index), false},
                                        {component.W(config[config_index].copy_to[0].column), static_cast<int>(config[config_index].copy_to[0].row + start_row_index), false}});
                bp.add_copy_constraint({instance_input.round_constant,
                                        {component.W(config[config_index].copy_to[1].column), static_cast<int>(config[config_index].copy_to[1].row + start_row_index), false}});
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
                using integral_type = typename BlueprintFieldType::integral_type;

                std::size_t row = start_row_index;
                if (component.last_round_call) {
                    assignment.constant(component.C(0), row + component.last_round_call_row) = 2097152;  // sparse 0x80
                }

                auto gate_map = component.gates_configuration_map;
                std::vector<std::size_t> rotate_rows;
                for (auto g : gate_map) {
                    if (g.first.first == 7) {
                        rotate_rows.insert(rotate_rows.end(), g.second.begin(), g.second.end());
                    }
                }
                std::sort(rotate_rows.begin(), rotate_rows.end());
                for (std::size_t i = 0; i < 5; i++) {
                    assignment.constant(component.C(0), row + rotate_rows[i]) = integral_type(1) << 3;
                    assignment.constant(component.C(0), row + rotate_rows[i] + 1) = integral_type(1) << 189;
                }
                for (std::size_t i = 5; i < 29; i++) {
                    assignment.constant(component.C(0), row + rotate_rows[i]) = integral_type(1) << (3 * component_type::rho_offsets[i]);
                    assignment.constant(component.C(0), row + rotate_rows[i] + 1) = integral_type(1) << (192 - 3 * component_type::rho_offsets[i]);
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

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                
                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);
                
                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                std::size_t index = 0;
                for (auto g : component.gates_configuration_map) {
                    for (std::size_t i = 0; i < component.gates_configuration[index].size(); ++i) {
                        for (auto j : g.second) {
                            assignment.enable_selector(first_selector_index + i,
                                                       start_row_index + j + 1 + component.gates_configuration[index][i].first_coordinate.row);
                        }
                    }
                    first_selector_index += component.gates_configuration[index++].size();
                }

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
                std::size_t strow = start_row_index;

                int config_index = 0;

                // inner_state ^ chunk
                std::array<value_type, 25> A_1;
                if (component.xor_with_mes) {
                    for (int index = 0; index < 17 - component.last_round_call; ++index) {
                        value_type state = var_value(assignment, instance_input.inner_state[index]);
                        value_type message = var_value(assignment, instance_input.padded_message_chunk[index]);
                        value_type sum = state + message;
                        integral_type integral_sum = integral_type(sum.data);
                        auto chunk_size = component.normalize3_chunk_size;
                        auto num_chunks = component.normalize3_num_chunks;
                        std::vector<integral_type> integral_chunks;
                        std::vector<integral_type> integral_normalized_chunks;
                        integral_type mask = (integral_type(1) << chunk_size) - 1;
                        integral_type power = 1;
                        integral_type integral_normalized_sum = 0;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            integral_chunks.push_back(integral_sum & mask);
                            integral_sum >>= chunk_size;
                            integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                            integral_normalized_sum += integral_normalized_chunks.back() * power;
                            power <<= chunk_size;
                        }
                        A_1[index] = value_type(integral_normalized_sum);

                        auto cur_config = component.full_configuration[index];
                        assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = state;
                        assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) = message;
                        assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = sum;
                        assignment.witness(component.W(cur_config.constraints[2][0].column), cur_config.constraints[2][0].row + strow) = value_type(integral_normalized_sum);
                        for (int j = 1; j < num_chunks + 1; ++j) {
                            assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + strow) = value_type(integral_chunks[j - 1]);
                            assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(integral_normalized_chunks[j - 1]);
                        }
                    }
                    // last round call
                    if (component.last_round_call) {
                        value_type state = var_value(assignment, instance_input.inner_state[16]);
                        value_type message = var_value(assignment, instance_input.padded_message_chunk[16]);
                        value_type sum = state + message + value_type(component.C(0));
                        integral_type integral_sum = integral_type(sum.data);
                        auto chunk_size = component.normalize4_chunk_size;
                        auto num_chunks = component.normalize4_num_chunks;
                        std::vector<integral_type> integral_chunks;
                        std::vector<integral_type> integral_normalized_chunks;
                        integral_type mask = (integral_type(1) << chunk_size) - 1;
                        integral_type power = 1;
                        integral_type integral_normalized_sum = 0;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            integral_chunks.push_back(integral_sum & mask);
                            integral_sum >>= chunk_size;
                            integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                            integral_normalized_sum += integral_normalized_chunks.back() * power;
                            power <<= chunk_size;
                        }
                        A_1[16] = value_type(integral_normalized_sum);

                        auto cur_config = component.full_configuration[16];
                        assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = state;
                        assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) = message;
                        assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = sum;
                        assignment.witness(component.W(cur_config.constraints[2][0].column), cur_config.constraints[2][0].row + strow) = value_type(integral_normalized_sum);
                        for (int j = 1; j < num_chunks + 1; ++j) {
                            assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + strow) = value_type(integral_chunks[j - 1]);
                            assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(integral_normalized_chunks[j - 1]);
                        }
                    }
                    for (int i = 17; i < 25; ++i) {
                        A_1[i] = var_value(assignment, instance_input.inner_state[i]);
                    }
                    config_index += 17;
                } else {
                    for (int i = 0; i < 25; ++i) {
                        A_1[i] = var_value(assignment, instance_input.inner_state[i]);
                    }
                }
                // std::cout << "inner_state ^ chunk:\n";
                // for (int i = 0; i < 25; ++i) {
                //     std::cout << A_1[i] << "\n";
                // }

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
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    C[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = A_1[5 * index];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) = A_1[5 * index + 1];
                    assignment.witness(component.W(cur_config.copy_to[2].column), cur_config.copy_to[2].row + strow) = A_1[5 * index + 2];
                    assignment.witness(component.W(cur_config.copy_to[3].column), cur_config.copy_to[3].row + strow) = A_1[5 * index + 3];
                    assignment.witness(component.W(cur_config.copy_to[4].column), cur_config.copy_to[4].row + strow) = A_1[5 * index + 4];
                    assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column), cur_config.constraints[2][0].row + strow) = value_type(integral_normalized_sum);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + strow) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                config_index += 5;
                // std::cout << "theta 0:\n";
                // for (int i = 0; i < 5; ++i) {
                //     std::cout << C[i] << "\n";
                // }

                std::array<value_type, 5> C_rot;
                for (int index = 0; index < 5; ++index) {
                    integral_type integral_C = integral_type(C[index].data);
                    integral_type smaller_part = integral_C >> 189;
                    integral_type bigger_part = integral_C & ((integral_type(1) << 189) - 1);
                    integral_type integral_C_rot = (bigger_part << 3) + smaller_part;
                    C_rot[index] = value_type(integral_C_rot);
                    integral_type bound_smaller = smaller_part - (integral_type(1) << 3) + (integral_type(1) << 192);
                    integral_type bound_bigger = bigger_part - (integral_type(1) << 189) + (integral_type(1) << 192);
                    auto copy_bound_smaller = bound_smaller;
                    auto copy_bound_bigger = bound_bigger;
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(bound_smaller & mask);
                        bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(bound_bigger & mask);
                        bound_bigger >>= chunk_size;
                    }

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = C[index];
                    assignment.witness(component.W(cur_config.copy_from.column), cur_config.copy_from.row + strow) = C_rot[index];
                    assignment.witness(component.W(cur_config.constraints[0][1].column), cur_config.constraints[0][1].row + strow) = value_type(smaller_part);
                    assignment.witness(component.W(cur_config.constraints[0][2].column), cur_config.constraints[0][2].row + strow) = value_type(bigger_part);
                    assignment.witness(component.W(cur_config.constraints[3][0].column), cur_config.constraints[3][0].row + strow) = value_type(copy_bound_smaller);
                    assignment.witness(component.W(cur_config.constraints[5][0].column), cur_config.constraints[5][0].row + strow) = value_type(copy_bound_bigger);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[3][j].column), cur_config.constraints[3][j].row + strow) = value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[5][j].column), cur_config.constraints[5][j].row + strow) = value_type(integral_big_chunks[j - 1]);
                    }
                }
                config_index += 5;
                // std::cout << "theta 1:\n";
                // for (int i = 0; i < 5; ++i) {
                //     std::cout << C_rot[i] << "\n";
                // }

                std::array<value_type, 25> A_2;
                for (int index = 0; index < 25; ++index) {
                    int x = index / 5;
                    int y = index % 5;
                    value_type sum = A_1[index] + C_rot[(x + 1) % 5] + C[(x + 4) % 5];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize4_chunk_size;
                    auto num_chunks = component.normalize4_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    A_2[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = A_1[index];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) = C_rot[(x + 1) % 5];
                    assignment.witness(component.W(cur_config.copy_to[2].column), cur_config.copy_to[2].row + strow) = C[(x + 4) % 5];
                    assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column), cur_config.constraints[2][0].row + strow) = A_2[index];
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + strow) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                config_index += 25;
                // std::cout << "theta 2:\n";
                // for (int i = 0; i < 25; ++i) {
                //     std::cout << A_2[i] << "\n";
                // }

                // rho/phi
                value_type B[5][5];
                B[0][0] = A_2[0];
                for (int index = 1; index < 25; ++index) {
                    int x = index / 5;
                    int y = index % 5;
                    int r = 3 * component.rho_offsets[index];
                    int minus_r = 192 - r;
                    integral_type integral_A = integral_type(A_2[index].data);
                    integral_type smaller_part = integral_A >> minus_r;
                    integral_type bigger_part = integral_A & ((integral_type(1) << minus_r) - 1);
                    integral_type integral_A_rot = (bigger_part << r) + smaller_part;
                    B[y][(2*x + 3*y) % 5] = value_type(integral_A_rot);
                    integral_type bound_smaller = smaller_part - (integral_type(1) << r) + (integral_type(1) << 192);
                    integral_type bound_bigger = bigger_part - (integral_type(1) << minus_r) + (integral_type(1) << 192);
                    auto copy_bound_smaller = bound_smaller;
                    auto copy_bound_bigger = bound_bigger;
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(bound_smaller & mask);
                        bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(bound_bigger & mask);
                        bound_bigger >>= chunk_size;
                    }

                    auto cur_config = component.full_configuration[index - 1 + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = A_2[index];
                    assignment.witness(component.W(cur_config.copy_from.column), cur_config.copy_from.row + strow) = value_type(integral_A_rot);
                    assignment.witness(component.W(cur_config.constraints[0][1].column), cur_config.constraints[0][1].row + strow) = value_type(smaller_part);
                    assignment.witness(component.W(cur_config.constraints[0][2].column), cur_config.constraints[0][2].row + strow) = value_type(bigger_part);
                    assignment.witness(component.W(cur_config.constraints[3][0].column), cur_config.constraints[3][0].row + strow) = value_type(copy_bound_smaller);
                    assignment.witness(component.W(cur_config.constraints[5][0].column), cur_config.constraints[5][0].row + strow) = value_type(copy_bound_bigger);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[3][j].column), cur_config.constraints[3][j].row + strow) = value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[5][j].column), cur_config.constraints[5][j].row + strow) = value_type(integral_big_chunks[j - 1]);
                    }
                }
                config_index += 24;
                // std::cout << "rho/phi:\n";
                // for (int i = 0; i < 5; ++i) {
                //     for (int j = 0; j < 5; ++j) {
                //         std::cout << B[i][j] << "\n";
                //     }
                // }

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
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_chi_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_chi_chunks.push_back(component.chi(integral_chunks.back()));
                        integral_chi_sum += integral_chi_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    A_3[index] = value_type(integral_chi_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = B[x][y];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) = B[(x+1)%5][y];
                    assignment.witness(component.W(cur_config.copy_to[2].column), cur_config.copy_to[2].row + strow) = B[(x+2)%5][y];
                    assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column), cur_config.constraints[2][0].row + strow) = value_type(integral_chi_sum);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + strow) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(integral_chi_chunks[j - 1]);
                    }
                }
                config_index += 25;
                // std::cout << "chi:\n";
                // for (int i = 0; i < 25; ++i) {
                //     std::cout << A_3[i] << "\n";
                // }

                // iota
                value_type A_4;
                {
                    value_type round_constant = var_value(assignment, instance_input.round_constant);
                    value_type sum = A_3[0] + round_constant;
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize3_chunk_size;
                    auto num_chunks = component.normalize3_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    A_4 = value_type(integral_normalized_sum);
                    
                    auto cur_config = component.full_configuration[config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) = A_3[0];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) = round_constant;
                    assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column), cur_config.constraints[2][0].row + strow) = value_type(integral_normalized_sum);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + strow) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(integral_normalized_chunks[j - 1]);
                    }
                    std::cout << "valuess: " << cur_config.copy_from.column << ' ' << cur_config.copy_from.row + strow << ' ' << var_value(assignment, var(cur_config.copy_from.column, cur_config.copy_from.row + strow)) << "\n";
                }
                // std::cout << "result:\n";
                // std::cout << A_4 << "\n";
                // for (int i = 1; i < 25; ++i) {
                //     std::cout << A_3[i] << "\n";
                // }

                return typename component_type::result_type(component, start_row_index);
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP