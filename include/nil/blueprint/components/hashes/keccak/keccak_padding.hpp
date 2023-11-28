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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PADDING_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PADDING_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <iostream>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class keccak_padding;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                struct coordinates {
                    std::size_t row;
                    std::size_t column;

                    coordinates() = default;
                    coordinates(std::size_t row_, std::size_t column_) : row(row_), column(column_) {};
                    coordinates(std::pair<std::size_t, std::size_t> pair) : row(pair.first), column(pair.second) {};
                    coordinates(std::vector<std::size_t> vec) : row(vec[0]), column(vec[1]) {};
                    bool operator==(const coordinates &other) const {
                        return row == other.row && column == other.column;
                    }
                    bool operator<(const coordinates &other) const {
                        return row < other.row || (row == other.row && column < other.column);
                    }
                };

                struct configuration {                    
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
                struct padding_gate {
                    coordinates relay;
                    std::vector<coordinates> value;
                    std::vector<coordinates> sum;
                    std::vector<coordinates> range_check;
                    std::vector<coordinates> first;
                    std::vector<coordinates> second;

                    padding_gate() = default;
                    padding_gate(coordinates relay_, std::vector<coordinates> value_, std::vector<coordinates> sum_,
                                 std::vector<coordinates> range_check_, std::vector<coordinates> first_,
                                 std::vector<coordinates> second_) :
                        relay(relay_),
                        value(value_), sum(sum_), range_check(range_check_), first(first_), second(second_) {};

                    bool operator==(const padding_gate &other) const {
                        return relay == other.relay && value == other.value && sum == other.sum &&
                               range_check == other.range_check && first == other.first && second == other.second;
                    }
                };

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    std::size_t num_blocks;
                    std::size_t num_bits;
                    bool range_check_input;
                    std::size_t limit_permutation_column;
                    static constexpr const std::size_t clamp = 15;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t num_blocks_, std::size_t num_bits_,
                                       bool range_check_input_, std::size_t limit_permutation_column_ = 7) :
                        witness_amount(std::min(witness_amount_, clamp)),
                        num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                        limit_permutation_column(limit_permutation_column_) {};

                    std::uint32_t gates_amount() const override {
                        return keccak_padding::get_gates_amount(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t num_blocks,
                                                       std::size_t num_bits,
                                                       bool range_check_input, 
                                                       std::size_t limit_permutation_column = 7) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<nil::blueprint::manifest_param>(
                                          new nil::blueprint::manifest_single_value_param(9)),
                                      true);
                    return manifest;
                }

                static const std::size_t lookup_rows = 65536;
                static const std::size_t num_chunks = 8;

                const std::size_t limit_permutation_column = 7;
                const bool range_check_input;

                const std::size_t num_blocks;
                const std::size_t num_bits;
                std::size_t shift = calculate_shift(num_blocks, num_bits);
                std::size_t num_padding_zeros = calculate_num_padding_zeros(num_blocks);

                const std::size_t num_cells = calculate_num_cells(num_blocks, num_bits, range_check_input);
                const std::size_t buff = calculate_buff(this->witness_amount(), range_check_input);

                const std::vector<configuration> full_configuration =
                    configure_all(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::map<std::size_t, std::vector<std::size_t>> gates_configuration_map =
                    configure_map(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::vector<std::vector<configuration>> gates_configuration =
                    configure_gates(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);

                std::vector<std::size_t> gates_rows = calculate_gates_rows(this->witness_amount());

                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::size_t gates_amount = get_gates_amount(this->witness_amount(), num_blocks, num_bits, range_check_input);

                struct input_type {
                    // initial message = message[0] * 2^(64 * (num_blocks - 1)) + ... + message[num_blocks - 2] * 2^64 +
                    // message[num_blocks - 1] all message[i] are 64-bit for i > 0 message[0] is <= 64-bit
                    std::vector<var> message;

                    std::vector<var> all_vars() const {
                        return message;
                    }
                };

                struct result_type {
                    std::vector<var> padded_message;

                    result_type(const keccak_padding &component, std::size_t start_row_index) {
                        for (std::size_t i = 0; i < component.full_configuration.size(); ++i) {
                            auto config = component.full_configuration[i];
                            padded_message.push_back(var(component.W(config.copy_to.back().column),
                                                    config.copy_to.back().row + start_row_index, false));
                        }
                        for (std::size_t i = 0; i < component.num_padding_zeros; ++i) {
                            padded_message.push_back(
                                var(component.C(0), start_row_index, false, var::column_type::constant));
                        }
                    }

                    std::vector<var> all_vars() const {
                        return padded_message;
                    }
                };

                static std::size_t calculate_shift(std::size_t num_blocks, std::size_t num_bits) {
                    return num_blocks * 64 - num_bits;
                }
                static std::size_t calculate_num_padding_zeros(std::size_t num_blocks) {
                    if (num_blocks % 17 == 0){
                        return 0;
                    }
                    return 17 - num_blocks % 17;
                }
                static std::size_t calculate_num_cells(std::size_t num_blocks, std::size_t num_bits, bool range_check_input) {
                    if (calculate_shift(num_blocks, num_bits) == 0 && range_check_input) {
                        return 1 + 8;       // chunk, chunk range_check
                    }
                    std::size_t res = 1     // relay
                                    + 1     // chunk = first * 2^k + second
                                    + 2     // first, second
                                    + 1     // sum = relay * 2^(64-k) + first
                                    + 8;    // sum range_check
                    if (range_check_input) {
                        res += 8;           // chunk range_check
                    }
                    return res;
                }
                static std::size_t calculate_buff(std::size_t witness_amount, bool range_check_input) {
                    if (!range_check_input) {
                        return 2;
                    }
                    if (witness_amount == 15) {
                        return 4;
                    }
                    return 0;
                }
                static int32_t calculate_row_shift(std::size_t num_blocks, std::size_t num_bits) {
                    auto shift = calculate_shift(num_blocks, num_bits);
                    if (shift == 0) {
                        return 0;
                    }
                    return 1;
                }

                static configuration configure_inner_no_padding(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits, 
                                                    bool range_check_input, std::size_t limit_permutation_column, std::size_t row, std::size_t column,
                                                    std::size_t num_cells, std::size_t buff) {
                    // std::cout << "configure_inner_no_padding\n";
                    
                    if (column > 0) {
                        row += 1;
                        column = 0;
                    }
                    
                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row,
                                last_column = column;
                                
                    // chunk
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    if (column > limit_permutation_column) {
                        copy_to.push_back({last_row + 1, 0});
                    } else {
                        copy_to.push_back({last_row + (last_column / witness_amount),
                                                        (last_column++) % witness_amount});
                    }
                    if (!range_check_input) {
                        return configuration(first_coordinate, {last_row, last_column}, copy_to, {}, {}, {});
                    }

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    // chunk range_check
                    constraints.push_back({copy_to[0]});
                    for (int i = 0; i < 8; ++i) {
                        constraints[0].push_back({last_row + (last_column / witness_amount),
                                                    (last_column++) % witness_amount});
                    }

                    last_row += last_column / witness_amount;
                    last_column %= witness_amount;

                    auto cur_config = configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, {}, {});
                    
                    // std::cout << "config: " << "\n";
                    // std::cout << cur_config.first_coordinate.row << " " << cur_config.first_coordinate.column << " " << cur_config.last_coordinate.row << " " << cur_config.last_coordinate.column << std::endl;
                    // std::cout << cur_config.copy_from.row << " " << cur_config.copy_from.column << std::endl;
                    // for (int j = 0; j < cur_config.copy_to.size(); ++j) {
                    //     std::cout << cur_config.copy_to[j].row << " " << cur_config.copy_to[j].column << std::endl;
                    // }
                    // for (int j = 0; j < cur_config.constraints.size(); ++j) {
                    //     for (int k = 0; k < cur_config.constraints[j].size(); ++k) {
                    //         std::cout << cur_config.constraints[j][k].row << " " << cur_config.constraints[j][k].column << ", ";
                    //     }
                    //     std::cout << std::endl;
                    // }

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, {}, {});
                }
                static configuration configure_inner_with_padding(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits, 
                                                    bool range_check_input, std::size_t row, std::size_t column,
                                                    std::size_t num_cells, std::size_t buff) {
                    // std::cout << "configure_inner_with_padding\n";
                    
                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row,
                                last_column = column;
                                
                    // relay, chunk, sum; second
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    if (column > 3) {
                        for (int i = 0; i < 3; ++i) {
                            copy_to.push_back({last_row + 1, i});
                        }
                        cell_copy_from = {last_row + 1, 3};
                    } else {
                        for (int i = 0; i < 3; ++i) {
                            copy_to.push_back({last_row + (last_column / witness_amount),
                                                            (last_column++) % witness_amount});
                        }
                        cell_copy_from = {last_row + (last_column / witness_amount),
                                            (last_column++) % witness_amount};
                    }
                    
                    
                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (column > 3) {
                        for (int i = column; i < witness_amount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - witness_amount + column;
                        std::size_t cur_row = row + 1,
                                    cur_column = 4;
                        while (cur_column < cells_left) {
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + 4;
                        while (cur_column - column < num_cells) {
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    }
                    std::size_t cell_index = 0;
                    
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(1 + range_check_input);
                    // chunk, first, second
                    constraints.push_back({copy_to[1]});
                    constraints[0].push_back(cells[cell_index++]);
                    constraints[0].push_back(cell_copy_from);
                    // sum, relay, first
                    constraints.push_back({copy_to[2]});
                    constraints[1].push_back(copy_to[0]);
                    constraints[1].push_back(constraints[0][1]);
                    // sum range_check
                    constraints.push_back({constraints[1][0]});
                    for (int i = 0; i < 8; ++i) {
                        constraints[2].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints.back().back());
                    }
                    // chunk range_check
                    if (range_check_input) {
                        constraints.push_back({constraints[0][0]});
                        for (int i = 0; i < 8; ++i) {
                            constraints[3].push_back(cells[cell_index++]);
                            lookups[1].push_back(constraints.back().back());
                        }
                    }

                    if (cell_copy_from.first > cells.back().first) {
                        cells.back() = cell_copy_from;
                    }

                    last_column = cells.back().second + 1 + buff;
                    last_row = cells.back().first + (last_column >= witness_amount);
                    last_column %= witness_amount;

                    auto cur_config = configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                    
                    // std::cout << "config: " << "\n";
                    // std::cout << cur_config.first_coordinate.row << " " << cur_config.first_coordinate.column << " " << cur_config.last_coordinate.row << " " << cur_config.last_coordinate.column << std::endl;
                    // std::cout << cur_config.copy_from.row << " " << cur_config.copy_from.column << std::endl;
                    // for (int j = 0; j < cur_config.copy_to.size(); ++j) {
                    //     std::cout << cur_config.copy_to[j].row << " " << cur_config.copy_to[j].column << std::endl;
                    // }
                    // for (int j = 0; j < cur_config.constraints.size(); ++j) {
                    //     for (int k = 0; k < cur_config.constraints[j].size(); ++k) {
                    //         std::cout << cur_config.constraints[j][k].row << " " << cur_config.constraints[j][k].column << ", ";
                    //     }
                    //     std::cout << std::endl;
                    // }

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                }
                static configuration configure_inner(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits, 
                                                    bool range_check_input, std::size_t limit_permutation_column,
                                                    std::size_t row, std::size_t column,
                                                    std::size_t num_cells, std::size_t buff) {
                    if (calculate_shift(num_blocks, num_bits) == 0) {
                        return configure_inner_no_padding(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column, row, column, num_cells, buff);
                    }
                    return configure_inner_with_padding(witness_amount, num_blocks, num_bits, range_check_input, row, column, num_cells, buff);
                }
                                                    
                static std::vector<configuration> configure_all(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits,
                                                                bool range_check_input, std::size_t limit_permutation_column) {

                    std::size_t row = 0,
                                column = 0;
                    std::vector<configuration> result;
                    if (calculate_shift(num_blocks, num_bits) == 0 && !range_check_input) {
                        for (std::size_t i = 0; i < num_blocks; ++i) {
                            configuration conf;
                            conf.copy_from = {row, column};
                            conf.copy_to.push_back({row, column});
                            column += 1;
                            if (column == limit_permutation_column) {
                                column = 0;
                                row += 1;
                            }
                            conf.last_coordinate = {row, column};
                            result.push_back(conf);
                        }
                        return result;
                    }

                    std::size_t num_cells = calculate_num_cells(num_blocks, num_bits, range_check_input);
                    std::size_t buff = calculate_buff(witness_amount, range_check_input);
                    for (std::size_t i = 0; i < num_blocks; ++i) {
                        auto conf = configure_inner(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column, row, column, num_cells, buff);
                        result.push_back(conf);
                        row = conf.last_coordinate.row;
                        column = conf.last_coordinate.column;
                    }

                    // std::cout << "num_cofigs: " << result.size() << "\n";
                    // for (std::size_t i = 0; i < result.size(); ++i) {
                    //     auto cur_config = result[i];
                    //     std::cout << "config: " << i << "\n";
                    //     std::cout << cur_config.first_coordinate.row << " " << cur_config.first_coordinate.column << " " << cur_config.last_coordinate.row << " " << cur_config.last_coordinate.column << std::endl;
                    //     std::cout << cur_config.copy_from.row << " " << cur_config.copy_from.column << std::endl;
                    //     for (int j = 0; j < cur_config.copy_to.size(); ++j) {
                    //         std::cout << cur_config.copy_to[j].row << " " << cur_config.copy_to[j].column << std::endl;
                    //     }
                    //     for (int j = 0; j < cur_config.constraints.size(); ++j) {
                    //         for (int k = 0; k < cur_config.constraints[j].size(); ++k) {
                    //             std::cout << cur_config.constraints[j][k].row << " " << cur_config.constraints[j][k].column << ", ";
                    //         }
                    //         std::cout << std::endl;
                    //     }
                    // }

                    return result;
                }
                static std::map<std::size_t, std::vector<std::size_t>> configure_map(std::size_t witness_amount,
                                                                                    std::size_t num_blocks,
                                                                                    std::size_t num_bits,
                                                                                    bool range_check_input,
                                                                                    std::size_t limit_permutation_column) {
                                                
                    auto shift = calculate_shift(num_blocks, num_bits);
                    if (shift == 0 && !range_check_input) {
                        return {};
                    }
                    
                    auto config = configure_all(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    std::size_t row = 0,
                                column = 0;
                    int32_t row_shift = (shift == 0 || witness_amount == 15) ? 0 : 1;

                    std::map<std::size_t, std::vector<std::size_t>> config_map;

                    for (std::size_t i = 0; i < num_blocks; ++i) {
                        row = config[i].first_coordinate.row;
                        column = config[i].first_coordinate.column;
                        if (config_map.find(column) != config_map.end()) {
                            config_map[column].push_back(row + row_shift);
                        } else {
                            config_map[column] = {row + row_shift};
                        }
                    }

                    // std::cout << "MAP\n";
                    // for (auto c : config_map) {
                    //     std::cout << c.first << ": ";
                    //     for (auto r : c.second) {
                    //         std::cout << r << " ";
                    //     }
                    //     std::cout << std::endl;
                    // }

                    return config_map;
                }

                static std::vector<std::vector<configuration>> configure_gates(std::size_t witness_amount,
                                                                            std::size_t num_blocks,
                                                                            std::size_t num_bits,
                                                                            bool range_check_input, 
                                                                            std::size_t limit_permutation_column) {
                    if (calculate_shift(num_blocks, num_bits) == 0 && !range_check_input) {
                        return {};
                    }

                    std::vector<std::vector<configuration>> result;
                    auto gates_configuration_map = configure_map(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    std::size_t num_cells = calculate_num_cells(num_blocks, num_bits, range_check_input);
                    std::size_t buff = calculate_buff(witness_amount, range_check_input);

                    for (auto config: gates_configuration_map) {
                        configuration cur_config = configure_inner(witness_amount, num_blocks, num_bits, 
                                                                    range_check_input, limit_permutation_column, 
                                                                    0, config.first, num_cells, buff);                    
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
                    
                    // for (std::size_t i = 0; i < result.size(); ++i) {
                    //     std::cout << "config " << i << ":\n";
                    //     for (auto cur_config : result[i]) {
                    //         std::cout << "gate:\n";
                    //         for (int j = 0; j < cur_config.constraints.size(); ++j) {
                    //             for (int k = 0; k < cur_config.constraints[j].size(); ++k) {
                    //                 std::cout << cur_config.constraints[j][k].row << " " << cur_config.constraints[j][k].column << ", ";
                    //             }
                    //             std::cout << std::endl;
                    //         }
                    //     }
                    // }

                    return result;
                }

                std::vector<std::size_t> calculate_gates_rows(std::size_t witness_amount) {
                    std::vector<std::size_t> res;
                    std::size_t incr = 3;
                    std::size_t block_per_gate = 5;
                    std::size_t first_block = 0;
                    if (witness_amount == 15) {
                        res.push_back(0);
                        incr = 2;
                        block_per_gate = 6;
                        first_block = 2;
                    }
                    std::size_t cur_row = 1;
                    for (std::size_t i = first_block; i < num_blocks; i += block_per_gate) {
                        res.push_back(cur_row);
                        cur_row += incr;
                    }
                    return res;
                }

                static std::size_t get_gates_amount(std::size_t witness_amount,
                                                    std::size_t num_blocks,
                                                    std::size_t num_bits,
                                                    bool range_check_input, 
                                                    std::size_t limit_permutation_column = 7) {
                    auto map = configure_map(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    return map.size() * 2;
                }
                static std::size_t get_rows_amount(std::size_t witness_amount,
                                                   std::size_t lookup_column_amount,
                                                   std::size_t num_blocks,
                                                   std::size_t num_bits,
                                                   bool range_check_input, 
                                                   std::size_t limit_permutation_column) {
                    auto confs = configure_all(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    std::cout << "NUM ROWS: " << confs.back().last_coordinate.row + 1 * (confs.back().last_coordinate.column != 0) << "\n";
                    return confs.back().last_coordinate.row + 1 * (confs.back().last_coordinate.column != 0);
                }

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_pack_table/range_check"] = 0; // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/64bit"] = 0; // REQUIRED_TABLE
                    lookup_tables["keccak_ONE_table/full"] = 0; // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_padding(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input, std::size_t num_blocks_, std::size_t num_bits_,
                               bool range_check_input_ = true, std::size_t limit_permutation_column_ = 7) :
                    component_type(witness, constant, public_input, get_manifest()),
                    num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                    limit_permutation_column(limit_permutation_column_) {};

                keccak_padding(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t num_blocks_, std::size_t num_bits_, bool range_check_input_ = true, std::size_t limit_permutation_column_ = 7) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                    limit_permutation_column(limit_permutation_column_) {};

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using padding_component =
                keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const padding_component<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename padding_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {

                using component_type = padding_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using lookup_gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, lookup_constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::vector<std::size_t> selector_indexes;
                auto gates_configuration = component.gates_configuration;
                std::size_t config_index = 0;
                std::size_t gate_index = 0;
                std::size_t lookup_gate_index = 0;
                int32_t row_shift = (component.shift == 0 || component.witness_amount() == 15) ? 0 : 1;

                std::vector<constraint_type> cur_constraints;
                std::vector<lookup_constraint_type> cur_lookup_constraints;
                if (component.shift == 0) {
                    if (component.range_check_input) {
                        for (auto confs : gates_configuration) {
                            auto conf = confs[0];
                            constraint_type constraint = var(conf.constraints[0][0].column, static_cast<int>(conf.constraints[0][0].row));
                            for (std::size_t i = 1; i < 9; ++i) {
                                constraint -= var(conf.constraints[0][i].column, static_cast<int>(conf.constraints[0][i].row))
                                            * (integral_type(1) << ((i-1) * 8));
                                if (i == 8) {
                                    cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/64bit"),
                                                                    {var(component.W(conf.constraints[0][i].column), static_cast<int>(conf.constraints[0][i].row))}});
                                } else {
                                    cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                                    {var(component.W(conf.constraints[0][i].column), static_cast<int>(conf.constraints[0][i].row))}});
                                }
                            }
                            selector_indexes.push_back(bp.add_gate(constraint));
                            gate_index++;
                            selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                            lookup_gate_index++;
                            cur_lookup_constraints.clear();
                        }
                    }
                } else {
                    for (auto confs : gates_configuration) {
                        auto conf = confs[0];
                        // chunk, first, second
                        cur_constraints.push_back(constraint_type(
                            var(conf.constraints[0][0].column, static_cast<int>(conf.constraints[0][0].row) - row_shift) -
                            var(conf.constraints[0][1].column, static_cast<int>(conf.constraints[0][1].row) - row_shift) *
                                (integral_type(1) << (64 - component.shift)) -
                            var(conf.constraints[0][2].column, static_cast<int>(conf.constraints[0][2].row) - row_shift)));
                        // sum, relay, first
                        cur_constraints.push_back(
                            var(conf.constraints[1][0].column, static_cast<int>(conf.constraints[1][0].row) - row_shift) -
                            var(conf.constraints[1][1].column, static_cast<int>(conf.constraints[1][1].row) - row_shift) *
                                (integral_type(1) << component.shift) -
                            var(conf.constraints[1][2].column, static_cast<int>(conf.constraints[1][2].row) - row_shift));
                        // sum, range_check
                        constraint_type constraint = var(conf.constraints[2][0].column, static_cast<int>(conf.constraints[2][0].row) - row_shift);
                        for (std::size_t i = 1; i < 9; ++i) {
                            constraint -= var(conf.constraints[2][i].column, static_cast<int>(conf.constraints[2][i].row) - row_shift)
                                        * (integral_type(1) << ((i-1) * 8));
                            if (i == 8) {
                                cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/64bit"),
                                                                {var(component.W(conf.constraints[2][i].column), static_cast<int>(conf.constraints[2][i].row) - row_shift)}});
                            } else {
                                cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                                {var(component.W(conf.constraints[2][i].column), static_cast<int>(conf.constraints[2][i].row) - row_shift)}});
                            }
                        }
                        cur_constraints.push_back(constraint);
                        if (component.range_check_input) {
                            // chunk, range_check
                            constraint = var(conf.constraints[3][0].column, static_cast<int>(conf.constraints[3][0].row) - row_shift);
                            for (std::size_t i = 1; i < 9; ++i) {
                                constraint -= var(conf.constraints[3][i].column, static_cast<int>(conf.constraints[3][i].row) - row_shift)
                                            * (integral_type(1) << ((i-1) * 8));
                                cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                                {var(component.W(conf.constraints[3][i].column), static_cast<int>(conf.constraints[3][i].row) - row_shift)}});
                            }
                            cur_constraints.push_back(constraint);
                        }
                        selector_indexes.push_back(bp.add_gate(cur_constraints));
                        gate_index++;
                        cur_constraints.clear();
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                        cur_lookup_constraints.clear();
                    }
                }
                // std::cout << "gate_index: " << gate_index << std::endl;
                // std::cout << "component.gates_amount: " << component.gates_amount << std::endl;
                // std::cout << "ind: " << gate_index << ' ' << lookup_gate_index << std::endl;
                // std::cout << "SELS: " << selector_indexes.size() << std::endl;
                BOOST_ASSERT(gate_index + lookup_gate_index == component.gates_amount);
                return selector_indexes;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const padding_component<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename padding_component<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = padding_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;

                std::size_t strow = start_row_index;
                std::size_t config_index = 0;
                std::size_t input_index = 0;
                std::size_t witness_amount = component.witness_amount();

                std::size_t conf_index_for_input = 0;
                if (component.shift != 0) {
                    bp.add_copy_constraint({instance_input.message[input_index++], var(component.W(0), strow, false)});
                    conf_index_for_input = 1;
                }

                while (config_index < component.full_configuration.size() - 1) {
                    auto config = component.full_configuration[config_index];
                    bp.add_copy_constraint({instance_input.message[input_index++],
                                            var(component.W(config.copy_to[conf_index_for_input].column),
                                                config.copy_to[conf_index_for_input].row + strow, false)});
                    if (component.shift != 0) {
                        auto next_config = component.full_configuration[config_index + 1];
                        bp.add_copy_constraint({var(component.W(config.copy_from.column),
                                                    config.copy_from.row + strow, false),
                                                var(component.W(next_config.copy_to[0].column),
                                                    next_config.copy_to[0].row + strow, false)});
                    }
                    config_index++;
                }
                if (component.shift != 0) {
                    auto config = component.full_configuration[config_index];
                    bp.add_copy_constraint({var(component.C(0), start_row_index, false, var::column_type::constant),
                                            var(component.W(config.copy_to[conf_index_for_input].column),
                                                config.copy_to[conf_index_for_input].row + strow, false)});
                } else {
                    auto config = component.full_configuration[config_index];
                    bp.add_copy_constraint({instance_input.message[input_index++],
                                            var(component.W(config.copy_to[conf_index_for_input].column),
                                                config.copy_to[conf_index_for_input].row + strow, false)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename padding_component<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const padding_component<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename padding_component<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = padding_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;

                auto selector_indexes = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                auto gc_map = component.gates_configuration_map;
                std::size_t sel_ind = 0;

                std::size_t gate_row_ind = 0;
                for (auto gc : gc_map) {
                    for (auto gate_row : gc.second) {
                        assignment.enable_selector(selector_indexes[sel_ind], gate_row + start_row_index);
                        assignment.enable_selector(selector_indexes[sel_ind + 1], gate_row + start_row_index);
                    }
                    sel_ind += 2;
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename padding_component<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const padding_component<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename padding_component<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t strow = start_row_index;

                using component_type = padding_component<BlueprintFieldType, ArithmetizationParams>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::size_t config_index = 0;
                std::size_t witness_amount = component.witness_amount();

                if (component.shift != 0) {
                    integral_type relay_chunk = integral_type(var_value(assignment, instance_input.message[0]).data);
                    for (std::size_t index = 1; index < component.num_blocks + 1; ++index) {
                        value_type chunk = 0;
                        if (index < component.num_blocks) {
                            chunk = var_value(assignment, instance_input.message[index]);
                        }
                        integral_type integral_chunk = integral_type(chunk.data);
                        integral_type mask = (integral_type(1) << (64 - component.shift)) - 1;
                        std::array<integral_type, 2> chunk_parts = {integral_chunk >> (64 - component.shift),
                                                                    integral_chunk & mask};
                        integral_type sum = (relay_chunk << component.shift) + chunk_parts[0];

                        integral_type mask_range_check = (integral_type(1) << 8) - 1;
                        std::vector<integral_type> sum_range_check;
                        integral_type sum_to_check = sum;
                        for (std::size_t i = 0; i < 7; ++i) {
                            sum_range_check.push_back(sum_to_check & mask_range_check);
                            sum_to_check >>= 8;
                        }
                        sum_range_check.push_back(sum_to_check);

                        auto cur_config = component.full_configuration[config_index];
                        // chunk, first, second
                        assignment.witness(component.W(cur_config.constraints[0][0].column), cur_config.constraints[0][0].row + strow) = chunk;
                        for (int j = 1; j < 3; ++j) {
                            assignment.witness(component.W(cur_config.constraints[0][j].column), cur_config.constraints[0][j].row + strow) = value_type(chunk_parts[j - 1]);
                        }
                        // sum, relay, first
                        assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = value_type(sum);
                        assignment.witness(component.W(cur_config.constraints[1][1].column), cur_config.constraints[1][1].row + strow) = value_type(relay_chunk);
                        assignment.witness(component.W(cur_config.constraints[1][2].column), cur_config.constraints[1][2].row + strow) = value_type(chunk_parts[0]);
                        // sum range_check
                        for (int j = 1; j < 9; ++j) {
                            std::cout << "sum_range_check: " << sum_range_check[j - 1] << std::endl;
                            assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(sum_range_check[j - 1]);
                        }
                        if (component.range_check_input) {
                            std::vector<integral_type> chunk_range_check;
                            integral_type chunk_to_check = integral_chunk;
                            for (std::size_t i = 0; i < 7; ++i) {
                                chunk_range_check.push_back(chunk_to_check & mask_range_check);
                                chunk_to_check >>= 8;
                            }
                            chunk_range_check.push_back(chunk_to_check);
                            // chunk range_check
                            for (int j = 1; j < 9; ++j) {
                                assignment.witness(component.W(cur_config.constraints[3][j].column), cur_config.constraints[3][j].row + strow) = value_type(chunk_range_check[j - 1]);
                            }
                        }
                        relay_chunk = chunk_parts[1];
                        config_index++;
                    }
                } else {
                    for (std::size_t index = 0; index < component.full_configuration.size(); ++index) {
                        auto cur_config = component.full_configuration[index];
                        
                        if (component.range_check_input) {
                            integral_type chunk_to_check = integral_type(var_value(assignment, instance_input.message[index]).data);
                            integral_type mask_range_check = (integral_type(1) << 8) - 1;
                            std::vector<integral_type> chunk_range_check;
                            for (std::size_t i = 0; i < 8; ++i) {
                                chunk_range_check.push_back(chunk_to_check & mask_range_check);
                                chunk_to_check >>= 8;
                            }
                            // chunk range_check
                            for (int j = 1; j < 9; ++j) {
                                assignment.witness(component.W(cur_config.constraints[0][j].column), cur_config.constraints[0][j].row + strow) = value_type(chunk_range_check[j - 1]);
                            }
                        }

                        assignment.witness(component.W(cur_config.copy_to[0].column),
                                           cur_config.copy_to[0].row + strow) =
                            var_value(assignment, instance_input.message[index]);
                    }
                }

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const padding_component<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename padding_component<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = padding_component<BlueprintFieldType, ArithmetizationParams>;

                assignment.constant(component.C(0), start_row_index) = 0;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PADDING_HPP