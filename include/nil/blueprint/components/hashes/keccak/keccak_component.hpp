//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
//               2024 Valeh Farzaliyev   <estoniaa@nil.foundation>
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

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>
#include <nil/blueprint/components/hashes/keccak/keccak_padding.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class keccak;

            template<typename BlueprintFieldType>
            class keccak<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

                using component_type = plonk_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                static std::size_t calculate_num_round_calls(std::size_t num_blocks) {
                    return (num_blocks + (17 - num_blocks % 17)) / 17;
                }

            public:
                using var = typename component_type::var;

                using round_component_type =
                    keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                using padding_component_type =
                    keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                using manifest_type = nil::blueprint::plonk_component_manifest;
                class gate_manifest_type : public component_gate_manifest {
                public:
                    static const constexpr std::size_t clamp = 15;
                    std::size_t witness_amount;
                    std::size_t num_blocks;
                    std::size_t num_bits;
                    bool range_check_input;
                    std::size_t limit_permutation_column;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t num_blocks_, std::size_t num_bits_,
                                       bool range_check_input_, std::size_t limit_permutation_column_) :
                        witness_amount(std::min(witness_amount_, clamp)),
                        num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                        limit_permutation_column(limit_permutation_column_) {
                    }

                    std::uint32_t gates_amount() const override {
                        return get_gates_amount(witness_amount, num_blocks, num_bits, range_check_input,
                                                limit_permutation_column);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t num_blocks,
                                                       std::size_t num_bits,
                                                       bool range_check_input,
                                                       std::size_t limit_permutation_column) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(
                        witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column));

                    manifest.merge_with(padding_component_type::get_gate_manifest(
                        witness_amount, num_blocks, num_bits, range_check_input));
                    manifest.merge_with(round_component_type::get_gate_manifest(witness_amount,
                                                                                true, true, limit_permutation_column));
                    // manifest.merge_with(round_component_type::get_gate_manifest(
                    //     witness_amount, lookup_column_amount, true, false, limit_permutation_column));
                    // manifest.merge_with(round_component_type::get_gate_manifest(
                    //     witness_amount, lookup_column_amount, false, false, limit_permutation_column));

                    return manifest;
                }

                static manifest_type get_manifest(
                       std::size_t num_blocks, std::size_t num_bits,
                       bool range_check_input, std::size_t lpc = 7
                ) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(9, 15)), false)
                            .merge_with(padding_component_type::get_manifest(num_blocks, num_bits, range_check_input, lpc))
                            .merge_with(round_component_type::get_manifest(num_blocks, num_bits, range_check_input, lpc));
                    return manifest;
                }

                using configuration = typename padding_component_type::configuration;

                const std::size_t lookup_rows = 65536;
                const std::size_t witnesses = this->witness_amount();

                const std::size_t num_blocks;
                const std::size_t num_bits;
                const bool range_check_input;
                const std::size_t limit_permutation_column = 7;

                std::size_t round_tt_rows = 0;
                std::size_t round_tf_rows = 0;
                std::size_t round_ff_rows = 0;
                std::size_t round_tt_gates = 0;
                std::size_t round_tf_gates = 0;
                std::size_t round_ff_gates = 0;

                const std::size_t num_round_calls = calculate_num_round_calls(num_blocks);
                const std::size_t num_configs = 5 + num_blocks + (17 - num_blocks % 17);

                const std::size_t pack_chunk_size = 8;
                const std::size_t pack_num_chunks = 8;
                const std::size_t unpack_chunk_size = 24;
                const std::size_t unpack_num_chunks = 8;
                const std::size_t pack_cells = 2 * (pack_num_chunks + 1);
                const std::size_t pack_buff = (this->witness_amount() == 15) * 2;

                padding_component_type padding;
                round_component_type round_tt;
                round_component_type round_tf;
                round_component_type round_ff;

                std::vector<configuration> full_configuration =
                    configure_all(this->witness_amount(), num_configs, num_round_calls, limit_permutation_column);
                const std::map<std::size_t, std::vector<std::size_t>> gates_configuration_map = configure_map(
                    this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::vector<std::vector<configuration>> gates_configuration = configure_gates(
                    this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), num_blocks, num_bits,
                                                                range_check_input, limit_permutation_column);
                const std::size_t gates_amount = get_gates_amount(this->witness_amount(), num_blocks, num_bits,
                                                                  range_check_input, limit_permutation_column);

                const std::size_t round_constant[24] = {1,
                                                        0x8082,
                                                        0x800000000000808a,
                                                        0x8000000080008000,
                                                        0x808b,
                                                        0x80000001,
                                                        0x8000000080008081,
                                                        0x8000000000008009,
                                                        0x8a,
                                                        0x88,
                                                        0x80008009,
                                                        0x8000000a,
                                                        0x8000808b,
                                                        0x800000000000008b,
                                                        0x8000000000008089,
                                                        0x8000000000008003,
                                                        0x8000000000008002,
                                                        0x8000000000000080,
                                                        0x800a,
                                                        0x800000008000000a,
                                                        0x8000000080008081,
                                                        0x8000000000008080,
                                                        0x80000001,
                                                        0x8000000080008008};

                struct input_type {
                    std::vector<var> message;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        res.reserve(message.size());
                        res.insert(res.end(), message.begin(), message.end());
                        return res;
                    }
                };

                struct result_type {
                    std::array<var, 5> final_inner_state;

                    result_type(const keccak &component, std::size_t start_row_index) {
                        auto offset =
                            component.full_configuration[component.num_configs - 1].last_coordinate.row +
                            (component.full_configuration[component.num_configs - 1].last_coordinate.column > 0);
                        for (std::size_t i = 0; i < 5; ++i) {
                            final_inner_state[i] =
                                var(component.W(
                                        component.full_configuration[component.num_configs - 5 + i].copy_from.column),
                                    start_row_index + component.rows_amount - offset +
                                        component.full_configuration[component.num_configs - 5 + i].copy_from.row,
                                    false);
                        }
                    }
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {final_inner_state[0], final_inner_state[1], final_inner_state[2], final_inner_state[3],
                                final_inner_state[4]};
                    }
                };
                static std::size_t get_rows_amount_round_tt() {
                    return 0;
                }

                integral_type pack(const integral_type &const_input) const {
                    integral_type input = const_input;
                    integral_type sparse_res = 0;
                    integral_type power = 1;
                    while (input > 0) {
                        auto bit = input & 1;
                        sparse_res += bit * power;
                        power <<= 3;
                        input >>= 1;
                    }
                    return sparse_res;
                }

                integral_type unpack(const integral_type &const_sparse_input) const {
                    integral_type sparse_input = const_sparse_input;
                    integral_type res = 0;
                    integral_type power = 1;
                    integral_type mask = (integral_type(1) << 3) - 1;
                    while (sparse_input > 0) {
                        auto bit = sparse_input & mask;
                        BOOST_ASSERT(bit * (1 - bit) == 0);
                        res += bit * power;
                        power <<= 1;
                        sparse_input >>= 3;
                    }
                    return res;
                }

                static configuration configure_pack_unpack(std::size_t witness_amount, std::size_t row,
                                                           std::size_t column, std::size_t pack_cells,
                                                           std::size_t pack_num_chunks, std::size_t pack_buff,
                                                           std::size_t limit_permutation_column) {
                    // regular constraints:
                    // input = input0 + input1 * 2^chunk_size + ... + inputk * 2^(k*chunk_size)
                    // output = output0 + output1 * 2^chunk_size + ... + outputk * 2^(k*chunk_size)

                    std::size_t last_row = row, last_column = column;
                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::vector<std::pair<std::size_t, std::size_t>> copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;

                    if (1 + column > limit_permutation_column) {
                        copy_from.push_back({last_row + 1, 0});
                    } else {
                        copy_from.push_back(
                            {last_row + (last_column / witness_amount), (last_column++) % witness_amount});
                    }

                    std::pair<std::size_t, std::size_t> cell_copy_to;
                    std::size_t final_row = (column + pack_cells - 1) / witness_amount + row;
                    if (final_row == copy_from[0].first) {
                        cell_copy_to = {final_row, copy_from.back().second + 1};
                    } else {
                        cell_copy_to = {final_row, 0};
                    }

                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (1 + column > limit_permutation_column) {
                        for (int i = column; i < witness_amount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = pack_cells - witness_amount + column;
                        std::size_t cur_row = row + 1, cur_column = 1;
                        while (cur_column < cells_left) {
                            if (cur_column % witness_amount == cell_copy_to.second &&
                                (cur_row + (cur_column / witness_amount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    } else {
                        std::size_t cur_row = row, cur_column = column + 1;
                        while (cur_column - column < pack_cells) {
                            if (cur_column % witness_amount == cell_copy_to.second &&
                                (cur_row + (cur_column / witness_amount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    }
                    std::size_t cell_index = 0;

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(
                        pack_num_chunks, std::vector<std::pair<std::size_t, std::size_t>>());

                    constraints.push_back({copy_from[0]});
                    constraints.push_back({cell_copy_to});
                    for (std::size_t i = 0; i < 2; ++i) {
                        for (std::size_t j = 0; j < pack_num_chunks; ++j) {
                            constraints[i].push_back(cells[cell_index++]);
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    last_column = cells.back().second + 1 + pack_buff;
                    last_row = cells.back().first + (last_column / witness_amount);
                    last_column %= witness_amount;

                    return configuration(first_coordinate, {last_row, last_column}, copy_from, constraints, lookups,
                                         cell_copy_to);
                }

                static std::vector<configuration> configure_all(std::size_t witness_amount,
                                                                const std::size_t num_configs,
                                                                const std::size_t num_round_calls,
                                                                std::size_t limit_permutation_column) {
                    std::vector<configuration> result;
                    std::size_t pack_num_chunks = 8;
                    std::size_t pack_cells = 2 * (pack_num_chunks + 1);
                    std::size_t pack_buff = (witness_amount == 15) * 2;

                    std::size_t row = 0, column = 0;

                    for (std::size_t index = 0; index < num_round_calls * 17; ++index) {
                        // to sparse representation
                        result.push_back(configure_pack_unpack(witness_amount, row, column, pack_cells, pack_num_chunks,
                                                               pack_buff, limit_permutation_column));
                        row = result[index].last_coordinate.row;
                        column = result[index].last_coordinate.column;
                    }
                    if (column > 0) {
                        column = 0;
                        row++;
                    }

                    // rounds
                    // for (std::size_t index = 0; index < num_round_calls; ++index) {
                    //     for (std::size_t i = 0; i < 24; ++i) {
                    //         if (index == num_round_calls - 1 && i == 0) {
                    //             row += round_component_type::get_rows_amount(witness_amount, true, true,
                    //                                                          limit_permutation_column);
                    //         } else if (i == 0) {
                    //             row += round_component_type::get_rows_amount(witness_amount, true, false,
                    //                                                          limit_permutation_column);
                    //         } else {
                    //             row += round_component_type::get_rows_amount(witness_amount, false, false,
                    //                                                          limit_permutation_column);
                    //         }
                    //     }
                    // }

                    row = 0;
                    // from sparse representation
                    for (std::size_t i = 0; i < 5; ++i) {
                        result.push_back(configure_pack_unpack(witness_amount, row, column, pack_cells, pack_num_chunks,
                                                               pack_buff, limit_permutation_column));
                        row = result.back().last_coordinate.row;
                        column = result.back().last_coordinate.column;
                    }

                    // std::cout << "num_cofigs: " << result.size() << "\n";
                    // for (std::size_t i = 0; i < result.size(); ++i) {
                    //     auto cur_config = result[i];
                    //     std::cout << "config: " << i << "\n";
                    //     std::cout << cur_config.first_coordinate.row << " " << cur_config.first_coordinate.column <<
                    //     " " << cur_config.last_coordinate.row << " " << cur_config.last_coordinate.column <<
                    //     std::endl; std::cout << cur_config.copy_from.row << " " << cur_config.copy_from.column <<
                    //     std::endl; for (int j = 0; j < cur_config.copy_to.size(); ++j) {
                    //         std::cout << cur_config.copy_to[j].row << " " << cur_config.copy_to[j].column <<
                    //         std::endl;
                    //     }
                    //     for (int j = 0; j < cur_config.constraints.size(); ++j) {
                    //         for (int k = 0; k < cur_config.constraints[j].size(); ++k) {
                    //             std::cout << cur_config.constraints[j][k].row << " " <<
                    //             cur_config.constraints[j][k].column << ", ";
                    //         }
                    //         std::cout << std::endl;
                    //     }
                    // }

                    return result;
                }

                static std::map<std::size_t, std::vector<std::size_t>>
                    configure_map(std::size_t witness_amount,
                                  std::size_t num_blocks,
                                  std::size_t num_bits,
                                  bool range_check_input,
                                  std::size_t limit_permutation_column) {

                    std::size_t num_configs = 5 + num_blocks + (17 - num_blocks % 17);
                    std::size_t num_round_calls = calculate_num_round_calls(num_blocks);
                    auto config = configure_all(witness_amount, num_configs, num_round_calls, limit_permutation_column);
                    std::size_t row = 0, column = 0;
                    std::size_t row_shift = 0;    // padding_component_type::get_rows_amount(
                    //     witness_amount, 0, num_blocks, num_bits, range_check_input, limit_permutation_column);

                    std::map<std::size_t, std::vector<std::size_t>> config_map;

                    for (std::size_t i = 0; i < config.size() - 5; ++i) {
                        row = config[i].first_coordinate.row;
                        column = config[i].first_coordinate.column;
                        if (config_map.find(column) != config_map.end()) {
                            config_map[column].push_back(row + row_shift);
                        } else {
                            config_map[column] = {row + row_shift};
                        }
                    }
                    // row_shift += config[config.size() - 6].last_coordinate.row;
                    for (std::size_t i = config.size() - 5; i < config.size(); ++i) {
                        row = config[i].first_coordinate.row;
                        column = config[i].first_coordinate.column + 10 * witness_amount;
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
                    std::vector<std::vector<configuration>> result;
                    auto gates_configuration_map = configure_map(witness_amount, num_blocks, num_bits,
                                                                 range_check_input, limit_permutation_column);
                    std::size_t pack_num_chunks = 8;
                    std::size_t num_cells = 2 * (pack_num_chunks + 1);
                    std::size_t buff = (witness_amount == 15) * 2;

                    for (auto config : gates_configuration_map) {
                        if (config.first >= 10 * witness_amount)
                            continue;
                        configuration cur_config =
                            configure_pack_unpack(witness_amount, 0, config.first, num_cells, pack_num_chunks, buff,
                                                  limit_permutation_column);
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
                            while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 &&
                                   pairs[cur_constr].first >= cur_row) {
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
                    //                 std::cout << cur_config.constraints[j][k].row << " " <<
                    //                 cur_config.constraints[j][k].column << ", ";
                    //             }
                    //             std::cout << std::endl;
                    //         }
                    //     }
                    // }

                    return result;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount,
                                                   std::size_t num_blocks, std::size_t num_bits, bool range_check_input,
                                                   std::size_t limit_permutation_column) {
                    std::size_t num_round_calls = calculate_num_round_calls(num_blocks);
                    std::size_t res =
                        padding_component_type::get_rows_amount(witness_amount, num_blocks,
                                                                num_bits, range_check_input, limit_permutation_column);
                    // + round_tt_rows
                    for (std::size_t i = 0; i < num_round_calls; i++) {
                        if (i == num_round_calls - 1) {
                            res += round_component_type::get_rows_amount(witness_amount, true,
                                                                         true, limit_permutation_column);
                        } else {
                            res += round_component_type::get_rows_amount(witness_amount, true,
                                                                         false, limit_permutation_column);
                        }
                        for (std::size_t j = 1; j < 24; ++j) {
                            res += round_component_type::get_rows_amount(witness_amount, false,
                                                                         false, limit_permutation_column);
                        }
                    }

                    auto config = configure_all(witness_amount, num_blocks, num_round_calls, limit_permutation_column);
                    auto index = config.size() - 1;
                    res += config[index].last_coordinate.row + (config[index].last_coordinate.column > 0);
                    res += config[index - 5].last_coordinate.row + (config[index - 5].last_coordinate.column > 0);
                    return res;
                }
                static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t num_blocks,
                                                    std::size_t num_bits, bool range_check_input,
                                                    std::size_t limit_permutation_column) {
                    std::size_t res = 0;
                    auto config = configure_map(witness_amount, num_blocks, num_bits, range_check_input,
                                                limit_permutation_column);
                    for (auto c : config) {
                        if (c.first >= 10 * witness_amount)
                            res += 2;
                        else
                            res += 2;
                    }
                    return res;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_pack_table/full"] = 0;                  // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check"] = 0;           // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/64bit"] = 0;                 // REQUIRED_TABLE
                    lookup_tables["keccak_sign_bit_table/full"] = 0;              // REQUIRED_TABLE
                    lookup_tables["keccak_normalize3_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize4_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize6_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_chi_table/full"] = 0;                   // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_sparse"] = 0;    // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak(WitnessContainerType witness, ConstantContainerType constant,
                       PublicInputContainerType public_input, std::size_t num_blocks_, std::size_t num_bits_,
                       bool range_check_input_, std::size_t lpc_ = 7) :
                    component_type(witness, constant, public_input,
                                   get_manifest(num_blocks_, num_bits_, range_check_input_, lpc_)),
                    num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                    limit_permutation_column(lpc_),
                    num_round_calls(calculate_num_round_calls(num_blocks_)),
                    padding(witness, constant, public_input, num_blocks_, num_bits_, range_check_input_, lpc_),
                    round_tt(witness, constant, public_input, true, true, lpc_),
                    round_tf(witness, constant, public_input, true, false, lpc_),
                    round_ff(witness, constant, public_input, false, false, lpc_) {

                    round_tt_rows = round_tt.rows_amount;
                    round_tf_rows = round_tf.rows_amount;
                    round_ff_rows = round_ff.rows_amount;
                    round_tt_gates = round_tt.gates_amount;
                    round_tf_gates = round_tf.gates_amount;
                    round_ff_gates = round_ff.gates_amount;
                };

                keccak(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                       std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                       std::initializer_list<typename component_type::public_input_container_type::value_type>
                           public_inputs,
                       std::size_t num_blocks_, std::size_t num_bits_, bool range_check_input_, std::size_t lpc_ = 7) :
                    component_type(witnesses, constants, public_inputs),
                    num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                    limit_permutation_column(lpc_),
                    padding(witnesses, constants, public_inputs, num_blocks_, num_bits_, range_check_input_, lpc_),
                    num_round_calls(calculate_num_round_calls(num_blocks_)),
                    round_tt(witnesses, constants, public_inputs, true, true, lpc_),
                    round_tf(witnesses, constants, public_inputs, true, false, lpc_),
                    round_ff(witnesses, constants, public_inputs, false, false, lpc_) {

                    round_tt_rows = round_tt.rows_amount;
                    round_tf_rows = round_tf.rows_amount;
                    round_ff_rows = round_ff.rows_amount;
                    round_tt_gates = round_tt.gates_amount;
                    round_tf_gates = round_tf.gates_amount;
                    round_ff_gates = round_ff.gates_amount;
                };
            };

            template<typename BlueprintFieldType>
            using keccak_component = keccak<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const keccak_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_component<BlueprintFieldType>::input_type &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {

                using component_type = keccak_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::vector<std::size_t> selector_indexes;
                auto gates_configuration = component.gates_configuration;

                for (auto config : gates_configuration) {
                    std::vector<lookup_constraint_type> lookup_constraints_0;
                    std::vector<lookup_constraint_type> lookup_constraints_1;
                    auto conf = config[0];

                    // pack gate
                    constraint_type constraint_0 =
                        var(conf.constraints[0][0].column, static_cast<int>(conf.constraints[0][0].row));
                    constraint_type constraint_1 =
                        var(conf.constraints[1][0].column, static_cast<int>(conf.constraints[1][0].row));

                    constraint_type constraint_2 =
                        var(conf.constraints[1][0].column, static_cast<int>(conf.constraints[1][0].row));
                    constraint_type constraint_3 =
                        var(conf.constraints[0][0].column, static_cast<int>(conf.constraints[0][0].row));
                    for (std::size_t i = 1; i < 9; ++i) {
                        constraint_0 -=
                            var(conf.constraints[0][i].column, static_cast<int>(conf.constraints[0][i].row)) *
                            (integral_type(1) << ((i - 1) * 8));
                        constraint_1 -=
                            var(conf.constraints[1][i].column, static_cast<int>(conf.constraints[1][i].row)) *
                            (integral_type(1) << ((8 - i) * 24));
                        constraint_2 -=
                            var(conf.constraints[1][i].column, static_cast<int>(conf.constraints[1][i].row)) *
                            (integral_type(1) << ((i - 1) * 8));
                        constraint_3 -=
                            var(conf.constraints[0][i].column, static_cast<int>(conf.constraints[0][i].row)) *
                            (integral_type(1) << ((i - 1) * 24));
                        lookup_constraints_0.push_back({lookup_tables_indices.at("keccak_pack_table/full"),
                                                        {var(component.W(conf.constraints[0][i].column),
                                                             static_cast<int>(conf.constraints[0][i].row)),
                                                         var(component.W(conf.constraints[1][i].column),
                                                             static_cast<int>(conf.constraints[1][i].row))}});
                        lookup_constraints_1.push_back({lookup_tables_indices.at("keccak_pack_table/full"),
                                                        {var(component.W(conf.constraints[1][i].column),
                                                             static_cast<int>(conf.constraints[1][i].row)),
                                                         var(component.W(conf.constraints[0][i].column),
                                                             static_cast<int>(conf.constraints[0][i].row))}});
                    }
                    selector_indexes.push_back(bp.add_gate({constraint_0, constraint_1}));
                    selector_indexes.push_back(bp.add_gate({constraint_2, constraint_3}));
                    selector_indexes.push_back(bp.add_lookup_gate(lookup_constraints_0));
                    selector_indexes.push_back(bp.add_lookup_gate(lookup_constraints_1));
                }

                return selector_indexes;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const keccak_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_component<BlueprintFieldType>;
                using padding_type = typename component_type::padding_component_type;
                using round_type = typename component_type::round_component_type;
                using var = typename component_type::var;
                std::uint32_t cur_row = start_row_index;

                std::size_t config_index = 0;
                auto config = component.full_configuration;

                auto padded_message =
                    typename padding_type::result_type(component.padding, start_row_index).padded_message;
                cur_row += component.padding.rows_amount;

                for (std::size_t i = 0; i < padded_message.size(); i++) {
                    bp.add_copy_constraint(
                        {padded_message[i],
                         var(component.W(config[config_index].copy_to[0].column),
                             static_cast<int>(config[config_index].copy_to[0].row + cur_row), false)});
                    config_index++;
                }
                cur_row += config[config_index - 1].last_coordinate.row +
                           (config[config_index - 1].last_coordinate.column > 0);

                std::array<var, 25> inner_state;

                auto gate_map_tf = component.round_tf.gates_configuration_map;
                std::vector<std::size_t> rotate_rows_tf;
                for (auto g : gate_map_tf) {
                    if (g.first.first == 7) {
                        rotate_rows_tf.insert(rotate_rows_tf.end(), g.second.begin(), g.second.end());
                    }
                }
                std::sort(rotate_rows_tf.begin(), rotate_rows_tf.end());

                auto gate_map_ff = component.round_ff.gates_configuration_map;
                std::vector<std::size_t> rotate_rows_ff;
                for (auto g : gate_map_ff) {
                    if (g.first.first == 7) {
                        rotate_rows_ff.insert(rotate_rows_ff.end(), g.second.begin(), g.second.end());
                    }
                }
                std::sort(rotate_rows_ff.begin(), rotate_rows_ff.end());

                for (int i = 0; i < component.num_round_calls; i++) {
                    for (int j = 0; j < 24; j++) {
                        // if (i + j != 0) {
                        //     std::cout << "prev: " << prev_row << " vs curr" << cur_row << std::endl;
                        //     for (int k = 0; k < 5; k++) {
                        //         auto ind1 = (j == 1) ? rotate_rows_tf[k] : rotate_rows_ff[k];
                        //         auto ind2 = rotate_rows_ff[k];
                        //         std::cout << ind1 << " , " << ind2 << std::endl;
                        //         std::cout
                        //             << var_value(assignment, var(component.C(0), prev_row + ind1, false)).data <<
                        //             "  vs  "
                        //             << var_value(assignment, var(component.C(0), cur_row + ind2, false)).data <<
                        //             std::endl;
                        //         bp.add_copy_constraint({var(component.C(0), prev_row + ind1, false),
                        //                                 var(component.C(0), cur_row + ind2, false)});
                        //     }
                        //     prev_row = cur_row;
                        // }
                        if (i == component.num_round_calls - 1 && j == 0) {
                            cur_row += component.round_tt.rows_amount;
                        } else if (j == 0) {
                            cur_row += component.round_tf.rows_amount;
                        } else {
                            inner_state = typename round_type::result_type(component.round_ff, cur_row).inner_state;
                            cur_row += component.round_ff.rows_amount;
                        }
                    }
                }

                for (std::size_t i = 0; i < 5; i++) {
                    bp.add_copy_constraint(
                        {inner_state[i], var(component.W(config[config_index].copy_to[0].column),
                                             static_cast<int>(config[config_index].copy_to[0].row + cur_row), false)});
                    config_index++;
                }

                cur_row += config[config_index - 1].last_coordinate.row +
                           (config[config_index - 1].last_coordinate.column > 0);

                // BOOST_ASSERT(cur_row == start_row_index + component.rows_amount);
            }

            template<typename BlueprintFieldType>
            typename keccak_component<BlueprintFieldType>::result_type generate_circuit(
                const keccak_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_component<BlueprintFieldType>;
                using padding_type = typename component_type::padding_component_type;
                using round_type = typename component_type::round_component_type;
                using var = typename component_type::var;

                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);
                std::size_t row = start_row_index;

                std::vector<std::uint32_t> witnesses;
                for (std::size_t i = 0; i < component.witnesses; ++i) {
                    witnesses.push_back(i);
                }
                std::vector<std::uint32_t> zero_column = {0};

                padding_type padding_component_instance(witnesses, zero_column, zero_column, component.num_blocks,
                                                        component.num_bits, component.range_check_input,
                                                        component.limit_permutation_column);
                typename padding_type::input_type padding_input = {instance_input.message};
                typename padding_type::result_type padding_result =
                    generate_circuit(padding_component_instance, bp, assignment, padding_input, row);
                row += padding_component_instance.rows_amount;

                auto selector_indexes =
                    generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                auto config_map = component.gates_configuration_map;
                std::size_t sel_ind = 0;
                for (auto config : config_map) {
                    if (config.first < component.witnesses) {
                        for (auto gate_row : config.second) {
                            // std::cout << "enabling: " << selector_indexes[sel_ind] << " "
                            //           << selector_indexes[sel_ind + 1] << " at " << gate_row + row << std::endl;
                            assignment.enable_selector(selector_indexes[sel_ind], gate_row + row);
                            assignment.enable_selector(selector_indexes[sel_ind + 2], gate_row + row);
                        }
                        std::cout << std::endl;
                        sel_ind += 1;
                    }
                }

                std::size_t config_index = 0;
                std::vector<var> sparse_padded_message_coords(padding_result.padded_message.size());
                for (std::size_t index = 0; index < padding_result.padded_message.size(); index++) {
                    auto cur_config = component.full_configuration[config_index];
                    sparse_padded_message_coords[index] = var(component.W(cur_config.constraints[1][0].column),
                                                              cur_config.constraints[1][0].row + row, false);
                    config_index++;
                }

                row += component.full_configuration[config_index - 1].last_coordinate.row +
                       (component.full_configuration[config_index - 1].last_coordinate.column > 0);

                // round circuits
                std::array<var, 25> inner_state;
                for (std::uint32_t i = 0; i < 25; i++) {
                    inner_state[i] = var(component.C(0), start_row_index, false, var::column_type::constant);
                }
                std::array<var, 17> pmc;
                std::size_t offset = 0;
                for (std::size_t i = 0; i < component.num_round_calls; ++i) {
                    std::copy(sparse_padded_message_coords.begin() + offset,
                              sparse_padded_message_coords.begin() + offset + 17,
                              pmc.begin());

                    for (std::size_t j = 0; j < 24; ++j) {
                        typename round_type::input_type round_input = {
                            inner_state, pmc,
                            var(component.C(0), start_row_index + j + 4, false, var::column_type::constant)};
                        if (i == component.num_round_calls - 1 && j == 0) {
                            typename round_type::result_type round_result =
                                generate_circuit(component.round_tt, bp, assignment, round_input, row);
                            inner_state = round_result.inner_state;
                            row += component.round_tt.rows_amount;
                        } else if (j == 0) {
                            typename round_type::result_type round_result =
                                generate_circuit(component.round_tf, bp, assignment, round_input, row);
                            inner_state = round_result.inner_state;
                            row += component.round_tf.rows_amount;
                        } else {
                            typename round_type::result_type round_result =
                                generate_circuit(component.round_ff, bp, assignment, round_input, row);
                            inner_state = round_result.inner_state;
                            row += component.round_ff.rows_amount;
                        }
                    }
                    offset += 17;
                }

                std::cout << "after rounds row: " << row << std::endl;
                // sel_ind = 0;
                for (auto config : config_map) {
                    if (config.first >= 10 * component.witnesses) {
                        for (auto gate_row : config.second) {
                            // std::cout << "enabling2: " << selector_indexes[sel_ind] << " "
                            //           << selector_indexes[sel_ind + 2] << " at " << gate_row + row << std::endl;
                            assignment.enable_selector(selector_indexes[sel_ind], gate_row + row);
                            assignment.enable_selector(selector_indexes[sel_ind + 2], gate_row + row);
                        }
                        std::cout << std::endl;
                        sel_ind += 1;
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename keccak_component<BlueprintFieldType>::result_type generate_assignments(
                const keccak_component<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t cur_row = start_row_index;

                using component_type = keccak_component<BlueprintFieldType>;
                using round_type = typename component_type::round_component_type;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                std::vector<var> padded_message =
                    generate_assignments(component.padding, assignment, {instance_input.message}, cur_row)
                        .padded_message;
                cur_row += component.padding.rows_amount;

                // to sparse
                std::size_t config_index = 0;
                std::vector<value_type> sparse_padded_message(padded_message.size());
                std::vector<var> sparse_padded_message_coords(padded_message.size());
                for (std::size_t index = 0; index < padded_message.size(); ++index) {
                    value_type regular_value = var_value(assignment, padded_message[index]);
                    integral_type regular = integral_type(regular_value.data);
                    // std::cout << "pad elem: " << regular << std::endl;
                    auto sparse = integral_type(0);
                    auto chunk_size = component.pack_chunk_size;
                    auto num_chunks = component.pack_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_sparse_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;

                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(regular & mask);
                        regular >>= chunk_size;
                        integral_sparse_chunks.push_back(component.pack(integral_chunks.back()));
                        // std::cout << "chunks: " << integral_chunks.back() << " " << integral_sparse_chunks.back()
                        //           << std::endl;
                    }
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        sparse = sparse + power * integral_sparse_chunks[num_chunks - j - 1];
                        power <<= (3 * chunk_size);
                    }
                    // std::cout << "sparse: " << sparse << std::endl;
                    sparse_padded_message[index] = value_type(sparse);

                    auto cur_config = component.full_configuration[config_index];
                    assignment.witness(component.W(cur_config.constraints[0][0].column),
                                       cur_config.constraints[0][0].row + cur_row) = regular_value;
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + cur_row) = value_type(sparse);
                    // std::cout << cur_config.constraints[1][0].column << ' ' << cur_config.constraints[1][0].row +
                    // cur_row << std::endl;
                    sparse_padded_message_coords[index] = var(component.W(cur_config.constraints[1][0].column),
                                                              cur_config.constraints[1][0].row + cur_row, false);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[0][j].column),
                                           cur_config.constraints[0][j].row + cur_row) =
                            value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + cur_row) =
                            value_type(integral_sparse_chunks[j - 1]);
                    }
                    config_index++;
                }

                cur_row += component.full_configuration[config_index - 1].last_coordinate.row +
                           (component.full_configuration[config_index - 1].last_coordinate.column > 0);

                std::array<var, 25> inner_state;
                for (std::uint32_t i = 0; i < 25; i++) {
                    inner_state[i] = var(component.C(0), start_row_index, false, var::column_type::constant);
                }

                std::size_t offset = 0;
                std::array<var, 17> pmc;
                for (std::size_t i = 0; i < component.num_round_calls; ++i) {
                    std::copy(sparse_padded_message_coords.begin() + offset,
                              sparse_padded_message_coords.begin() + offset + 17, pmc.begin());
                    for (auto &el : pmc) {
                        std::cout << component.unpack(integral_type(var_value(assignment, el).data)) << ",";
                    }
                    std::cout << std::endl;

                    for (std::size_t j = 0; j < 24; ++j) {
                        typename round_type::input_type round_input = {
                            inner_state, pmc,
                            var(component.C(0), start_row_index + j + 4, false, var::column_type::constant)};
                        if (i == component.num_round_calls - 1 && j == 0) {
                            typename round_type::result_type round_result =
                                generate_assignments(component.round_tt, assignment, round_input, cur_row);
                            inner_state = round_result.inner_state;
                            cur_row += component.round_tt.rows_amount;
                        } else if (j == 0) {
                            typename round_type::result_type round_result =
                                generate_assignments(component.round_tf, assignment, round_input, cur_row);
                            inner_state = round_result.inner_state;
                            cur_row += component.round_tf.rows_amount;
                        } else {
                            typename round_type::result_type round_result =
                                generate_assignments(component.round_ff, assignment, round_input, cur_row);
                            inner_state = round_result.inner_state;
                            cur_row += component.round_ff.rows_amount;
                        }
                    }
                    offset += 17;
                }

                // from sparse
                for (std::size_t index = 0; index < 5; ++index) {
                    value_type sparse_value = var_value(assignment, inner_state[index]);
                    integral_type sparse = integral_type(sparse_value.data);
                    integral_type regular = component.unpack(sparse);
                    // std::cout << "from sparse: " << sparse << " to regular " << regular << std::endl;
                    auto chunk_size = component.pack_chunk_size * 3;
                    auto num_chunks = component.pack_num_chunks;
                    std::vector<integral_type> integral_sparse_chunks;
                    std::vector<integral_type> integral_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(sparse & mask);
                        sparse >>= chunk_size;
                        integral_sparse_chunks.push_back(component.unpack(integral_chunks.back()));
                    }

                    sparse_padded_message[index] = value_type(regular);

                    auto cur_config = component.full_configuration[config_index];
                    assignment.witness(component.W(cur_config.constraints[0][0].column),
                                       cur_config.constraints[0][0].row + cur_row) = sparse_value;
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + cur_row) = value_type(regular);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[0][j].column),
                                           cur_config.constraints[0][j].row + cur_row) =
                            value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + cur_row) =
                            value_type(integral_sparse_chunks[j - 1]);
                    }
                    config_index++;
                }

                cur_row += component.full_configuration[config_index - 1].last_coordinate.row +
                           (component.full_configuration[config_index - 1].last_coordinate.column > 0);

                // BOOST_ASSERT(cur_row == start_row_index + component.rows_amount);
                std::cout << cur_row << " vs " << component.rows_amount << std::endl;

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const keccak_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index + 4;
                for (std::size_t i = 0; i < 24; ++i) {
                    assignment.constant(component.C(0), row + i) = component.pack(component.round_constant[i]);
                }
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP