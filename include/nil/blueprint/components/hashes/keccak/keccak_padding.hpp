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
                    std::int32_t row;
                    std::size_t column;

                    coordinates() = default;
                    coordinates(std::int32_t row_, std::size_t column_) : row(row_), column(column_) {};
                    coordinates(std::pair<std::int32_t, std::size_t> pair) : row(pair.first), column(pair.second) {};
                    coordinates(std::vector<std::int32_t> vec) : row(vec[0]), column(vec[1]) {};
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
                    std::size_t row;

                    configuration() = default;
                    configuration(std::pair<std::size_t, std::size_t> first_coordinate_,
                                  std::pair<std::size_t, std::size_t> last_coordinate_,
                                  std::vector<std::pair<std::size_t, std::size_t>> copy_to_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups_,
                                  std::pair<std::size_t, std::size_t> copy_from_, std::size_t row_) {
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
                        row = row_;
                    };
                    bool operator==(const configuration &other) const {
                        return first_coordinate == other.first_coordinate && last_coordinate == other.last_coordinate &&
                               copy_to == other.copy_to && constraints == other.constraints &&
                               lookups == other.lookups && copy_from == other.copy_from;
                    }
                    bool operator<(const configuration &other) const {
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
                    std::size_t last_gate;
                    static constexpr const std::size_t clamp = 15;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t num_blocks_, std::size_t num_bits_,
                                       std::size_t last_gate_) :
                        witness_amount(std::min(witness_amount_, clamp)),
                        num_blocks(num_blocks_), num_bits(num_bits_), last_gate(last_gate_) {};

                    std::uint32_t gates_amount() const override {
                        return keccak_padding::get_gates_amount(witness_amount, num_blocks, num_bits, last_gate);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t num_blocks,
                                                       std::size_t num_bits,
                                                       std::size_t limit_permutation_column) {
                    auto last_gate = calculate_last_gate(witness_amount, num_blocks);
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount, num_blocks, num_bits, last_gate));
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

                const std::size_t limit_permutation_column = 7;

                const std::size_t num_blocks;
                const std::size_t num_bits;
                std::size_t shift = get_shift();
                std::size_t num_padding_zeros = calculate_num_padding_zeros();

                padding_gate first_gate_15 = calculate_first_gate_15();
                std::size_t last_gate = calculate_last_gate(this->witness_amount(), num_blocks);
                std::size_t confs_per_gate = calculate_confs_per_gate(this->witness_amount());
                const std::vector<configuration> full_configuration =
                    configure_all(this->witness_amount(), num_blocks, num_bits, limit_permutation_column);
                std::vector<std::size_t> gates_rows = calculate_gates_rows(this->witness_amount());
                // const std::vector<std::size_t> lookup_gates_configuration =
                // configure_lookup_gates(this->witness_amount());

                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, num_blocks, num_bits, limit_permutation_column);
                const std::size_t gates_amount = get_gates_amount(this->witness_amount(), num_blocks, shift, last_gate);

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
                        for (std::size_t i = 0;
                             i < component.full_configuration.size() -
                                     1 * (component.witness_amount() == 15 && component.num_blocks == 1);
                             ++i) {
                            auto config = component.full_configuration[i];
                            padded_message.push_back(var(component.W(config.copy_from.column),
                                                         config.copy_from.row + config.row + start_row_index, false));
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

                std::size_t get_shift() {
                    return num_blocks * 64 - num_bits;
                }

                static padding_gate padding(std::size_t witness_amount, std::size_t row = 0) {
                    if (witness_amount == 9)
                        return padding_9(row);
                    if (witness_amount == 15)
                        return padding_15(row);
                    return padding_gate();
                }
                static padding_gate padding_9(std::size_t row = 0) {
                    padding_gate res;
                    res.relay = {-1, 0};
                    res.value = {{-1, 1}, {-1, 3}, {0, 0}, {0, 2}, {1, 0}};
                    res.sum = {{-1, 2}, {-1, 4}, {0, 1}, {0, 3}, {1, 1}};
                    res.first = {{-1, 5}, {-1, 7}, {0, 4}, {0, 6}, {1, 2}};
                    res.second = {{-1, 6}, {-1, 8}, {0, 5}, {0, 7}, {1, 3}};
                    res.range_check = {{1, 4}, {1, 5}, {1, 6}, {1, 7}, {1, 8}};
                    return res;
                }
                static padding_gate padding_15(std::size_t row = 0) {
                    padding_gate res;
                    res.relay = {-1, 11};
                    res.value = {{0, 0}, {0, 1}, {0, 2}, {1, 0}, {1, 1}, {1, 2}};
                    res.sum = {{1, 3}, {1, 4}, {1, 5}, {0, 3}, {0, 4}, {0, 5}};
                    res.first = {{0, 6}, {0, 7}, {0, 8}, {1, 6}, {1, 7}, {1, 8}};
                    res.second = {{0, 9}, {0, 10}, {0, 11}, {1, 9}, {1, 10}, {1, 11}};
                    res.range_check = {{0, 12}, {0, 13}, {0, 14}, {1, 12}, {1, 13}, {1, 14}};
                    return res;
                }

                std::size_t calculate_num_padding_zeros() {
                    if(num_blocks % 17 == 0){
                        return 0;
                    }
                    return 17 - num_blocks % 17;
                }
                padding_gate calculate_first_gate_15(std::size_t row = 0) {
                    padding_gate res;
                    res.relay = {0, 0};
                    res.value = {{0, 1}, {0, 2}};
                    res.sum = {{0, 3}, {0, 4}};
                    res.first = {{0, 5}, {0, 6}};
                    res.second = {{0, 7}, {0, 11}};
                    res.range_check = {{0, 8}, {0, 9}};
                    return res;
                }
                static std::size_t calculate_last_gate(std::size_t witness_amount, std::size_t num_blocks) {
                    if (witness_amount == 9) {
                        return num_blocks % 5;
                    } else if (witness_amount == 15) {
                        if (num_blocks <= 2) {
                            return 7;
                        }
                        return (num_blocks - 2) % 6;
                    }
                    return 0;
                }
                static std::size_t calculate_confs_per_gate(std::size_t witness_amount) {
                    if (witness_amount == 9) {
                        return 5;
                    } else if (witness_amount == 15) {
                        return 6;
                    }
                    return 0;
                }

                static std::vector<configuration> configure_batching(std::size_t witness_amount,
                                                                     std::size_t num_blocks) {
                    std::vector<configuration> result;
                    std::size_t conf_ind = 0;
                    std::size_t row = 1;
                    std::size_t confs_per_gate = calculate_confs_per_gate(witness_amount);
                    std::size_t loop_end = num_blocks;
                    if (witness_amount == 15) {
                        if (num_blocks <= 2) {
                            loop_end = 0;
                        } else {
                            loop_end -= 2;
                        }
                    }

                    while (conf_ind < loop_end) {
                        auto pg = padding(witness_amount, row);
                        std::size_t j = 0;
                        {
                            configuration conf;
                            conf.row = row;
                            conf.last_coordinate = pg.second[0];
                            conf.copy_to = {pg.value[0], pg.relay};
                            conf.constraints = {{pg.value[0], pg.first[0], pg.second[0]},
                                                {pg.sum[0], pg.relay, pg.first[0]},
                                                {pg.range_check[0], pg.relay}};
                            conf.lookups = {{{pg.range_check[0].row, pg.range_check[0].column}}};
                            conf.copy_from = pg.sum[0];
                            result.push_back(conf);
                            j++;
                            conf_ind++;
                        }
                        while ((j < confs_per_gate) && (conf_ind < loop_end)) {
                            configuration conf;
                            conf.row = row;
                            conf.last_coordinate = pg.second[j];
                            conf.copy_to = {pg.value[j]};
                            conf.constraints = {{pg.value[j], pg.first[j], pg.second[j]},
                                                {pg.sum[j], pg.second[j - 1], pg.first[j]},
                                                {pg.range_check[j], pg.second[j - 1]}};
                            conf.lookups = {{pg.range_check[j]}};
                            conf.copy_from = pg.sum[j];
                            result.push_back(conf);
                            j++;
                            conf_ind++;
                        }
                        if (witness_amount == 9)
                            row += 3;
                        if (witness_amount == 15)
                            row += 2;
                    }
                    return result;
                }

                static std::vector<configuration> configure_all(std::size_t witness_amount,
                                                                std::size_t num_blocks,
                                                                std::size_t num_bits,
                                                                std::size_t limit_permutation_column) {
                    std::size_t shift = num_blocks * 64 - num_bits;
                    std::vector<configuration> result;
                    if (shift == 0) {
                        std::int32_t row = 0;
                        std::size_t column = 0;
                        for (std::size_t i = 0; i < num_blocks; ++i) {
                            configuration conf;
                            conf.copy_from = {row, column};
                            column += 1;
                            if (column == limit_permutation_column) {
                                column = 0;
                                row += 1;
                            }
                            result.push_back(conf);
                        }
                    } else {
                        if (witness_amount % 15 == 0) {
                            configuration conf0;
                            conf0.row = 0;
                            conf0.last_coordinate = {0, 7};
                            conf0.copy_to = {{0, 1}, {0, 0}};
                            conf0.constraints = {{{0, 1}, {0, 5}, {0, 7}}, {{0, 3}, {0, 0}, {0, 5}}, {{0, 8}, {0, 0}}};
                            conf0.lookups = {{{0, 8}}};
                            conf0.copy_from = {0, 3};
                            result.push_back(conf0);
                            configuration conf1;
                            conf1.row = 0;
                            conf1.copy_to = {{0, 2}};
                            conf1.last_coordinate = {0, 11};
                            conf1.constraints = {{{0, 2}, {0, 6}, {0, 11}}, {{0, 4}, {0, 7}, {0, 6}}, {{0, 9}, {0, 7}}};
                            conf1.lookups = {{{0, 9}}};
                            conf1.copy_from = {0, 4};
                            result.push_back(conf1);
                        }

                        auto batch_configs = configure_batching(witness_amount, num_blocks);
                        result.insert(result.end(), batch_configs.begin(), batch_configs.end());
                    }

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
                                                    std::size_t last_gate) {
                    if (num_blocks * 64 - num_bits == 0) {
                        return 0;
                    }
                    if (witness_amount == 9) {
                        if (last_gate == 0 || last_gate == num_blocks) {
                            return 1 * 2;
                        }
                        return 2 * 2;
                    } else if (witness_amount == 15) {
                        if (last_gate == 7) {
                            return 1 * 2;
                        }
                        if (last_gate == 0 || last_gate == num_blocks - 2) {
                            return 2 * 2;
                        }
                        return 3 * 2;
                    }
                    return 0;
                }
                static std::size_t get_rows_amount(std::size_t witness_amount,
                                                   std::size_t lookup_column_amount,
                                                   std::size_t num_blocks,
                                                   std::size_t num_bits,
                                                   std::size_t limit_permutation_column) {
                    
                    if (witness_amount == 9) {
                        return std::ceil(num_blocks/ 5.0) * 3;
                    }
                    if (witness_amount == 15) {
                        if (num_blocks <= 2) {
                            return 1;
                        }
                        return 1 + std::ceil((num_blocks - 2) / 6.0) * 2;
                    }
                }

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_pack_table/range_check"] = 0; // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_padding(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input, std::size_t num_blocks_, std::size_t num_bits_,
                               std::size_t lpc_ = 7) :
                    component_type(witness, constant, public_input, get_manifest()),
                    num_blocks(num_blocks_), num_bits(num_bits_), limit_permutation_column(lpc_) {};

                keccak_padding(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t num_blocks_, std::size_t num_bits_, std::size_t lpc_ = 7) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    num_blocks(num_blocks_), num_bits(num_bits_), limit_permutation_column(lpc_) {};

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
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
                const std::map<std::string, std::size_t> lookup_tables_indices) {

                using component_type = padding_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using lookup_gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, lookup_constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::vector<std::size_t> selector_indexes;
                auto config = component.full_configuration;
                std::size_t config_index = 0;
                std::size_t gate_index = 0;
                std::size_t lookup_gate_index = 0;

                const std::size_t two = 2;
                if (component.shift > 0) {
                    std::vector<constraint_type> cur_constraints;
                    std::vector<lookup_constraint_type> cur_lookup_constraints;
                    if (component.witness_amount() == 15) {
                        for (std::size_t i = 0; i < std::min(two, component.num_blocks); ++i) {
                            auto cur_config = config[config_index];
                            cur_constraints.push_back(
                                var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row) -
                                var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row) *
                                    (integral_type(1) << (64 - component.shift)) -
                                var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row));
                            cur_constraints.push_back(
                                var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row) -
                                var(cur_config.constraints[1][1].column, cur_config.constraints[1][1].row) *
                                    (integral_type(1) << component.shift) -
                                var(cur_config.constraints[1][2].column, cur_config.constraints[1][2].row));
                            cur_constraints.push_back(
                                var(cur_config.constraints[2][1].column, cur_config.constraints[2][1].row) -
                                (integral_type(1) << (64 - component.shift)) + (integral_type(1) << 64) -
                                var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row));
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(cur_config.lookups[0][0].column), cur_config.lookups[0][0].row)}});
                            config_index++;
                        }
                        selector_indexes.push_back(bp.add_gate(cur_constraints));
                        gate_index++;
                        cur_constraints.clear();
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                        cur_lookup_constraints.clear();
                    }
                    std::cout << "gate_index: " << gate_index << std::endl;
                    std::cout << "component.gates_amount: " << component.gates_amount << std::endl;
                    std::cout << "component.last_gate: " << component.last_gate << std::endl;
                    if (component.gates_amount - gate_index - (bool)(component.last_gate % 7) > 0) {
                        for (int i = 0; i < component.confs_per_gate; ++i) {
                            auto cur_config = config[config_index];
                            cur_constraints.push_back(constraint_type(
                                var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row) -
                                var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row) *
                                    (integral_type(1) << (64 - component.shift)) -
                                var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row)));
                            cur_constraints.push_back(
                                var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row) -
                                var(cur_config.constraints[1][1].column, cur_config.constraints[1][1].row) *
                                    (integral_type(1) << component.shift) -
                                var(cur_config.constraints[1][2].column, cur_config.constraints[1][2].row));
                            cur_constraints.push_back(
                                var(cur_config.constraints[2][1].column, cur_config.constraints[2][1].row) -
                                (integral_type(1) << (64 - component.shift)) + (integral_type(1) << 64) -
                                var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row));
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(cur_config.lookups[0][0].column), cur_config.lookups[0][0].row)}});
                            config_index++;
                            if (config_index >= config.size()) {
                                break;
                            }
                        }
                        selector_indexes.push_back(bp.add_gate(cur_constraints));
                        gate_index++;
                        cur_constraints.clear();
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                        cur_lookup_constraints.clear();
                    }
                    if (component.last_gate % 7 && config_index < config.size()) {
                        for (int i = 0; i < component.last_gate; ++i) {
                            auto cur_config = config[config_index];
                            cur_constraints.push_back(
                                var(cur_config.constraints[0][0].column, cur_config.constraints[0][0].row) -
                                var(cur_config.constraints[0][1].column, cur_config.constraints[0][1].row) *
                                    (integral_type(1) << (64 - component.shift)) -
                                var(cur_config.constraints[0][2].column, cur_config.constraints[0][2].row));
                            cur_constraints.push_back(
                                var(cur_config.constraints[1][0].column, cur_config.constraints[1][0].row) -
                                var(cur_config.constraints[1][1].column, cur_config.constraints[1][1].row) *
                                    (integral_type(1) << component.shift) -
                                var(cur_config.constraints[1][2].column, cur_config.constraints[1][2].row));
                            cur_constraints.push_back(
                                var(cur_config.constraints[2][1].column, cur_config.constraints[2][1].row) -
                                (integral_type(1) << (64 - component.shift)) + (integral_type(1) << 64) -
                                var(cur_config.constraints[2][0].column, cur_config.constraints[2][0].row));
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(cur_config.lookups[0][0].column), cur_config.lookups[0][0].row)}});
                            config_index++;
                            if (config_index >= config.size()) {
                                break;
                            }
                        }
                        selector_indexes.push_back(bp.add_gate(cur_constraints));
                        gate_index++;
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                    }
                }
                BOOST_ASSERT(gate_index + lookup_gate_index == component.gates_amount);
                std::cout << "SELS: " << selector_indexes.size() << std::endl;
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

                if (component.shift != 0) {
                    bp.add_copy_constraint({instance_input.message[input_index++], var(component.W(0), strow, false)});
                }

                while (config_index < component.full_configuration.size() - (component.shift != 0) -
                                          (witness_amount == 15 && component.num_blocks == 1)) {
                    auto config = component.full_configuration[config_index];
                    bp.add_copy_constraint({instance_input.message[input_index++],
                                            var(component.W(config.copy_to[0].column),
                                                config.copy_to[0].row + strow + config.row, false)});
                    config_index++;
                }

                if (component.shift != 0) {
                    auto config = component.full_configuration[config_index];
                    bp.add_copy_constraint({var(component.C(0), start_row_index, false, var::column_type::constant),
                                            var(component.W(config.copy_to[0].column),
                                                config.copy_to[0].row + strow + config.row, false)});

                    if (witness_amount == 9) {
                        config_index = component.confs_per_gate;
                        while (config_index < component.full_configuration.size()) {
                            auto config1 = component.full_configuration[config_index];
                            auto config2 = component.full_configuration[config_index - 1];
                            bp.add_copy_constraint({var(component.W(config1.copy_to[1].column),
                                                        config1.copy_to[1].row + strow + config1.row, false),
                                                    var(component.W(config2.last_coordinate.column),
                                                        config2.last_coordinate.row + strow + config2.row, false)});
                            config_index += component.confs_per_gate;
                        }
                    }
                }

                // if (component.shift != 0) {
                //     std::size_t config_index = 0;
                //     std::size_t input_index = 0;
                //     auto config = component.full_configuration[config_index++];
                //     bp.add_copy_constraint({instance_input.message[input_index++],
                //                             var(component.W(config.copy_to[0].column), config.copy_to[0].row + strow,
                //                             false)});
                //     bp.add_copy_constraint({instance_input.message[input_index++],
                //                             var(component.W(config.copy_to[1].column), config.copy_to[1].row + strow,
                //                             false)});
                //     while (input_index < instance_input.message.size()) {
                //         std::cout << input_index << ' ' << config_index << ' ' << component.full_configuration.size()
                //         << std::endl; config = component.full_configuration[config_index++];
                //         bp.add_copy_constraint({instance_input.message[input_index++],
                //                                 var(component.W(config.copy_to[0].column), config.copy_to[0].row +
                //                                 strow, false)});
                //     }
                //     // config = component.full_configuration[config_index];
                //     // bp.add_copy_constraint({var(component.C(0), start_row_index, false,
                //     var::column_type::constant),
                //     //                         var(component.W(config.copy_to[0].column), config.copy_to[0].row +
                //     strow, false)});
                // } else {
                //     for (std::size_t i = 0; i < component.full_configuration.size(); ++i) {
                //         auto config = component.full_configuration[i];
                //         bp.add_copy_constraint({instance_input.message[i],
                //                                 var(component.W(config.copy_to[0].column), config.copy_to[0].row +
                //                                 strow, false)});
                //     }
                // }
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
                std::size_t ind = 0;

                std::size_t gate_row_ind = 0;
                if (component.witness_amount() == 15) {
                    assignment.enable_selector(selector_indexes[ind++],
                                               component.gates_rows[gate_row_ind] + start_row_index);
                    assignment.enable_selector(selector_indexes[ind++],
                                               component.gates_rows[gate_row_ind++] + start_row_index);
                }
                if (gate_row_ind < component.gates_rows.size() - (bool)(component.last_gate % 7)) {
                    for (std::size_t i = gate_row_ind;
                         i < component.gates_rows.size() - (bool)(component.last_gate % 7);
                         ++i) {
                        assignment.enable_selector(selector_indexes[ind],
                                                   component.gates_rows[gate_row_ind] + start_row_index);
                        assignment.enable_selector(selector_indexes[ind + 1],
                                                   component.gates_rows[gate_row_ind++] + start_row_index);
                    }
                    ind += 2;
                }
                if (component.last_gate % 7) {
                    assignment.enable_selector(selector_indexes[ind++],
                                               component.gates_rows[gate_row_ind] + start_row_index);
                    assignment.enable_selector(selector_indexes[ind],
                                               component.gates_rows[gate_row_ind] + start_row_index);
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

                // batching
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
                        integral_type first_chunk = (relay_chunk << component.shift) + chunk_parts[0];
                        integral_type relay_range_check =
                            relay_chunk - (integral_type(1) << (64 - component.shift)) + (integral_type(1) << 64);

                        auto cur_config = component.full_configuration[config_index];
                        assignment.witness(component.W(cur_config.constraints[0][0].column),
                                           cur_config.constraints[0][0].row + strow + cur_config.row) = chunk;
                        if (witness_amount == 9) {
                            if (config_index % component.confs_per_gate == 0) {
                                assignment.witness(component.W(cur_config.constraints[1][1].column),
                                                   cur_config.constraints[1][1].row + strow + cur_config.row) =
                                    value_type(relay_chunk);
                            }
                        }
                        if (witness_amount == 15) {
                            if (config_index == 0) {
                                assignment.witness(component.W(cur_config.constraints[1][1].column),
                                                   cur_config.constraints[1][1].row + strow + cur_config.row) =
                                    value_type(relay_chunk);
                            }
                        }
                        for (int j = 1; j < 3; ++j) {
                            assignment.witness(component.W(cur_config.constraints[0][j].column),
                                               cur_config.constraints[0][j].row + strow + cur_config.row) =
                                value_type(chunk_parts[j - 1]);
                        }
                        assignment.witness(component.W(cur_config.constraints[1][0].column),
                                           cur_config.constraints[1][0].row + strow + cur_config.row) =
                            value_type(first_chunk);
                        assignment.witness(component.W(cur_config.constraints[2][0].column),
                                           cur_config.constraints[2][0].row + strow + cur_config.row) =
                            value_type(relay_range_check);

                        relay_chunk = chunk_parts[1];
                        config_index++;
                    }
                } else {
                    for (std::size_t index = 0; index < component.full_configuration.size(); ++index) {
                        auto cur_config = component.full_configuration[index];
                        assignment.witness(component.W(cur_config.copy_from.column),
                                           cur_config.copy_from.row + strow + cur_config.row) =
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