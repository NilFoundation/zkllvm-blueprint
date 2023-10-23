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

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
// #include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>
#include <nil/blueprint/components/hashes/keccak/keccak_padding.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class keccak;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class keccak<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                static std::size_t calculate_num_round_calls(std::size_t num_blocks) {
                    return (num_blocks + (17 - num_blocks % 17)) / 17;
                }

            public:
                using var = typename component_type::var;

                // using round_component_type = keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                //                                                             ArithmetizationParams>>;
                // round_component_type round_true_true;
                // std::vector<round_component_type> rounds_true_false;
                // std::vector<round_component_type> rounds_false_false;
                // std::vector<round_component_type> rounds;

                using padding_component_type = keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>>;
                padding_component_type padding;

                using manifest_type = nil::blueprint::plonk_component_manifest;
                class gate_manifest_type : public component_gate_manifest {
                public:
                    static const constexpr std::size_t clamp = 15;
                    std::size_t witness_amount;
                    std::size_t num_blocks;
                    std::size_t num_bits;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t num_blocks_, std::size_t num_bits_)
                        : witness_amount(std::min(witness_amount_, clamp)), num_blocks(num_blocks_), num_bits(num_bits_) {}

                    std::uint32_t gates_amount() const override {
                        return get_gates_amount(witness_amount);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t num_blocks,
                                                       std::size_t num_bits) {
                    std::size_t num_round_calls = calculate_num_round_calls(num_blocks);
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount, num_blocks, num_bits))
                        .merge_with(
                            padding_component_type::get_gate_manifest(witness_amount, lookup_column_amount,
                                                                          num_blocks, num_bits));
                    // manifest.merge_with(round_component_type::get_gate_manifest(witness_amount, lookup_column_amount,
                    //                                                       true, true));
                    // for (std::size_t i = 1; i < num_round_calls; ++i) {
                    //     manifest.merge_with(round_component_type::get_gate_manifest(witness_amount, lookup_column_amount,
                    //                                                           true, false));
                    // }
                    // for (std::size_t i = 0; i < num_round_calls; ++i) {
                    //     for (std::size_t j = 0; j < 23; ++j) {
                    //         manifest.merge_with(round_component_type::get_gate_manifest(witness_amount, lookup_column_amount,
                    //                                                               false, false));
                    //     }
                    // }
                    
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(9, 15)),
                        false
                    ).merge_with(padding_component_type::get_manifest());
                    return manifest;
                }

                using configuration = typename padding_component_type::configuration;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;
                
                const std::size_t num_blocks;
                const std::size_t num_bits;
                const std::size_t limit_permutation_column = 7;

                const std::size_t round_tt_rows = 0;
                const std::size_t round_tf_rows = 0;
                const std::size_t round_ff_rows = 0;
                const std::size_t round_tt_gates = 0;
                const std::size_t round_tf_gates = 0;
                const std::size_t round_ff_gates = 0;

                const std::size_t num_round_calls = calculate_num_round_calls(num_blocks);
                const std::size_t num_configs = 5 + num_blocks + (17 - num_blocks % 17);

                const std::size_t pack_chunk_size = 8;
                const std::size_t pack_num_chunks = 8;
                const std::size_t pack_cells = 2 * (pack_num_chunks + 1);
                const std::size_t pack_buff = (this->witness_amount() == 15) * 2;
                
                std::vector<configuration> full_configuration = configure_all(this->witness_amount(), num_configs, num_round_calls);

                const std::size_t rows_amount = get_rows_amount(num_round_calls);
                const std::size_t gates_amount = get_gates_amount(this->witness_amount());

                const std::size_t round_constant[24] = {1, 0x8082, 0x800000000000808a, 0x8000000080008000,
                                                        0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
                                                        0x8a, 0x88, 0x80008009, 0x8000000a,
                                                        0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                                                        0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a,
                                                        0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008};

                struct input_type {
                    std::vector<var> message;

                    std::vector<var> all_vars() const {
                        return message;
                    }
                };

                struct result_type {
                    std::array<var, 5> final_inner_state;

                    result_type(const keccak &component, std::size_t start_row_index) {
                        for (std::size_t i = 0; i < 5; ++i) {
                            final_inner_state[i] = var(component.W(component.full_configuration[component.num_configs - 5 + i].copy_from.column),
                                                        start_row_index + component.full_configuration[component.num_configs - 5 + i].copy_from.row, false);
                        }
                    }
                    std::vector<var> all_vars() const {
                        return {final_inner_state[0], final_inner_state[1], final_inner_state[2], final_inner_state[3], final_inner_state[4]};
                    }
                };

                // std::vector<round_component_type> create_rounds() {
                //     std::vector<round_component_type> rounds;
                //     rounds.push_back(round_true_true);
                //     rounds.insert(rounds.end(), rounds_false_false.begin(), rounds_false_false.begin() + 23);
                //     for (std::size_t i = 1; i < num_round_calls; ++i) {
                //         rounds.push_back(rounds_true_false[i - 1]);
                //         rounds.insert(rounds.end(), rounds_false_false.begin() + i * 23, rounds_false_false.begin() + (i + 1) * 23);
                //     }
                //     return rounds;
                // }

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

                configuration configure_pack_unpack(std::size_t witness_amount, std::size_t row, std::size_t column) {
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
                        copy_from.push_back({last_row + (last_column / witness_amount),
                                                        (last_column++) % witness_amount});
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
                        std::size_t cur_row = row + 1,
                                    cur_column = 1;
                        while (cur_column < cells_left) {
                            if (cur_column % witness_amount == cell_copy_to.second && (cur_row + (cur_column / witness_amount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + 1;
                        while (cur_column - column < pack_cells) {
                            if (cur_column % witness_amount == cell_copy_to.second && (cur_row + (cur_column / witness_amount) == cell_copy_to.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
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
                    last_row = cells.back().first + (last_column / witness_amount);
                    last_column %= witness_amount;
                    
                    return configuration(first_coordinate, {last_row, last_column}, copy_from, constraints, lookups, cell_copy_to);
                }

                std::vector<configuration> configure_all(std::size_t witness_amount, const std::size_t num_configs,
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
                            result.push_back(configure_pack_unpack(witness_amount, row, column));
                            row = result[i].last_coordinate.row;
                            column = result[i].last_coordinate.column;
                        }
                        // round
                        if (column > 0) {
                            column = 0;
                            row++;
                        }
                        // for (std::size_t i = 0; i < 24; ++i) {
                        //     row += rounds[index * 24 + i].rows_amount;
                        // }
                    }

                    // from sparse representation
                    for (std::size_t i = 0; i < 5; ++i) {
                        result.push_back(configure_pack_unpack(witness_amount, row, column));
                        row = result[i].last_coordinate.row;
                        column = result[i].last_coordinate.column;
                    }

                    return result;
                }

                std::size_t get_rows_amount(std::size_t num_round_calls) {
                    std::size_t res = padding_component_type::get_rows_amount()
                                    + round_tt_rows
                                    + round_tf_rows * (num_round_calls - 1)
                                    + round_ff_rows * num_round_calls * 23;
                    res += full_configuration.back().last_coordinate.row;
                    return res;
                }
                static std::size_t get_gates_amount(std::size_t witness_amount) {
                    std::size_t res = 0;
                    if (witness_amount == 9) res = 1;
                    if (witness_amount == 15) res = 3;
                    res += padding_component_type::gates_amount;
                    return res;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t lookup_rows_,
                                   std::size_t lookup_columns_,
                                   std::size_t num_blocks_,
                                   std::size_t num_bits_,
                                   std::size_t lpc_ = 7) :
                    component_type(witness, constant, public_input, get_manifest()),
                    lookup_rows(lookup_rows_),
                    lookup_columns(lookup_columns_),
                    num_blocks(num_blocks_),
                    num_bits(num_bits_),
                    limit_permutation_column(lpc_),
                    padding(witness, constant, public_input, lookup_rows_, lookup_columns_, num_blocks_, num_bits_, lpc_),
                    num_round_calls(calculate_num_round_calls(num_blocks_)) {};
                    // {
                    //     round_true_true = round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, true, true, lpc_),
                    //     for (std::size_t i = 1; i < num_round_calls; ++i) {
                    //         rounds_true_false.push_back(round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, true, false, lpc_));
                    //     }
                    //     for (std::size_t i = 0; i < num_round_calls; ++i) {
                    //         for (std::size_t j = 0; j < 23; ++j) {
                    //             rounds_false_false.push_back(round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, false, false, lpc_));
                    //         }
                    //     }
                    //     round_tt_rows = round_true_true.rows_amount;
                    //     round_tf_rows = rounds_true_false[0].rows_amount;
                    //     round_ff_rows = rounds_false_false[0].rows_amount;
                    //     round_tt_gates = round_true_true.gates_amount;
                    //     round_tf_gates = rounds_true_false[0].gates_amount;
                    //     round_ff_gates = rounds_false_false[0].gates_amount;
                    // };

                keccak(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs,
                        std::size_t lookup_rows_, std::size_t lookup_columns_, std::size_t num_blocks_, std::size_t num_bits_, std::size_t lpc_ = 7) :
                        component_type(witnesses, constants, public_inputs),
                        lookup_rows(lookup_rows_),
                        lookup_columns(lookup_columns_),
                        num_blocks(num_blocks_),
                        num_bits(num_bits_),
                        limit_permutation_column(lpc_),
                        padding(witnesses, constants, public_inputs, lookup_rows_, lookup_columns_, num_blocks_, num_bits_, lpc_),
                        num_round_calls(calculate_num_round_calls(num_blocks_)) {};
                    // round_true_true(witness, constant, public_input, lookup_rows_, lookup_columns_, true, true, lpc_),
                    // {
                    //     for (std::size_t i = 1; i < num_round_calls; ++i) {
                    //         rounds_true_false.push_back(round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, true, false, lpc_));
                    //     }
                    //     for (std::size_t i = 0; i < num_round_calls; ++i) {
                    //         for (std::size_t j = 0; j < 23; ++j) {
                    //             rounds_false_false.push_back(round_component_type(witness, constant, public_input, lookup_rows_, lookup_columns_, false, false, lpc_));
                    //         }
                    //     }
                    // };


                using lookup_table_definition = typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                
                class sparse_values_base8_table: public lookup_table_definition{
                public:
                    sparse_values_base8_table(): lookup_table_definition("keccak_sparse_base8"){
                        this->subtables["full"] = {{0,1}, 0, 255};
                        this->subtables["first_column"] = {{0}, 0, 255};
                        this->subtables["second_column"] = {{1}, 0, 255};
                    };
                    virtual void generate(){
                        this->_table.resize(2);
                        std::vector<std::size_t> value_sizes = {8};

                        // lookup table for sparse values with base = 8
                        std::cout << "keccak_sparse_base8" << std::endl;
                        for (typename BlueprintFieldType::integral_type i = 0;
                            i < typename BlueprintFieldType::integral_type(256);
                            i++
                        ) { 
                            std::vector<bool> value(8);
                            for (std::size_t j = 0; j < 8; j++) {
                                value[8 - j - 1] = crypto3::multiprecision::bit_test(i, j);
                            }
                            std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> value_chunks =
                                detail::split_and_sparse<BlueprintFieldType>(value, value_sizes, 8);
                            std::cout << value_chunks[0][0] << " " << value_chunks[1][0] << std::endl;
                            this->_table[0].push_back(value_chunks[0][0]);
                            this->_table[1].push_back(value_chunks[1][0]);
                        }                
                        std::cout << "=============================" << std::endl;
                    }
                    
                    virtual std::size_t get_columns_number(){return 2;}
                    virtual std::size_t get_rows_number(){return 256;}
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using keccak_component =
                keccak<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const keccak_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                    
                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;


            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const keccak_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                std::uint32_t row = start_row_index;


            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename keccak_component<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_circuit(
                const keccak_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                auto selector_index = generate_gates(component, bp, assignment, instance_input);
                std::size_t first_selector_index;
                std::size_t row = start_row_index;

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename keccak_component<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_assignments(
                const keccak_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                std::vector<var> padded_message = generate_assignments(component.padding, assignment,
                                                                                    {instance_input.message}, row).padded_message;
                row += component.padding.rows_amount;

                // to sparse
                std::size_t config_index = 0;
                std::vector<value_type> sparse_padded_message;
                for (std::size_t index = 0; index < padded_message.size(); ++index) {
                    value_type regular_value = var_value(assignment, padded_message[index]);
                    integral_type regular = integral_type(regular_value.data);
                    integral_type sparse = component.pack(regular);
                    auto chunk_size = component.pack_chunk_size;
                    auto num_chunks = component.pack_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_sparse_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(regular & mask);
                        regular >>= chunk_size;
                        integral_sparse_chunks.push_back(component.pack(integral_chunks.back()));
                    }
                    sparse_padded_message[index] = value_type(sparse);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.constraints[0][0].column), cur_config.constraints[0][0].row + row) = regular_value;
                    assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + row) = value_type(sparse);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[0][j].column), cur_config.constraints[0][j].row + row) = value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + row) = value_type(integral_sparse_chunks[j - 1]);
                    }
                }
                config_index += padded_message.size();
                row += component.full_configuration[config_index - 1].last_coordinate.row;

                std::array<var, 25> inner_state;
                // for (std::size_t i = 0; i < component.num_round_calls; ++i) {
                //     for (std::size_t j = 0; j < 24; ++j) {
                //         auto round_input = typename component_type::round_component_type::input_type();
                //         round_input.padded_message_chunk;// = instance_input.message;
                //         round_input.inner_state = inner_state;
                //         round_input.round_constant = var(component.C(0), row + i, false, var::column_type::constant);
                //         inner_state = generate_assignments(component.rounds[i * 24 + j], assignment, round_input, row).inner_state;
                //         row += component.rounds[i * 24 + j].rows_amount;
                //     }
                // }

                // from sparse
                std::array<value_type, 5> result_message;
                for (std::size_t index = 0; index < 5; ++index) {
                    value_type sparse_value = var_value(assignment, inner_state[index]);
                    integral_type sparse = integral_type(sparse_value.data);
                    integral_type regular = component.unpack(sparse);
                    auto chunk_size = component.pack_chunk_size;
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

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.constraints[0][0].column), cur_config.constraints[0][0].row + start_row_index) = sparse_value;
                    assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + start_row_index) = value_type(regular);
                    for (int j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[0][j].column), cur_config.constraints[0][j].row + start_row_index) = value_type(integral_sparse_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[1][j].column), cur_config.constraints[1][j].row + start_row_index) = value_type(integral_chunks[j - 1]);
                    }
                }
                row += component.full_configuration[config_index + 5].last_coordinate.row - component.full_configuration[config_index - 1].last_coordinate.row;

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const keccak_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename keccak_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_component<BlueprintFieldType, ArithmetizationParams>;
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