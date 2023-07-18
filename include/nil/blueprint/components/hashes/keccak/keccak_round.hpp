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

                std::size_t calculate_normalize_num_chunks(std::size_t num_rows, std::size_t base) {
                    std::size_t chunk_size = 0;
                    std::size_t power = base;
                    while (power < num_rows) {
                        ++chunk_size;
                        power *= base;
                    }
                    return chunk_size;
                }
                std::size_t calculate_chi_num_chunks(std::size_t num_rows) {
                    std::size_t chunk_size = 0;
                    std::size_t power = 2;
                    while (power < num_rows) {
                        ++chunk_size;
                        power *= 2;
                    }
                    return chunk_size;
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
                    std::vector<coordinates> copy_to;

                    configuration() = default;
                    configuration(std::pair<std::size_t, std::size_t> last_coordinate_,
                                  std::vector<std::pair<std::size_t, std::size_t>> copy_from_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints_,
                                  std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups_,
                                  std::vector<std::pair<std::size_t, std::size_t>> copy_to_) :
                        last_coordinate(last_coordinate_), copy_from(copy_from_),
                        constraints(constraints_), lookups(lookups_), copy_to(copy_to_) {};
                };

            public:
                using var = typename component_type::var;

                const std::size_t lookup_rows;
                const std::size_t lookup_columns;

                const std::size_t normalize3_chunk_size;
                const std::size_t normalize4_chunk_size;
                const std::size_t normalize6_chunk_size;
                const std::size_t chi_chunk_size;

                const std::size_t xor2_cells;
                const std::size_t xor3_cells;
                const std::size_t xor5_cells;
                const std::size_t rot_cells = 22;
                const std::size_t chi_cells;

                // full configuration is precalculated, then used in other functions
                std::array<configuration, 102> full_configuration;

                const std::size_t rows_amount;
                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    std::array<var, 25> inner_state;
                    std::array<var, 17> padded_message_chunk;
                    var round_constant;
                };

                struct result_type {
                    std::array<var, 25> inner_state;

                    result_type(const keccak_round &component, std::size_t start_row_index) {
                        
                    }
                };

                value_type normalize(value_type value) {
                    integral_type result = 0;
                    integral_type power = 1;
                    integral_type integral_value = integral_type(value.data);
                    for (std::size_t i = 0; i < 64; ++i) {
                        result += (integral_value & 1) * power;
                        power *= 8;
                        integral_value >>= 3;
                    }
                    return value_type(result);
                }

                configuration configure_xor(std::size_t row, std::size_t column, std::size_t num_args) {
                    std::size_t num_chunks = num_args == 2 ? normalize3_num_chunks
                                            : num args == 3 ? normalize4_num_chunks
                                            : normalize6_num_chunks;
                    std::size_t last_row = row,
                                last_column = column;
                    std::vector<std::pair<std::size_t, std::size_t>> copy_constrain_from = {{last_row, last_column++}};
                    for (int i = 0; i < num_args - 1; ++i) {
                        copy_constrain_from.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                    }

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints = 
                                {{{last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount}}};
                    for (int i = 0; i < num_args; ++i) {
                        constraints[0].push_back(copy_constrain_from[i]);
                    }
                    constraints.push_back({constraints[0][0]});
                    constraints.push_back({{last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount}});
                    std::vector<std::pair<std::size_t, std::size_t>> copy_constrain_to = {constraints[2][0]};
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(num_chunks, std::vector<std::pair<std::size_t, std::size_t>>);
                    for (std::size_t i = 1; i < 3; ++i) {
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            constraints[i].push_back({last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount});
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    BOOST_ASSERT(last_column - column == xor2_cells);
                    last_row += last_column / WitnessesAmount;
                    last_column %= WitnessesAmount;
                    return configuration({last_row, last_column}, copy_constrain_from, constraints, lookups, copy_constrain_to);
                }

                configuration configure_chi(std::size_t row, std::size_t column) {
                    std::size_t last_row = row,
                                last_column = column;
                    std::vector<std::pair<std::size_t, std::size_t>> copy_constrain_from;
                    for (int i = 0; i < 3; ++i) {
                        copy_constrain_from.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                    }

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints = 
                                {{{last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount}}};
                    for (int i = 0; i < 3; ++i) {
                        constraints[0].push_back(copy_constrain_from[i]);
                    }
                    constraints.push_back({constraints[0][0]});
                    constraints.push_back({{last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount}});
                    std::vector<std::pair<std::size_t, std::size_t>> copy_constrain_to = {constraints[2][0]};
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(chi_num_chunks, std::vector<std::pair<std::size_t, std::size_t>>);
                    for (std::size_t i = 1; i < 3; ++i) {
                        for (std::size_t j = 0; j < chi_num_chunks; ++j) {
                            constraints[i].push_back({last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount});
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    BOOST_ASSERT(last_column - column == xor2_cells);
                    last_row += last_column / WitnessesAmount;
                    last_column %= WitnessesAmount;
                    return configuration({last_row, last_column}, copy_constrain_from, constraints, lookups, copy_constrain_to);
                }

                configuration configure_rot(std::size_t row, std::size_t column) {
                    std::size_t last_row = row,
                                last_column = column;
                    std::vector<std::pair<std::size_t, std::size_t>> copy_constrain_from;
                    for (int i = 0; i < 3; ++i) {
                        copy_constrain_from.push_back({last_row + (last_column / WitnessesAmount),
                                                        (last_column++) % WitnessesAmount});
                    }

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints = 
                                {{{last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount}}};
                    for (int i = 0; i < 3; ++i) {
                        constraints[0].push_back(copy_constrain_from[i]);
                    }
                    constraints.push_back({constraints[0][0]});
                    constraints.push_back({{last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount}});
                    std::vector<std::pair<std::size_t, std::size_t>> copy_constrain_to = {constraints[2][0]};
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(chi_num_chunks, std::vector<std::pair<std::size_t, std::size_t>>);
                    for (std::size_t i = 1; i < 3; ++i) {
                        for (std::size_t j = 0; j < chi_num_chunks; ++j) {
                            constraints[i].push_back({last_row + (last_column / WitnessesAmount), (last_column++) % WitnessesAmount});
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    BOOST_ASSERT(last_column - column == xor2_cells);
                    last_row += last_column / WitnessesAmount;
                    last_column %= WitnessesAmount;
                    return configuration({last_row, last_column}, copy_constrain_from, constraints, lookups, copy_constrain_to);
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
                    normalize3_chunk_size(calculate_normalize_num_chunks(lookup_rows_, 3)), \
                    normalize4_chunk_size(calculate_normalize_num_chunks(lookup_rows_, 4)), \
                    normalize6_chunk_size(calculate_normalize_num_chunks(lookup_rows_, 6)), \
                    chi_chunk_size(calculate_chi_num_chunks(lookup_rows_)), \
                    xor2_cells((64 / normalize3_chunk_size + bool(64 % normalize3_chunk_size)) * 2 + 2 + 2), \
                    xor3_cells((64 / normalize4_chunk_size + bool(64 % normalize4_chunk_size)) * 2 + 3 + 2), \
                    xor5_cells((64 / normalize6_chunk_size + bool(64 % normalize6_chunk_size)) * 2 + 5 + 2), \
                    chi_cells((64 / chi_chunk_size + bool(64 % chi_chunk_size)) * 2 + 5), \
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
                using var_address = typename component_type::var_address;
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
                using var_address = typename component_type::var_address;
                std::uint32_t row = start_row_index;
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
                using var_address = typename component_type::var_address;
                

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

                std::size_t row = start_row_index;

                using component_type = keccak_round_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;

                int config_index = 0;

                // inner_state ^ chunk
                std::array<value_type, 25> A_1;
                for (int index = 0; index < 17; ++index) {
                    value_type state = var_value(assignment, instance_input.inner_state[index]);
                    value_type message = var_value(assignment, instance_input.padded_message_chunk[index]);
                    value_type sum = state + message;
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize3_chunk_size;
                    std::size_t num_chunks = 64 / chunk_size + bool(64 % chunk_size);
                    std::vector<value_type> chunks;
                    std::vector<value_type> normalized_chunks;
                    integral_type mask = (1 << (3 * chunk_size)) - 1;
                    value_type power = 1;
                    value_type normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        chunks.push_back(value_type(integral_sum & mask));
                        integral_sum >>= chunk_size;
                        normalized_chunks.push_back(normalize(chunks.back()));
                        normalized_sum += normalized_chunks.back() * power;
                        power *= chunk_size;
                    }
                    A_1[index] = normalized_sum;

                    auto cur_config = component.full_configuration[index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = state;
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = message;
                    assignment.witness(component.W(cur_config.constraint[1][0].row), cur_config.constraint[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraint[2][0].row), cur_config.constraint[2][0].column) = normalized_sum;
                    for (int j = 1; j < cur_config.constraint[1].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[1][j].row), cur_config.constraint[1][j].column) = chunks[j - 1];
                    }
                    for (int j = 1; j < cur_config.constraint[2].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[2][j].row), cur_config.constraint[2][j].column) = normalized_chunks[j - 1];
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
                        sum += A_1[index + 5 * j];
                    }
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize6_chunk_size;
                    std::size_t num_chunks = 64 / chunk_size + bool(64 % chunk_size);
                    std::vector<value_type> chunks;
                    std::vector<value_type> normalized_chunks;
                    integral_type mask = (1 << (3 * chunk_size)) - 1;
                    value_type power = 1;
                    value_type normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        chunks.push_back(value_type(integral_sum & mask));
                        integral_sum >>= chunk_size;
                        normalized_chunks.push_back(normalize(chunks.back()));
                        normalized_sum += normalized_chunks.back() * power;
                        power *= chunk_size;
                    }
                    C[index] = normalized_sum;

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_1[index];
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = A_1[index + 5];
                    assignment.witness(component.W(cur_config.copy_from[2].row), cur_config.copy_from[2].column) = A_1[index + 10];
                    assignment.witness(component.W(cur_config.copy_from[3].row), cur_config.copy_from[3].column) = A_1[index + 15];
                    assignment.witness(component.W(cur_config.copy_from[4].row), cur_config.copy_from[4].column) = A_1[index + 20];
                    assignment.witness(component.W(cur_config.constraint[1][0].row), cur_config.constraint[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraint[2][0].row), cur_config.constraint[2][0].column) = normalized_sum;
                    for (int j = 1; j < cur_config.constraint[1].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[1][j].row), cur_config.constraint[1][j].column) = chunks[j - 1];
                    }
                    for (int j = 1; j < cur_config.constraint[2].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[2][j].row), cur_config.constraint[2][j].column) = normalized_chunks[j - 1];
                    }
                }
                config_index += 5;

                // TODO: rot
                std::array<value_type, 5> C_rot;
                for (int index = 0; index < 5; ++index) {
                    integral_type integral_C = integral_type(C[index].data);
                    integral_type smaller_part = integral_C & ((1 << 3) - 1);
                    integral_type bigger_part = integral_C >> 3;
                    integral_type integral_C_rot = (bigger_part << 3) + smaller_part;
                    C_rot[index] = value_type(integral_C_rot);
                    integral_type bound_smaller = smaller_part - (1 << 3) + 

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = C[index];

                }
                config_index += 5;

                std::array<value_type, 25> A_2;
                for (int index = 0; index < 25; ++index) {
                    value_type sum = A_1[index] + C_rot[(index + 1) % 5] + C[(index - 1) % 5];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize4_chunk_size;
                    std::size_t num_chunks = 64 / chunk_size + bool(64 % chunk_size);
                    std::vector<value_type> chunks;
                    std::vector<value_type> normalized_chunks;
                    integral_type mask = (1 << (3 * chunk_size)) - 1;
                    value_type power = 1;
                    value_type normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        chunks.push_back(value_type(integral_sum & mask));
                        integral_sum >>= chunk_size;
                        normalized_chunks.push_back(normalize(chunks.back()));
                        normalized_sum += normalized_chunks.back() * power;
                        power *= chunk_size;
                    }
                    A_2[index] = normalized_sum;

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_1[index];
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = C_rot[(index + 1) % 5];
                    assignment.witness(component.W(cur_config.copy_from[2].row), cur_config.copy_from[2].column) = C[(index - 1) % 5];
                    assignment.witness(component.W(cur_config.constraint[1][0].row), cur_config.constraint[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraint[2][0].row), cur_config.constraint[2][0].column) = normalized_sum;
                    for (int j = 1; j < cur_config.constraint[1].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[1][j].row), cur_config.constraint[1][j].column) = chunks[j - 1];
                    }
                    for (int j = 1; j < cur_config.constraint[2].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[2][j].row), cur_config.constraint[2][j].column) = normalized_chunks[j - 1];
                    }
                }
                config_index += 25;

                // rho/phi
                std::array<std::array<value_type, 5>, 5> B;
                B[0][0] = A_2[0];
                // TODO: finish rot(r)
                for (int index = 1; index < 25; ++index) {
                    int x = index % 5;
                    int y = index / 5;
                    integral_type integral_A = integral_type(A_2[index].data);
                    integral_type smaller_part = integral_A & ((1 << 3) - 1);
                    integral_type bigger_part = integral_A >> 3;
                    integral_type integral_A_rot = (bigger_part << 3) + smaller_part;
                    B[y][2*x + 3*y] = value_type(integral_A_rot);

                }
                config_index += 24;

                // chi
                // TODO: chunk size need to be for sparse form so no times 3 anywhere
                std::array<value_type, 25> A_3;
                for (int index = 0; index < 25; ++index) {
                    int x = index % 5;
                    int y = index / 5;
                    value_type sum = component.sparse_3 - 2 * B[x][y] + B[(x+1)%5][y] - B[(x+2)%5][y];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.chi_chunk_size;
                    std::size_t num_chunks = 64 / chunk_size + bool(64 % chunk_size);
                    std::vector<value_type> chunks;
                    std::vector<value_type> chi_chunks;
                    integral_type mask = (1 << (3 * chunk_size)) - 1;
                    value_type power = 1;
                    value_type chi_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        chunks.push_back(value_type(integral_sum & mask));
                        integral_sum >>= chunk_size;
                        chi_chunks.push_back(chi(chunks.back()));
                        chi_sum += chi_chunks.back() * power;
                        power *= chunk_size;
                    }
                    A_3[index] = chi_sum;

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = B[x][y];
                    assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = B[(x+1)%5][y];
                    assignment.witness(component.W(cur_config.copy_from[2].row), cur_config.copy_from[2].column) = B[(x+2)%5][y];
                    assignment.witness(component.W(cur_config.constraint[1][0].row), cur_config.constraint[1][0].column) = sum;
                    assignment.witness(component.W(cur_config.constraint[2][0].row), cur_config.constraint[2][0].column) = chi_sum;
                    for (int j = 1; j < cur_config.constraint[1].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[1][j].row), cur_config.constraint[1][j].column) = chunks[j - 1];
                    }
                    for (int j = 1; j < cur_config.constraint[2].size(); ++j) {
                        assignment.witness(component.W(cur_config.constraint[2][j].row), cur_config.constraint[2][j].column) = chi_chunks[j - 1];
                    }
                }
                config_index += 25;

                // iota
                // TODO: power and norm_sum - maybe integral type?
                value_type round_constant = var_value(assignment, instance_input.round_constant);
                value_type sum = A_3[0] + round_constant;
                integral_type integral_sum = integral_type(sum.data);
                auto chunk_size = component.chi_chunk_size;
                std::size_t num_chunks = 64 / chunk_size + bool(64 % chunk_size);
                std::vector<value_type> chunks;
                std::vector<value_type> normalized_chunks;
                integral_type mask = (1 << (3 * chunk_size)) - 1;
                value_type power = 1;
                value_type normalized_sum = 0;
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    chunks.push_back(value_type(integral_sum & mask));
                    integral_sum >>= chunk_size;
                    normalized_chunks.push_back(chi(chunks.back()));
                    normalized_sum += normalized_chunks.back() * power;
                    power *= chunk_size;
                }
                value_type A_4 = normalized_sum;
                
                auto cur_config = component.full_configuration[config_index];
                assignment.witness(component.W(cur_config.copy_from[0].row), cur_config.copy_from[0].column) = A_3[0];
                assignment.witness(component.W(cur_config.copy_from[1].row), cur_config.copy_from[1].column) = round_constant;
                assignment.witness(component.W(cur_config.constraint[1][0].row), cur_config.constraint[1][0].column) = sum;
                assignment.witness(component.W(cur_config.constraint[2][0].row), cur_config.constraint[2][0].column) = normalized_sum;
                for (int j = 1; j < cur_config.constraint[1].size(); ++j) {
                    assignment.witness(component.W(cur_config.constraint[1][j].row), cur_config.constraint[1][j].column) = chunks[j - 1];
                }
                for (int j = 1; j < cur_config.constraint[2].size(); ++j) {
                    assignment.witness(component.W(cur_config.constraint[2][j].row), cur_config.constraint[2][j].column) = chi_chunks[j - 1];
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

        
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP