//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256_process.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/decomposition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input:
            // Output:
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class sha256;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class sha256<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 9>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 9, 1, 0> {

                constexpr static const std::uint32_t WitnessesAmount = 9;
                constexpr static const std::uint32_t ConstantsAmount = 1;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 0>;

            public:
                using var = typename component_type::var;

                std::size_t num_blocks;
                std::size_t rows_amount;

                const std::size_t gates_amount = 1;

                struct input_type {
                    std::vector<var> block_data;
                };

                struct result_type {
                    std::array<var, 2> output;

                    result_type(const sha256 &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + component.rows_amount - 1, false),
                                  var(component.W(1), start_row_index + component.rows_amount - 1, false)};
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessesAmount << "_" << num_blocks;
                    return ss.str();
                }

                template<typename ContainerType>
                sha256(ContainerType witness, std::size_t num_blocks_) :
                    component_type(witness, {}, {}), num_blocks(num_blocks_) {
                    rows_amount =
                        sha256_process<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 9,
                            1>::rows_amount *
                            (num_blocks / 4 + 1) +
                        decomposition<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, 9>::rows_amount *
                            ((num_blocks + 1) / 2) +
                        2;
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                sha256(WitnessContainerType witness, ConstantContainerType constant,
                       PublicInputContainerType public_input, std::size_t num_blocks_) :
                    component_type(witness, constant, public_input),
                    num_blocks(num_blocks_) {
                    rows_amount =
                        sha256_process<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 9,
                            1>::rows_amount *
                            (num_blocks / 4 + 1) +
                        decomposition<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, 9>::rows_amount *
                            ((num_blocks + 1) / 2) +
                        2;
                };

                sha256(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                       std::initializer_list<typename component_type::constant_container_type::value_type>
                           constants,
                       std::initializer_list<typename component_type::public_input_container_type::value_type>
                           public_inputs,
                       std::size_t num_blocks_) :
                    component_type(witnesses, constants, public_inputs),
                    num_blocks(num_blocks_) {
                    rows_amount =
                        sha256_process<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 9,
                            1>::rows_amount *
                            (num_blocks / 4 + 1) +
                        decomposition<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, 9>::rows_amount *
                            ((num_blocks + 1) / 2) +
                        2;
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            using plonk_sha256 =
                sha256<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                       WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::result_type generate_assignments(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::input_type instance_input,
                const std::uint32_t start_row_index) {

                assert(instance_input.block_data.size() == component.num_blocks);

                std::size_t row = start_row_index;

                using var = typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::var;
                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                decomposition<ArithmetizationType, BlueprintFieldType, 9> decomposition_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {}, {});

                sha256_process<ArithmetizationType, 9, 1> sha256_process_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {component.C(0)}, {});

                std::array<typename BlueprintFieldType::value_type, 8> constants = {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
                for (int i = 0; i < 8; i++) {
                    assignment.constant(component.C(0), start_row_index + i) = constants[i];
                }
                std::array<var, 8> first_block_state = {
                    var(component.C(0), start_row_index, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 2, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 3, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 4, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 5, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 6, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 7, false, var::column_type::constant)};

                std::array<var, 16> input_words_vars;

                std::size_t curr_block = 0;
                for (std::size_t i = 0; i < component.num_blocks / 4; i++) {
                    std::array<var, 2> input_1 = {instance_input.block_data[4 * i + 0],
                                                  instance_input.block_data[4 * i + 1]};
                    typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type decomposition_input =
                        {input_1};
                    typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type sha_block_part_1 =
                        generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                    row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                    std::array<var, 2> input_2 = {instance_input.block_data[4 * i + 2],
                                                  instance_input.block_data[4 * i + 3]};
                    decomposition_input = {input_2};

                    typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type sha_block_part_2 =
                        generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                    row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                    for (int i = 0; i < 8; i++) {
                        input_words_vars[i] = sha_block_part_1.output[i];
                        input_words_vars[8 + i] = sha_block_part_2.output[i];
                    }
                    typename sha256_process<ArithmetizationType, 9, 1>::input_type sha256_process_input = {
                        first_block_state, input_words_vars};

                    first_block_state =
                        generate_assignments(sha256_process_instance, assignment, sha256_process_input, row)
                            .output_state;
                    row += sha256_process<ArithmetizationType, 9, 1>::rows_amount;

                    curr_block += 4;
                }

                // process last padding bits;
                std::array<typename BlueprintFieldType::value_type, 16> constants2 = {
                    2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, component.num_blocks << 7};

                for (int i = 0; i < 16; i++) {
                    assignment.constant(component.C(0), start_row_index + 8 + i) = constants2[i];
                }
                switch (component.num_blocks % 4) {
                    case 0: {
                        input_words_vars = {
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 15, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 16, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 17, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 18, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 19, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 20, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 21, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 22, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                        break;
                    }
                    case 1: {
                        std::array<var, 2> input_1 = {
                            instance_input.block_data[curr_block],
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant)};    // 0
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type
                            decomposition_input = {input_1};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_1 =
                                generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        input_words_vars = {
                            sha_block_part_1.output[0],
                            sha_block_part_1.output[1],
                            sha_block_part_1.output[2],
                            sha_block_part_1.output[3],
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 15, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 16, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 17, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 18, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                        break;
                    }
                    case 2: {
                        std::array<var, 2> input_1 = {instance_input.block_data[curr_block],
                                                      instance_input.block_data[curr_block + 1]};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type
                            decomposition_input = {input_1};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_1 =
                                generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        input_words_vars = {
                            sha_block_part_1.output[0],
                            sha_block_part_1.output[1],
                            sha_block_part_1.output[2],
                            sha_block_part_1.output[3],
                            sha_block_part_1.output[4],
                            sha_block_part_1.output[5],
                            sha_block_part_1.output[6],
                            sha_block_part_1.output[7],
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                        break;
                    }
                    case 3: {
                        std::array<var, 2> input_1 = {instance_input.block_data[curr_block],
                                                      instance_input.block_data[curr_block + 1]};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type
                            decomposition_input = {input_1};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_1 =
                                generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        std::array<var, 2> input_2 = {
                            instance_input.block_data[curr_block + 2],
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant)};    // 0
                        decomposition_input = {input_2};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_2 =
                                generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        input_words_vars = {
                            sha_block_part_1.output[0],
                            sha_block_part_1.output[1],
                            sha_block_part_1.output[2],
                            sha_block_part_1.output[3],
                            sha_block_part_1.output[4],
                            sha_block_part_1.output[5],
                            sha_block_part_1.output[6],
                            sha_block_part_1.output[7],
                            sha_block_part_2.output[0],
                            sha_block_part_2.output[1],
                            sha_block_part_2.output[2],
                            sha_block_part_2.output[3],
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};
                    }
                }

                typename sha256_process<ArithmetizationType, 9, 1>::input_type sha256_process_input_2 = {
                    first_block_state, input_words_vars};

                std::array<var, 8> second_block_state =
                    generate_assignments(sha256_process_instance, assignment, sha256_process_input_2, row).output_state;

                row += sha256_process<ArithmetizationType, 9, 1>::rows_amount;

                typename ArithmetizationType::field_type::integral_type one = 1;
                for (std::size_t i = 0; i < 8; i++) {
                    assignment.witness(component.W(i), row) = var_value(assignment, second_block_state[i]);
                }

                row++;

                assignment.witness(component.W(1), row) = var_value(assignment, second_block_state[7]) +
                                                          var_value(assignment, second_block_state[6]) * (one << 32) +
                                                          var_value(assignment, second_block_state[5]) * (one << 64) +
                                                          var_value(assignment, second_block_state[4]) * (one << 96);
                assignment.witness(component.W(0), row) = var_value(assignment, second_block_state[3]) +
                                                          var_value(assignment, second_block_state[2]) * (one << 32) +
                                                          var_value(assignment, second_block_state[1]) * (one << 64) +
                                                          var_value(assignment, second_block_state[0]) * (one << 96);

                return typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_gates(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::input_type &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::var;

                typename BlueprintFieldType::integral_type one = 1;
                auto constraint_1 =
                    bp.add_constraint(var(component.W(1), +1) -
                                      (var(component.W(7), 0) + var(component.W(6), 0) * (one << 32) +
                                       var(component.W(5), 0) * (one << 64) + var(component.W(4), 0) * (one << 96)));
                auto constraint_2 =
                    bp.add_constraint(var(component.W(0), +1) -
                                      (var(component.W(3), 0) + var(component.W(2), 0) * (one << 32) +
                                       var(component.W(1), 0) * (one << 64) + var(component.W(0), 0) * (one << 96)));
                bp.add_gate(first_selector_index, {constraint_1, constraint_2});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::input_type &instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::result_type generate_circuit(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t row = start_row_index;
                assert(component.num_blocks == instance_input.block_data.size());

                using var = typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::var;
                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                decomposition<ArithmetizationType, BlueprintFieldType, 9> decomposition_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {}, {});

                sha256_process<ArithmetizationType, 9, 1> sha256_process_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {component.C(0)}, {});

                std::array<var, 16> input_words_vars;

                std::array<var, 8> first_block_state = {
                    var(component.C(0), start_row_index, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 2, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 3, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 4, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 5, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 6, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 7, false, var::column_type::constant)};

                std::size_t curr_block = 0;
                for (std::size_t i = 0; i < component.num_blocks / 4; i++) {
                    std::array<var, 2> input_1 = {instance_input.block_data[4 * i + 0],
                                                  instance_input.block_data[4 * i + 1]};
                    typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type decomposition_input =
                        {input_1};
                    typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type sha_block_part_1 =
                        generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                    row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                    std::array<var, 2> input_2 = {instance_input.block_data[4 * i + 2],
                                                  instance_input.block_data[4 * i + 3]};
                    decomposition_input = {input_2};

                    typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type sha_block_part_2 =
                        generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                    row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                    for (int i = 0; i < 8; i++) {
                        input_words_vars[i] = sha_block_part_1.output[i];
                        input_words_vars[8 + i] = sha_block_part_2.output[i];
                    }
                    typename sha256_process<ArithmetizationType, 9, 1>::input_type sha256_process_input = {
                        first_block_state, input_words_vars};

                    first_block_state =
                        generate_circuit(sha256_process_instance, bp, assignment, sha256_process_input, row)
                            .output_state;
                    row += sha256_process<ArithmetizationType, 9, 1>::rows_amount;

                    curr_block += 4;
                }

                switch (component.num_blocks % 4) {
                    case 0: {
                        input_words_vars = {
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 15, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 16, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 17, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 18, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 19, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 20, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 21, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 22, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                        break;
                    }
                    case 1: {
                        std::array<var, 2> input_1 = {
                            instance_input.block_data[curr_block],
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant)};    // 0
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type
                            decomposition_input = {input_1};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_1 =
                                generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        input_words_vars = {
                            sha_block_part_1.output[0],
                            sha_block_part_1.output[1],
                            sha_block_part_1.output[2],
                            sha_block_part_1.output[3],
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 15, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 16, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 17, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 18, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                        break;
                    }
                    case 2: {
                        std::array<var, 2> input_1 = {instance_input.block_data[curr_block],
                                                      instance_input.block_data[curr_block + 1]};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type
                            decomposition_input = {input_1};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_1 =
                                generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        input_words_vars = {
                            sha_block_part_1.output[0],
                            sha_block_part_1.output[1],
                            sha_block_part_1.output[2],
                            sha_block_part_1.output[3],
                            sha_block_part_1.output[4],
                            sha_block_part_1.output[5],
                            sha_block_part_1.output[6],
                            sha_block_part_1.output[7],
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                        break;
                    }
                    case 3: {
                        std::array<var, 2> input_1 = {instance_input.block_data[curr_block],
                                                      instance_input.block_data[curr_block + 1]};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::input_type
                            decomposition_input = {input_1};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_1 =
                                generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        std::array<var, 2> input_2 = {
                            instance_input.block_data[curr_block + 2],
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant)};    // 0

                        decomposition_input = {input_2};
                        typename decomposition<ArithmetizationType, BlueprintFieldType, 9>::result_type
                            sha_block_part_2 =
                                generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                        row += decomposition<ArithmetizationType, BlueprintFieldType, 9>::rows_amount;

                        input_words_vars = {
                            sha_block_part_1.output[0],
                            sha_block_part_1.output[1],
                            sha_block_part_1.output[2],
                            sha_block_part_1.output[3],
                            sha_block_part_1.output[4],
                            sha_block_part_1.output[5],
                            sha_block_part_1.output[6],
                            sha_block_part_1.output[7],
                            sha_block_part_2.output[0],
                            sha_block_part_2.output[1],
                            sha_block_part_2.output[2],
                            sha_block_part_2.output[3],
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                            var(component.C(0), start_row_index + 23, false, var::column_type::constant)};
                    }
                }

                typename sha256_process<ArithmetizationType, 9, 1>::input_type sha256_process_input_2 = {
                    first_block_state, input_words_vars};

                generate_circuit(sha256_process_instance, bp, assignment, sha256_process_input_2, row);

                row = row + sha256_process<ArithmetizationType, 9, 1>::rows_amount;
                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                assignment.enable_selector(first_selector_index, row);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_sha256<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_HPP