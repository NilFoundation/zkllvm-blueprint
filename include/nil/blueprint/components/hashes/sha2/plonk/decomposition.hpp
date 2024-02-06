//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the DECOMPOSITION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DECOMPOSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DECOMPOSITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input:
            // Output:
            template<typename ArithmetizationType, typename FieldType>
            class decomposition;

            template<typename BlueprintFieldType>
            class decomposition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return decomposition::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<nil::blueprint::manifest_param>(
                            new nil::blueprint::manifest_single_value_param(9)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 4;
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 1;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                constexpr static const std::size_t gates_amount = 2;

                struct input_type {
                    std::array<var, 2> data;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {data[0], data[1]};
                    }
                };

                struct result_type {
                    std::array<var, 8> output;

                    result_type(const decomposition &component, std::uint32_t start_row_index) {
                        output = {var(component.W(6), start_row_index + 1, false),
                                  var(component.W(5), start_row_index + 1, false),
                                  var(component.W(4), start_row_index + 1, false),
                                  var(component.W(3), start_row_index + 1, false),
                                  var(component.W(6), start_row_index + 3, false),
                                  var(component.W(5), start_row_index + 3, false),
                                  var(component.W(4), start_row_index + 3, false),
                                  var(component.W(3), start_row_index + 3, false)};
                    }

                    result_type(const decomposition &component, std::uint32_t start_row_index, bool skip) {
                        output = {var(component.W(0), start_row_index, false),
                                  var(component.W(1), start_row_index, false),
                                  var(component.W(2), start_row_index, false),
                                  var(component.W(3), start_row_index, false),
                                  var(component.W(4), start_row_index, false),
                                  var(component.W(5), start_row_index, false),
                                  var(component.W(6), start_row_index, false),
                                  var(component.W(7), start_row_index, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output[0], output[1], output[2], output[3],
                                output[4], output[5], output[6], output[7]};
                    }
                };

                template<typename ContainerType>
                explicit decomposition(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                decomposition(WitnessContainerType witness, ConstantContainerType constant,
                              PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                decomposition(std::initializer_list<typename component_type::witness_container_type::value_type>
                                  witnesses,
                              std::initializer_list<typename component_type::constant_container_type::value_type>
                                  constants,
                              std::initializer_list<typename component_type::public_input_container_type::value_type>
                                  public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                static std::array<typename BlueprintFieldType::value_type, 8>
                        calculate(std::array<typename BlueprintFieldType::value_type, 2> data) {
                    std::array<typename BlueprintFieldType::integral_type, 16> range_chunks;
                    std::size_t shift = 0;

                    for (std::size_t i = 0; i < 8; i++) {
                        range_chunks[i] = (typename BlueprintFieldType::integral_type(data[0].data) >> shift) & ((65536) - 1);
                        range_chunks[i + 8] = (typename BlueprintFieldType::integral_type(data[1].data) >> shift) & ((65536) - 1);
                        shift += 16;
                    }

                    std::array<typename BlueprintFieldType::integral_type, 8> integral_output =
                                                {range_chunks[7] * (65536) + range_chunks[6],
                                                range_chunks[5] * (65536) + range_chunks[4],
                                                range_chunks[3] * (65536) + range_chunks[2],
                                                range_chunks[1] * (65536) + range_chunks[0],
                                                range_chunks[15] * (65536) + range_chunks[14],
                                                range_chunks[13] * (65536) + range_chunks[12],
                                                range_chunks[11] * (65536) + range_chunks[10],
                                                range_chunks[9] * (65536) + range_chunks[8]};
                    std::array<typename BlueprintFieldType::value_type, 8> output;
                    for (std::size_t i = 0; i < output.size(); i++){
                        output[i] = typename BlueprintFieldType::value_type(integral_output[i]);
                    }
                    return output;
                }

                std::map<std::string, std::size_t> component_lookup_tables() const {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["sha256_sparse_base4/first_column"] = 0; // REQUIRED_TABLE

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_native_decomposition =
                decomposition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                              BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_native_decomposition<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_native_decomposition<BlueprintFieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_native_decomposition<BlueprintFieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {
                using integral_type = typename BlueprintFieldType::integral_type;

                std::array<integral_type, 2> data = {
                    integral_type(var_value(assignment, instance_input.data[0]).data),
                    integral_type(var_value(assignment, instance_input.data[1]).data)};
                std::array<std::array<std::array<integral_type, 3>, 4>, 2> range_chunks;
                std::array<std::array<integral_type, 4>, 2> output_chunks;

                for (std::size_t data_idx = 0; data_idx < 2; data_idx++) {
                    for (std::size_t chunk_idx = 0; chunk_idx < 4; chunk_idx++) {
                        output_chunks[data_idx][chunk_idx] = (data[data_idx] >> (chunk_idx * 32)) & 0xFFFFFFFF;
                        // subchunks are 14, 14, and 4 bits long respectively
                        range_chunks[data_idx][chunk_idx][0] =
                            (output_chunks[data_idx][chunk_idx] & 0b11111111111111000000000000000000) >> 18;
                        range_chunks[data_idx][chunk_idx][1] =
                            (output_chunks[data_idx][chunk_idx] & 0b00000000000000111111111111110000) >> 4;
                        range_chunks[data_idx][chunk_idx][2] =
                            (output_chunks[data_idx][chunk_idx] & 0b00000000000000000000000000001111);
                        BOOST_ASSERT(
                            output_chunks[data_idx][chunk_idx] ==
                            range_chunks[data_idx][chunk_idx][0] * (1 << 18) +
                            range_chunks[data_idx][chunk_idx][1] * (1 << 4) +
                            range_chunks[data_idx][chunk_idx][2]);
                    }
                }
                for (std::size_t data_idx = 0; data_idx < 2; data_idx++) {
                    const std::size_t first_row = start_row_index + 2 * data_idx,
                                      second_row = start_row_index + 2 * data_idx + 1;
                    // placing subchunks for first three chunks
                    for (std::size_t chunk_idx = 0; chunk_idx < 3; chunk_idx++) {
                        for (std::size_t subchunk_idx = 0; subchunk_idx < 3; subchunk_idx++) {
                            assignment.witness(component.W(3 * chunk_idx + subchunk_idx), first_row) =
                                range_chunks[data_idx][chunk_idx][subchunk_idx];
                        }
                    }
                    // placing subchunk for the last chunk
                    for (std::size_t subchunk_idx = 0; subchunk_idx < 3; subchunk_idx++) {
                        assignment.witness(component.W(subchunk_idx), second_row) =
                            range_chunks[data_idx][3][subchunk_idx];
                    }
                    // placing chunks
                    for (std::size_t chunk_idx = 0; chunk_idx < 4; chunk_idx++) {
                        assignment.witness(component.W(3 + chunk_idx), second_row) =
                            output_chunks[data_idx][chunk_idx];
                    }
                    // placing the original data
                    assignment.witness(component.W(7), second_row) = data[data_idx];
                }

                return typename plonk_native_decomposition<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
            template<typename BlueprintFieldType>
            typename plonk_native_decomposition<BlueprintFieldType>::result_type
                generate_empty_assignments(
                    const plonk_native_decomposition<BlueprintFieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_native_decomposition<BlueprintFieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_native_decomposition<BlueprintFieldType>;

                std::size_t row = start_row_index;
                std::array<typename BlueprintFieldType::value_type, 2> data = {var_value(assignment, instance_input.data[0]).data,
                                                                                var_value(assignment, instance_input.data[1]).data};

                std::array<typename BlueprintFieldType::value_type, 8> output = component_type::calculate(data);
                for (std::size_t i = 0; i < 8; i++) {
                    assignment.witness(component.W(i), row) = output[i];
                }

                return typename plonk_native_decomposition<BlueprintFieldType>::result_type(
                    component, start_row_index, true);
            }

            template<typename BlueprintFieldType>
            std::array<std::size_t, 2> generate_gates(
                const plonk_native_decomposition<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_native_decomposition<BlueprintFieldType>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices) {

                using var = typename plonk_native_decomposition<BlueprintFieldType>::var;
                using constraint = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                const typename BlueprintFieldType::integral_type one = 1;
                std::array<std::size_t, 2> selectors;

                std::vector<lookup_constraint> subchunk_lookup_constraints(12);
                // lookup constraints for the first three chunks
                for (std::size_t chunk_idx = 0; chunk_idx < 3; chunk_idx++) {
                    subchunk_lookup_constraints[3 * chunk_idx] =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(3 * chunk_idx), -1)}};
                    subchunk_lookup_constraints[3 * chunk_idx + 1] =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(3 * chunk_idx + 1), -1)}};
                    subchunk_lookup_constraints[3 * chunk_idx + 2] =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {1024 * var(component.W(3 * chunk_idx + 2), -1)}};
                }
                // lookup constraints for the last chunk
                subchunk_lookup_constraints[9] =
                    {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                     {var(component.W(0), 0)}};
                subchunk_lookup_constraints[10] =
                    {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                     {var(component.W(1), 0)}};
                subchunk_lookup_constraints[11] =
                    {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                     {1024 * var(component.W(2), 0)}};

                selectors[0] = bp.add_lookup_gate(subchunk_lookup_constraints);

                std::vector<constraint> chunk_constraints(5);
                // chunk sum constraints for the first three chunks
                for (std::size_t chunk_idx = 0; chunk_idx < 3; chunk_idx++) {
                    chunk_constraints[chunk_idx] =
                        var(component.W(3 * chunk_idx), -1) * (1 << 18) +
                        var(component.W(3 * chunk_idx + 1), -1) * (1 << 4) +
                        var(component.W(3 * chunk_idx + 2), -1) -
                        var(component.W(3 + chunk_idx), 0);
                }
                // chunk sum constraints for the last chunk
                chunk_constraints[3] =
                    var(component.W(0), 0) * (1 << 18) +
                    var(component.W(1), 0) * (1 << 4) +
                    var(component.W(2), 0) -
                    var(component.W(6), 0);
                // chunk sum constraint for input
                chunk_constraints[4] =
                    var(component.W(3), 0) + var(component.W(4), 0) * (one << 32) +
                    var(component.W(5), 0) * (one << 64) + var(component.W(6), 0) * (one << 96) -
                    var(component.W(7), 0);
                selectors[1] = bp.add_gate(chunk_constraints);

                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_native_decomposition<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_native_decomposition<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_native_decomposition<BlueprintFieldType>::var;

                bp.add_copy_constraint({instance_input.data[0], var(component.W(7), start_row_index + 1, false)});
                bp.add_copy_constraint({instance_input.data[1], var(component.W(7), start_row_index + 3, false)});
            }

            template<typename BlueprintFieldType>
            typename plonk_native_decomposition<BlueprintFieldType>::result_type
                generate_circuit(
                    const plonk_native_decomposition<BlueprintFieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_native_decomposition<BlueprintFieldType>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::array<std::size_t, 2>  selector_indices =
                    generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());

                assignment.enable_selector(selector_indices[0], start_row_index + 1);
                assignment.enable_selector(selector_indices[0], start_row_index + 3);
                assignment.enable_selector(selector_indices[1], start_row_index + 1);
                assignment.enable_selector(selector_indices[1], start_row_index + 3);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_native_decomposition<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DECOMPOSITION_HPP
