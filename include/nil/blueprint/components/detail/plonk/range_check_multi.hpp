//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
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
// @file Declaration of interfaces for k-bit range check with 16 bit lookup table.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_RANGE_CHECK_MULTI_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_RANGE_CHECK_MULTI_HPP

#include <numeric>
#include <algorithm>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Constraints value to be of a certain bit size at most
            // Parameters: bit_size_chunk
            // Input: x
            // Output: none
            //
            template<typename ArithmetizationType, typename BlueprintFieldType,
                    std::size_t num_chunks_, std::size_t bit_size_chunk_>
            class range_check_multi;

            template<typename BlueprintFieldType, std::size_t num_chunks_, std::size_t bit_size_chunk_>
            class range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           num_chunks_,
                           bit_size_chunk_>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                static const std::size_t num_chunks = num_chunks_;
                static const std::size_t bit_size_chunk = bit_size_chunk_;

                static const std::size_t bit_size_rc = 16;
                static const std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) + (bit_size_chunk % bit_size_rc > 0);
                static const std::size_t first_chunk_size = bit_size_chunk % bit_size_rc;
                const std::size_t chunks_per_gate = get_chunks_per_gate(this->witness_amount());
                const std::size_t single_gate_cells = chunks_per_gate * (num_rc_chunks + (first_chunk_size != 0) + 1);
                const std::size_t single_gate_rows = single_gate_cells / this->witness_amount() + (single_gate_cells % this->witness_amount() > 0);
                
                static std::size_t get_chunks_per_gate(std::size_t witness_amount) {
                    auto num_cells = num_rc_chunks + (first_chunk_size != 0) + 1;
                    if (num_cells > witness_amount) {
                        return 1;
                    }
                    return witness_amount / num_cells;
                }

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return range_check_multi::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // ready to use any number of columns that fit num_rc_chunks+1 cells into less than 3 rows
                        std::shared_ptr<manifest_param>(new manifest_range_param(num_rc_chunks / 3 + 1,3*num_rc_chunks + 1,1)),
                        false // constant column not needed
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                    std::size_t lookup_column_amount) {
                    std::size_t ch_per_gate = get_chunks_per_gate(witness_amount);
                    if (ch_per_gate > 1) {
                        return num_chunks / ch_per_gate + (num_chunks % ch_per_gate > 0);
                    }
                    bool is_first_chunk = (first_chunk_size != 0);
                    std::size_t single_num_cells = num_rc_chunks + is_first_chunk + 1;
                    return num_chunks * (single_num_cells / witness_amount + (single_num_cells % witness_amount > 0));
                }

                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "range check multi";

                struct input_type {
                    std::vector<var> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            res.push_back(x[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    result_type(const range_check_multi &component, std::uint32_t start_row_index) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        return res;
                    }
                };

                struct coordinates {
                    std::size_t row;
                    std::size_t column;
                    std::size_t witness_amount;

                    coordinates(std::size_t row, std::size_t column, std::size_t witness_amount) : 
                                row(row), column(column), witness_amount(witness_amount) {}
                    coordinates() : row(0), column(0), witness_amount(1) {}

                    coordinates operator++() {
                        column++;
                        if (column == witness_amount) {
                            column = 0;
                            row++;
                        }
                        return *this;
                    }
                    coordinates operator+=(std::size_t shift) {
                        column += shift;
                        row += column / witness_amount;
                        column %= witness_amount;
                        return *this;
                    }
                    coordinates operator--() {
                        if (column == 0) {
                            column = witness_amount - 1;
                            row--;
                        } else {
                            column--;
                        }
                        return *this;
                    }
                };

                template<typename ContainerType>
                explicit range_check_multi(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                range_check_multi(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                range_check_multi(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["range_16bit/full"] = 0;

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            using plonk_range_check_multi =
                range_check_multi<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    num_chunks,
                    bit_size_chunk>;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk>::result_type generate_assignments(
                const plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using component_type = plonk_range_check_multi<BlueprintFieldType, num_chunks, bit_size_chunk>;

                const std::size_t WA = component.witness_amount();
                integral_type mask = (1 << component.bit_size_rc) - 1;
                typename component_type::coordinates coords(start_row_index, 0, WA);

                for (std::size_t k = 0; k < component.num_chunks; k += component.chunks_per_gate) {
                    for (std::size_t i = 0; i < std::min(component.chunks_per_gate, component.num_chunks - k); ++i) {
                        value_type y[component.num_rc_chunks];
                        value_type x = var_value(assignment, instance_input.x[k + i]);
                        integral_type x_integral = integral_type(x.data);
                        integral_type y_integral;
                        for (std::size_t j = 0; j < component.num_rc_chunks; ++j) {
                            y_integral = x_integral & mask;
                            y[j] = value_type(y_integral);
                            x_integral >>= component.bit_size_rc;
                        }
                        assignment.witness(component.W(coords.column), coords.row) = x;
                        ++coords;
                        for (std::size_t j = 0; j < component.num_rc_chunks; ++j) {
                            assignment.witness(component.W(coords.column), coords.row) = y[j];
                            ++coords;
                        }
                        if (component.first_chunk_size != 0) {
                            integral_type y_integral = integral_type(y[component.num_rc_chunks-1].data) * (integral_type(1) << (component.bit_size_rc - component.first_chunk_size));
                            assignment.witness(component.W(coords.column), coords.row) = value_type(y_integral);
                            ++coords;
                        }
                    }
                    if (coords.column != 0) {
                        coords.row++;
                        coords.column = 0;
                    }
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {

                using component_type = plonk_range_check_multi<BlueprintFieldType, num_chunks, bit_size_chunk>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using lookup_gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, lookup_constraint_type>;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::vector<std::size_t> selector_indexes;

                const std::size_t WA = component.witness_amount();
                const int row_shift = (component.single_gate_rows == 3) ? -1 : 0;

                std::vector<constraint_type> constraints;
                std::vector<lookup_constraint_type> lookup_constraints;
                typename component_type::coordinates coords(row_shift, 0, WA);

                for (std::size_t j = 0; j < component.chunks_per_gate; ++j) {
                    integral_type power = 1;
                    constraint_type constr = var(component.W(coords.column), coords.row, true);
                    ++coords;
                    for (std::size_t j = 0; j < component.num_rc_chunks; ++j) {
                        auto var_value = var(component.W(coords.column), coords.row, true);
                        constr -= var_value * power;
                        lookup_constraints.push_back({lookup_tables_indices.at("range_16bit/full"), {var_value}});
                        power <<= component.bit_size_rc;
                        ++coords;
                    }
                    constraints.push_back(constr);

                    if (component.first_chunk_size != 0) {
                        lookup_constraints.push_back({lookup_tables_indices.at("range_16bit/full"), {var(component.W(coords.column), coords.row, true)}});
                        constraint_type constr1 = var(component.W(coords.column), coords.row, true);
                        --coords;
                        constr1 -= var(component.W(coords.column), coords.row, true) * (1 << (component.bit_size_rc - component.first_chunk_size));
                        coords += 2;
                        constraints.push_back(constr1);
                    }
                }

                selector_indexes.push_back(bp.add_gate(constraints));
                selector_indexes.push_back(bp.add_lookup_gate(lookup_constraints));
                return selector_indexes;
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();
                using component_type = plonk_range_check_multi<BlueprintFieldType, num_chunks, bit_size_chunk>;
                using var = typename component_type::var;

                typename component_type::coordinates coords(start_row_index, 0, WA);
                std::size_t idx = 0;

                for (std::size_t k = 0; k < component.num_chunks; k += component.chunks_per_gate) {
                    for (std::size_t i = 0; i < std::min(component.chunks_per_gate, component.num_chunks - k); ++i) {
                        bp.add_copy_constraint({var(component.W(coords.column), coords.row, false), instance_input.x[idx++]});
                        coords += 1 + component.num_rc_chunks + (component.first_chunk_size != 0);
                    }
                    if (coords.column != 0) {
                        coords.row++;
                        coords.column = 0;
                    }
                }
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk>::result_type generate_circuit(
                const plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check_multi<BlueprintFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_range_check_multi<BlueprintFieldType, num_chunks, bit_size_chunk>;

                const std::size_t WA = component.witness_amount();
                std::size_t row = ((component.single_gate_rows == 3) ? 1 : 0) + start_row_index;

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                for (std::size_t i = 0; i < selector_index.size(); i += 2) {
                    assignment.enable_selector(selector_index[i], row);
                    assignment.enable_selector(selector_index[i + 1], row);
                    row += component.single_gate_rows;
                }
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_RANGE_CHECK_MULTI_HPP
