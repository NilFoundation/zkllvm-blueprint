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
// @file Declaration of interfaces for non-native range check for k-chunked values.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_range_check_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_range_check_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>
#include <nil/blueprint/lookup_library.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Choice function guided by bit q (constrained)
            // operates on k-chunked x,y,z
            // Parameters: num_chunks = k
            // Input: x[0], ..., x[k-1]
            // Output: z[i] = (1-q) x[i] + q y[i], i = 0,...,k-1
            //
            template<typename ArithmetizationType, typename BlueprintFieldType,
                    std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            class range_check;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            class range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           num_chunks,
                           bit_size_chunk,
                           num_bits>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                static const std::size_t bit_size_rc = 16;
                static const std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) + (bit_size_chunk % bit_size_rc > 0);

                static std::size_t get_num_chunks() {
                    return num_chunks;
                }
                static std::size_t get_bit_size_chunk() {
                    return bit_size_chunk;
                }
                static std::size_t get_num_bits() {
                    return num_bits;
                }

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return range_check::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // ready to use any number of columns that fit 3*num_chunks+1 cells into less than 3 rows
                        std::shared_ptr<manifest_param>(new manifest_range_param(num_chunks + 1,3*num_chunks + 1,1)),
                        false // constant column not needed
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    std::size_t num_cells = num_chunks * (num_rc_chunks + 1);
                    return num_cells / witness_amount + (num_cells % witness_amount > 0);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "range check for 16bit chunks";

                struct input_type {
                    var x[num_chunks];

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    result_type(const range_check &component, std::uint32_t start_row_index) {}

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
                };

                template<typename ContainerType>
                explicit range_check(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                range_check(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                range_check(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                // using lookup_table_definition = typename
                //     nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                // std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables(){
                //     std::vector<std::shared_ptr<lookup_table_definition>> result = {};

                //     auto range_16bit_table = std::shared_ptr<lookup_table_definition>(new range_16bit_table());
                //     result.push_back(range_16bit_table);

                //     return result;
                // }

                // std::map<std::string, std::size_t> component_lookup_tables(){
                //     std::map<std::string, std::size_t> lookup_tables;
                //     lookup_tables["range_16bit/full"] = 0;

                //     return lookup_tables;
                // }
            };

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            using plonk_range_check =
                range_check<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    num_chunks, bit_size_chunk, num_bits>;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            typename plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits>::result_type generate_assignments(
                const plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {
                    std::cout << "Generating assignments" << std::endl;

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename value_type::integral_type;
                using component_type = plonk_range_check<BlueprintFieldType, num_chunks, bit_size_chunk, num_bits>;

                const std::size_t WA = component.witness_amount();

                value_type x[num_chunks];

                value_type y[component.num_rc_chunks];
                integral_type mask = (1 << component.bit_size_rc) - 1;
                typename component_type::coordinates coords(start_row_index, 0, WA);
                std::cout << "Start coords: " << coords.row << " " << coords.column << std::endl;

                for (std::size_t i = 0; i < num_chunks; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                    integral_type x_integral = integral_type(x[i].data);
                    std::cout << "x[" << i << "] = " << x_integral << std::endl;
                    integral_type y_integral;
                    for (std::size_t j = 0; j < component.num_rc_chunks; ++j) {
                        y_integral = x_integral & mask;
                        y[j] = value_type(y_integral);
                        std::cout << y_integral << std::endl;
                        x_integral >>= component.bit_size_rc;
                    }
                    assignment.witness(component.W(coords.column), coords.row) = x[i];
                    ++coords;
                    for (std::size_t j = 0; j < component.num_rc_chunks; ++j) {
                        assignment.witness(component.W(coords.column), coords.row) = y[j];
                        ++coords;
                    }
                }
                std::cout << "Finish coords: " << coords.row << " " << coords.column << std::endl;

                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            std::vector<std::size_t> generate_gates(
                const plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {
                        std::cout << "Generating gates" << std::endl;

                using component_type = plonk_range_check<BlueprintFieldType, num_chunks, bit_size_chunk, num_bits>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using lookup_gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, lookup_constraint_type>;

                std::vector<std::size_t> selector_indexes;

                const std::size_t WA = component.witness_amount();
                const std::size_t num_rows = component.get_rows_amount(WA, 0);
                const int row_shift = num_rows == 3 ? -1 : 0;
                std::size_t power = 1;

                std::vector<constraint_type> constraints;
                std::vector<lookup_constraint_type> lookup_constraints;
                typename component_type::coordinates coords(row_shift, 0, WA);
                var x;
                var y[component.num_rc_chunks];
                for(std::size_t i = 0; i < num_chunks; i++) {
                    constraint_type constr = var(component.W(coords.column), coords.row, true);
                    ++coords;
                    for (std::size_t j = 0; j < component.num_rc_chunks; ++j) {
                        auto value = var(component.W(coords.column), coords.row, true);
                        constr -= value * power;
                        // lookup_constraints.push_back({lookup_tables_indices.at("range_16bit"), {value}});
                        power <<= component.bit_size_rc;
                        ++coords;
                    }

                    constraints.push_back(constr);
                    power = 1;
                }

                selector_indexes.push_back(bp.add_gate(constraints));
                // selector_indexes.push_back(bp.add_lookup_gate(lookup_constraints));
                return selector_indexes;
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            void generate_copy_constraints(
                const plonk_range_check<BlueprintFieldType, num_chunks, bit_size_chunk, num_bits> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits>::input_type &instance_input,
                const std::size_t start_row_index) {
                    std::cout << "Generating copy constraints" << std::endl;

                const std::size_t WA = component.witness_amount();
                using component_type = plonk_range_check<BlueprintFieldType, num_chunks, bit_size_chunk, num_bits>;
                using var = typename component_type::var;

                typename component_type::coordinates coords(start_row_index, 0, WA);

                for(std::size_t i = 0; i < num_chunks; i++) {
                    bp.add_copy_constraint({var(component.W(coords.column), coords.row ,false), instance_input.x[i]});
                    coords += component.num_rc_chunks + 1;
                }
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            typename plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits>::result_type generate_circuit(
                const plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType,num_chunks,bit_size_chunk,num_bits>::input_type &instance_input,
                const std::size_t start_row_index) {
                    std::cout << "Generating circuit" << std::endl;

                using component_type = plonk_range_check<BlueprintFieldType, num_chunks, bit_size_chunk, num_bits>;

                const std::size_t WA = component.witness_amount();
                const std::size_t num_rows = component.get_rows_amount(WA, 0);
                const std::size_t row_shift = num_rows == 3 ? 1 : 0;

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                assignment.enable_selector(selector_index[0], start_row_index + row_shift);
                // assignment.enable_selector(selector_index[1], start_row_index + row_shift);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_range_check_HPP
