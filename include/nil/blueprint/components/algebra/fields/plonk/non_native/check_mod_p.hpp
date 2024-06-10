//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for checking that a value is in an interval
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CHECK_MOD_P_ECDSA_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CHECK_MOD_P_ECDSA_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/detail/plonk/carry_on_addition.hpp>
#include <nil/blueprint/components/detail/plonk/range_check_multi.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Parameters: num_chunks = k, bit_size_chunk = b
            // Checking that x is in the interval [0;p-1]
            // operates on k-chunked x and p' = 2^(kb) - p
            // Input: x[0], ..., x[k-1], pp[0], ..., pp[k-1], 0
            // (expects zero constant as input)
            // Output: none
            //
            template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output = false>
            class check_mod_p;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output>
            class check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           num_chunks,
                           bit_size_chunk,
                           expect_output>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using carry_on_addition_component = carry_on_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks, bit_size_chunk>;
                using range_check_component = range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return check_mod_p::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(carry_on_addition_component::get_gate_manifest(witness_amount))
                        .merge_with(range_check_component::get_gate_manifest(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // all requirements come from sub-components, the component itself has no personal requirements
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(expect_output)),
                        false // constant column not needed
                    ).merge_with(carry_on_addition_component::get_manifest())
                     .merge_with(range_check_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return expect_output + carry_on_addition_component::get_rows_amount(witness_amount)
                           + range_check_component::get_rows_amount(witness_amount);
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "multichunk interval checking function";

                struct input_type {
                    var x[num_chunks], pp[num_chunks], zero;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {zero};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                            res.push_back(pp[i]);
                        }
                        return res;
                    }
                };

                struct result_type_no_output {
                    result_type_no_output(const check_mod_p &component, std::uint32_t start_row_index) { }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        return res;
                    }
                };
                struct result_type_with_output {
                    var q;
                    result_type_with_output(const check_mod_p &component, std::uint32_t start_row_index) {
                       q = var(component.W(0), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {q};
                    }
                };
                using result_type = typename std::conditional<expect_output,result_type_with_output,result_type_no_output>::type;

                template<typename ContainerType>
                explicit check_mod_p(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,"double chunk should fit into circuit field");
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                check_mod_p(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,"double chunk should fit into circuit field");
                };

                check_mod_p(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,"double chunk should fit into circuit field");
                };

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["range_16bit/full"] = 0;

                    return lookup_tables;
                }
           };

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output>
            using plonk_check_mod_p =
                check_mod_p<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    num_chunks,
                    bit_size_chunk,
                    expect_output>;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output>
            typename plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>::result_type generate_assignments(
                const plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using range_check_type = typename component_type::range_check_component;

                carry_on_addition_type carry_on_addition_instance( component._W, component._C, component._PI);
                range_check_type range_check_instance( component._W, component._C, component._PI);

                typename carry_on_addition_type::input_type carry_on_addition_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = instance_input.x[i];
                    carry_on_addition_input.y[i] = instance_input.pp[i];
                }

                typename carry_on_addition_type::result_type carry_on_addition_result =
                    generate_assignments(carry_on_addition_instance, assignment, carry_on_addition_input, start_row_index + expect_output);
                if constexpr(expect_output) {
                    assignment.witness(component.W(0), start_row_index) = var_value(assignment, carry_on_addition_result.ck);
                }

                // perform range check
                typename range_check_type::input_type range_check_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input.x[i] = carry_on_addition_result.z[i];
                }
                generate_assignments(range_check_instance, assignment, range_check_input,
                    start_row_index + expect_output + carry_on_addition_instance.rows_amount);

                return typename plonk_check_mod_p<BlueprintFieldType, num_chunks, bit_size_chunk,expect_output>::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output>
            std::vector<std::size_t> generate_gates(
                const plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>::input_type
                    &instance_input) {

                // never actually called
                return {};
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output>
            void generate_copy_constraints(
                const plonk_check_mod_p<BlueprintFieldType, num_chunks, bit_size_chunk,expect_output> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool expect_output>
            typename plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>::result_type generate_circuit(
                const plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>::input_type &instance_input,
                const std::size_t start_row_index) {
                using component_type = plonk_check_mod_p<BlueprintFieldType,num_chunks,bit_size_chunk,expect_output>;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using range_check_type = typename component_type::range_check_component;

                using var = typename component_type::var;

                carry_on_addition_type carry_on_addition_instance( component._W, component._C, component._PI);
                range_check_type range_check_instance( component._W, component._C, component._PI);

                typename carry_on_addition_type::input_type carry_on_addition_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = instance_input.x[i];
                    carry_on_addition_input.y[i] = instance_input.pp[i];
                }
                typename carry_on_addition_type::result_type carry_on_addition_result =
                    generate_circuit(carry_on_addition_instance, bp, assignment, carry_on_addition_input, start_row_index + expect_output);

                bp.add_copy_constraint({carry_on_addition_result.ck,
                                        (expect_output ? var(component.W(0),start_row_index,false) : instance_input.zero)});

                // perform range check
                typename range_check_type::input_type range_check_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input.x[i] = carry_on_addition_result.z[i];
                }
                generate_circuit(range_check_instance, bp, assignment, range_check_input,
                    start_row_index + expect_output + carry_on_addition_instance.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index); // does nothing, may be skipped?

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CHECK_MOD_P_ECDSA_HPP
