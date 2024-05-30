//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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
// @file Declaration of interfaces for non-native negation modulo p
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NEGATION_MOD_P_ECDSA_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NEGATION_MOD_P_ECDSA_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/detail/plonk/carry_on_addition.hpp>
#include <nil/blueprint/components/detail/plonk/range_check_multi.hpp>
#include <nil/blueprint/components/detail/plonk/choice_function.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/check_mod_p.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Parameters: num_chunks = k, bit_size_chunk = b
            // Finding the negative y of integer x, modulo p and checking that x + y = 0 mod p
            // Input: x[0], ..., x[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1], 0 (expects zero constant as input)
            // Output: y[0], ..., y[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class negation_mod_p;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                using carry_on_addition_component =
                      carry_on_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                        BlueprintFieldType, num_chunks, bit_size_chunk>;
                using range_check_component =
                      range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                  BlueprintFieldType, num_chunks, bit_size_chunk>;
                using check_mod_p_component =
                      check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                  BlueprintFieldType, num_chunks, bit_size_chunk>;
                using choice_function_component =
                      choice_function<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return negation_mod_p::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type())
                        .merge_with(choice_function_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(carry_on_addition_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(range_check_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        // the following is unnecessary because check_mod_p uses only carry_on_addition and range_check,
                        // while gate_manifest cannot process intersecting gate sets correctly
                        // .merge_with(check_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        ;
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // all requirements come from sub-components, the component itself has no personal requirements
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(0)),
                        false // constant column not needed
                    )
                     .merge_with(choice_function_component::get_manifest())
                     .merge_with(carry_on_addition_component::get_manifest())
                     .merge_with(range_check_component::get_manifest())
                     .merge_with(check_mod_p_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    const std::size_t negation_rows_amount = (num_chunks + 1)/witness_amount + ((num_chunks + 1) % witness_amount > 0);

                    return negation_rows_amount
                         + choice_function_component::get_rows_amount(witness_amount,lookup_column_amount)
                         + carry_on_addition_component::get_rows_amount(witness_amount,lookup_column_amount)
                         + range_check_component::get_rows_amount(witness_amount,lookup_column_amount)
                         + check_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount);
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "multichunk negation mod p function";

                struct input_type {
                    var x[num_chunks], p[num_chunks], pp[num_chunks], zero;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                            res.push_back(p[i]);
                            res.push_back(pp[i]);
                        }
                        res.push_back(zero);
                        return res;
                    }
                };

                struct result_type {
                    var y[num_chunks];
                    result_type(const negation_mod_p &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            std::size_t row = start_row_index + (1 + i)/WA;
                            std::size_t col = (1 + i) % WA;
                            y[i] = var(component.W(col), row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(y[i]);
                        }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit negation_mod_p(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,"double chunk should fit into circuit field");
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,"non-native field should fit into chunks");
                };

                template<typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                negation_mod_p(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,"double chunk should fit into circuit field");
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,"non-native field should fit into chunks");
                };

                negation_mod_p(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,"double chunk should fit into circuit field");
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,"non-native field should fit into chunks");
                };

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["range_16bit/full"] = 0;

                    return lookup_tables;
                }
           };

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            using plonk_negation_mod_p =
                negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_assignments(
                const plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;

                using choice_function_type = typename component_type::choice_function_component;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using range_check_type = typename component_type::range_check_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using foreign_integral_type = typename NonNativeFieldType::integral_type;

                const std::size_t WA = component.witness_amount();

                const foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk;
                // x_full, p_full, y_full: the full integer representations of x, p, y
                foreign_integral_type x_full = 0,
                                      p_full = 0,
                                      y_full;

                for(std::size_t i = num_chunks; i > 0; i--) {
                    x_full *= B;
                    p_full *= B;
                    x_full += foreign_integral_type(var_value(assignment, instance_input.x[i-1]).data);
                    p_full += foreign_integral_type(var_value(assignment, instance_input.p[i-1]).data);
                }

                value_type q = (x_full == 0) ? 0 : 1;
                y_full = (x_full == 0) ? 0 : p_full - x_full; // if x = 0, then y = 0

                assignment.witness(component.W(0), start_row_index) = q;

                // converting y_full to chunks using modulo and division by B
                for(std::size_t i = 0; i < num_chunks; i++) {
                    assignment.witness(component.W((1 + i) % WA), start_row_index + (1 + i) / WA) = value_type(y_full % B);
                    y_full /= B;
                }

                const std::size_t negation_rows_amount = (num_chunks + 1)/WA + ((num_chunks + 1) % WA > 0);

                choice_function_type choice_function_instance(component._W, component._C, component._PI);
                carry_on_addition_type carry_on_addition_instance(component._W, component._C, component._PI);
                range_check_type range_check_instance(component._W, component._C, component._PI);
                check_mod_p_type check_mod_p_instance(component._W, component._C, component._PI);

                // Initializing choice_function component
                typename choice_function_type::input_type choice_function_input;
                choice_function_input.q = var(component.W(0), start_row_index, false);
                for(std::size_t i = 0; i < num_chunks; i++) {
                    choice_function_input.x[i] = instance_input.zero;
                    choice_function_input.y[i] = instance_input.p[i];
                }

                typename choice_function_type::result_type choice_function_result =
                    generate_assignments(choice_function_instance, assignment, choice_function_input, start_row_index
                                        + negation_rows_amount);

                // Initializing carry_on_addition component
                typename carry_on_addition_type::input_type carry_on_addition_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = instance_input.x[i];
                    carry_on_addition_input.y[i] = var(component.W((1 + i) % WA), start_row_index + (1 + i) / WA, false);
                }

                typename carry_on_addition_type::result_type carry_on_addition_result =
                    generate_assignments(carry_on_addition_instance, assignment, carry_on_addition_input, start_row_index
                                        + negation_rows_amount + choice_function_instance.rows_amount);

                // Initializing range_check component
                typename range_check_type::input_type range_check_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input.x[i] = carry_on_addition_input.y[i];
                }
                generate_assignments(range_check_instance, assignment, range_check_input, start_row_index
                    + negation_rows_amount + choice_function_instance.rows_amount + carry_on_addition_instance.rows_amount);

                // Initializing check_mod_p component
                typename check_mod_p_type::input_type check_mod_p_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    check_mod_p_input.x[i] = carry_on_addition_input.y[i];
                    check_mod_p_input.pp[i] = instance_input.pp[i];
                }
                check_mod_p_input.zero = instance_input.zero;

                generate_assignments(check_mod_p_instance, assignment, check_mod_p_input, start_row_index
                                    + negation_rows_amount + choice_function_instance.rows_amount
                                    + carry_on_addition_instance.rows_amount + range_check_instance.rows_amount);

                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input) {

                // never actually called
                return {};
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_negation_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }


            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_circuit(
                const plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_negation_mod_p<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;

                using choice_function_type = typename component_type::choice_function_component;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using range_check_type = typename component_type::range_check_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;

                using var = typename component_type::var;

                const std::size_t WA = component.witness_amount();
                const std::size_t negation_rows_amount = (num_chunks + 1)/WA + ((num_chunks + 1) % WA > 0);

                choice_function_type choice_function_instance(component._W, component._C, component._PI);
                carry_on_addition_type carry_on_addition_instance(component._W, component._C, component._PI);
                range_check_type range_check_instance(component._W, component._C, component._PI);
                check_mod_p_type check_mod_p_instance(component._W, component._C, component._PI);

                // choice-function component
                typename choice_function_type::input_type choice_function_input;
                choice_function_input.q = var(component.W(0 % WA), start_row_index + (0) / WA, false);
                for(std::size_t i = 0; i < num_chunks; i++) {
                    choice_function_input.x[i] = instance_input.zero;
                    choice_function_input.y[i] = instance_input.p[i];
                }

                typename choice_function_type::result_type choice_function_result =
                    generate_circuit(choice_function_instance, bp, assignment, choice_function_input, start_row_index
                                    + negation_rows_amount);

                // carry_on_addition component
                typename carry_on_addition_type::input_type carry_on_addition_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = instance_input.x[i];
                    carry_on_addition_input.y[i] = var(component.W((1 + i) % WA), start_row_index + (1 + i) / WA, false);
                }

                typename carry_on_addition_type::result_type carry_on_addition_result =
                    generate_circuit(carry_on_addition_instance, bp, assignment, carry_on_addition_input, start_row_index
                                    + negation_rows_amount + choice_function_instance.rows_amount);

                bp.add_copy_constraint({carry_on_addition_result.ck, instance_input.zero}); // ck = zero, zero comes in component input

                for(std::size_t i = 0; i < num_chunks; i++) {
                    bp.add_copy_constraint({choice_function_result.z[i], carry_on_addition_result.z[i]});
                }

                // range_check component
                typename range_check_type::input_type range_check_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input.x[i] = carry_on_addition_input.y[i];
                }
                generate_circuit(range_check_instance, bp, assignment, range_check_input, start_row_index
                    + negation_rows_amount + choice_function_instance.rows_amount + carry_on_addition_instance.rows_amount);

                // check_mod_p component
                typename check_mod_p_type::input_type check_mod_p_input;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    check_mod_p_input.x[i] = carry_on_addition_input.y[i];
                    check_mod_p_input.pp[i] = instance_input.pp[i];
                }
                check_mod_p_input.zero = instance_input.zero;

                generate_circuit(check_mod_p_instance, bp, assignment, check_mod_p_input, start_row_index
                                + negation_rows_amount + choice_function_instance.rows_amount
                                + carry_on_addition_instance.rows_amount + range_check_instance.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index); // does nothing, may be skipped?

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NEGATION_MOD_P_ECDSA_HPP
