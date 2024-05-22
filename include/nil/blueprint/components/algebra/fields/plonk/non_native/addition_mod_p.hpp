//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoninaa@nil.foundation>
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
// @file Declaration of interfaces for addition function on mod p.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ADDITION_MOD_P_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ADDITION_MOD_P_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/components/detail/plonk/carry_on_addition.hpp>
#include <nil/blueprint/components/detail/plonk/choice_function.hpp>
#include <nil/blueprint/components/detail/plonk/range_check.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/check_mod_p.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Addition mod p
            // operates on k-chunked x,y, p, p'
            // Parameters: num_chunks = k, bit_size_chunk = b
            // Input: x[0], ..., x[k-1], y[0], ..., y[k-1], p[0], ..., p[k-1], p'[0], ..., p'[k-1], 0
            // Intemmediate values: q, t[0], ..., t[k-1], carry[k-1], t'[0], ..., t'[k-1], t"[0], ..., t"[k-1],
            // carry"[k-1] Output: z[0] = x[0] + y[0] - qp[0], ..., z[k-1] = x[k-1] + y[k-1] -qp[k-1]
            //
            template<typename ArithmetizationType,
                     typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            class addition_mod_p;

            template<typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            class addition_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                 BlueprintFieldType,
                                 NonNativeFieldType,
                                 num_chunks,
                                 bit_size_chunk> : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using carry_on_addition_component =
                    carry_on_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                      BlueprintFieldType,
                                      num_chunks,
                                      bit_size_chunk>;
                using range_check_component =
                    range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                BlueprintFieldType,
                                bit_size_chunk>;
                using choice_component =
                    choice_function<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                    BlueprintFieldType,
                                    num_chunks>;
                using check_mod_p_component =
                    check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                BlueprintFieldType,
                                num_chunks,
                                bit_size_chunk>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return addition_mod_p::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                            .merge_with(choice_component::get_gate_manifest(witness_amount, lookup_column_amount))
                            .merge_with(carry_on_addition_component::get_gate_manifest(witness_amount, lookup_column_amount))
                            .merge_with(range_check_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(0)), false)
                            .merge_with(choice_component::get_manifest())
                            .merge_with(carry_on_addition_component::get_manifest())
                            .merge_with(range_check_component::get_manifest())
                            .merge_with(check_mod_p_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    std::size_t rows = (num_chunks + 1) / witness_amount + ((num_chunks + 1) % witness_amount > 0);
                    rows += carry_on_addition_component::get_rows_amount(witness_amount, lookup_column_amount);
                    rows += num_chunks * range_check_component::get_rows_amount(witness_amount, lookup_column_amount);
                    rows += choice_component::get_rows_amount(witness_amount, lookup_column_amount);
                    rows += carry_on_addition_component::get_rows_amount(witness_amount, lookup_column_amount);
                    rows += num_chunks * range_check_component::get_rows_amount(witness_amount, lookup_column_amount);
                    rows += num_chunks * range_check_component::get_rows_amount(witness_amount, lookup_column_amount);
                    rows += check_mod_p_component::get_rows_amount(witness_amount, lookup_column_amount);

                    return rows;
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "multichunk binary addition mod p";

                struct input_type {
                    var x[num_chunks], y[num_chunks], p[num_chunks], pp[num_chunks], zero;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {zero};
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                            res.push_back(y[i]);
                            res.push_back(p[i]);
                            res.push_back(pp[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    var z[num_chunks];

                    result_type(const addition_mod_p &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            std::size_t row = start_row_index + (1 + i) / WA;
                            std::size_t col = (1 + i) % WA;
                            z[i] = var(component.W(col), row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(z[i]);
                        }
                        return res;
                    }
                };

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["range_16bit/full"] = 0;

                    return lookup_tables;
                }

                template<typename ContainerType>
                explicit addition_mod_p(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,
                                  "double chunk should fit into circuit field");
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,
                                  "non-native field should fit into chunks");
                };

                template<typename WitnessContainerType,
                         typename ConstantContainerType,
                         typename PublicInputContainerType>
                addition_mod_p(WitnessContainerType witness,
                               ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,
                                  "double chunk should fit into circuit field");
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,
                                  "non-native field should fit into chunks");
                };

                addition_mod_p(std::initializer_list<typename component_type::witness_container_type::value_type>
                                   witnesses,
                               std::initializer_list<typename component_type::constant_container_type::value_type>
                                   constants,
                               std::initializer_list<typename component_type::public_input_container_type::value_type>
                                   public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {
                    static_assert(bit_size_chunk + 1 < BlueprintFieldType::modulus_bits,
                                  "double chunk should fit into circuit field");
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,
                                  "non-native field should fit into chunks");
                };
            };

            template<typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            using plonk_addition_mod_p = addition_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                                        BlueprintFieldType,
                                                        NonNativeFieldType,
                                                        num_chunks,
                                                        bit_size_chunk>;

            template<typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            typename plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>::
                result_type
                generate_assignments(
                    const plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_addition_mod_p<BlueprintFieldType,
                                                        NonNativeFieldType,
                                                        num_chunks,
                                                        bit_size_chunk>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                using component_type =
                    plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using range_check_type = typename component_type::range_check_component;
                using choice_function_type = typename component_type::choice_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using foreign_integral_type = typename NonNativeFieldType::integral_type;
                using var = typename component_type::var;

                std::uint32_t row = start_row_index;

                const std::size_t WA = component.witness_amount();
                value_type q = value_type::zero();
                const foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk;
                foreign_integral_type x_full = 0, y_full = 0, z_full = 0, p_full = 0;

                for (std::size_t i = num_chunks; i > 0; i--) {
                    x_full *= B;
                    y_full *= B;
                    p_full *= B;
                    x_full += foreign_integral_type(var_value(assignment, instance_input.x[i - 1]).data);
                    y_full += foreign_integral_type(var_value(assignment, instance_input.y[i - 1]).data);
                    p_full += foreign_integral_type(var_value(assignment, instance_input.p[i - 1]).data);
                }
                
                z_full = x_full + y_full;   // x + y = z + qp
                if (z_full >= p_full) {
                    z_full -= p_full;
                    q = value_type::one();
                }

                assignment.witness(component.W(0), row) = q;
                for (std::size_t i = 0; i < num_chunks; i++) {
                    assignment.witness(component.W((1 + i) % WA), row + (1 + i) / WA) = value_type(z_full % B);
                    z_full /= B;
                }

                row += (num_chunks + 1) / WA + ((num_chunks + 1) % WA > 0);

                carry_on_addition_type carry_on_addition_instance(component._W, component._C, component._PI);
                range_check_type range_check_instance(component._W, component._C, component._PI);
                choice_function_type choice_function_instance(component._W, component._C, component._PI);
                check_mod_p_type check_mod_p_instance(component._W, component._C, component._PI);

                // carry_on_addition component (x + y)
                typename carry_on_addition_type::input_type carry_on_addition_input;
                for (std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = instance_input.x[i];
                    carry_on_addition_input.y[i] = instance_input.y[i];
                }

                typename carry_on_addition_type::result_type first_carry_on_addition_result =
                    generate_assignments(carry_on_addition_instance, assignment, carry_on_addition_input, row);

                row += carry_on_addition_instance.rows_amount;

                // perform num_chunks range checks. To be replaced by a single batched range check in the future
                for (std::size_t i = 0; i < num_chunks; i++) {
                    typename range_check_type::input_type range_check_input = {first_carry_on_addition_result.z[i]};
                    generate_assignments(range_check_instance, assignment, range_check_input, row);
                    row += range_check_instance.rows_amount;
                }

                // choice-function component  (qp = 0 or p)
                typename choice_function_type::input_type choice_function_input;
                choice_function_input.q = var(component.W(0), start_row_index, false);
                for (std::size_t i = 0; i < num_chunks; i++) {
                    choice_function_input.x[i] = instance_input.zero;
                    choice_function_input.y[i] = instance_input.p[i];
                }

                typename choice_function_type::result_type choice_function_result =
                    generate_assignments(choice_function_instance, assignment, choice_function_input, row);

                row += choice_function_instance.rows_amount;

                // carry_on_addition component (z + qp)
                for (std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = choice_function_result.z[i];
                    carry_on_addition_input.y[i] =
                        var(component.W((1 + i) % WA), start_row_index + (1 + i) / WA, false);
                }

                typename carry_on_addition_type::result_type second_carry_on_addition_result =
                    generate_assignments(carry_on_addition_instance, assignment, carry_on_addition_input, row);

                row += carry_on_addition_instance.rows_amount;

                // perform num_chunks range checks. To be replaced by a single batched range check in the future
                for (std::size_t i = 0; i < num_chunks; i++) {
                    typename range_check_type::input_type range_check_input = {second_carry_on_addition_result.z[i]};
                    generate_assignments(range_check_instance, assignment, range_check_input, row);
                    row += range_check_instance.rows_amount;
                }
                for (std::size_t i = 0; i < num_chunks; i++) {
                    typename range_check_type::input_type range_check_input = {carry_on_addition_input.y[i]};
                    generate_assignments(range_check_instance, assignment, range_check_input, row);
                    row += range_check_instance.rows_amount;
                }

                // check_mod_p component
                typename check_mod_p_type::input_type check_mod_p_input;
                check_mod_p_input.zero = instance_input.zero;
                for (std::size_t i = 0; i < num_chunks; i++) {
                    check_mod_p_input.x[i] = carry_on_addition_input.y[i];
                    check_mod_p_input.pp[i] = instance_input.pp[i];
                }
                generate_assignments(check_mod_p_instance, assignment, check_mod_p_input, row);
                row += check_mod_p_instance.rows_amount;

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return
                    typename plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>::
                        result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_addition_mod_p<BlueprintFieldType,
                                                    NonNativeFieldType,
                                                    num_chunks,
                                                    bit_size_chunk>::input_type &instance_input) {
                // never actually called                                
                return {};
            }

            template<typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_addition_mod_p<BlueprintFieldType,
                                                    NonNativeFieldType,
                                                    num_chunks,
                                                    bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }

            template<typename BlueprintFieldType,
                     typename NonNativeFieldType,
                     std::size_t num_chunks,
                     std::size_t bit_size_chunk>
            typename plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>::
                result_type
                generate_circuit(
                    const plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_addition_mod_p<BlueprintFieldType,
                                                        NonNativeFieldType,
                                                        num_chunks,
                                                        bit_size_chunk>::input_type &instance_input,
                    const std::size_t start_row_index) {

                using component_type =
                    plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using range_check_type = typename component_type::range_check_component;
                using choice_function_type = typename component_type::choice_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                std::uint32_t row = start_row_index;

                const std::size_t WA = component.witness_amount();
                row += (num_chunks + 1) / WA + ((num_chunks + 1) % WA > 0);

                carry_on_addition_type carry_on_addition_instance(component._W, component._C, component._PI);
                range_check_type range_check_instance(component._W, component._C, component._PI);
                choice_function_type choice_function_instance(component._W, component._C, component._PI);
                check_mod_p_type check_mod_p_instance(component._W, component._C, component._PI);

                // carry_on_addition component (x + y)
                typename carry_on_addition_type::input_type carry_on_addition_input;
                for (std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = instance_input.x[i];
                    carry_on_addition_input.y[i] = instance_input.y[i];
                }

                typename carry_on_addition_type::result_type first_carry_on_addition_result =
                    generate_circuit(carry_on_addition_instance, bp, assignment, carry_on_addition_input, row);

                row += carry_on_addition_instance.rows_amount;

                // perform num_chunks range checks. To be replaced by a single batched range check in the future
                for (std::size_t i = 0; i < num_chunks; i++) {
                    typename range_check_type::input_type range_check_input = {first_carry_on_addition_result.z[i]};
                    generate_circuit(range_check_instance, bp, assignment, range_check_input, row);
                    row += range_check_instance.rows_amount;
                }

                // choice-function component  (qp = 0 or p)
                typename choice_function_type::input_type choice_function_input;
                choice_function_input.q = var(component.W(0), start_row_index, false);
                for (std::size_t i = 0; i < num_chunks; i++) {
                    choice_function_input.x[i] = instance_input.zero;
                    choice_function_input.y[i] = instance_input.p[i];
                }

                typename choice_function_type::result_type choice_function_result =
                    generate_circuit(choice_function_instance, bp, assignment, choice_function_input, row);

                row += choice_function_instance.rows_amount;

                // carry_on_addition component (z + qp)
                for (std::size_t i = 0; i < num_chunks; i++) {
                    carry_on_addition_input.x[i] = choice_function_result.z[i];
                    carry_on_addition_input.y[i] =
                        var(component.W((1 + i) % WA), start_row_index + (1 + i) / WA, false);
                }

                typename carry_on_addition_type::result_type second_carry_on_addition_result =
                    generate_circuit(carry_on_addition_instance, bp, assignment, carry_on_addition_input, row);

                // carry_on_addition results should be equal to each other  x + y = z + qp
                for (std::size_t i = 0; i < num_chunks; i++) {
                    bp.add_copy_constraint({first_carry_on_addition_result.z[i], second_carry_on_addition_result.z[i]});
                }
                bp.add_copy_constraint({first_carry_on_addition_result.ck, second_carry_on_addition_result.ck});
                row += carry_on_addition_instance.rows_amount;

                // perform num_chunks range checks. To be replaced by a single batched range check in the future
                for (std::size_t i = 0; i < num_chunks; i++) {
                    typename range_check_type::input_type range_check_input = {second_carry_on_addition_result.z[i]};
                    generate_circuit(range_check_instance, bp, assignment, range_check_input, row);
                    row += range_check_instance.rows_amount;
                }
                for (std::size_t i = 0; i < num_chunks; i++) {
                    typename range_check_type::input_type range_check_input = {carry_on_addition_input.y[i]};
                    generate_circuit(range_check_instance, bp, assignment, range_check_input, row);
                    row += range_check_instance.rows_amount;
                }

                // check_mod_p component
                typename check_mod_p_type::input_type check_mod_p_input;
                check_mod_p_input.zero = instance_input.zero;
                for (std::size_t i = 0; i < num_chunks; i++) {
                    check_mod_p_input.x[i] = carry_on_addition_input.y[i];
                    check_mod_p_input.pp[i] = instance_input.pp[i];
                }
                generate_circuit(check_mod_p_instance, bp, assignment, check_mod_p_input, row);
                row += check_mod_p_instance.rows_amount;

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return
                    typename plonk_addition_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>::
                        result_type(component, start_row_index);
            }

        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ADDITION_MOD_P_HPP
