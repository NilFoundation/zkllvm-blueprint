//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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
// @file Declaration of interfaces for choice function on k-chunked values.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CARRY_ON_ADDITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CARRY_ON_ADDITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

std::size_t bit_size = 16;

namespace nil {
    namespace blueprint {
        namespace components {
            // Carry-on-addition 
            // operates on k-chunked x,y,carry
            // Parameters: num_chunks = k
            // Input: x[0], ..., x[k-1], y[0], ..., y[k-1]
            // Intemmediate values: carry[0], ..., carry[k-1]
            // Output: z[0] = x[0] + y[0], ..., z[k-1] = x[k-1] + y[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t num_chunks>
            class carry_on_addition;

            template<typename BlueprintFieldType, std::size_t num_chunks>
            class carry_on_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return carry_on_addition::gates_amount;
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

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    return (4*num_chunks)/witness_amount + ((4*num_chunks) % witness_amount > 0);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "multichunk binary carry on addition";

                struct input_type {
                    var x[num_chunks], y[num_chunks];

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                            res.push_back(y[i]);
                        }
                        return res;
                    }
                };

            struct result_type {
		    var z[num_chunks];

                    result_type(const carry_on_addition &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            std::size_t row = start_row_index + (3*num_chunks + i)/WA;
                            std::size_t col = (3*num_chunks + i) % WA;
                            z[i] = var(component.W(col), row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(z[i]);
                        }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit carry_on_addition(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                carry_on_addition(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                carry_on_addition(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, std::size_t num_chunks>
            using plonk_carry_on_addition =
                carry_on_addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    num_chunks>;

            template<typename BlueprintFieldType, std::size_t num_chunks>
            typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::result_type generate_assignments(
                const plonk_carry_on_addition<BlueprintFieldType,num_chunks> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.witness_amount();

                value_type x[num_chunks], y[num_chunks], carry[num_chunks]; 

                for(std::size_t i = 0; i < num_chunks; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                    y[i] = var_value(assignment, instance_input.y[i]);

                    assignment.witness(component.W((i) % WA), start_row_index + (i)/WA) = x[i];
                    assignment.witness(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA) = y[i];

                    if (i == 0){
                        if ((x[i] + y[i]) < (1 << bit_size)){
                            carry[i] = 0;
                        }
                        else{
                            carry[i] = 1;
                        }
                        assignment.witness(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA) = carry[i];
                        assignment.witness(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA) = 
                        x[i] + y[i] - carry[i]*(1 << bit_size);
                    }
                    else{
                        if ((x[i] + y[i]) < (1 << bit_size)){
                            carry[i] = 0;
                        }
                        else{
                            carry[i] = 1;
                        }
                        assignment.witness(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA) = carry[i];
                        assignment.witness(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA) = 
                        x[i] + y[i] + carry[i-1] - carry[i]*(1 << bit_size);
                    }
                }

                return typename plonk_carry_on_addition<BlueprintFieldType, num_chunks>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, std::size_t num_chunks>
            std::size_t generate_gates(
                const plonk_carry_on_addition<BlueprintFieldType,num_chunks> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::input_type
                    &instance_input) {

                using var = typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = -(4*num_chunks > 2*WA);

                var X, Y, C_, C, Z; 

                std::vector<constraint_type> carry_on_constraints = { }; // Q(1-Q) = 0

                for(std::size_t i = 0; i < num_chunks; i++) {
                    C = var(component.W((i+2*num_chunks) % WA), (i+2*num_chunks)/WA + row_shift, true);
                    carry_on_constraints.push_back(C - C*C);
                }

                for(std::size_t i = 0; i < num_chunks; i++) {
                    X = var(component.W((i) % WA), (i)/WA + row_shift, true);
                    Y = var(component.W((i+num_chunks) % WA), (i+num_chunks)/WA + row_shift, true);
                    C = var(component.W((i+2*num_chunks) % WA), (i+2*num_chunks)/WA + row_shift, true);
                    Z = var(component.W((i+3*num_chunks) % WA), (i+3*num_chunks)/WA + row_shift, true);

                    if (i == 0){
                        carry_on_constraints.push_back(X + Y - C*(1 << bit_size) - Z);
                    }
                    else{
                        C_ = var(component.W((i+2*num_chunks - 1) % WA), (i+2*num_chunks - 1)/WA + row_shift, true);
                        carry_on_constraints.push_back(X + Y + C_ - C*(1 << bit_size) - Z);
                    }
                }
                return bp.add_gate(carry_on_constraints);
            }

            template<typename BlueprintFieldType, std::size_t num_chunks>
            void generate_copy_constraints(
                const plonk_carry_on_addition<BlueprintFieldType, num_chunks> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();

                using var = typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::var;

                for(std::size_t i = 0; i < num_chunks; i++) {
                    bp.add_copy_constraint({var(component.W((i) % WA), start_row_index + (i)/WA,false), instance_input.x[i]});
                    bp.add_copy_constraint({var(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA,false), instance_input.y[i]});
                }
            }

            template<typename BlueprintFieldType, std::size_t num_chunks>
            typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::result_type generate_circuit(
                const plonk_carry_on_addition<BlueprintFieldType,num_chunks> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = (4*num_chunks > 2*WA);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index + row_shift);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_carry_on_addition<BlueprintFieldType,num_chunks>::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CARRY_ON_ADDITION_HPP
