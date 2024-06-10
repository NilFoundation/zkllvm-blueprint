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
// @file Declaration of interfaces for choice function on k-chunked values.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CHOICE_FUNCTION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CHOICE_FUNCTION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Choice function guided by bit q (constrained)
            // operates on k-chunked x,y,z
            // Parameters: num_chunks = k
            // Input: q, x[0], ..., x[k-1], y[0], ..., y[k-1]
            // Output: z[i] = (1-q) x[i] + q y[i], i = 0,...,k-1
            //
            template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t num_chunks>
            class choice_function;

            template<typename BlueprintFieldType, std::size_t num_chunks>
            class choice_function<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           num_chunks>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return choice_function::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
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

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return (3*num_chunks + 1)/witness_amount + ((3*num_chunks + 1) % witness_amount > 0);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "multichunk binary choice function";

                struct input_type {
                    var q, x[num_chunks], y[num_chunks];

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {q};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                            res.push_back(y[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
		    var z[num_chunks];

                    result_type(const choice_function &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            std::size_t row = start_row_index + (1 + 2*num_chunks + i)/WA;
                            std::size_t col = (1 + 2*num_chunks + i) % WA;
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
                explicit choice_function(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                choice_function(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                choice_function(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, std::size_t num_chunks>
            using plonk_choice_function =
                choice_function<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    num_chunks>;

            template<typename BlueprintFieldType, std::size_t num_chunks>
            typename plonk_choice_function<BlueprintFieldType,num_chunks>::result_type generate_assignments(
                const plonk_choice_function<BlueprintFieldType,num_chunks> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_choice_function<BlueprintFieldType,num_chunks>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.witness_amount();

                value_type x[num_chunks], y[num_chunks],
                           q = var_value(assignment, instance_input.q);

                assignment.witness(component.W(0), start_row_index) = q;

                for(std::size_t i = 0; i < num_chunks; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                    y[i] = var_value(assignment, instance_input.y[i]);

                    assignment.witness(component.W((1 + i) % WA), start_row_index + (1 + i)/WA) = x[i];
                    assignment.witness(component.W((1 + num_chunks + i) % WA), start_row_index + (1 + num_chunks + i)/WA) = y[i];
                    assignment.witness(component.W((1 + 2*num_chunks + i) % WA), start_row_index + (1 + 2*num_chunks + i)/WA) =
                        x[i] + q*(y[i] - x[i]);
                }

                return typename plonk_choice_function<BlueprintFieldType, num_chunks>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, std::size_t num_chunks>
            std::size_t generate_gates(
                const plonk_choice_function<BlueprintFieldType,num_chunks> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_choice_function<BlueprintFieldType,num_chunks>::input_type
                    &instance_input) {

                using var = typename plonk_choice_function<BlueprintFieldType,num_chunks>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = -(3*num_chunks + 1 > 2*WA);

                var X, Y, Z,
                    Q = var(component.W(0), 0 + row_shift, true);

                std::vector<constraint_type> choice_constraints = { Q - Q*Q }; // Q(1-Q) = 0

                for(std::size_t i = 0; i < num_chunks; i++) {
                    X = var(component.W((i+1) % WA), (i+1)/WA + row_shift, true);
                    Y = var(component.W((i+num_chunks+1) % WA), (i+num_chunks+1)/WA + row_shift, true);
                    Z = var(component.W((i+2*num_chunks+1) % WA), (i+2*num_chunks+1)/WA + row_shift, true);

                    choice_constraints.push_back(X + Q*(Y - X) - Z);
                }

                return bp.add_gate(choice_constraints);
            }

            template<typename BlueprintFieldType, std::size_t num_chunks>
            void generate_copy_constraints(
                const plonk_choice_function<BlueprintFieldType, num_chunks> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_choice_function<BlueprintFieldType,num_chunks>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();

                using var = typename plonk_choice_function<BlueprintFieldType,num_chunks>::var;

                bp.add_copy_constraint({var(component.W(0), start_row_index, false), instance_input.q});

                for(std::size_t i = 0; i < num_chunks; i++) {
                    bp.add_copy_constraint({var(component.W((1 + i) % WA), start_row_index + (1 + i)/WA,false), instance_input.x[i]});
                    bp.add_copy_constraint({var(component.W((1 + num_chunks + i) % WA), start_row_index + (1 + num_chunks + i)/WA,false), instance_input.y[i]});
                }
            }

            template<typename BlueprintFieldType, std::size_t num_chunks>
            typename plonk_choice_function<BlueprintFieldType,num_chunks>::result_type generate_circuit(
                const plonk_choice_function<BlueprintFieldType,num_chunks> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_choice_function<BlueprintFieldType,num_chunks>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = (3*num_chunks + 1 > 2*WA);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index + row_shift);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_choice_function<BlueprintFieldType,num_chunks>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CHOICE_FUNCTION_HPP
