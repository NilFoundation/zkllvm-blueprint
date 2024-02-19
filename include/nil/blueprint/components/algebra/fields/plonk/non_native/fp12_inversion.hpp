//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for F_p^{12} field inversion.
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_INVERSION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_INVERSION_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp12.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // F_p^12 inversion gate
            // Input: x[12], x != 0
            // Output: y[12]: x*y = 1 as elements of F_p^12

            template<typename ArithmetizationType>
            class fp12_inversion;

            template<typename BlueprintFieldType>
            class fp12_inversion<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fp12_inversion::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24)), // from 12 to 24
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1 + (witness_amount < 24); // anything that's smaller than 24 columns wide requires 2 rows
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,12> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(auto & e : x) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const fp12_inversion &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W((i+12) % WA), start_row_index + (i+12)/WA, false, var::column_type::witness);
                        }
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit fp12_inversion(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_inversion(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fp12_inversion(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_fp12_inversion =
                fp12_inversion<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_fp12_inversion<BlueprintFieldType>::result_type generate_assignments(
                const plonk_fp12_inversion<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_inversion<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.witness_amount();

                std::array<value_type,12> x;

                for(std::size_t i = 0; i < 12; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                    assignment.witness(component.W(i),start_row_index) = x[i];
                }

                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                fp12_element X = fp12_element({ {x[0],x[1]}, {x[2],x[3]}, {x[4],x[5]} }, { {x[6],x[7]}, {x[8],x[9]}, {x[10],x[11]} }),
                             Y = (X == fp12_element::zero())? fp12_element::zero() : X.inversed(); // if X == 0, we fail with Y=0

                for(std::size_t i = 0; i < 12; i++) {
                    assignment.witness(component.W((12 + i) % WA),start_row_index + (12 + i)/WA) = Y.data[i/6].data[(i % 6)/2].data[i % 2];
                }

                return typename plonk_fp12_inversion<BlueprintFieldType>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_fp12_inversion<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_inversion<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_inversion<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp12_constraint = detail::abstract_fp12_element<constraint_type>;

                const std::size_t WA = component.witness_amount();

                fp12_constraint X, Y, C;

                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), 0, true);
                    Y[i] = var(component.W((i+12) % WA), (i+12)/WA, true);
                }
                C = X * Y;

                std::vector<constraint_type> Cs = { C[0] - 1 };
                for(std::size_t i = 1; i < 12; i++) {
                    Cs.push_back(C[i]);
                }

                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_fp12_inversion<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_inversion<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_inversion<BlueprintFieldType>::var;

                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.x[i]});
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_fp12_inversion<BlueprintFieldType>::result_type generate_circuit(
                const plonk_fp12_inversion<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_inversion<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_inversion<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_INVERSION_HPP
