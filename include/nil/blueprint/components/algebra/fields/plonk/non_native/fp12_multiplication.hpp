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
// @file Declaration of interfaces for F_p^{12} field multiplication.
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_MULTIPLICATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_MULTIPLICATION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp12.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // F_p^12 multiplication gate
            // Input: a[12], b[12]
            // Output: c[12] = a*b as elements of F_p^12

            template<typename ArithmetizationType>
            class fp12_multiplication;

            template<typename BlueprintFieldType>
            class fp12_multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fp12_multiplication::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,36)), // from 12 to 36
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 36/witness_amount + (36 % witness_amount > 0);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,12> a;
                    std::array<var,12> b;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(auto & e : a) { res.push_back(e); }
                        for(auto & e : b) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
                    std::array<var,12> output;

                    result_type(const fp12_multiplication &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W((i+24) % WA), start_row_index + (i+24)/WA, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit fp12_multiplication(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_multiplication(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fp12_multiplication(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_fp12_multiplication =
                fp12_multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_fp12_multiplication<BlueprintFieldType>::result_type generate_assignments(
                const plonk_fp12_multiplication<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.witness_amount();

                std::array<value_type,12> a;
                std::array<value_type,12> b;

                for(std::size_t i = 0; i < 12; i++) {
                    a[i] = var_value(assignment, instance_input.a[i]);
                    b[i] = var_value(assignment, instance_input.b[i]);
                    assignment.witness(component.W(i),start_row_index) = a[i];
                    assignment.witness(component.W((12 + i) % WA),start_row_index + (12 + i)/WA) = b[i];
                }

                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                fp12_element A = fp12_element({ {a[0],a[1]}, {a[2],a[3]}, {a[4],a[5]} }, { {a[6],a[7]}, {a[8],a[9]}, {a[10],a[11]} }),
                             B = fp12_element({ {b[0],b[1]}, {b[2],b[3]}, {b[4],b[5]} }, { {b[6],b[7]}, {b[8],b[9]}, {b[10],b[11]} }),
                             C = A*B;

                for(std::size_t i = 0; i < 12; i++) {
                    assignment.witness(component.W((24 + i) % WA),start_row_index + (24 + i)/WA) = C.data[i/6].data[(i % 6)/2].data[i % 2];
                }

                return typename plonk_fp12_multiplication<BlueprintFieldType>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_fp12_multiplication<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_multiplication<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp12_constraint = detail::abstract_fp12_element<constraint_type>;

                const std::size_t WA = component.witness_amount();
                const int shift = -(WA < 24); // if WA is small we use 3 rows, and need to shift everything

                fp12_constraint A, B, C;

                for(std::size_t i = 0; i < 12; i++) {
                    A[i] = var(component.W(i), 0 + shift, true);
                    B[i] = var(component.W((i+12) % WA), (i+12)/WA + shift, true);
                }
                C = A * B;

                std::vector<constraint_type> Cs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    Cs.push_back(C[i] - var(component.W((i+24) % WA), (i+24)/WA + shift, true));
                }

                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_fp12_multiplication<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_multiplication<BlueprintFieldType>::var;

                const std::size_t WA = component.witness_amount();

                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.a[i]});
                    bp.add_copy_constraint({var(component.W((12 + i) % WA), start_row_index + (12 + i)/WA, false), instance_input.b[i]});
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_fp12_multiplication<BlueprintFieldType>::result_type generate_circuit(
                const plonk_fp12_multiplication<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // if less then 24 witness columns are used, we apply the gate to the second row
                assignment.enable_selector(selector_index, start_row_index + (component.witness_amount() < 24));

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_multiplication<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_MULTIPLICATION_HPP
