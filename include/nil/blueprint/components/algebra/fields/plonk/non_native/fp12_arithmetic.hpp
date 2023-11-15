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
// @file Declaration of interfaces for F_p^{12} field arithmetic.
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_ARITHMETIC_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_ARITHMETIC_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                // actually compute all bilinear forms that represent multiplication in F_p^12
                template<typename T>
                std::array<T,12> perform_fp12_mult(std::array<T,12> a, std::array<T,12> b) {
                    std::array<T,12> c;

                    for(std::size_t i = 0; i < 12; i++) {
                        c[i] = a[0] - a[0]; // hack because we can't actually write c[i] = 0: type T might have casting problems
                    }

                    for(std::size_t i = 0; i < 12; i++) {
                        for(std::size_t j = 0; j < 12; j++) {
                            std::size_t dw = i/6 + j/6;
                            std::size_t dv = (i % 6)/2 + (j % 6)/2;
                            std::size_t du = (i % 2) + (j % 2);

                            if (dw == 2) {
                                // reduction according to w^2 = v
                                dw = 0; dv++;
                            }
                            // possible change of sign according to u^2 = -1
                            c[6*dw + 2*(dv % 3) + (du % 2)] += a[i] * b[j] * (du > 1? -1 : 1);
                            if (dv > 2) {
                                // reduction according to v^3 = u + 1
                                dv -= 3; du++;
                                // account for u in the reduction v^3 = u + 1
                                c[6*dw + 2*dv + (du % 2)] += a[i] * b[j] * (du > 1? -1 : 1);
                            }
                        }
                    }
                    return c;
                }
            } // namespace detail

            // F_p^12 multiplication gate
            // Input: a[12], b[12]
            // Output: c[12] = a*b as elements of F_p^12

            using detail::perform_fp12_mult;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class fp12_multiplication;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class fp12_multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

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

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};
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

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

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

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fp12_multiplication =
                fp12_multiplication<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.witness_amount();

                std::array<value_type,12> a;
                std::array<value_type,12> b;
                std::array<value_type,12> c;


                for(std::size_t i = 0; i < 12; i++) {
                    a[i] = var_value(assignment, instance_input.a[i]);
                    b[i] = var_value(assignment, instance_input.b[i]);
                    assignment.witness(component.W(i),start_row_index) = a[i];
                    assignment.witness(component.W((12 + i) % WA),start_row_index + (12 + i)/WA) = b[i];
                }

                c = perform_fp12_mult(a,b);

                for(std::size_t i = 0; i < 12; i++) {
                    assignment.witness(component.W((24 + i) % WA),start_row_index + (24 + i)/WA) = c[i];
                }

                return typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t WA = component.witness_amount();
                const int shift = -(WA < 24); // if WA is small we use 3 rows, and need to shift everything

                std::array<constraint_type,12> A, B, C;

                for(std::size_t i = 0; i < 12; i++) {
                    A[i] = var(component.W(i), 0 + shift, true);
                    B[i] = var(component.W((i+12) % WA), (i+12)/WA + shift, true);
                }

                C = perform_fp12_mult(A,B);
                std::vector<constraint_type> Cs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    Cs.push_back(C[i] - var(component.W((i+24) % WA), (i+24)/WA + shift, true));
                }

                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t WA = component.witness_amount();

                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.a[i]});
                    bp.add_copy_constraint({var(component.W((12 + i) % WA), start_row_index + (12 + i)/WA, false), instance_input.b[i]});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // if less then 24 witness columns are used, we apply the gate to the second row
                assignment.enable_selector(selector_index, start_row_index + (component.witness_amount() < 24));

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_ARITHMETIC_HPP
