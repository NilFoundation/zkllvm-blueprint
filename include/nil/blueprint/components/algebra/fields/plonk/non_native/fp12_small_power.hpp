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
// @file Declaration of interfaces for F_p^{12} computation of small powers (2,3,4)
// as a unary operation x[12] -> y[12], y = x^R
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_SMALL_POWER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_SMALL_POWER_HPP

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
            namespace detail {
                enum small_power {square = 2, cube = 3, power4 = 4};
            } // namespace detail

            // F_p^12 gate for computing small powers (2,3,4)
            // Parameter: Power = 2,3,4
            // Input: x[12], x
            // Output: y[12], y = x^Power as elements of F_p^12

            using namespace detail;

            template<typename ArithmetizationType, typename BlueprintFieldType, small_power Power>
            class fp12_small_power;

            template<typename BlueprintFieldType, typename ArithmetizationParams, small_power Power>
            class fp12_small_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, Power>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fp12_small_power::gates_amount;
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

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};
                        for(auto & e : x) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const fp12_small_power &component, std::uint32_t start_row_index) {
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
                explicit fp12_small_power(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_small_power(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fp12_small_power(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, small_power Power>
            using plonk_fp12_small_power =
                fp12_small_power<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, Power>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, small_power Power>
            typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::result_type generate_assignments(
                const plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::input_type
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
                             Y = X.pow(int(Power));

                for(std::size_t i = 0; i < 12; i++) {
                    assignment.witness(component.W((12 + i) % WA),start_row_index + (12 + i)/WA) = Y.data[i/6].data[(i % 6)/2].data[i % 2];
                }

                return typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams, small_power Power>
            std::size_t generate_gates(
                const plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp12_constraint = detail::abstract_fp12_element<constraint_type>;

                const std::size_t WA = component.witness_amount();

                fp12_constraint X, Y, C;

                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), 0, true);
                    Y[i] = var(component.W((i+12) % WA), (i+12)/WA, true);
                }

                C = X * X;
                switch(Power) {
                    case square: {
                        break;
                    }
                    case cube: {
                        C = C * X; // 3
                        break;
                    }
                    case power4: {
                        C = C * C; // 4
                        break;
                    }
                }

                std::vector<constraint_type> Cs = {};
                for(std::size_t i = 1; i < 12; i++) {
                    Cs.push_back(C[i] - Y[i]);
                }

                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, small_power Power>
            void generate_copy_constraints(
                const plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::var;

                const std::size_t WA = component.witness_amount();

                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.x[i]});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, small_power Power>
            typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::result_type generate_circuit(
                const plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_small_power<BlueprintFieldType, ArithmetizationParams, Power>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_SMALL_POWER_HPP
