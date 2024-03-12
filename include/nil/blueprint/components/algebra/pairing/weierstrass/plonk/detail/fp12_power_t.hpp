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
// @file Declaration of interfaces for F_p^{12} raising to power -t = 0xD201000000010000.
// This is very BLS12-381 specific. We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_T_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_T_HPP

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
            //
            // Component for raising to power -t = 0xD201000000010000 in F_p^12
            // Input: x[12]
            // Output: y[12]: y = x^{-t} as elements of F_p^12
            //
            // We realize the circuit in two versions - 12-column and 24-column
            // The order of exponent computation for the 12-column version is:
            //
            // 1, 3, 12, 1, 13, 26, 104, 1, 105, 210, 4*210, ..., 4^4*210 = 53760, 1, 53761, 4*53761,...,
            // 4^16 *53761, 1, 1+4^16*53761, 4(1+4^16*53761), ..., 4^8(1+4^16*53761) = -t
            //
            // In the 24-column version we compute two exponents per row,
            // writing the value 53760 twice for better alignment of gates.
            //

            template<typename ArithmetizationType>
            class fp12_power_t;

            template<typename BlueprintFieldType>
            class fp12_power_t<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            static std::size_t gates_amount_internal(std::size_t witness_amount) {
                return (witness_amount == 12) ? 4 : 5;
            }

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;


                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return fp12_power_t::gates_amount_internal(witness_amount);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        return (witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24,12)), // 12 or 24
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return (witness_amount == 12)? 42 : 22; // 12 -> 42, 24 -> 22
                }

//                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,12> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]};
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const fp12_power_t &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        std::size_t last_row = start_row_index + ((WA == 12)? 41 : 21);

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W(i), last_row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit fp12_power_t(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_power_t(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fp12_power_t(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_fp12_power_t =
                fp12_power_t<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_fp12_power_t<BlueprintFieldType>::result_type generate_assignments(
                const plonk_fp12_power_t<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_power_t<BlueprintFieldType>::input_type
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
                             Y = X;

                std::size_t slot = 0;

                auto fill_slot = [&](fp12_element V) {
                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W((12*slot + i) % WA),start_row_index + (12*slot)/WA) =
                            V.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    slot++;
                };

                fill_slot(X); // X
                Y = Y.pow(3); fill_slot(Y); // X^3
                Y = Y.pow(4); fill_slot(Y); // X^12
                fill_slot(X); // X
                Y *= X; fill_slot(Y); // X^13
                Y = Y.pow(2); fill_slot(Y); // X^26
                Y = Y.pow(4); fill_slot(Y); // X^104
                fill_slot(X); // X
                Y *= X; fill_slot(Y); // X^105
                Y = Y.pow(2); fill_slot(Y); // X^210
                for(std::size_t j = 0; j < 4; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^{4*210},...,X^{4^4 * 210}
                }
                if (WA == 24) { fill_slot(Y); } // additional slot for better alignment when WA=24
                fill_slot(X); // X
                Y *= X; fill_slot(Y); // X^53761
                for(std::size_t j = 0; j < 16; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^{4*53761},...,X^{4^16 * 53761}
                }
                fill_slot(X); // X
                Y *= X; fill_slot(Y); // X^{1 + 4^16 * 53761}
                for(std::size_t j = 0; j < 8; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^{4(1 + 4^16*53761)},...,X^{4^8(1 + 4^16 * 53761)}
                }

                return typename plonk_fp12_power_t<BlueprintFieldType>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_fp12_power_t<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_power_t<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_power_t<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp12_constraint = detail::abstract_fp12_element<constraint_type,BlueprintFieldType>;

                const std::size_t WA = component.witness_amount();
                std::vector<std::size_t> gate_list = {}; // 5 gate ids (if WA==12, the last two are the same)

                fp12_constraint X, Y, Z, C;

                // squaring gate
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -(WA == 12), true);
                    Y[i] = var(component.W((i+12) % WA), 0, true);
                }
                C = X * X;

                std::vector<constraint_type> square_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    square_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(square_constrs));

                // cubing gate
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -(WA == 12), true);
                    Y[i] = var(component.W((i+12) % WA), 0, true);
                }
                C = X * X * X;

                std::vector<constraint_type> cube_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    cube_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(cube_constrs));

                // multiplication gate
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -(WA == 12), true);
                    Y[i] = var(component.W((i+12) % WA), 0, true);
                    Z[i] = var(component.W(i), 1, true);
                }
                C = X * Y;

                std::vector<constraint_type> mult_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    mult_constrs.push_back(C[i] - Z[i]);
                }
                gate_list.push_back(bp.add_gate(mult_constrs));

                // power-4 gate type 1 (second column = (first column)^4)
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -(WA == 12), true);
                    Y[i] = var(component.W((i+12) % WA), 0, true);
                }
                C = (X * X) * (X * X);

                std::vector<constraint_type> pow4_1_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    pow4_1_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(pow4_1_constrs));

                // power-4 gate type 2 (first column = (second column, prev row)^4)
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W((i+12) % WA), -1, true);
                    Y[i] = var(component.W(i), 0, true);
                }
                C = (X * X) * (X * X);

                std::vector<constraint_type> pow4_2_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    pow4_2_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(pow4_2_constrs));

                return gate_list;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_fp12_power_t<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_power_t<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_power_t<BlueprintFieldType>::var;

                const std::size_t WA = component.witness_amount();
                std::vector<std::size_t> apply_list;

                if (WA == 12) {
                    apply_list = {0,3,7,14,32};
                } else {
                    apply_list = {0,3,7,15,33};
                }
                // copies of initial data
                for( std::size_t slot : apply_list ) {
                    for(std::size_t i = 0; i < 12; i++) {
                        bp.add_copy_constraint({var(component.W((12*slot + i) % WA), start_row_index + (12*slot)/WA, false),
                                                instance_input.x[i]});
                    }
                }
                if (WA == 24) { // 13th and 14th slot are equal
                    for(std::size_t i = 0; i < 12; i++) {
                        bp.add_copy_constraint({ var(component.W((12*13 + i) % WA), start_row_index + (12*13)/WA, false),
                                                 var(component.W((12*14 + i) % WA), start_row_index + (12*14)/WA, false) });
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_fp12_power_t<BlueprintFieldType>::result_type generate_circuit(
                const plonk_fp12_power_t<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_power_t<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                std::vector<std::size_t> apply_list;

                if (WA == 12) {
                    apply_list = {5,9};
                } else {
                    apply_list = {2,4};
                }
                for( std::size_t row : apply_list ) {
                    assignment.enable_selector(selector_index[0], start_row_index + row); // square gate
                }

                assignment.enable_selector(selector_index[1], start_row_index + (WA == 12)); // cube gate

                if (WA == 12) {
                    apply_list = {3,7,14,32};
                } else {
                    apply_list = {1,3,7,16};
                }
                for( std::size_t row : apply_list ) {
                    assignment.enable_selector(selector_index[2], start_row_index + row); // multiplication gate
                }

                // power4 gate
                if (WA == 12) {
                    assignment.enable_selector(selector_index[3], start_row_index + 2);
                    assignment.enable_selector(selector_index[3], start_row_index + 6);
                    for(std::size_t row = 10; row < 14; row++ ) {
                        assignment.enable_selector(selector_index[3], start_row_index + row);
                    }
                    for(std::size_t row = 16; row < 32; row++ ) {
                        assignment.enable_selector(selector_index[3], start_row_index + row);
                    }
                    for(std::size_t row = 34; row < 42; row++ ) {
                        assignment.enable_selector(selector_index[3], start_row_index + row);
                    }
                } else {
                    assignment.enable_selector(selector_index[4], start_row_index + 1);
                    assignment.enable_selector(selector_index[4], start_row_index + 3);
                    assignment.enable_selector(selector_index[3], start_row_index + 5);
                    assignment.enable_selector(selector_index[3], start_row_index + 6);
                    assignment.enable_selector(selector_index[4], start_row_index + 5);
                    assignment.enable_selector(selector_index[4], start_row_index + 6);

                    for(std::size_t row = 8; row < 16; row++ ) {
                        assignment.enable_selector(selector_index[3], start_row_index + row);
                        assignment.enable_selector(selector_index[4], start_row_index + row + 1);
                    }
                    for(std::size_t row = 17; row < 21; row++ ) {
                        assignment.enable_selector(selector_index[3], start_row_index + row);
                        assignment.enable_selector(selector_index[4], start_row_index + row + 1);
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_power_t<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_T_HPP
