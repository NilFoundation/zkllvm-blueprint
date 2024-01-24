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
// @file Declaration of interfaces for F_p^{12} raising to power (t-1)^2/3
// with -t = 0xD201000000010000.
// This is very BLS12-381 specific. We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_TMINUS1SQ3_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_TMINUS1SQ3_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp12.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/detail/fp12_power_t.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            //
            // Component for raising to power (1-t)^2/3 with -t = 0xD201000000010000 in F_p^12
            // Input: x[12]
            // Output: y[12]: y = x^{(1-t)^2/3} as elements of F_p^12
            //
            // We realize the circuit in two versions - 12-column and 24-column.
            //
            // We first compute x^{(1-t)/3} then raise it to power -t using an external
            // subcomponent and finally multiply by x^{(1-t)/3} to obtain the result.
            //

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class fp12_power_tm1sq3;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class fp12_power_tm1sq3<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            static std::size_t gates_amount_internal(std::size_t witness_amount) {
                return (witness_amount == 12) ? 5 : 6;
            }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using power_t_type = fp12_power_t<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return fp12_power_tm1sq3::gates_amount_internal(witness_amount);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        return (witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount)) ;
//                        .merge_with(power_t_type::get_gate_manifest(witness_amount,lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24,12)), // 12 or 24
                        false
                    ).merge_with(power_t_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return ((witness_amount == 12)? (59+3) : (32+2)) +  // 12 -> 59+3, 24 -> 32+2
                            power_t_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,12> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]};
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const fp12_power_tm1sq3 &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        std::size_t last_row = start_row_index + component.rows_amount - 1;

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W(i), last_row, false, var::column_type::witness);
                        }
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit fp12_power_tm1sq3(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_power_tm1sq3(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fp12_power_tm1sq3(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fp12_power_tm1sq3 =
                fp12_power_tm1sq3<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::input_type
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
                             Y = X,
                             M = X.pow(21845); // 21845 = (4^8 - 1)/3
                std::size_t slot = 0;

                auto fill_slot = [&](fp12_element V) {
                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W((12*slot + i) % WA),start_row_index + (12*slot)/WA) =
                            V.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    slot++;
                };

                fill_slot(X.inversed()); // X^{-1}
                fill_slot(X); // X
                for(std::size_t j = 0; j < 8; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^4,....,X^{4^8}
                }
                if (WA == 24) { fill_slot(Y); } // additional slot for alignment when WA = 24
                fill_slot(X.inversed()); // X^{-1}
                Y = Y * X.inversed(); fill_slot(Y); // X^{4^8-1}
                if (WA == 24) { slot++; } // ensure alignment when WA = 24
                fill_slot(M); // X^{(4^8-1)/3}
                fill_slot(Y); // power m = (4^8-1)/3 is now computed
                // ------------------- start of (1-t)/3 proper computation
                fill_slot(M); // X^m
                fill_slot(M.pow(2)); // X^{2m}
                Y = X.pow(16); fill_slot(Y); // X^{4^2}
                fill_slot(X); // X
                Y = Y*X; fill_slot(Y); //X^{17}
                Y = Y.pow(2); fill_slot(Y); // X^{34}
                if (WA == 24) { fill_slot(Y); } // additional slot for alignment when WA = 24
                fill_slot(X); // X
                Y = Y*X; fill_slot(Y); // X^{35}
                for(std::size_t j = 0; j < 12; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^{4 * 35},....,X^{4^12 * 35}
                }
                Y = Y.pow(2); fill_slot(Y); // X^{2 * 4^12 * 35}
                if (WA == 24) { fill_slot(Y); } // additional slot for alignment when WA = 24
                fill_slot(M); // X^m
                Y = Y*M; fill_slot(Y); // X^{m + 2 * 4^12 * 35}
                for(std::size_t j = 0; j < 8; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^{4(m + 2 * 4^12 * 35)},...,X^{4^8(m + 2 * 4^12 * 35)}
                }
                fill_slot(M); // X^m
                Y = Y*M; fill_slot(Y); // X^{m + 4^8(m + 2 * 4^12 * 35)}
                for(std::size_t j = 0; j < 8; j++) {
                    Y = Y.pow(4); fill_slot(Y); // X^{4(m + 4^8(m + 2 * 4^12 * 35))},...,X^{4^8(m + 4^8(m + 2 * 4^12 * 35))}
                }
                fill_slot(M.pow(2)); // X^{2m}
                Y = Y*M.pow(2); fill_slot(Y); // X^{2m + 4^8(m + 4^8(m + 2 * 4^12 * 35))}
                fill_slot(X);
                Y = Y*X; fill_slot(Y); // X^{1 + 2m + 4^8(m + 4^8(m + 2 * 4^12 * 35))}
                // now we need to raise this to power (1-t)

                using component_type = plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using power_t_type = typename component_type::power_t_type;

                power_t_type power_t_instance( component._W, component._C, component._PI);

                slot--; // rewind to last slot
                std::array<var,12> transfer_vars;
                for(std::size_t i = 0; i < 12; i++) {
                    transfer_vars[i] = var(component.W((12*slot + i) % WA),start_row_index + (12*slot)/WA,false);
                }
                typename power_t_type::input_type power_t_input = {transfer_vars};
                std::size_t current_row = start_row_index + (12*slot)/WA + 1;
                typename power_t_type::result_type power_t_res =
                    generate_assignments(power_t_instance, assignment, power_t_input, current_row); // this computes x^{-t(1-t)/3}
                current_row += power_t_instance.rows_amount;

                std::array<value_type,12> z;
                for(std::size_t i = 0; i < 12; i++) {
                    z[i] = var_value(assignment, power_t_res.output[i]);
                }
                fp12_element Z = fp12_element({ {z[0],z[1]}, {z[2],z[3]}, {z[4],z[5]} }, { {z[6],z[7]}, {z[8],z[9]}, {z[10],z[11]} });

                slot = ((current_row - start_row_index)*WA)/12;
                fill_slot(Z); fill_slot(Y); fill_slot(Y*Z); // x^{-t(1-t)/3}, x^{(1-t)/3}, x^{(1-t)*(1-t)/3}

                return typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::var;
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

                // inversion gate
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -(WA == 12), true);
                    Y[i] = var(component.W((i+12) % WA), 0, true);
                }
                C = X * Y;

                std::vector<constraint_type> inversion_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    inversion_constrs.push_back(C[i] - (i > 0? 0 : 1));
                }
                gate_list.push_back(bp.add_gate(inversion_constrs));

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

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t WA = component.witness_amount();

                // copies of initial data
                std::vector<std::size_t> apply_list = (WA == 12) ?
                    std::vector<std::size_t>{1, 14 + 3, 14 + 6, 14 + 43}:
                    std::vector<std::size_t>{1, 16 + 3, 16 + 7, 16 + 45};

                for( std::size_t slot : apply_list ) {
                    for(std::size_t i = 0; i < 12; i++) {
                        bp.add_copy_constraint({var(component.W((12*slot + i) % WA), start_row_index + (12*slot)/WA, false),
                                                instance_input.x[i]});
                    }
                }

                std::vector<std::array<std::size_t,2>> pairs = (WA == 12) ?
                    std::vector<std::array<std::size_t,2>> {
                      {12, 14 + 0}, {12, 14 + 21}, {12, 14 + 31}, // copies of x^m
                      {11, 13}, // copies of x^{4^8 - 1}
                      {14 + 1, 14 + 41}, // copies of x^{2m}
                      {58, 102} // copies of x^{(1-t)/3}
                    } :
                    std::vector<std::array<std::size_t,2>> {
                      {14, 16 + 0}, {14, 16 + 23}, {14, 16 + 33}, // copies of x^m
                      {12, 15}, // copies of x^{4^8 - 1}
                      {16 + 1, 16 + 43}, // copies of x^{2m}
                      {62, 109}, // copies of x^{(1-t)/3}
                      {9, 10}, {16 + 5, 16+5+1}, {16 + 21, 16+21+1} // additional copies for alignment
                    };
                for( std::array<std::size_t,2> pair : pairs ) {
                    for(std::size_t i = 0; i < 12; i++) {
                        bp.add_copy_constraint({var(component.W((12*pair[0] + i) % WA), start_row_index + (12*pair[0])/WA, false),
                                                var(component.W((12*pair[1] + i) % WA), start_row_index + (12*pair[1])/WA, false)});
                    }
                }

            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);
                std::vector<std::size_t> apply_list;

                auto apply_selector = [&assignment, &selector_index, &start_row_index](
                    std::size_t gate_id, std::vector<std::size_t> apply_list) {
                    for( std::size_t row : apply_list ) {
                        assignment.enable_selector(selector_index[gate_id], start_row_index + row);
                    }
                };

                // square gate #0
                apply_selector(0, (WA == 12)? std::vector<std::size_t>{14+1,14+5,14+20}: std::vector<std::size_t>{8+0,8+2,8+10});

                // cube gate #1
                apply_selector(1, (WA == 12)? std::vector<std::size_t>{13}: std::vector<std::size_t>{7});

                // multiplication gate #2
                apply_selector(2, (WA == 12)?
                                  std::vector<std::size_t>{10, 14 + 3, 14 + 6, 14 + 21, 14 + 31,14+ 41, 14+ 43, 14 + 45 + 42 + 3 - 2 }:
                                  std::vector<std::size_t>{5, 8 + 1,  8 + 3,  8 + 11,  8 + 16, 8 + 21, 8 + 22, 8 + 24 + 22 + 2 - 2});

                // inversion gate #3
                apply_selector(3, (WA == 12)? std::vector<std::size_t>{1}: std::vector<std::size_t>{0});

                // power4 gate
                if (WA == 12) {
                    for(std::size_t row = 2; row < 10; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                    }
                    for(std::size_t row = 14 + 8; row < 14 + 8 + 12; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                    }
                    for(std::size_t row = 14 + 23; row < 14 + 23 + 8; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                    }
                    for(std::size_t row = 14 + 33; row < 14 + 33 + 8; row++) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                    }
                } else {
                    for(std::size_t row = 1; row < 5; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                        assignment.enable_selector(selector_index[5], start_row_index + row);
                    }
                    for(std::size_t row = 8 + 4; row < 8 + 10; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                        assignment.enable_selector(selector_index[5], start_row_index + row + 1);
                    }
                    for(std::size_t row = 8 + 12; row < 8 + 16; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                        assignment.enable_selector(selector_index[5], start_row_index + row + 1);
                    }
                    for(std::size_t row = 8 + 17; row < 8 + 21; row++ ) {
                        assignment.enable_selector(selector_index[4], start_row_index + row);
                        assignment.enable_selector(selector_index[5], start_row_index + row + 1);
                    }
                }

                using component_type = plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using power_t_type = typename component_type::power_t_type;

                power_t_type power_t_instance( component._W, component._C, component._PI);

                std::size_t slot = (WA == 12)? (14+45-1) : (16+47-1); // the number of the final 12-block slot
                std::array<var,12> transfer_vars;
                for(std::size_t i = 0; i < 12; i++) {
                    transfer_vars[i] = var(component.W((12*slot + i) % WA),start_row_index + (12*slot)/WA,false);
                }
                typename power_t_type::input_type power_t_input = {transfer_vars};
                std::size_t current_row = start_row_index + (12*slot)/WA + 1;
                typename power_t_type::result_type power_t_res =
                    generate_circuit(power_t_instance, bp, assignment, power_t_input, current_row);

                slot = (WA == 12)? 101 : 108; // the block after power (-t)
                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({power_t_res.output[i],
                                            var(component.W((12*slot + i) % WA), start_row_index + (12*slot)/WA, false)});
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_power_tm1sq3<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_TMINUS1SQ3_HPP
