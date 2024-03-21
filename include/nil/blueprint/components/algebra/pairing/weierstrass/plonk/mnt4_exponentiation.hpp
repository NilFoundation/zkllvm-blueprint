//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// @file Circuit for final exponentiation for MNT4 elliptic curve pairings
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_EXPONENTIATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_EXPONENTIATION_HPP

#include "nil/blueprint/components/algebra/fields/plonk/non_native/mnt4_fp4_fixed_power.hpp"
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp4.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            //
            // Curve E over prime field (F_p) as q points
            //
            // Pairing is possible due to q | p^k-1
            //
            // This component raises element in F_{p^k} to power F = (p^k-1)/q
            //
            // For MNT4 curve k = 4 and F = (p^2-1)(p+w_0)
            //
            // The process of raising x to power F takes 6 stages:
            // 1. Raise x to power p, x <- x^p (on Fp4 this is cheap)
            // 2. Repeat: x <- x^p, now x holds x^(p^2)
            // 3. Divide by initial value x, now x holds x^(p^2-1), save to x'
            // 4. Raise x' to power p: x1 <- x'^p (cheap)
            // 5. Raise x' to power w0: x2 <- x'^w0 (this is hard)
            // 6. Result is x1*x2
            //
            // Circuit requires 4 witnesses, 4 inputs and 4 outputs
            // 6 gates are used:
            // Gate 0: Raising to power p, "Frobenius map"
            // Gate 1: "Division in Fp4"
            // Gate 2: "Multiplication"
            // Gate 3: "Squaring"
            // Gate 4: "Cubing"
            // Gate 5: "Fourth power"
            // Gates 3-5 are used for powering to w0
            using namespace detail;

            template<typename ArithmetizationType>
            class mnt4_exponentiation;

            template<typename BlueprintFieldType>
            class mnt4_exponentiation<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using curve_type = nil::crypto3::algebra::curves::mnt4<298>;

                using fixed_power_type = mnt4_fp4_fixed_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    gate_manifest_type() {}

                    std::uint32_t gates_amount() const override {
                        return mnt4_exponentiation::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                        std::size_t witness_amount)
                {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(4)),
                        false
                    );

                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                        std::size_t witness_amount)
                {
                    return fixed_power_type::get_rows_amount(crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0) + 9 - 1;
                }

                constexpr static const std::size_t gates_amount = 7;
                const std::size_t rows_amount = get_rows_amount(0);

                struct input_type {
                    std::array<var,4> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x[0], x[1], x[2], x[3]};
                    }
                };

                struct result_type {
                    std::array<var, 4> output;

                    result_type(const mnt4_exponentiation &component, std::uint32_t start_row_index) {
                        std::size_t last_row = start_row_index + component.rows_amount - 1;
                        for(std::size_t i = 0; i < 4; i++) {
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
                explicit mnt4_exponentiation(ContainerType witness) :
                    component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                mnt4_exponentiation(
                    WitnessContainerType witness,
                    ConstantContainerType constant,
                    PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                mnt4_exponentiation(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs, unsigned long long T_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_mnt4_exponentiation =
                mnt4_exponentiation<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_mnt4_exponentiation<BlueprintFieldType>::result_type
            generate_assignments(
                plonk_mnt4_exponentiation<BlueprintFieldType> const& component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                typename plonk_mnt4_exponentiation<BlueprintFieldType>::input_type const& instance_input,
                const std::uint32_t start_row_index)
            {
                using component_type = plonk_mnt4_exponentiation<BlueprintFieldType>;
                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using curve_type = nil::crypto3::algebra::curves::mnt4<298>;

                using fixed_power_type = mnt4_fp4_fixed_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                fixed_power_type fixed_power_instance(component._W, component._C, component._PI, crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0);

                std::array<value_type, 4> x;

                for(std::size_t i = 0; i < 4; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                }

                using policy_type_fp4 = crypto3::algebra::fields::fp4<BlueprintFieldType>;
                using fp4_element = typename policy_type_fp4::value_type;

                fp4_element
                    input = fp4_element({ {x[0],x[1]}, {x[2],x[3]}, }),
                    elt = input;

                std::size_t row = start_row_index;

                auto fill_row = [&assignment, &component, &row](fp4_element const& V)
                {
                    for(std::size_t i = 0; i < 4; ++i) {
                        assignment.witness(component.W(i),row) = V.data[i/2].data[i%2];
                    }
                    ++row;
                };

                // Initial value
                fill_row(elt);

                // elt <- elt^p
                elt = elt.Frobenius_map(1);
                fill_row(elt);

                // elt <- (elt^p), now elt holds= x^(p^2)
                elt = elt.Frobenius_map(1);
                fill_row(elt);

                // elt <- elt/x, elt now holds x^(p^2-1)
                fill_row(input);
                elt = elt*input.inversed();
                fill_row(elt);

                // elt2 <- elt^p, elt2 = x^(p^2-1)*p
                fp4_element elt2 = elt.Frobenius_map(1);
                fill_row(elt2);

                /* Fill rows for raising elt = x^(p^2-1) to power w0 */

                // The input is from 4th row
                std::array<var, 4> transfer_vars = {
                    var(component.W(0), start_row_index + 4, false),
                    var(component.W(1), start_row_index + 4, false),
                    var(component.W(2), start_row_index + 4, false),
                    var(component.W(3), start_row_index + 4, false),
                };

                typename fixed_power_type::input_type pow_input = { transfer_vars };
                typename fixed_power_type::result_type pow_output =
                    generate_assignments(fixed_power_instance, assignment, pow_input, row);
                row += fixed_power_instance.rows_amount;

                fp4_element elt3({
                    {
                        var_value(assignment, pow_output.output[0]),
                        var_value(assignment, pow_output.output[1]),
                    } , {
                        var_value(assignment, pow_output.output[2]),
                        var_value(assignment, pow_output.output[3])
                    }
                });
                // Now elt3 holds x^(p^2-1)*w0
                // fill_row(elt3);

                // Final result is elt2*elt3 = x^((p^2-1)*p) * x^((p^2-1)*w0) = x^(p^2-1)*(p+w0)
                fill_row(elt2);
                elt = elt2*elt3;
                fill_row(elt);

                return typename plonk_mnt4_exponentiation<BlueprintFieldType>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t>
            generate_gates(
                plonk_mnt4_exponentiation<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                typename plonk_mnt4_exponentiation<BlueprintFieldType>::input_type const& instance_input)
            {
                using var = typename plonk_mnt4_exponentiation<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using fp4_constraint = detail::abstract_fp4_element<constraint_type,BlueprintFieldType>;

                std::vector<std::size_t> gate_list = {};

                std::vector<constraint_type> constrs = {};

                fp4_constraint X, Xn, Xp, R;

                for(std::size_t i = 0; i < 4; ++i) {
                    X[i] = var(component.W(i), 0, true);
                    Xn[i] = var(component.W(i), 1, true);
                    Xp[i] = var(component.W(i), -1, true);
                }

                /* Frobenius gate - 0
                 * Ensures x_next = x^p = x.frobenius_map(1)
                 */
                {
                    using fp4_ep = typename crypto3::algebra::fields::fp4<BlueprintFieldType>::extension_policy;
                    using fp2_ep = typename crypto3::algebra::fields::fp2<BlueprintFieldType>::extension_policy;

                    constrs.clear();
                    for(std::size_t i = 0; i < 4; ++i) {
                        typename BlueprintFieldType::value_type
                            fc4 = fp4_ep::Frobenius_coeffs_c1[i/2],
                            fc2 = fp2_ep::Frobenius_coeffs_c1[i%2];
                        constraint_type coeff = constraint_type() + fc4*fc2;
                        constrs.push_back(Xn[i] - coeff*X[i]);
                    }

                    gate_list.push_back(bp.add_gate(constrs));
                }

                /* Division gate - 1
                 * Ensures x_next = x_prev/x : x_next * x - x_prev = 0
                 */
                {
                    R = Xn*X - Xp;

                    constrs.clear();
                    constrs.push_back(R[0]);
                    constrs.push_back(R[1]);
                    constrs.push_back(R[2]);
                    constrs.push_back(R[3]);

                    gate_list.push_back(bp.add_gate(constrs));
                }

                /* Multiplication gate - 2
                 * Ensures x_next = x*x_prev: x_next - x*x_prev = 0
                 */
                {
                    R = Xn - X*Xp;

                    constrs.clear();
                    constrs.push_back(R[0]);
                    constrs.push_back(R[1]);
                    constrs.push_back(R[2]);
                    constrs.push_back(R[3]);

                    gate_list.push_back(bp.add_gate(constrs));
                }

                return gate_list;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                plonk_mnt4_exponentiation<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_mnt4_exponentiation<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {
                using component_type = plonk_mnt4_exponentiation<BlueprintFieldType>;
                using var = typename plonk_mnt4_exponentiation<BlueprintFieldType>::var;
                
                using fixed_power_type = typename component_type::fixed_power_type;
                using curve_type = nil::crypto3::algebra::curves::mnt4<298>;
                fixed_power_type power_instance( component._W, component._C, component._PI,
                        crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0);
                std::size_t R = power_instance.rows_amount;

                // initial data in row 0
                for(std::size_t i = 0; i < 4; ++i) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.x[i]});
                }

                // initial data in row 3
                for(std::size_t i = 0; i < 4; ++i) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index + 3, false), instance_input.x[i]});
                }

                // Copy from 5 row to R+6 row
                for(std::size_t i = 0; i < 4; ++i) {
                    bp.add_copy_constraint({
                        var(component.W(i), start_row_index + R + 6, false),
                        var(component.W(i), start_row_index + 5, false),
                    });
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_mnt4_exponentiation<BlueprintFieldType>::result_type
            generate_circuit(
                plonk_mnt4_exponentiation<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_mnt4_exponentiation<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {
                using component_type = plonk_mnt4_exponentiation<BlueprintFieldType>;
                using var = typename component_type::var;
                using fixed_power_type = typename component_type::fixed_power_type;
                using curve_type = nil::crypto3::algebra::curves::mnt4<298>;

                fixed_power_type power_instance( component._W, component._C, component._PI,
                        crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0);
                std::size_t R = power_instance.rows_amount;

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                // Frobenius gates
                assignment.enable_selector(selector_index[0], start_row_index + 0);
                assignment.enable_selector(selector_index[0], start_row_index + 1);
                assignment.enable_selector(selector_index[0], start_row_index + 4);

                // Division gate
                assignment.enable_selector(selector_index[1], start_row_index + 3);

                // Power to w0 sub-circuit takes input from 4th rouw
                std::array<var,4> power_input_vars;
                power_input_vars[0] = var(component.W(0), start_row_index + 4, false);
                power_input_vars[1] = var(component.W(1), start_row_index + 4, false);
                power_input_vars[2] = var(component.W(2), start_row_index + 4, false);
                power_input_vars[3] = var(component.W(3), start_row_index + 4, false);

                typename fixed_power_type::input_type power_input = { power_input_vars };
                typename fixed_power_type::result_type power_output =
                        generate_circuit(power_instance, bp, assignment, power_input, start_row_index + 6);

                // expect result at start_rows_index + 6 + R

                // Multiplication gate
                assignment.enable_selector(selector_index[2], start_row_index + R + 6);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_mnt4_exponentiation<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_mnt4_exponentiation_HPP
