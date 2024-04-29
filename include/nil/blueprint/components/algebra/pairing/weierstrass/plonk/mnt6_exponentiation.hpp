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
// @file Circuit for final exponentiation for MNT6 elliptic curve pairings
// Circuit summary:
// 6 witness, 0 constant, 7 gates, 199 rows
// 366 copy constraints
// each gate has 6 constraints, max degree is 2
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT6_EXPONENTIATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT6_EXPONENTIATION_HPP

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp6.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/mnt6_fp6_fixed_power.hpp>

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
            // For MNT6 curve k = 6 and F = (p^3 - 1)*(p + 1)*(p - w_0)
            //
            // The process of raising x to power F takes 6 stages:
            // 1. Raise x to power p, x <- x^p (Frobenius map)
            // 2. Repeat: x <- x^p, now x holds x^(p^2)
            // 3. Repeat: x <- x^p, now x holds x^(p^3)
            // 4. Divide by initial value x, now x holds x^(p^3-1), save to x'
            // 5. Raise x' to power p: x1 <- x'^p = x^((p^3-1)*p)
            // 6. Multiply x1 by x', now x1 holds x^((p^3-1)*(p+1)), save to x''
            // 7. Raise x'' to power p: x2 <- x''^p, x2 = x^((p^3-1)*(p+1)*p)
            // 8. Raise x'' to power w_0: x3 <- x''^w_0, x3 = x^((p^3-1)*(p+1)*w_0), done with sub-circuit
            // 9. Final result: inverse division x2 * x3^-1
            //
            // Circuit requires 6 witnesses, 6 inputs and 6 outputs
            // 6 gates are used:
            // Gate 0: Raising to power p, "Frobenius map"
            // Gate 1: "Division in Fp6" : x_next = x_prev / x
            // Gate 2: "Inverse Division in Fp6": x_next = x / x_prev
            // Gate 3: "Multiplication"
            // Gate 4: "Squaring"
            // Gate 5: "Cubing"
            // Gates 3-5 are used for powering to w_0
            using namespace detail;

            template<typename ArithmetizationType>
            class mnt6_exponentiation;

            template<typename BlueprintFieldType>
            class mnt6_exponentiation<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using curve_type = nil::crypto3::algebra::curves::mnt6<298>;

                using fixed_power_type = mnt6_fp6_fixed_power<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    gate_manifest_type() {}

                    std::uint32_t gates_amount() const override {
                        return mnt6_exponentiation::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                        std::size_t witness_amount)
                {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type())
                        .merge_with(fixed_power_type::get_gate_manifest(witness_amount, crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0));
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
                    return fixed_power_type::get_rows_amount(
                            witness_amount,
                            crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0)
                        + 12;
                }

                constexpr static const std::size_t gates_amount = 3;
                const std::size_t rows_amount = get_rows_amount(0);

                struct input_type {
                    std::array<var, 6> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x[0], x[1], x[2], x[3], x[4], x[5]};
                    }
                };

                struct result_type {
                    std::array<var, 6> output;

                    result_type(const mnt6_exponentiation &component, std::uint32_t start_row_index) {
                        std::size_t last_row = start_row_index + component.rows_amount - 1;
                        for(std::size_t i = 0; i < 6; i++) {
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
                explicit mnt6_exponentiation(ContainerType witness) :
                    component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                mnt6_exponentiation(
                    WitnessContainerType witness,
                    ConstantContainerType constant,
                    PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                mnt6_exponentiation(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs, unsigned long long T_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_mnt6_exponentiation =
                mnt6_exponentiation<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_mnt6_exponentiation<BlueprintFieldType>::result_type
            generate_assignments(
                plonk_mnt6_exponentiation<BlueprintFieldType> const& component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                typename plonk_mnt6_exponentiation<BlueprintFieldType>::input_type const& instance_input,
                const std::uint32_t start_row_index)
            {
                using component_type = plonk_mnt6_exponentiation<BlueprintFieldType>;
                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using curve_type = nil::crypto3::algebra::curves::mnt6<298>;

                using fixed_power_type = mnt6_fp6_fixed_power<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                fixed_power_type fixed_power_instance(
                        component._W, component._C, component._PI,
                        crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0);

                std::array<value_type, 6> x;

                for(std::size_t i = 0; i < x.size(); i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                }

                using policy_type_fp6 = crypto3::algebra::fields::fp6_2over3<BlueprintFieldType>;
                using fp6_element = typename policy_type_fp6::value_type;

                fp6_element
                    input = fp6_element({ {x[0], x[1], x[2]}, {x[3], x[4], x[5]} }),
                    elt = input;

                std::size_t row = start_row_index;

                auto fill_row = [&assignment, &component, &row](fp6_element const& V)
                {
                    for(std::size_t i = 0; i < 6; ++i) {
                        assignment.witness(component.W(i),row) = V.data[i/3].data[i%3];
                    }
                    ++row;
                };

                // 0: Initial value
                fill_row(elt);

                // 1: elt <- elt^p
                elt = elt.Frobenius_map(1);
                fill_row(elt);

                // 2: elt <- (elt^p), now elt holds= x^(p^2)
                elt = elt.Frobenius_map(1);
                fill_row(elt);

                // 3: elt <- (elt^p), now elt holds= x^(p^3)
                elt = elt.Frobenius_map(1);
                fill_row(elt);

                // 4: elt <- elt/x, elt now holds x^(p^3-1)
                fill_row(input);
                elt = elt*input.inversed();
                // 5:
                fill_row(elt);

                // 6: elt2 <- (elt^p), now elt2 holds x^((p^3-1)*p)
                fp6_element elt2 = elt.Frobenius_map(1);
                fill_row(elt2);

                // 7: elt2 <- elt2*elt, now elt2 holds x^((p^3-1)*(p+1))
                elt2 = elt2*elt;
                fill_row(elt2);

                // 8: elt <- (elt2^p), now elt holds x^((p^3-1)*(p+1)*p)
                elt = elt2.Frobenius_map(1);
                fill_row(elt);

                /* Fill rows for raising elt2 = x^((p^3-1)*(p+1)) to power w0 */

                // The input is from 7th row
                std::array<var, 6> transfer_vars = {
                    var(component.W(0), start_row_index + 7, false),
                    var(component.W(1), start_row_index + 7, false),
                    var(component.W(2), start_row_index + 7, false),
                    var(component.W(3), start_row_index + 7, false),
                    var(component.W(4), start_row_index + 7, false),
                    var(component.W(5), start_row_index + 7, false),
                };

                typename fixed_power_type::input_type pow_input = { transfer_vars };
                typename fixed_power_type::result_type pow_output =
                    generate_assignments(fixed_power_instance, assignment, pow_input, row);
                row += fixed_power_instance.rows_amount;

                fp6_element elt3({
                    {
                        var_value(assignment, pow_output.output[0]),
                        var_value(assignment, pow_output.output[1]),
                        var_value(assignment, pow_output.output[2]),
                    } , {
                        var_value(assignment, pow_output.output[3]),
                        var_value(assignment, pow_output.output[4]),
                        var_value(assignment, pow_output.output[5])
                    }
                });
                // Now elt3 holds x^((p^3-1)*(p+1)*w0)
                // The output of "fixed_power" circuit is copied into 9+R row

                // 8+R: Final result is elt/elt3 = x^((p^3-1)*(p+1)*p) * x^(-(p^3-1)(p+1)*w0) = x^((p^3-1)*(p+1)*(p-w0))
                fill_row(elt);
                fill_row(elt3);
                elt = elt*elt3.inversed();
                // 10+R
                fill_row(elt);

                return typename plonk_mnt6_exponentiation<BlueprintFieldType>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t>
            generate_gates(
                plonk_mnt6_exponentiation<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                typename plonk_mnt6_exponentiation<BlueprintFieldType>::input_type const& instance_input)
            {
                using var = typename plonk_mnt6_exponentiation<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using fp6_constraint = detail::abstract_fp6_element<constraint_type,BlueprintFieldType>;

                std::vector<std::size_t> gate_list = {};

                std::vector<constraint_type> constrs = {};

                fp6_constraint X, Xn, Xp, R;

                for(std::size_t i = 0; i < 6; ++i) {
                    X[i] = var(component.W(i), 0, true);
                    Xn[i] = var(component.W(i), 1, true);
                    Xp[i] = var(component.W(i), -1, true);
                }

                /* Frobenius gate - 0
                 * Ensures x_next = x^p = x.frobenius_map(1)
                 */
                {
                    using fp6_ep = typename crypto3::algebra::fields::fp6_2over3<BlueprintFieldType>::extension_policy;
                    using fp3_ep = typename crypto3::algebra::fields::fp3<BlueprintFieldType>::extension_policy;

                    typename BlueprintFieldType::value_type fc3[] = {
                        1,
                        fp3_ep::Frobenius_coeffs_c1[1],
                        fp3_ep::Frobenius_coeffs_c2[1]
                    };

                    typename BlueprintFieldType::value_type fc6[] = {
                        1,
                        fp6_ep::Frobenius_coeffs_c1[1],
                    };

                    constrs.clear();
                    for(std::size_t i = 0; i < 6; ++i) {
                        constraint_type coeff = constraint_type() + fc6[i/3]*fc3[i%3];
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
                    for(std::size_t i = 0; i < 6; ++i) {
                        constrs.push_back(R[i]);
                    }

                    gate_list.push_back(bp.add_gate(constrs));
                }

                /* Multiplication gate - 2
                 * Ensures x_next = x*x_prev: x_next - x*x_prev = 0
                 */
                {
                    R = Xn - X*Xp;

                    constrs.clear();
                    for(std::size_t i = 0; i < 6; ++i) {
                        constrs.push_back(R[i]);
                    }

                    gate_list.push_back(bp.add_gate(constrs));
                }

                return gate_list;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                plonk_mnt6_exponentiation<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_mnt6_exponentiation<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {
                using component_type = plonk_mnt6_exponentiation<BlueprintFieldType>;
                using var = typename plonk_mnt6_exponentiation<BlueprintFieldType>::var;

                using fixed_power_type = typename component_type::fixed_power_type;
                using curve_type = nil::crypto3::algebra::curves::mnt6<298>;
                fixed_power_type power_instance( component._W, component._C, component._PI,
                        crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0);
                std::size_t R = power_instance.rows_amount;

                // Initial data in row 0
                for(std::size_t i = 0; i < 6; ++i) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.x[i]});
                }

                // Initial data in row 4
                for(std::size_t i = 0; i < 6; ++i) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index + 4, false), instance_input.x[i]});
                }

                // Copy from 8 row to R+9 row
                for(std::size_t i = 0; i < 6; ++i) {
                    bp.add_copy_constraint({
                        var(component.W(i), start_row_index + R + 9, false),
                        var(component.W(i), start_row_index + 8, false),
                    });
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_mnt6_exponentiation<BlueprintFieldType>::result_type
            generate_circuit(
                plonk_mnt6_exponentiation<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_mnt6_exponentiation<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {
                using component_type = plonk_mnt6_exponentiation<BlueprintFieldType>;
                using var = typename component_type::var;
                using fixed_power_type = typename component_type::fixed_power_type;
                using curve_type = nil::crypto3::algebra::curves::mnt6<298>;

                fixed_power_type power_instance( component._W, component._C, component._PI,
                        crypto3::algebra::pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0);

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                // Frobenius gates
                assignment.enable_selector(selector_index[0], start_row_index + 0);
                assignment.enable_selector(selector_index[0], start_row_index + 1);
                assignment.enable_selector(selector_index[0], start_row_index + 2);
                // Copy at 3
                // Division gate at 4
                assignment.enable_selector(selector_index[1], start_row_index + 4);
                // Frobenius at 5
                assignment.enable_selector(selector_index[0], start_row_index + 5);
                // Multiplication at 6
                assignment.enable_selector(selector_index[2], start_row_index + 6);
                // Frobenius at 7
                assignment.enable_selector(selector_index[0], start_row_index + 7);
 
                // Power to w0 sub-circuit takes input from 7-th rouw
                std::array<var, 6> power_input_vars;
                for(std::size_t i = 0 ; i < 6; ++i ) {
                    power_input_vars[i] = var(component.W(i), start_row_index + 7, false);
                }

                typename fixed_power_type::input_type power_input = { power_input_vars };
                typename fixed_power_type::result_type power_output =
                        generate_circuit(power_instance, bp, assignment, power_input, start_row_index + 9);
                std::size_t R = power_instance.rows_amount;

                // Copy from subcircuit result to R+10 row
                for(std::size_t i = 0; i < 6; ++i) {
                    bp.add_copy_constraint({
                        var(component.W(i), start_row_index + R + 10, false),
                        power_output.output[i]
                        });
                }

                // Division gate at R + 10
                assignment.enable_selector(selector_index[1], start_row_index + R + 10);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_mnt6_exponentiation<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_mnt6_exponentiation_HPP
