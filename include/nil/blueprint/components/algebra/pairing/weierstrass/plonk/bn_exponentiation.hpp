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
// @file Declaration of the exponentiation for BN elliptic curve pairings
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BN_EXPONENTIATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BN_EXPONENTIATION_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp12.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/fp12_fixed_power.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/fp12_frobenius_coefs.hpp>

/*
#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/detail/fp12_power_t.hpp>
#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/detail/fp12_power_tminus1sq_over3.hpp>
*/
namespace nil {
    namespace blueprint {
        namespace components {
            //
            // Component for raising to power N = (p^12 - 1)/r in F_p^12
            // where p = 36t^4 + 36t^3 + 24t^2 + 6t + 1
            //       r = 36t^4 + 36t^3 + 18t^2 + 6t + 1
            // with parameter t
            // Input: x[12]
            // Output: y[12]: y = x^N as elements of F_p^12
            //
            // We use the representation N = (p^6 - 1)(p^2 + 1) (p^4 - p^2 + 1)/r
            // and compute (p^4 - p^2 + 1)/r according to https://eprint.iacr.org/2007/390.pdf
            // as follows:
            // a := x^{6t-5}, b := a^p, b := a*b,
            // x^{(p^4-p^2+1)/r} = x^{p^3} * (b * (x^p)^2 * x^{p^2})^{6t^2 + 1} * b * (x^p * x)^9 * a * x^4
            //
            using namespace detail;

            template<typename ArithmetizationType>
            class bn_exponentiation;

            template<typename BlueprintFieldType>
            class bn_exponentiation<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using fixed_power_type = fp12_fixed_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    gate_manifest_type() {}

                    std::uint32_t gates_amount() const override {
                        return bn_exponentiation::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       unsigned long long T) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
//                        .merge_with(fixed_power_type::get_gate_manifest(witness_amount,lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(12)),
                        false
                    ).merge_with(fixed_power_type::get_manifest());

                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, unsigned long long T) {
                    return 48 + 3 * fixed_power_type::get_rows_amount(witness_amount, lookup_column_amount, T);
                }

                unsigned long long T; // the BN parameter

                constexpr static const std::size_t gates_amount = 8;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, T);

                struct input_type {
                    std::array<var,12> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]};
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const bn_exponentiation &component, std::uint32_t start_row_index) {
                        std::size_t last_row = start_row_index + component.rows_amount - 1;

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
                explicit bn_exponentiation(ContainerType witness, unsigned long long T_) :
                    component_type(witness, {}, {}, get_manifest()), T(T_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bn_exponentiation(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, unsigned long long T_) :
                    component_type(witness, constant, public_input, get_manifest()), T(T_) {};

                bn_exponentiation(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs, unsigned long long T_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()), T(T_) {};
            };

            template<typename BlueprintFieldType>
            using plonk_bn_exponentiation =
                bn_exponentiation<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_bn_exponentiation<BlueprintFieldType>::result_type generate_assignments(
                const plonk_bn_exponentiation<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bn_exponentiation<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {
                using component_type = plonk_bn_exponentiation<BlueprintFieldType>;
                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using fixed_power_type = typename component_type::fixed_power_type;

                fixed_power_type power_t_instance( component._W, component._C, component._PI, component.T );
                std::size_t R = power_t_instance.rows_amount;

                typename BlueprintFieldType::integral_type field_p = BlueprintFieldType::modulus;

                std::array<value_type,12> x;

                for(std::size_t i = 0; i < 12; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                }

                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                fp12_element X = fp12_element({ {x[0],x[1]}, {x[2],x[3]}, {x[4],x[5]} }, { {x[6],x[7]}, {x[8],x[9]}, {x[10],x[11]} }),
                             F, A, B, C, D;

                std::size_t row = 0;
                auto fill_row = [&assignment, &component, &start_row_index, &row](fp12_element V) {
                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W(i),start_row_index + row) = V.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    row++;
                };
                auto row_vars = [&component, &start_row_index](std::size_t input_row) {
                    std::array<var,12> transfer_vars;
                    for(std::size_t i = 0; i < 12; i++) {
                        transfer_vars[i] = var(component.W(i),start_row_index + input_row,false);
                    }
                    return transfer_vars;
                };
                auto use_power_t = [&assignment, &start_row_index, &row, &power_t_instance](std::array<var,12> transfer_vars) {
                    typename fixed_power_type::input_type block_input = {transfer_vars};
                    typename fixed_power_type::result_type block_res =
                        generate_assignments(power_t_instance, assignment, block_input, start_row_index + row);
                    row += power_t_instance.rows_amount;
                    return block_res.output;
                };
                auto vars_to_fp12 = [&assignment](std::array<var,12> o) {
                    std::array<value_type,12> v;
                    for(std::size_t i = 0; i < 12; i++) {
                        v[i] = var_value(assignment, o[i]);
                    }
                    return fp12_element({ {v[0],v[1]}, {v[2],v[3]}, {v[4],v[5]} }, { {v[6],v[7]}, {v[8],v[9]}, {v[10],v[11]} });
                };

                fill_row(X.inversed());                             // 0: x^{-1}
                fill_row(X);                                        // 1: x
                fill_row(X.pow(field_p).pow(field_p).pow(field_p)); // 2: x^{p^3}
                F = X.unitary_inversed(); fill_row(F);              // 3: x^{p^6} = conjugated(x) = conjugated(a + wb) = a - wb
                fill_row(X.inversed());                             // 4: x^{-1}
                F = F * X.inversed(); fill_row(F);                  // 5: x^{p^6 - 1}
                fill_row(F.pow(field_p).pow(field_p));              // 6: (x^{p^6 -1})^{p^2}
                F = F * F.pow(field_p).pow(field_p); fill_row(F);   // 7: f = (x^{p^6 -1})^{p^2 + 1}
                fill_row(F.pow(4));                                 // 8: f^4
                fill_row(F.pow(5));                                 // 9: f^5
                fill_row(F.pow(5).inversed());                      // 10: f^{-5}
                A = vars_to_fp12(use_power_t(row_vars(7)));         // R rows: f^t computation
                fill_row(A);                                        // R+11: f^t
                A = A.pow(2); fill_row(A);                          // R+12: f^{2t}
                A = A.pow(3); fill_row(A);                          // R+13: f^{6t}
                fill_row(F.pow(5).inversed());                      // R+14: f^{-5}
                A = A * F.pow(5).inversed(); fill_row(A);           // R+15: a = f^{6t-5}
                fill_row(A.pow(field_p));                           // R+16: a^p
                B = A.pow(field_p + 1); fill_row(B);                // R+17: b = a^{p+1}
                fill_row(F);                                        // R+18: f
                fill_row(F.pow(field_p));                           // R+19: f^p
                fill_row(F.pow(field_p+1));                         // R+20: f^{p+1}
                fill_row(F.pow(field_p+1).pow(3));                  // R+21: (f^{p+1})^3
                fill_row(F.pow(field_p+1).pow(9));                  // R+22: (f^{p+1})^9
                fill_row(F.pow(field_p));                           // R+23: f^p
                fill_row(F.pow(field_p).pow(2));                    // R+24: f^{2p}
                fill_row(F);                                        // R+25: f
                C = F.pow(field_p).pow(field_p); fill_row(C);       // R+26: f^{p^2}
                fill_row(F.pow(field_p).pow(2));                    // R+27: f^{2p}
                C = C * F.pow(field_p).pow(2); fill_row(C);         // R+28: f^{2p + p^2}
                fill_row(B);                                        // R+29: b
                C = B * C; fill_row(C);                             // R+30: c = b*f^{2p + p^2}
                D = vars_to_fp12(use_power_t(
                                 use_power_t(row_vars(R+30))));     // 2R rows: c^{t^2} computation
                fill_row(D);                                        // 3R+31: c^{t^2}
                D = D.pow(2); fill_row(D);                          // 3R+32: c^{2t^2}
                D = D.pow(3); fill_row(D);                          // 3R+33: c^{6t^2}
                fill_row(C);                                        // 3R+34: c
                D = D * C; fill_row(D);                             // 3R+35: c^{6t^2+1}
                fill_row(F);                                        // 3R+36: f
                fill_row(F.pow(field_p).pow(field_p).pow(field_p)); // 3R+37: f^{p^3}
                fill_row(D);                                        // 3R+38: c^{6t^2+1}
                D = D * F.pow(field_p).pow(field_p).pow(field_p);
                fill_row(D);                                        // 3R+39: f^{p^3} c^{6t^2+1}
                fill_row(B);                                        // 3R+40: b
                D = D * B; fill_row(D);                             // 3R+41: f^{p^3} c^{6t^2+1} b
                fill_row(F.pow(field_p+1).pow(9));                  // 3R+42: (f^{p+1})^9
                D = D * F.pow(field_p+1).pow(9); fill_row(D);       // 3R+43: f^{p^3} c^{6t^2+1} b (f^{p+1})^9
                fill_row(A);                                        // 3R+44: a
                D = D * A; fill_row(D);                             // 3R+45: f^{p^3} c^{6t^2+1} b (f^{p+1})^9 a
                fill_row(F.pow(4));                                 // 3R+46: f^4
                D = D * F.pow(4); fill_row(D);                      // 3R+47: f^{p^3} c^{6t^2+1} b (f^{p+1})^9 a f^4

                return typename plonk_bn_exponentiation<BlueprintFieldType>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_bn_exponentiation<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bn_exponentiation<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_bn_exponentiation<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;

                using fp12_constraint = detail::abstract_fp12_element<constraint_type,BlueprintFieldType>;

                std::vector<std::size_t> gate_list = {};

                fp12_constraint X, Y, Z, C;

                // general setup for all Fp12-unitary gates
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -1, true);
                    Y[i] = var(component.W(i), 0, true);
                }

                // inversion gate #0
                C = X * Y;
                std::vector<constraint_type> inversion_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    inversion_constrs.push_back(C[i] - (i > 0? 0 : 1));
                }
                gate_list.push_back(bp.add_gate(inversion_constrs));

                // power p^k gates #1,2,3
                std::array<std::array<constraint_type,2>,6> Z2;
                std::array<typename BlueprintFieldType::value_type,12> F;
                for( auto &Power : { p_one, p_two, p_three } ) {
                    F = get_fp12_frobenius_coefficients<BlueprintFieldType>(Power);
                    for(std::size_t i = 0; i < 6; i++) {
                        // i -> i/2 + 3(i % 2) is a rearrangement of coefficients by increasing w powers, w.r.t. v = w²
                        Z2[i][0] = X[2*(i/2 + 3*(i % 2))];
                        // Fp2 elements are conjugated when raising to p and p^3
                        Z2[i][1] = X[2*(i/2 + 3*(i % 2)) + 1] * (Power != p_two ? -1 : 1);

                        C[2*(i/2 + 3*(i % 2))] = Z2[i][0]*F[2*i] - Z2[i][1]*F[2*i+1];
                        C[2*(i/2 + 3*(i % 2)) + 1] = Z2[i][0]*F[2*i+1] + Z2[i][1]*F[2*i];
                    }

                    std::vector<constraint_type> frobenius_constrs = {};
                    for(std::size_t i = 0; i < 12; i++) {
                        frobenius_constrs.push_back(C[i] - Y[i]);
                    }
                    gate_list.push_back(bp.add_gate(frobenius_constrs));
                }

                // squaring gate #4
                C = X * X;

                std::vector<constraint_type> square_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    square_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(square_constrs));

                // cubing gate #5
                C = X * X * X;
                std::vector<constraint_type> cube_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    cube_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(cube_constrs));

                // power-4 gate #6
                C = (X * X) * (X * X);
                std::vector<constraint_type> pow4_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    pow4_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(pow4_constrs));

                // multiplication gate (binary) #7
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -1, true);
                    Y[i] = var(component.W(i), 0, true);
                    Z[i] = var(component.W(i), 1, true);
                }
                C = X * Y;

                std::vector<constraint_type> mult_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    mult_constrs.push_back(C[i] - Z[i]);
                }
                gate_list.push_back(bp.add_gate(mult_constrs));

                return gate_list;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_bn_exponentiation<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bn_exponentiation<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index, std::size_t R) { // R = number of rows in external sub-circuit

                using var = typename plonk_bn_exponentiation<BlueprintFieldType>::var;

                // initial data in row 1
                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index + 1, false), instance_input.x[i]});
                }

                std::vector<std::array<std::size_t,2>> pairs = { {0,4}, {10, R+14}, {7, R+18}, {R+19,R+23},
                                                                 {7, R+25}, {R+24,R+27}, {R+17,R+29}, {R+30, 3*R+34},
                                                                 {7, 3*R+36}, {3*R+35, 3*R+38}, {R+17,3*R+40}, {R+22, 3*R+42},
                                                                 {R+15, 3*R+44}, {8, 3*R+46} };
                for( std::array<std::size_t,2> pair : pairs ) {
                    for(std::size_t i = 0; i < 12; i++) {
                        bp.add_copy_constraint({var(component.W(i), start_row_index + pair[0], false),
                                                var(component.W(i), start_row_index + pair[1], false)});
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_bn_exponentiation<BlueprintFieldType>::result_type generate_circuit(
                const plonk_bn_exponentiation<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bn_exponentiation<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_bn_exponentiation<BlueprintFieldType>;
                using var = typename component_type::var;
                using fixed_power_type = typename component_type::fixed_power_type;

                fixed_power_type power_t_instance( component._W, component._C, component._PI, component.T );
                std::size_t R = power_t_instance.rows_amount;

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                auto apply_selector = [&assignment, &selector_index, &start_row_index](
                    std::size_t gate_id, std::vector<std::size_t> apply_list) {
                    for( std::size_t row : apply_list ) {
                        assignment.enable_selector(selector_index[gate_id], start_row_index + row);
                    }
                };
                auto row_vars = [&component, &start_row_index](std::size_t input_row) {
                    std::array<var,12> transfer_vars;
                    for(std::size_t i = 0; i < 12; i++) {
                        transfer_vars[i] = var(component.W(i),start_row_index + input_row,false);
                    }
                    return transfer_vars;
                };

                // inversion gate #0
                apply_selector(0, {1, 10});

                // Frobenius gates (powers p, p^2, p^3) ## 1,2,3
                // p
                apply_selector(1, {R+16, R+19});
                // p^2
                apply_selector(2, {6, R+26});
                // p^3
                apply_selector(3, {2, 3, 3*R+37});

                // squaring gate #4
                apply_selector(4, {R+12, R+24, 3*R+32});

                // cubing gate #5
                apply_selector(5, {R+13, R+21, R+22, 3*R+33});

                // power-4 gate #6
                apply_selector(6, {8});

                // multiplication gate #7
                apply_selector(7, {4, 6, 8, R+14, R+16, R+19, R+27, R+29, 3*R+34, 3*R+38, 3*R+40, 3*R+42, 3*R+44, 3*R+46});

                typename fixed_power_type::input_type power_t_input = {row_vars(7)};
                typename fixed_power_type::result_type power_t_res_1 =
                        generate_circuit(power_t_instance, bp, assignment, power_t_input, start_row_index + 11);
                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({power_t_res_1.output[i], var(component.W(i), start_row_index + R + 11, false)});
                }

                power_t_input = {row_vars(R+30)};
                typename fixed_power_type::result_type power_t_res_2 =
                        generate_circuit(power_t_instance, bp, assignment, power_t_input, start_row_index + R+31);
                power_t_input = {power_t_res_2.output};
                typename fixed_power_type::result_type power_t_res_3 =
                        generate_circuit(power_t_instance, bp, assignment, power_t_input, start_row_index + 2*R+31);
                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({power_t_res_3.output[i], var(component.W(i), start_row_index + 3*R + 31, false)});
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index, R);

                return typename plonk_bn_exponentiation<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BN_EXPONENTIATION_HPP
