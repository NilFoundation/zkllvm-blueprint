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
// @file Declaration of Miller loop component for MNT4 pairings
// Circuit summary:
// 16 witness, 1 constant, 2 gates, 219 rows
// 724 copy constraints
// each gate has 12 constraints, max degree is 4
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_MILLER_LOOP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_MILLER_LOOP_HPP

#include <cstdint>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/types.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp2.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp4.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<std::uint8_t B, typename T>
                std::vector<std::uint8_t> base(T x) {
                    std::vector<std::uint8_t> res = {(std::uint8_t)(x % B)};
                    if (x > 0) {
                        x /= B;
                        while (x > 0) {
                            res.insert(res.begin(), std::uint8_t(x % B));
                            x /= B;
                        }
                    }
                    return res;
                }
            } // namespace detail
              //
            using mnt4_g2_params = crypto3::algebra::curves::detail::
                mnt4_g2_params<298,crypto3::algebra::curves::forms::short_weierstrass>;

            using mnt4_pairing_params = crypto3::algebra::pairing::detail::
                pairing_params<crypto3::algebra::curves::mnt4_298>;

            //
            // Component for computing the result of applying the Miller loop for MNT4 curve
            // to two points P from E(F_p) and Q from E'(F_p^2).
            // Input: P[2], Q[4] ( we assume P and Q are NOT (0,0), i.e. not the points at infinity, NOT CHECKED )
            // Output: f[4]: an element of F_p^4
            //
            // Each iteration of the Miller loop adds "doubling" row to the circuit:
            //
            // f0 f1 f2 f3 P0 P1 T0 T1 T2 T3 Q0 Q1 Q2 Q3 [L0] [L1] L2 L3
            // Gate 0: "doubling"
            // Constraints:
            // 0. UT = untwisted T
            // 1. L = (3*UT.x^2+a)/(2*UT.y)
            // 2. f_next = f*f*(L*(P.x-UT.x) - (P.y - UT.y))
            // 3. T_next = T + T
            //
            // If current iteration needs to add addition, then "addition" row is inserted:
            // f0 f1 f2 f3 P0 P1 T0 T1 T2 T3 Q0 Q1 Q2 Q3 [L0] [L1] L2 L3
            // Gate 1: "addition"
            // Constraints:
            // 0. UT = untwisted T, UQ = untwisted Q
            // 1. L = (UT.y - UQ.y) / (UT.x - UQ.x)
            // 2. f_next = f*(L*(P.x - UT.x) - (P.y - UT.y))
            // 3. T_next = T + Q
            //
            // 219 rows total: 147 doubling and 71 addition + 1 row with result
            // P is copied in addition and doubling rows of the circuit
            // Q is copied only in addition rows.
            // Initial value f (1,0,0,0) is copied from constants column
            //
            // Witnesses for L0 and L1 are removed as they are always zero

            using namespace detail;
            using detail::base;

            template<typename ArithmetizationType>
            class mnt4_miller_loop;

            template<typename BlueprintFieldType>
            class mnt4_miller_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return mnt4_miller_loop::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                        std::size_t witness_amount)
                {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest()
                {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_single_value_param(16)),
                        true // constant column required
                    );
                    return manifest;
                }

                static std::size_t get_rows_amount(
                        std::size_t witness_amount)
                {
                    std::vector<std::uint8_t> C_bin = base<2>(C_val);

                    std::size_t result = 0;

                    // doubling blocks x LineFunctions
                    result += C_bin.size()-1;
                    // adding blocks x LineFunctions
                    result += std::count(C_bin.begin(),C_bin.end(), 1) - 1;
                    // final result (for gate uniformity)
                    result += 1;
                    return result;
                }

                constexpr static integral_type C_val = mnt4_pairing_params::ate_loop_count;
                std::vector<std::uint8_t> C_bin = base<2>(C_val);

                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());

                struct input_type {
                    std::array<var, 2> P;
                    std::array<var, 4> Q;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {P[0], P[1], Q[0], Q[1], Q[2], Q[3]};
                    }
                };

                struct result_type {
                    std::array<var, 4> output;

                    result_type(mnt4_miller_loop const& component, std::uint32_t start_row_index) {
                        std::size_t res_row = start_row_index + component.rows_amount - 1;
                        for(std::size_t i = 0; i < 4; i++) {
                            output[i] = var(component.W(i), res_row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit mnt4_miller_loop(ContainerType witness) :
                    component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                mnt4_miller_loop(
                        WitnessContainerType witness,
                        ConstantContainerType constant,
                        PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                mnt4_miller_loop(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_miller_loop =
                mnt4_miller_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_miller_loop<BlueprintFieldType>::result_type
            generate_assignments(
                plonk_miller_loop<BlueprintFieldType> const& component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                typename plonk_miller_loop<BlueprintFieldType>::input_type const& instance_input,
                const std::uint32_t start_row_index)
            {
                using value_type = typename BlueprintFieldType::value_type;

                using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                using fp2_element = typename policy_type_fp2::value_type;
                using curve_point = std::array<fp2_element,2>;

                using curve_type = nil::crypto3::algebra::curves::mnt4<298>;

                value_type
                    xP = var_value(assignment, instance_input.P[0]),
                    yP = var_value(assignment, instance_input.P[1]);

                std::array<value_type,2>
                    xQ = {
                        var_value(assignment, instance_input.Q[0]),
                        var_value(assignment, instance_input.Q[1])
                    },
                    yQ = {
                        var_value(assignment, instance_input.Q[2]),
                        var_value(assignment, instance_input.Q[3])
                    };

                curve_point Q = { fp2_element(xQ[0], xQ[1]), fp2_element(yQ[0], yQ[1])};

                /* Calculate point doubling on E', affine coordinates */
                auto double_point = [](curve_point const& T) {
                    fp2_element
                        a(curve_type::g2_type<>::params_type::a),
                        lambda = (3*T[0].pow(2) + a) * (2*T[1]).inversed(),
                        xR = lambda.pow(2) - 2*T[0],
                        yR = (3*T[0])*lambda - lambda.pow(3) - T[1];
                    return curve_point({xR, yR});
                };

                /* Calculate point addition on E', affine coordinates */
                auto add_points = [](curve_point const& T, curve_point const& Q) {
                    fp2_element
                        lambda = (T[1] - Q[1])*(T[0] - Q[0]).inversed(),
                        xR = lambda*lambda - T[0] - Q[0],
                        yR = (2*T[0] + Q[0])*lambda - lambda.pow(3) - T[1];
                    return curve_point({xR, yR});
                };

                using policy_type_fp4 = crypto3::algebra::fields::fp4<BlueprintFieldType>;
                using fp4_element = typename policy_type_fp4::value_type;

                auto insert_row_doubling = [
                    &double_point, &assignment, &component, &start_row_index, &xP, &yP]
                    (fp4_element const& f, curve_point& T, std::size_t row)
                    {
                        fp4_element x, y, x1, y1, g, three({{3,0},{0,0}});

                        x  = fp4_element({ {xP, 0}, {0, 0} });
                        y  = fp4_element({ {yP, 0}, {0, 0} });

                        // Untwisting: E'/Fp2 -> E/Fp4
                        // x * u^-1, y * (uv)^-1
                        // MNT4 nr = 0x11,
                        // u = (0,1), v = ((0,0), (1,0))
                        // u^2 = nr, v^2 = u
                        // u = ((0,1),(0,0)), u^-1 = ((0,1/nr),(0,0))
                        // v = ((0,0),(1,0)), (uv)^-1 = ((0,0), (1/nr, 0))
                        //
                        // ((x0,x1),(x2,x3)) * ((0,1/nr),(0,0)) = ( (x1, x0/nr), (x3, x2/nr) )
                        // ((x0,x1),(x2,x3)) * ((0,0),(1/nr,0)) = ( (x3, x2/nr), (x0/nr, x1/nr) )
                        //
                        // T is in form (X,Y)/Fp2:
                        // X: ((x0,x1),(0,0)) * ((0,1/nr),(0,0)) = ( (x1, x0/nr), (0, 0) )
                        // Y: ((y0,y1),(0,0)) * ((0,0),(1/nr,0)) = ( (0, 0), (y0/nr, y1/nr) )
                        //
                        value_type nri = policy_type_fp2::extension_policy::non_residue.inversed();

                        x1 = fp4_element({ {T[0].data[1], T[0].data[0]*nri }, {0,0} });
                        y1 = fp4_element({ {0,0}, {T[1].data[0]*nri, T[1].data[1]*nri}});

                        fp4_element a({{curve_type::g1_type<>::params_type::a,0},{0,0}});

                        fp4_element lf =(three*x1.pow(2) + a)*(y1+y1).inversed();
                        g = f.pow(2) * (lf*(x-x1) + (y1-y));

                        // f
                        assignment.witness(component.W(0),start_row_index + row) = f.data[0].data[0];
                        assignment.witness(component.W(1),start_row_index + row) = f.data[0].data[1];
                        assignment.witness(component.W(2),start_row_index + row) = f.data[1].data[0];
                        assignment.witness(component.W(3),start_row_index + row) = f.data[1].data[1];

                        // P
                        assignment.witness(component.W(4),start_row_index + row ) = xP;
                        assignment.witness(component.W(5),start_row_index + row ) = yP;

                        // T <- T+T
                        assignment.witness(component.W(6),start_row_index + row) = T[0].data[0];
                        assignment.witness(component.W(7),start_row_index + row) = T[0].data[1];
                        assignment.witness(component.W(8),start_row_index + row) = T[1].data[0];
                        assignment.witness(component.W(9),start_row_index + row) = T[1].data[1];
                        T = double_point(T);

                        // Q is not used in doubling rows
                        assignment.witness(component.W(10),start_row_index + row) = 0;
                        assignment.witness(component.W(11),start_row_index + row) = 0;
                        assignment.witness(component.W(12),start_row_index + row) = 0;
                        assignment.witness(component.W(13),start_row_index + row) = 0;

                        // lf
                        // lf.data[0] is always zero, not inserted into witness columns
                        assignment.witness(component.W(14),start_row_index + row) = lf.data[1].data[0];
                        assignment.witness(component.W(15),start_row_index + row) = lf.data[1].data[1];
                        return g;
                    };

                auto insert_row_addition = [
                    &add_points, &assignment, &component, &start_row_index, &xP, &yP, &Q]
                    (fp4_element const& f, curve_point& T, std::size_t row)
                    {
                        fp4_element x, y, x1, y1, x2, y2, lf, g;

                        x  = fp4_element({ {xP, 0}, {0, 0} });
                        y  = fp4_element({ {yP, 0}, {0, 0} });

                        value_type nri = policy_type_fp2::extension_policy::non_residue.inversed();

                        // Untwist T and Q: E'/Fp2 -> E/Fp4
                        x1 = fp4_element({ {T[0].data[1], T[0].data[0]*nri }, {0, 0} });
                        y1 = fp4_element({ {0, 0}, {T[1].data[0]*nri, T[1].data[1]*nri}});

                        x2 = fp4_element({ {Q[0].data[1], Q[0].data[0]*nri }, {0, 0} });
                        y2 = fp4_element({ {0, 0}, {Q[1].data[0]*nri, Q[1].data[1]*nri}});

                        lf = (y2-y1)*(x2-x1).inversed();
                        g = f * (lf*(x-x1) + y1 - y);

                        // f
                        assignment.witness(component.W(0),start_row_index + row) = f.data[0].data[0];
                        assignment.witness(component.W(1),start_row_index + row) = f.data[0].data[1];
                        assignment.witness(component.W(2),start_row_index + row) = f.data[1].data[0];
                        assignment.witness(component.W(3),start_row_index + row) = f.data[1].data[1];

                        // P
                        assignment.witness(component.W(4),start_row_index + row ) = xP;
                        assignment.witness(component.W(5),start_row_index + row ) = yP;

                        // T <- T+Q
                        assignment.witness(component.W(6),start_row_index + row) = T[0].data[0];
                        assignment.witness(component.W(7),start_row_index + row) = T[0].data[1];
                        assignment.witness(component.W(8),start_row_index + row) = T[1].data[0];
                        assignment.witness(component.W(9),start_row_index + row) = T[1].data[1];
                        T = add_points(T, Q);

                        // Q
                        assignment.witness(component.W(10),start_row_index + row) = Q[0].data[0];
                        assignment.witness(component.W(11),start_row_index + row) = Q[0].data[1];
                        assignment.witness(component.W(12),start_row_index + row) = Q[1].data[0];
                        assignment.witness(component.W(13),start_row_index + row) = Q[1].data[1];

                        // lf
                        // lf.data[0] is always zero, not inserted into witness columns
                        assignment.witness(component.W(14),start_row_index + row) = lf.data[1].data[0];
                        assignment.witness(component.W(15),start_row_index + row) = lf.data[1].data[1];
                        return g;
                    };

                std::size_t rel_row = 0;

                fp4_element f = fp4_element::one();
                curve_point T = Q;

                /* Miller loop */
                for(std::size_t i = 1; i < component.C_bin.size(); ++i) {
                    f = insert_row_doubling(f, T, rel_row++);
                    if (component.C_bin[i]) {
                        f = insert_row_addition(f, T, rel_row++);
                    }
                }

                // The last row contains the result, f.
                // f
                assignment.witness(component.W(0),start_row_index + rel_row) = f.data[0].data[0];
                assignment.witness(component.W(1),start_row_index + rel_row) = f.data[0].data[1];
                assignment.witness(component.W(2),start_row_index + rel_row) = f.data[1].data[0];
                assignment.witness(component.W(3),start_row_index + rel_row) = f.data[1].data[1];

                /*
                // P
                assignment.witness(component.W(4),start_row_index + rel_row ) = xP;
                assignment.witness(component.W(5),start_row_index + rel_row ) = yP;
                */

                /* T is needed as previous row has constraints on it */
                assignment.witness(component.W(6),start_row_index + rel_row) = T[0].data[0];
                assignment.witness(component.W(7),start_row_index + rel_row) = T[0].data[1];
                assignment.witness(component.W(8),start_row_index + rel_row) = T[1].data[0];
                assignment.witness(component.W(9),start_row_index + rel_row) = T[1].data[1];

                /*
                // Q
                assignment.witness(component.W(10),start_row_index + rel_row) = Q[0].data[0];
                assignment.witness(component.W(11),start_row_index + rel_row) = Q[0].data[1];
                assignment.witness(component.W(12),start_row_index + rel_row) = Q[1].data[0];
                assignment.witness(component.W(13),start_row_index + rel_row) = Q[1].data[1];
                */

                return typename plonk_miller_loop<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t>
            generate_gates(
                plonk_miller_loop<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_miller_loop<BlueprintFieldType>::input_type &instance_input)
            {
                using var = typename plonk_miller_loop<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using curve_type = nil::crypto3::algebra::curves::mnt4<298>;
                using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;

                using fp2_constraint = detail::abstract_fp2_element<
                    constraint_type, BlueprintFieldType>;

                using fp4_constraint = detail::abstract_fp4_element<
                    constraint_type, BlueprintFieldType>;

                using value_type = typename BlueprintFieldType::value_type;

                fp2_constraint C2;
                fp4_constraint C4;

                std::vector<std::size_t> gate_list = {};
                constraint_type c_zero = constraint_type(), c_one = c_zero + 1;
                constraint_type c_g1_a = c_zero + curve_type::g1_type<>::params_type::a;
                constraint_type c_g2_a0 = c_zero + curve_type::g2_type<>::params_type::a.data[0];
                constraint_type c_g2_a1 = c_zero + curve_type::g2_type<>::params_type::a.data[1];

                value_type nri = policy_type_fp2::extension_policy::non_residue.inversed();

                /* Constraints for the doubling gate
                 * 1. f = f_prev^2 * line_function_doubling(T,T,P)
                 * 2. T_next = T + T
                 */
                std::vector<constraint_type> doubling_constrs = {};
                {
                fp4_constraint
                    one4 = {c_one, c_zero, c_zero, c_zero },
                    a4 = { c_g1_a, c_zero, c_zero, c_zero, },
                    f = {
                        var(component.W(0), 0, true),
                        var(component.W(1), 0, true),
                        var(component.W(2), 0, true),
                        var(component.W(3), 0, true)
                    },
                    fnext = {
                        var(component.W(0), 1, true),
                        var(component.W(1), 1, true),
                        var(component.W(2), 1, true),
                        var(component.W(3), 1, true)
                    },
                    x = {
                        var(component.W(4), 0, true),
                        c_zero, c_zero, c_zero
                    },
                    y = {
                        var(component.W(5), 0, true),
                        c_zero, c_zero, c_zero
                    },
                    x1 = {
                        var(component.W(7), 0, true),
                        var(component.W(6), 0, true) * nri,
                        c_zero, c_zero
                    },
                    y1 = {
                        c_zero, c_zero,
                        var(component.W(8), 0, true) * nri,
                        var(component.W(9), 0, true) * nri
                    },
                    lf = {
                        c_zero, c_zero,
                        var(component.W(14), 0, true),
                        var(component.W(15), 0, true),
                    };

                C4 = lf*(2*y1) - (3*x1*x1 + a4);
                for(auto const& c: C4.x) {
                    doubling_constrs.push_back(c);
                }

                C4 = fnext - f*f*(lf*(x - x1) - (y - y1));
                for(auto const& c: C4.x) {
                    doubling_constrs.push_back(c);
                }
                }

                /* Constraints for point doubling: Tnext = T + T:
                 * Tnext.x = (3*T.x^2+a)^2/(2T.y)^2 - 2T.x
                 * Tnext.y = (3*T.x^2+a)/2T.y *(T.x-Tnext.x)-T.y
                 * Rewrite:
                 * (Tnext.x + 2*Tx) * (2*T.y)^2 - (3*T.x^2+a)^2 = 0
                 * (Tnext.y + T.y) * (2*T.y) - (3*T.x^2+a)*(T.x-Tnext.x) = 0
                 */
                fp2_constraint
                    a = {c_g2_a0, c_g2_a1},
                    Tx  = {var(component.W(6), 0, true), var(component.W(7), 0, true)},
                    Ty  = {var(component.W(8), 0, true), var(component.W(9), 0, true)},
                    Tnx = {var(component.W(6), 1, true), var(component.W(7), 1, true)},
                    Tny = {var(component.W(8), 1, true), var(component.W(9), 1, true)};

                C2 = (Tnx + 2*Tx)*(2*Ty)*(2*Ty) - (3*Tx*Tx + a)*(3*Tx*Tx + a);
                doubling_constrs.push_back(C2[0]);
                doubling_constrs.push_back(C2[1]);

                C2 = (Tny + Ty)*(2*Ty) - (3*Tx*Tx + a)*(Tx - Tnx);
                doubling_constrs.push_back(C2[0]);
                doubling_constrs.push_back(C2[1]);

                gate_list.push_back(bp.add_gate(doubling_constrs));

                /* Constraints for the addition row
                 * 1. f = f_prev * line_function_addition(T,Q,P)
                 * 2. T = T_prev + Q
                 */
                std::vector<constraint_type> adding_constrs = {};
                {
                fp4_constraint
                    f = {
                        var(component.W(0), 0, true),
                        var(component.W(1), 0, true),
                        var(component.W(2), 0, true),
                        var(component.W(3), 0, true)
                    },
                    fnext = {
                        var(component.W(0), 1, true),
                        var(component.W(1), 1, true),
                        var(component.W(2), 1, true),
                        var(component.W(3), 1, true)
                    },
                    x = {
                        var(component.W(4), 0, true),
                        c_zero, c_zero, c_zero
                    },
                    y = {
                        var(component.W(5), 0, true),
                        c_zero, c_zero, c_zero
                    },
                    x1 = {
                        var(component.W(7), 0, true),
                        var(component.W(6), 0, true) * nri,
                        c_zero, c_zero
                    },
                    y1 = {
                        c_zero, c_zero,
                        var(component.W(8), 0, true) * nri,
                        var(component.W(9), 0, true) * nri
                    },
                    x2 = {
                        var(component.W(11), 0, true),
                        var(component.W(10), 0, true) * nri,
                        c_zero, c_zero
                    },
                    y2 = {
                        c_zero, c_zero,
                        var(component.W(12), 0, true) * nri,
                        var(component.W(13), 0, true) * nri
                    },
                    lf = {
                        c_zero, c_zero,
                        var(component.W(14), 0, true),
                        var(component.W(15), 0, true),
                    };

                C4 = lf*(x2 - x1) - (y2 - y1);
                for(auto const& c: C4.x) {
                    adding_constrs.push_back(c);
                }

                C4 = fnext - f*(lf*(x-x1) - (y-y1));
                for(auto const& c: C4.x) {
                    adding_constrs.push_back(c);
                }

                }

                /* Constraints for point addition: Tnext = T + Q:
                 * Tnext.x = (Q.y - T.y)^2/(Q.x - T.x)^2- T.x - Q.x
                 * Tnext.y = (Q.y - T.y)/(Q.x - T.x)*(T.x - Tnext.x) - T.y
                 * Rewrite:
                 * (Tnext.x + T.x + Q.x)*(Q.x - T.x)^2 - (Q.y - T.y)^2 = 0
                 * (Tnext.y + T.y)*(Q.x - T.x) - (Q.y - T.y) * (T.x - Tnext.x) = 0
                */
                fp2_constraint
                    Qx  = {var(component.W(10), 0, true), var(component.W(11), 0, true)},
                    Qy  = {var(component.W(12), 0, true), var(component.W(13), 0, true)};

                C2 = (Tnx + Tx + Qx)*(Qx - Tx)*(Qx - Tx) - (Qy - Ty)*(Qy - Ty);
                adding_constrs.push_back(C2[0]);
                adding_constrs.push_back(C2[1]);

                C2 = (Tny + Ty)*(Qx - Tx) - (Qy - Ty)*(Tx - Tnx);
                adding_constrs.push_back(C2[0]);
                adding_constrs.push_back(C2[1]);

                gate_list.push_back(bp.add_gate(adding_constrs));

                return gate_list;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                plonk_miller_loop<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_miller_loop<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {

                using component_type = plonk_miller_loop<BlueprintFieldType>;
                using var = typename component_type::var;

                /* Copy constraints for f in the first row to constants (1,0,0,0) in constant column */
                bp.add_copy_constraint({
                    var(0, start_row_index + 1, false, var::column_type::constant),
                    var(component.W(0), start_row_index, false)});
                bp.add_copy_constraint({
                    var(0, start_row_index, false, var::column_type::constant),
                    var(component.W(1), start_row_index, false)});
                bp.add_copy_constraint({
                    var(0, start_row_index, false, var::column_type::constant),
                    var(component.W(2), start_row_index, false)});
                bp.add_copy_constraint({
                    var(0, start_row_index, false, var::column_type::constant),
                    var(component.W(3), start_row_index, false)});

                /* T on the first row is Q */
                bp.add_copy_constraint({var(component.W(6), start_row_index, false), instance_input.Q[0]});
                bp.add_copy_constraint({var(component.W(7), start_row_index, false), instance_input.Q[1]});
                bp.add_copy_constraint({var(component.W(8), start_row_index, false), instance_input.Q[2]});
                bp.add_copy_constraint({var(component.W(9), start_row_index, false), instance_input.Q[3]});

                std::size_t row = 0;

                /* Copy P and Q along the circuit */
                for(std::size_t i = 1; i < component.C_bin.size(); ++i) {
                    // P
                    bp.add_copy_constraint({var(component.W(4), start_row_index + row, false), instance_input.P[0]});
                    bp.add_copy_constraint({var(component.W(5), start_row_index + row, false), instance_input.P[1]});
                    ++row;

                    if (component.C_bin[i]) {
                        // P
                        bp.add_copy_constraint({var(component.W(4), start_row_index + row, false), instance_input.P[0]});
                        bp.add_copy_constraint({var(component.W(5), start_row_index + row, false), instance_input.P[1]});
                        // Q
                        bp.add_copy_constraint({var(component.W(10), start_row_index + row, false), instance_input.Q[0]});
                        bp.add_copy_constraint({var(component.W(11), start_row_index + row, false), instance_input.Q[1]});
                        bp.add_copy_constraint({var(component.W(12), start_row_index + row, false), instance_input.Q[2]});
                        bp.add_copy_constraint({var(component.W(13), start_row_index + row, false), instance_input.Q[3]});
                        ++row;
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_miller_loop<BlueprintFieldType>::result_type
            generate_circuit(
                plonk_miller_loop<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_miller_loop<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {
                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                std::size_t row = 0;
                for(std::size_t i = 1; i < component.C_bin.size(); i++) {
                    assignment.enable_selector(selector_index[0], start_row_index + row);
                    ++row;
                    if (component.C_bin[i]) {
                        assignment.enable_selector(selector_index[1], start_row_index + row);
                        ++row;
                    }
                }

                return typename plonk_miller_loop<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const plonk_miller_loop<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_miller_loop<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                // '0' to make copy-constraints with
                assignment.constant(component.C(0), start_row_index) = 0;
                // '1' to make copy-constraints with
                assignment.constant(component.C(0), start_row_index + 1) = 1;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MILLER_LOOP_HPP
