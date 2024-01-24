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
// @file Declaration of unified Miller loop component for BLS12 and BN pairings
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MILLER_LOOP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MILLER_LOOP_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp12.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/fp12_frobenius_coefs.hpp>

#include <nil/blueprint/components/algebra/curves/detail/plonk/bls12_g2_point_addition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<unsigned short int B, typename T>
                std::vector<unsigned short int> base(T x) {
                    std::vector<unsigned short int> res = {x % B};
                    if (x > 0) {
                        x /= B;
                        while (x > 0) {
                            res.insert(res.begin(), x % B);
                            x /= B;
                        }
                    }
                    return res;
                }
            } // namespace detail

            //
            // Component for computing the result of applying the Miller loop
            // to two points P from E(F_p) and Q from E'(F_p^2).
            // The loop parameter C_val is passed to the constructor.
            // Input: P[2], Q[4] ( we assume P and Q are NOT (0,0), i.e. not the points at infinity, NOT CHECKED )
            // Output: f[12]: an element of F_p^12
            //
            // Each iteration of the Miller loop adds two rows to the circuit:
            // +------+------+------+------+------+------+-------+-------+-------+-------+
            // | f[0] | f[1] | f[2] | f[3] | f[4] | f[5] | f[6]  | f[7]  |  .... | f[11] |
            // +------+------+------+------+------+------+-------+-------+-------+-------+
            // | P[0] | P[1] | T[0] | T[1] | T[2] | T[3] | ZC[0] | ZC[1] |               |
            // +------+------+------+------+------+------+-------+-------+---------------+
            //
            // These two rows are always followed by two similar rows with f := f² * LineFunction(P,T,T) and T:=T+T
            // In case the current bit of the loop-driving bit sequence iz 0, these two rows are formed by the
            // next iteration of the loop. In case this bit is 1, these two rows are part of the addition block.
            // The addition block is designed as follows:
            // +------+------+------+------+------+------+-------+-------+------+------+-------+-------+
            // | f[0] | f[1] | f[2] | f[3] | f[4] | f[5] | f[6]  | f[7]  | f[8] | f[9] | f[10] | f[11] |
            // +------+------+------+------+------+------+-------+-------+------+------+-------+-------+
            // |      |      | T[0] | T[1] | T[2] | T[3] |                                             |
            // +------+------+------+------+------+------+---------------------------------------------+
            // |                                                                                       |
            // |               External subcomponent assuring the computation of T + Q                 |
            // |                                                                                       |
            // +------+------+------+------+------+------+-------+-------+------+------+-------+-------+
            // | f[0] | f[1] | f[2] | f[3] | f[4] | f[5] | f[6]  | f[7]  | f[8] | f[9] | f[10] | f[11] |
            // +------+------+------+------+------+------+-------+-------+------+------+-------+-------+
            // | P[0] | P[1] | T[0] | T[1] | T[2] | T[3] | Q[0]  | Q[1]  | Q[2] | Q[3] |       |       |
            // +------+------+------+------+------+------+-------+-------+------+------+-------+-------+
            //
            // The last two rows contain the result of the Miller loop and the result of the last point operation
            // (this point data is irrelevant, but kept for the sake of gate uniformity):
            // +------+------+------+------+------+------+------+-------+
            // | f[0] | f[1] | f[2] | f[3] | f[4] | f[5] | .... | f[11] |
            // +------+------+------+------+------+------+------+-------+
            // |      |      | T[0] | T[1] | T[2] | T[3] |              |
            // +------+------+------+------+------+------+--------------+
            //
            using namespace detail;
            using detail::base;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class miller_loop;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class miller_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using point_addition_type = bls12_g2_point_addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return miller_loop::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount))
                        .merge_with(point_addition_type::get_gate_manifest(witness_amount,lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(12)),
                        true // constant column required
                    ).merge_with(point_addition_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, unsigned long long C_val) {
                    std::vector<unsigned short int> C_bin = base<2>(C_val);

                    return (C_bin.size()-1)*2 + // doubling LineFunctions
                                        (std::count(C_bin.begin(),C_bin.end(),1)-1)* // number of Adding blocks
                                        // LineFunction and point adder
                                        (4 + point_addition_type::get_rows_amount(witness_amount, lookup_column_amount))
                                        + 2; // final result and extra point (for gate uniformity)
                }

                unsigned long long C_val;
                std::vector<unsigned short int> C_bin = base<2>(C_val);

                constexpr static const std::size_t gates_amount = 3;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, C_val);

                struct input_type {
                    std::array<var,2> P;
                    std::array<var,4> Q;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {P[0], P[1], Q[0], Q[1], Q[2], Q[3]};
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const miller_loop &component, std::uint32_t start_row_index) {
                        std::size_t res_row = start_row_index + component.rows_amount - 2;
                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W(i), res_row, false, var::column_type::witness);
                        }
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit miller_loop(ContainerType witness, unsigned long long C_val_) :
                    component_type(witness, {}, {}, get_manifest()), C_val(C_val_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                miller_loop(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, unsigned long long C_val_) :
                    component_type(witness, constant, public_input, get_manifest()), C_val(C_val_) {};

                miller_loop(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs, unsigned long long C_val_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()), C_val(C_val_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_miller_loop =
                miller_loop<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;

                using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                using fp2_element = typename policy_type_fp2::value_type;
                using curve_point = std::array<fp2_element,2>;
                using point_addition_type = typename component_type::point_addition_type;

                std::vector<unsigned short int> C_bin = component.C_bin;

                point_addition_type point_addition_instance( component._W, component._C, component._PI);

                value_type xP = var_value(assignment, instance_input.P[0]),
                           yP = var_value(assignment, instance_input.P[1]);

                std::array<value_type,2> xQ = {var_value(assignment, instance_input.Q[0]), var_value(assignment, instance_input.Q[1])},
                                         yQ = {var_value(assignment, instance_input.Q[2]), var_value(assignment, instance_input.Q[3])};
                curve_point Q = { fp2_element(xQ[0], xQ[1]), fp2_element(yQ[0], yQ[1])};

                auto double_point = [](curve_point P) {
                    fp2_element lambda = 3*P[0].pow(2) / (2*P[1]),
                                nu = P[1] - lambda*P[0],
                                xR = lambda.pow(2) - 2*P[0],
                                yR = -(lambda*xR + nu);
                    return curve_point({xR, yR});
                };

                auto add_point_Q = [&assignment, &component, &start_row_index, &instance_input, &point_addition_instance]
                                               (std::size_t input_row, std::size_t rel_row) {
                    std::array<var,4> T, Q;
                    for(std::size_t i = 0; i < 4; i++) {
                        T[i] = var(component.W(2 + i),start_row_index + input_row,false);
                        Q[i] = instance_input.Q[i];
                    }
                    typename point_addition_type::input_type block_input = {T,Q};
                    typename point_addition_type::result_type block_res =
                        generate_assignments(point_addition_instance, assignment, block_input, start_row_index + rel_row);

                    std::array<value_type,4> R;
                    for(std::size_t i = 0; i < 4; i++) {
                        R[i] = var_value(assignment, block_res.R[i]);
                    }
                    return curve_point({fp2_element(R[0],R[1]),fp2_element(R[2],R[3])});
                };

                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                auto LineFunctionDouble = [&assignment, &component, &start_row_index, &xP, &yP](
                        fp12_element f, curve_point t, std::size_t row) {
                    fp2_element ty_inv = t[1].inversed();
                    std::array<value_type,6> T = { t[0].data[0], t[0].data[1], t[1].data[0], t[1].data[1], ty_inv.data[0], ty_inv.data[1] };

                    fp12_element x  = fp12_element::one() * xP,
                                 y  = fp12_element::one() * yP,
                                 x1 = fp12_element({ {0,0}, {0,0}, {(T[1] + T[0])/2, (T[1] - T[0])/2} }, { {0,0}, {0,0}, {0,0} }),
                                 y1 = fp12_element({ {0,0}, {0,0}, {0,0}}, { {0,0}, {(T[3] + T[2])/2, (T[3] - T[2])/2} , {0,0} }),
                                 g = f.pow(2) * (3*x1.pow(2)*(x-x1)*((2*y1).inversed()) + y1 - y);

                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W(i),start_row_index + row) = f.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    assignment.witness(component.W(0),start_row_index + row + 1) = xP;
                    assignment.witness(component.W(1),start_row_index + row + 1) = yP;
                    for(std::size_t i = 0; i < 6; i++) {
                        assignment.witness(component.W(2 + i),start_row_index + row + 1) = T[i];
                    }
                    return g;
                };

                auto LineFunctionAdd = [&assignment, &component, &start_row_index, &xP, &yP, &xQ, &yQ](
                        fp12_element f, curve_point t, std::size_t row) {
                    std::array<value_type,4> T = {t[0].data[0], t[0].data[1], t[1].data[0], t[1].data[1]};

                    fp12_element x  = fp12_element::one() * xP,
                                 y  = fp12_element::one() * yP,
                                 x1 = fp12_element({ {0,0}, {0,0}, {(T[1] + T[0])/2, (T[1] - T[0])/2} }, { {0,0}, {0,0}, {0,0} }),
                                 y1 = fp12_element({ {0,0}, {0,0}, {0,0}}, { {0,0}, {(T[3] + T[2])/2, (T[3] - T[2])/2} , {0,0} }),
                                 x2 = fp12_element({ {0,0}, {0,0}, {(xQ[1] + xQ[0])/2, (xQ[1] - xQ[0])/2} }, { {0,0}, {0,0}, {0,0} }),
                                 y2 = fp12_element({ {0,0}, {0,0}, {0,0}}, { {0,0}, {(yQ[1] + yQ[0])/2, (yQ[1] - yQ[0])/2} , {0,0} }),
                                 l = (y2-y1)*(x2-x1).inversed(),
                                 g = f * (l*(x-x1) + y1 - y);
                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W(i),start_row_index + row) = f.data[i/6].data[(i % 6)/2].data[i % 2];
                    }

                    std::vector<value_type> second_row = {xP, yP, T[0], T[1], T[2], T[3], xQ[0], xQ[1], yQ[0], yQ[1]};
                    for(std::size_t i = 0; i < 10; i++) {
                        assignment.witness(component.W(i),start_row_index + row + 1) = second_row[i];
                    }
                    return g;
                };

                std::size_t rel_row = 0; // current row relative number
                fp12_element f = fp12_element::one(); // initial f value for Miller loop is 1
                curve_point T = Q;

                for(std::size_t i = 1; i < C_bin.size(); i++) {
                    f = LineFunctionDouble(f,T,rel_row);
                    T = double_point(T);
                    rel_row += 2; // 2 rows for each LineFunction
                    if (C_bin[i]) {
                        // fill in the output row of the previous doubling LineFunction
                        for(std::size_t j = 0; j < 12; j++) {
                            assignment.witness(component.W(j), start_row_index + rel_row) = f.data[j/6].data[(j % 6)/2].data[j % 2];
                        }
                        rel_row++;
                        // fill in the output doubled point
                        for(std::size_t j = 0; j < 4; j++) {
                            assignment.witness(component.W(j+2), start_row_index + rel_row) = T[j/2].data[j % 2];
                        }
                        rel_row++;
                        // perform point addition
                        curve_point TplusQ = add_point_Q(rel_row - 1, rel_row); // argument row, output row
                        rel_row += point_addition_instance.rows_amount;

                        f = LineFunctionAdd(f,T,rel_row);
                        T = TplusQ;
                        rel_row += 2; // 2 rows for each LineFunction
                    }
                }
                // the result
                for(std::size_t j = 0; j < 12; j++) {
                    assignment.witness(component.W(j), start_row_index + rel_row) = f.data[j/6].data[(j % 6)/2].data[j % 2];
                }
                // the extra point for gate uniformity
                for(std::size_t j = 0; j < 4; j++) {
                    assignment.witness(component.W(j+2), start_row_index + rel_row + 1) = T[j/2].data[j % 2];
                }

                return typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp2_constraint = detail::abstract_fp2_element<constraint_type>;

                std::vector<std::size_t> gate_list = {};

                constraint_type cnstr_zero = constraint_type(),
                                 cnstr_one = cnstr_zero + 1;
                fp2_constraint one = {cnstr_one, cnstr_zero},
                                xQ = {var(component.W(2),-1,true),
                                      var(component.W(3),-1,true)},
                                yQ = {var(component.W(4),-1,true),
                                      var(component.W(5),-1,true)},
                                ZC = {var(component.W(6),-1,true),
                                      var(component.W(7),-1,true)},
                                xR = {var(component.W(2),1,true),
                                      var(component.W(3),1,true)},
                                yR = {var(component.W(4),1,true),
                                      var(component.W(5),1,true)},
                                C;

                // the defining equations are
                // xR = (3xQ^2 / 2yP)^2 - 2xQ
                // yR = - (3xQ^2 / 2yQ) xR - yQ + (3xQ^2 / 2yQ)xQ
                // We transform them into constraints:
                // (2yQ)^2 (xR + 2xQ) - (3xQ^2)^2 = 0
                // (2yQ) (yR + yQ) + (3xQ^2)(xR - xQ) = 0
                // Additional constraint to assure that the double of (0,0) is (0,0):
                // (ZC * yQ - 1) * yQ = 0
                // (ZC * yQ - 1) * xR = 0
                // (ZC * yQ - 1) * yR = 0
                std::vector<constraint_type> doubling_constrs = {};

                C = (2*yQ)*(2*yQ)*(xR + 2*xQ) - (3*xQ*xQ)*(3*xQ*xQ);
                doubling_constrs.push_back(C[0]);
                doubling_constrs.push_back(C[1]);

                C = (2*yQ)*(yR + yQ) + (3*xQ*xQ)*(xR - xQ);
                doubling_constrs.push_back(C[0]);
                doubling_constrs.push_back(C[1]);

                C = (ZC*yQ - one)*yQ;
                doubling_constrs.push_back(C[0]);
                doubling_constrs.push_back(C[1]);

                C = (ZC*yQ - one)*xR;
                doubling_constrs.push_back(C[0]);
                doubling_constrs.push_back(C[1]);

                C = (ZC*yQ - one)*yR;
                doubling_constrs.push_back(C[0]);
                doubling_constrs.push_back(C[1]);

                gate_list.push_back(bp.add_gate(doubling_constrs));

                // All the following constraints are for Fp12 elements
                using fp12_constraint = detail::abstract_fp12_element<constraint_type,BlueprintFieldType>;

                // LineFunction Doubling case gate
                fp12_constraint X, Y, twoX1, twoY1, F, G, C12;
                for(std::size_t i = 0; i < 12; i++) {
                    F[i] = var(component.W(i), -1, true);
                    G[i] = var(component.W(i), 1, true);
                    X[i] = constraint_type();
                    Y[i] = constraint_type();
                    twoX1[i] = constraint_type();
                    twoY1[i] = constraint_type();
                }
                X[0] = var(component.W(0), 0, true);
                Y[0] = var(component.W(1), 0, true);
                twoX1[4] = var(component.W(3),0, true) + var(component.W(2),0, true);
                twoX1[5] = var(component.W(3),0, true) - var(component.W(2),0, true);
                twoY1[8] = var(component.W(5),0, true) + var(component.W(4),0, true);
                twoY1[9] = var(component.W(5),0, true) - var(component.W(4),0, true);

                C12 = 8*twoY1*G - F*F*(6*twoX1*twoX1*X - 3*twoX1*twoX1*twoX1 + 4*twoY1*twoY1 - 8*twoY1*Y);
                std::vector<constraint_type> line_func_double_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    line_func_double_constrs.push_back(C12[i]);
                }
                gate_list.push_back(bp.add_gate(line_func_double_constrs));

                // LineFunction Adding case gate
                fp12_constraint twoX2, twoY2;
                // we REUSE X, Y, twoX1, twoX2, F, G from the previous gate and REDEFINE C12
                for(std::size_t i = 0; i < 12; i++) {
                    twoX2[i] = constraint_type();
                    twoY2[i] = constraint_type();
                }
                twoX2[4] = var(component.W(7),0, true) + var(component.W(6),0, true);
                twoX2[5] = var(component.W(7),0, true) - var(component.W(6),0, true);
                twoY2[8] = var(component.W(9),0, true) + var(component.W(8),0, true);
                twoY2[9] = var(component.W(9),0, true) - var(component.W(8),0, true);

                C12 = 2*(twoX2 - twoX1)*G - F*((twoY2 - twoY1)*(2*X - twoX1) - (2*Y - twoY1)*(twoX2 - twoX1));
                std::vector<constraint_type> line_func_add_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    line_func_add_constrs.push_back(C12[i]);
                }
                gate_list.push_back(bp.add_gate(line_func_add_constrs));

                return gate_list;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using point_addition_type = typename component_type::point_addition_type;

                point_addition_type point_addition_instance( component._W, component._C, component._PI);

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                std::vector<unsigned short int> C_bin = component.C_bin;

                // Copy constraints for the 0-th f row to constants (1,0,...,0) in constant column
                bp.add_copy_constraint({var(0, start_row_index + 1, false, var::column_type::constant),
                                        var(component.W(0), start_row_index, false)});
                for(std::size_t j = 1; j < 12; j++) {
                    bp.add_copy_constraint({var(0, start_row_index, false, var::column_type::constant),
                                            var(component.W(j), start_row_index, false)});
                }
                std::size_t rel_row = 0;
                for(std::size_t j = 0; j < 4; j++) {
                    bp.add_copy_constraint({ var(component.W(2+j),start_row_index + 1), instance_input.Q[j]});
                }

                for(std::size_t i = 1; i < C_bin.size(); i++) {
                    bp.add_copy_constraint({var(component.W(0),start_row_index + rel_row + 1),instance_input.P[0]});
                    bp.add_copy_constraint({var(component.W(1),start_row_index + rel_row + 1),instance_input.P[1]});
                    assignment.enable_selector(selector_index[1], start_row_index + rel_row + 1); // doubling LineFunction gate
                    assignment.enable_selector(selector_index[0], start_row_index + rel_row + 2); // point doubling gate
                    rel_row += 2; // 2 rows for each LineFunction
                    if (C_bin[i]) {
                        std::array<var,4> input_T;
                        for(std::size_t j = 0; j < 4; j++) {
                            input_T[j] = var(component.W(2 + j),start_row_index + rel_row + 1,false);
                        }
                        // point adder subcomponent
                        typename point_addition_type::input_type point_addition_input = {input_T, instance_input.Q};
                        typename point_addition_type::result_type point_addition_res =
                            generate_circuit(point_addition_instance, bp, assignment, point_addition_input, start_row_index + rel_row + 2);
                        // assure a copy of the previous result is passed on to the adding LineFunction
                        for(std::size_t j = 0; j < 12; j++) {
                            bp.add_copy_constraint({var(component.W(j),start_row_index + rel_row),
                                                    var(component.W(j),start_row_index + rel_row +2+point_addition_instance.rows_amount)});
                        }
                        // assure a copy of the doubled point is passed on to the adding LineFunction
                        for(std::size_t j = 0; j < 4; j++) {
                            bp.add_copy_constraint({var(component.W(2+j),start_row_index + rel_row +1),
                                                    var(component.W(2+j),start_row_index + rel_row +3+point_addition_instance.rows_amount)});
                        }

                        // Now that copies are assured we can modify rel_row to be at the top of adding LineFunction
                        rel_row += 2 + point_addition_instance.rows_amount;
                        bp.add_copy_constraint({var(component.W(0),start_row_index + rel_row + 1),instance_input.P[0]});
                        bp.add_copy_constraint({var(component.W(1),start_row_index + rel_row + 1),instance_input.P[1]});
                        for(std::size_t j = 0; j < 4; j++) {
                            bp.add_copy_constraint({var(component.W(6 + j),start_row_index + rel_row + 1),instance_input.Q[j]});
                        }
                        assignment.enable_selector(selector_index[2], start_row_index + rel_row + 1); // adding LineFunction
                        // skip 2 more rows after LineFunction
                        rel_row += 2;
                        // Link point addition output to cells in circuit
                        for(std::size_t j = 0; j < 4; j++) {
                            bp.add_copy_constraint({point_addition_res.R[j],
                                                   var(component.W(2 + j), start_row_index + rel_row + 1, false)});
                        }
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = 0; // a zero to make copy-constraints with
                assignment.constant(component.C(0), start_row_index + 1) = 1; // a one to make copy-constraints with
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MILLER_LOOP_HPP
