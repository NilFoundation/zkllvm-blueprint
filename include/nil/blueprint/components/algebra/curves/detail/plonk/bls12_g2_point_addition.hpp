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
// @file Declaration of interfaces for point addition in the elliptic
// curve group G2 = E'(F_p^2) : y^2 = x^3 + 4(1+u) with
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_G2_POINT_ADDITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_G2_POINT_ADDITION_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp2.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // E'(F_p^2) : y^2 = x^3 + 4(1+u) point addition gate.
            // Expects point at infinity encoded by (0,0) in input and output
            // Input: (xP, yP) = P[4], (xQ, yQ) = Q[4]
            // Output: (xR, yR) = R[4], R = P + Q as element of E'(F_p^2)
            //
            // We organize the computations in 2-cell blocks for storing Fp2 elements
            // The 12 blocks used are stored in 1 row with 24 cells or 2 rows with 12 cells.
            // Block contents are:
            //  0  1  2  3  4  5  6   7   8  9  10 11
            // +--+--+--+--+--+--+---+---+--+--+--+--+
            // |xP|yP|xQ|yQ|zP|zQ|zPQ|wPQ|la|  |xR|yR|
            // +--+--+--+--+--+--+---+---+--+--+--+--+
            //

            template<typename ArithmetizationType>
            class bls12_g2_point_addition;

            template<typename BlueprintFieldType>
            class bls12_g2_point_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return bls12_g2_point_addition::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
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
                    return 1 + (witness_amount < 24);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,4> P, Q;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(auto & e : P) { res.push_back(e); }
                        for(auto & e : Q) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
		    std::array<var,4> R;

                    result_type(const bls12_g2_point_addition &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        for(std::size_t i = 0; i < 4; i++) {
                            R[i] = var(component.W(WA - 4 + i), start_row_index + (WA < 24), false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};

                        for(auto & e : R) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit bls12_g2_point_addition(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bls12_g2_point_addition(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                bls12_g2_point_addition(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_bls12_g2_point_addition =
                bls12_g2_point_addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_bls12_g2_point_addition<BlueprintFieldType>::result_type generate_assignments(
                const plonk_bls12_g2_point_addition<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_g2_point_addition<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                const std::size_t WA = component.witness_amount();

                using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                using fp2_element = typename policy_type_fp2::value_type;

                fp2_element fp2zero = fp2_element(0,0),
                            xP = fp2_element(var_value(assignment, instance_input.P[0]),
                                             var_value(assignment, instance_input.P[1])),
                            yP = fp2_element(var_value(assignment, instance_input.P[2]),
                                             var_value(assignment, instance_input.P[3])),
                            xQ = fp2_element(var_value(assignment, instance_input.Q[0]),
                                             var_value(assignment, instance_input.Q[1])),
                            yQ = fp2_element(var_value(assignment, instance_input.Q[2]),
                                             var_value(assignment, instance_input.Q[3])),
                            zP = yP.inversed(), // NB: division by 0 is defined as 0
                            zQ = yQ.inversed(),
                            zPQ = (xP - xQ).inversed(),
                            wPQ = (yP + yQ).inversed(),
                            lambda = (xP == xQ)? (3*xP.pow(2) / (2*yP)) : ((yP-yQ)/(xP-xQ)),
                            nu = yP - lambda*xP,
                            xR, yR;
                if (yP == fp2zero) {
                    xR = xQ;
                    yR = yQ;
                } else {
                    if (yQ == fp2zero) {
                        xR = xP;
                        yR = yP;
                    } else {
                        if ((xP == xQ) && (yP == -yQ)) {
                            xR = fp2zero;
                            yR = fp2zero;
                        } else {
                            xR = lambda.pow(2) - xP - xQ,
                            yR = -(lambda*xR + nu);
                        }
                    }
                }

                for(std::size_t i = 0; i < 2; i++) {
                    assignment.witness(component.W(i),start_row_index) = xP.data[i];
                    assignment.witness(component.W(2 + i),start_row_index) = yP.data[i];
                    assignment.witness(component.W(4 + i),start_row_index) = xQ.data[i];
                    assignment.witness(component.W(6 + i),start_row_index) = yQ.data[i];
                    assignment.witness(component.W(8 + i),start_row_index) = zP.data[i];
                    assignment.witness(component.W(10 + i),start_row_index) = zQ.data[i];

                    assignment.witness(component.W((12 + i) % WA),start_row_index + (WA < 24)) = zPQ.data[i];
                    assignment.witness(component.W((14 + i) % WA),start_row_index + (WA < 24)) = wPQ.data[i];
                    assignment.witness(component.W((16 + i) % WA),start_row_index + (WA < 24)) = lambda.data[i];
                    // block #9 is skipped for alignment purposes
                    assignment.witness(component.W((20 + i) % WA),start_row_index + (WA < 24)) = xR.data[i];
                    assignment.witness(component.W((22 + i) % WA),start_row_index + (WA < 24)) = yR.data[i];
                }

                return typename plonk_bls12_g2_point_addition<BlueprintFieldType>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_bls12_g2_point_addition<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_g2_point_addition<BlueprintFieldType>::input_type
                    &instance_input) {

                const std::size_t WA = component.witness_amount();

                using var = typename plonk_bls12_g2_point_addition<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                // Fp2 field over constraints:
                using fp2_constraint = detail::abstract_fp2_element<constraint_type>;

                constraint_type cnstr_zero = constraint_type(),
                                cnstr_one = cnstr_zero + 1;

                fp2_constraint one = {cnstr_one,cnstr_zero},
                               xP = {var(component.W(0), 0, true),var(component.W(1), 0, true)},
                               yP = {var(component.W(2), 0, true),var(component.W(3), 0, true)},
                               xQ = {var(component.W(4), 0, true),var(component.W(5), 0, true)},
                               yQ = {var(component.W(6), 0, true),var(component.W(7), 0, true)},
                               zP = {var(component.W(8), 0, true),var(component.W(9), 0, true)},
                               zQ = {var(component.W(10), 0, true),var(component.W(11), 0, true)},
                              zPQ = {var(component.W(12 % WA), (WA < 24), true),var(component.W(13 % WA), (WA < 24), true)},
                              wPQ = {var(component.W(14 % WA), (WA < 24), true),var(component.W(15 % WA), (WA < 24), true)},
                               la = {var(component.W(16 % WA), (WA < 24), true),var(component.W(17 % WA), (WA < 24), true)},
                               xR = {var(component.W(20 % WA), (WA < 24), true),var(component.W(21 % WA), (WA < 24), true)},
                               yR = {var(component.W(22 % WA), (WA < 24), true),var(component.W(23 % WA), (WA < 24), true)};
                fp2_constraint C;

                std::vector<constraint_type> Cs = {};

                // yP(1 - yP zP) = 0  (1)
                C = yP * (one - yP * zP);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // yQ(1 - yQ zQ) = 0  (2)
                C = yQ * (one - yQ * zQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // (xR - xQ)(1 - yP zP) = 0 (3)
                C = (xR - xQ) * (one - yP * zP);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // (yR - yQ)(1 - yP zP) = 0 (4)
                C = (yR - yQ)*(one - yP * zP);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // (xR - xP)(1 - yQ zQ) = 0 (5)
                C = (xR - xP)*(one - yQ*zQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // (yR - yP)(1 - yQ zQ) = 0 (6)
                C = (yR - yP)*(one - yQ*zQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // (xP - xQ)(1 - (xP-xQ) zPQ) = 0 (7)
                C = (xP - xQ)*(one - (xP - xQ)*zPQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // zPQ (1 - (xP - xQ) zPQ) = 0 (8)
                C = zPQ * (one - (xP - xQ) * zPQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // (yP + yQ)(1 - (yP + yQ) wPQ) = 0 (9)
                C = (yP + yQ)*(one - (yP + yQ)*wPQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // wPQ (1 - (yP + yQ) wPQ) = 0 (10)
                C = wPQ * (one - (yP + yQ)*wPQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // yP(1 - (xP - xQ) zPQ) yQ(1 - (yP + yQ) wPQ) xR = 0 (11)
                C = yP * (one - (xP-xQ)*zPQ) * yQ * (one - (yP + yQ)* wPQ) * xR;
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // yP(1 - (xP - xQ) zPQ) yQ(1 - (yP + yQ) wPQ) yR = 0 (12)
                C = yP * (one - (xP-xQ)*zPQ) * yQ * (one - (yP + yQ)* wPQ) * yR;
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // yP yQ (zPQ + wPQ (1 - (xP - xQ) zPQ)) (xR - la^2 + xP + xQ) = 0 (13)
                C = yP * yQ * (zPQ + wPQ * (one - (xP - xQ)*zPQ)) * (xR - la*la + xP + xQ);
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // yP yQ (zPQ + wPQ (1 - (xP - xQ) zPQ)) (yR + yP + la(xR - xP)) = 0 (14)
                C = yP * yQ * (zPQ + wPQ * (one - (xP - xQ)*zPQ)) * (yR + yP + la*(xR - xP));
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                // yQ ( 2yP zPQ ( (xP - xQ)la - (yP - yQ) ) + (1 - (xP - xQ)zPQ) wPQ (2yP la - 3xP^2)) = 0 (15)
                C = yQ * (2*yP * zPQ * ((xP - xQ)*la - (yP - yQ)) + (one - (xP - xQ)*zPQ) * wPQ *(2*yP*la - 3*xP*xP));
                Cs.push_back(C[0]); Cs.push_back(C[1]);

                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_bls12_g2_point_addition<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_g2_point_addition<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_bls12_g2_point_addition<BlueprintFieldType>::var;

                for(std::size_t i = 0; i < 4; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.P[i]});
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_bls12_g2_point_addition<BlueprintFieldType>::result_type generate_circuit(
                const plonk_bls12_g2_point_addition<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_bls12_g2_point_addition<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bls12_g2_point_addition<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_G2_POINT_ADDITION_HPP
