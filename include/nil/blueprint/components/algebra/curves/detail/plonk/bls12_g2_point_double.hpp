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
// @file Declaration of interfaces for point doubling in the elliptic
// curve group G2 = E'(F_p^2) : y^2 = x^3 + 4(1+u) with
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_G2_POINT_DOUBLE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_G2_POINT_DOUBLE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/perform_fp2.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // E'(F_p^2) : y^2 = x^3 + 4(1+u) point doubling gate.
            // Expects point at infinity encoded by (0,0) in input and outputs (0,0) for its double
            // Input: (xP, yP) = P[4]
            // Output: (xR, yR) = R[4], R = [2]P as element of E'(F_p^2)

            // constraint-generating functions
            using detail::perform_fp2_mult;
            using detail::perform_fp2_add;
            using detail::perform_fp2_sub;
            using detail::perform_fp2_scale;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class bls12_g2_point_double;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bls12_g2_point_double<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return bls12_g2_point_double::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(10)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,4> P;

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};
                        for(auto & e : P) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
		    std::array<var,4> R;

                    result_type(const bls12_g2_point_double &component, std::uint32_t start_row_index) {
                        for(std::size_t i = 0; i < 4; i++) {
                            R[i] = var(component.W(i+6), start_row_index, false, var::column_type::witness);
                        }
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : R) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit bls12_g2_point_double(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bls12_g2_point_double(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                bls12_g2_point_double(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_bls12_g2_point_double =
                bls12_g2_point_double<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                using fp2_element = typename policy_type_fp2::value_type;

                fp2_element xP = fp2_element(var_value(assignment, instance_input.P[0]),
                                             var_value(assignment, instance_input.P[1])),
                            yP = fp2_element(var_value(assignment, instance_input.P[2]),
                                             var_value(assignment, instance_input.P[3])),
                            lambda = 3*xP.pow(2) / (2*yP), // apparently division by 0 is defined as 0 to avoid exceptions
                            nu = yP - lambda*xP,
                            xR = lambda.pow(2) - 2*xP,
                            yR = -(lambda*xR + nu),
                            zero_check = yP.inversed();

                for(std::size_t i = 0; i < 2; i++) {
                    assignment.witness(component.W(i),start_row_index) = xP.data[i];
                    assignment.witness(component.W(2 + i),start_row_index) = yP.data[i];
                    assignment.witness(component.W(4 + i),start_row_index) = zero_check.data[i];
                    assignment.witness(component.W(6 + i),start_row_index) = xR.data[i];
                    assignment.witness(component.W(8 + i),start_row_index) = yR.data[i];
                }

                return typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::array<constraint_type,2> xP, yP, ZC, xR, yR, C1, C2, C3, C4, C5;

                for(std::size_t i = 0; i < 2; i++) {
                    xP[i] = var(component.W(i), 0, true);
                    yP[i] = var(component.W(i+2), 0, true);
                    ZC[i] = var(component.W(i+4), 0, true);
                    xR[i] = var(component.W(i+6), 0, true);
                    yR[i] = var(component.W(i+8), 0, true);
                }
                // the defining equations are
                // xR = (3xP^2 / 2yP)^2 - 2xP
                // yR = - (3xP^2 / 2yP) xR - yP + (3xP^2 / 2yP)xP
                // We transform them into constraints:
                // (2yP)^2 (xR + 2xP) - (3xP^2)^2 = 0
                // (2yP) (yR + yP) + (3xP^2)(xR - xP) = 0
                // Additional constraint to assure that the double of (0,0) is (0,0):
                // ZC * yP^2 -  yP = 0
                // ZC * yP * xR - ZC * yP = 0
                // ZC * yP * yR - ZC * yP = 0

                C1 = perform_fp2_sub(
                   perform_fp2_mult(
                    perform_fp2_mult(perform_fp2_scale(yP,2),perform_fp2_scale(yP,2)),
                    perform_fp2_add(xR, perform_fp2_scale(xP,2))
                   ),
                   perform_fp2_mult(
                    perform_fp2_scale(perform_fp2_mult(xP,xP),3),
                    perform_fp2_scale(perform_fp2_mult(xP,xP),3)
                   )
                  );
                C2 = perform_fp2_add(
                       perform_fp2_mult(
                         perform_fp2_scale(yP,2),
                         perform_fp2_add(yR,yP)
                       ),
                       perform_fp2_mult(
                         perform_fp2_scale(perform_fp2_mult(xP,xP),3),
                         perform_fp2_sub(xR,xP)
                       )
                     );

                C3 = perform_fp2_sub( perform_fp2_mult(ZC,perform_fp2_mult(yP,yP)), yP);

                C4 = perform_fp2_sub( xR, perform_fp2_mult(perform_fp2_mult(ZC,xR),yP));
                C5 = perform_fp2_sub( yR, perform_fp2_mult(perform_fp2_mult(ZC,yR),yP));

                std::vector<constraint_type> Cs = {};
                for(std::size_t i = 0; i < 2; i++) {
                    Cs.push_back(C1[i]);
                    Cs.push_back(C2[i]);
                    Cs.push_back(C3[i]);
                    Cs.push_back(C4[i]);
                    Cs.push_back(C5[i]);
                }
                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t WA = component.witness_amount();

                for(std::size_t i = 0; i < 4; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.P[i]});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bls12_g2_point_double<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_G2_POINT_DOUBLE_HPP
