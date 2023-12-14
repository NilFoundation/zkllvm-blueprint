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
// @file Declaration of the Miller loop for BLS12-381 pairing
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_MILLER_LOOP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_MILLER_LOOP_HPP

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
            //
            // Component for computing the result of applying the Miller loop
            // to two points P from E(F_p) and Q from E'(F_p^2)
            // The curve parameter t is fixed
            // with -t = 0xD201000000010000
            // Input: P[2], Q[4] ( we assume P and Q are NOT (0,0), i.e. not the points at infinity, NOT CHECKED )
            // Output: f[12]: an element of F_p^12
            //
            // We realize the circuit in two versions - 12-column and 24-column.
            //

            using namespace detail;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class bls12_miller_loop;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bls12_miller_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            static std::size_t gates_amount_internal(std::size_t witness_amount) {
                return (witness_amount == 12) ? 4 : 5;
            }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

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
                        return bls12_miller_loop::gates_amount_internal(witness_amount);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        return (witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount);
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
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24,12)), // 12 or 24
                        false
                    ).merge_with(point_addition_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return ( (witness_amount == 12)? (36 + 2*63 + 2*5 + 1) : (20 + 63 + 5 + 1)) +
                           5*point_addition_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,2> P;
                    std::array<var,4> Q;

                    std::vector<var> all_vars() const {
                        return {P[0], P[1], Q[0], Q[1], Q[2], Q[3]};
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const bls12_miller_loop &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        std::size_t last_row = start_row_index + component.rows_amount - 1;

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W(i), last_row, false, var::column_type::witness); // TODO check!
                        }
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit bls12_miller_loop(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bls12_miller_loop(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                bls12_miller_loop(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_bls12_miller_loop =
                bls12_miller_loop<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;

                using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                using fp2_element = typename policy_type_fp2::value_type;
                using curve_point = std::array<fp2_element,2>;
                using point_addition_type = typename component_type::point_addition_type;

                point_addition_type point_addition_instance( component._W, component._C, component._PI);

                const std::size_t WA = component.witness_amount();

                value_type xP = var_value(assignment, instance_input.P[0]),
                           yP = var_value(assignment, instance_input.P[1]);

                std::array<value_type,2> xQ = {var_value(assignment, instance_input.Q[0]), var_value(assignment, instance_input.Q[1])},
                                         yQ = {var_value(assignment, instance_input.Q[2]), var_value(assignment, instance_input.Q[3])};
                curve_point Q = { fp2_element(xQ[0], xQ[1]), fp2_element(yQ[0], yQ[1])},
                            R = Q;

                // for storing all precomputed points, every point is represented by 4 elements,
                // for each doubled point we additionally store the "zero-check" = inversed y coordinate
                std::vector<value_type> all_point_coords = {};

                // precomputation of all curve points that appear in the Miller loop
                // we consider a slot to be 2 cells wide
                std::size_t slot   = (WA == 12)? 1 : 7, // start slot depending on WA
                            Q_slot = slot; // save slot number for further use

                auto fill_slot = [&assignment, &component, &start_row_index, &slot, &WA, &all_point_coords](fp2_element V) {
                    for(std::size_t i = 0; i < 2; i++) {
                        assignment.witness(component.W((2*slot + i) % WA),start_row_index + (2*slot)/WA) = V.data[i];
                        all_point_coords.push_back(V.data[i]);
                    }
                    slot++;
                };
                auto double_point = [](curve_point P) {
                    fp2_element lambda = 3*P[0].pow(2) / (2*P[1]),
                                nu = P[1] - lambda*P[0],
                                xR = lambda.pow(2) - 2*P[0],
                                yR = -(lambda*xR + nu);
                    return curve_point({xR, yR});
                };

                auto use_addition = [&assignment, &component, &start_row_index, &WA, &point_addition_instance]
                                               (std::size_t input_slot_1, std::size_t input_slot_2, std::size_t &row) {
                    std::array<var,4> P, Q;
                    for(std::size_t i = 0; i < 4; i++) {
                        P[i] = var(component.W((2*input_slot_1 + i) % WA),start_row_index + (2*input_slot_1)/WA,false);
                        Q[i] = var(component.W((2*input_slot_2 + i) % WA),start_row_index + (2*input_slot_2)/WA,false);
                    }
                    typename point_addition_type::input_type block_input = {P,Q};
                    typename point_addition_type::result_type block_res =
                        generate_assignments(point_addition_instance, assignment, block_input, row);
                    row += point_addition_instance.rows_amount;

                    std::array<value_type,4> R;
                    for(std::size_t i = 0; i < 4; i++) {
                        R[i] = var_value(assignment, block_res.R[i]);
                    }
                    return curve_point({fp2_element(R[0],R[1]),fp2_element(R[2],R[3])});
                };

                fill_slot(Q[0]); fill_slot(Q[1]);
                // the standard doubling triple = (zero check, xR, yR)
                fill_slot(R[1].inversed()); R = double_point(R); fill_slot(R[0]); fill_slot(R[1]);

                std::size_t current_row = start_row_index + 1;
                R = use_addition(slot - 2, Q_slot, current_row); // 1st addition
                slot = ((current_row - start_row_index)*WA)/2;
                slot++; fill_slot(R[0]); fill_slot(R[1]); // the output

                for(std::size_t i = 0; i < 2; i++) {
                    fill_slot(R[1].inversed()); R = double_point(R); fill_slot(R[0]); fill_slot(R[1]);
                }
                current_row = start_row_index + (2*(slot-1))/WA + 1; // next row after the one where the last slot was
                R = use_addition(slot - 2, Q_slot, current_row); // 2nd addition
                slot = ((current_row - start_row_index)*WA)/2;
                slot++; fill_slot(R[0]); fill_slot(R[1]); // the output

                for(std::size_t i = 0; i < 3; i++) {
                    fill_slot(R[1].inversed()); R = double_point(R); fill_slot(R[0]); fill_slot(R[1]);
                }
                current_row = start_row_index + (2*(slot-1))/WA + 1; // next row after the one where the last slot was
                R = use_addition(slot - 2, Q_slot, current_row); // 3d addition
                slot = ((current_row - start_row_index)*WA)/2;
                if (WA == 24) { slot += 2*3; } // skip 6 slots in 24-column layout
                slot++; fill_slot(R[0]); fill_slot(R[1]); // the output

                for(std::size_t i = 0; i < 9; i++) {
                    fill_slot(R[1].inversed()); R = double_point(R); fill_slot(R[0]); fill_slot(R[1]);
                }

                current_row = start_row_index + (2*(slot-1))/WA + 1; // next row after the one where the last slot was
                R = use_addition(slot - 2, Q_slot, current_row); // 4th addition
                slot = ((current_row - start_row_index)*WA)/2;
                slot += (WA == 12)? 1*3 : 3*3; // number of slots to skip
                slot++; fill_slot(R[0]); fill_slot(R[1]); // the output

                for(std::size_t i = 0; i < 32; i++) { // 32 doublings one after another
                    fill_slot(R[1].inversed()); R = double_point(R); fill_slot(R[0]); fill_slot(R[1]);
                }
                current_row = start_row_index + (2*(slot-1))/WA + 1; // next row after the one where the last slot was
                R = use_addition(slot - 2, Q_slot, current_row); // 5th addition
                slot = ((current_row - start_row_index)*WA)/2;
                slot += (WA == 12)? 1*3 : 3*3; // number of slots to skip
                slot++; fill_slot(R[0]); fill_slot(R[1]); // the output

                for(std::size_t i = 0; i < 16; i++) { // 16 doublings one after another
                    fill_slot(R[1].inversed()); R = double_point(R); fill_slot(R[0]); fill_slot(R[1]);
                }
                current_row = start_row_index + (2*slot)/WA;

                // Now all curve points have been precomputed. We mostly work with Fp12 elements from now on.
                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                auto LineFunctionDouble = [&assignment, &component, &current_row, &WA, &xP, &yP](
                        fp12_element f,
                        std::array<value_type,6> T) { // T = the point to double and it's zero check
                    fp12_element x  = fp12_element::one() * xP,
                                 y  = fp12_element::one() * yP,
                                 x1 = fp12_element({ {0,0}, {0,0}, {(T[1] + T[0])/2, (T[1] - T[0])/2} }, { {0,0}, {0,0}, {0,0} }),
                                 y1 = fp12_element({ {0,0}, {0,0}, {0,0}}, { {0,0}, {(T[3] + T[2])/2, (T[3] - T[2])/2} , {0,0} }),
                                 g = f.pow(2) * (3*x1.pow(2)*(x-x1)*((2*y1).inversed()) + y1 - y);

                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W(i),current_row) = f.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    if (WA == 12) { current_row++; } // in 12-column version go to next row
                    assignment.witness(component.W((12 + 0) % WA),current_row) = xP;
                    assignment.witness(component.W((12 + 1) % WA),current_row) = yP;
                    for(std::size_t i = 0; i < 6; i++) {
                        assignment.witness(component.W((12 + 2 + i) % WA),current_row) = T[i];
                    }

                    current_row++; // unconditional
                    return g;
                };

                auto LineFunctionAdd = [&assignment, &component, &current_row, &WA, &xP, &yP, &xQ, &yQ](
                        fp12_element f,
                        std::array<value_type,4> T) {
                    fp12_element x  = fp12_element::one() * xP,
                                 y  = fp12_element::one() * yP,
                                 x1 = fp12_element({ {0,0}, {0,0}, {(T[1] + T[0])/2, (T[1] - T[0])/2} }, { {0,0}, {0,0}, {0,0} }),
                                 y1 = fp12_element({ {0,0}, {0,0}, {0,0}}, { {0,0}, {(T[3] + T[2])/2, (T[3] - T[2])/2} , {0,0} }),
                                 x2 = fp12_element({ {0,0}, {0,0}, {(xQ[1] + xQ[0])/2, (xQ[1] - xQ[0])/2} }, { {0,0}, {0,0}, {0,0} }),
                                 y2 = fp12_element({ {0,0}, {0,0}, {0,0}}, { {0,0}, {(yQ[1] + yQ[0])/2, (yQ[1] - yQ[0])/2} , {0,0} }),
                                 l = (y2-y1)*(x2-x1).inversed(),
                                 g = f * (l*(x-x1) + y1 - y);
                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W(i),current_row) = f.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    if (WA == 12) { current_row++; } // in 12-column version go to next row
                    assignment.witness(component.W((12 + 0) % WA),current_row) = xP;
                    assignment.witness(component.W((12 + 1) % WA),current_row) = yP;
                    assignment.witness(component.W((12 + 2) % WA),current_row) = T[0];
                    assignment.witness(component.W((12 + 3) % WA),current_row) = T[1];
                    assignment.witness(component.W((12 + 4) % WA),current_row) = T[2];
                    assignment.witness(component.W((12 + 5) % WA),current_row) = T[3];
                    assignment.witness(component.W((12 + 6) % WA),current_row) = xQ[0];
                    assignment.witness(component.W((12 + 7) % WA),current_row) = xQ[1];
                    assignment.witness(component.W((12 + 8) % WA),current_row) = yQ[0];
                    assignment.witness(component.W((12 + 9) % WA),current_row) = yQ[1];
                    current_row++; // unconditional

                     return g;
                };

                fp12_element f = fp12_element::one(); // initial f value for Miller loop is 1
                std::size_t point_idx = 0; // the index of the current curve point in all_point_coords (it's Q actually)

                std::set<std::size_t> addition_bits = {1,3,6,15,47};
                for(std::size_t bit_num = 1; bit_num < 64; bit_num++) {
                    std::array<value_type,6> q = {all_point_coords[point_idx],
                                              all_point_coords[point_idx + 1],
                                              all_point_coords[point_idx + 2],
                                              all_point_coords[point_idx + 3],
                                              all_point_coords[point_idx + 4],
                                              all_point_coords[point_idx + 5] };
                    point_idx += 6;
                    f = LineFunctionDouble(f,q);

                    if(addition_bits.count(bit_num)) {
                        std::array<value_type,4> t = {all_point_coords[point_idx],
                                                      all_point_coords[point_idx + 1],
                                                      all_point_coords[point_idx + 2],
                                                      all_point_coords[point_idx + 3] };
                        point_idx += 4;
                        f = LineFunctionAdd(f,t);
                    }
                }
                for(std::size_t i = 0; i < 12; i++) {
                    assignment.witness(component.W(i),current_row) = f.data[i/6].data[(i % 6)/2].data[i % 2];
                }

                return typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp2_constraint = detail::abstract_fp2_element<constraint_type>;

                const std::size_t WA = component.witness_amount();
                std::vector<std::size_t> gate_list = {};

                auto make_doubling_constraints = [&component, &WA](int block) {
                    constraint_type cnstr_zero = constraint_type(),
                                    cnstr_one = cnstr_zero + 1;
                    fp2_constraint one = {cnstr_one, cnstr_zero},
                                   xQ = {var(component.W((WA + 6*(block-1) + 2)% WA),-(block == 0),true),
                                         var(component.W((WA + 6*(block-1) + 3)% WA),-(block == 0),true)},
                                   yQ = {var(component.W((WA + 6*(block-1) + 4)% WA),-(block == 0),true),
                                         var(component.W((WA + 6*(block-1) + 5)% WA),-(block == 0),true)},
                                   ZC = {var(component.W(6*block + 0),0,true),
                                         var(component.W(6*block + 1),0,true)},
                                   xR = {var(component.W(6*block + 2),0,true),
                                         var(component.W(6*block + 3),0,true)},
                                   yR = {var(component.W(6*block + 4),0,true),
                                         var(component.W(6*block + 5),0,true)},
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
                    std::vector<constraint_type> res = {};
                    C = (2*yQ)*(2*yQ)*(xR + 2*xQ) - (3*xQ*xQ)*(3*xQ*xQ);
                    res.push_back(C[0]); res.push_back(C[1]);
                    C = (2*yQ)*(yR + yQ) + (3*xQ*xQ)*(xR - xQ);
                    res.push_back(C[0]); res.push_back(C[1]);
                    C = (ZC*yQ - one)*yQ;
                    res.push_back(C[0]); res.push_back(C[1]);
                    C = (ZC*yQ - one)*xR;
                    res.push_back(C[0]); res.push_back(C[1]);
                    C = (ZC*yQ - one)*yR;
                    res.push_back(C[0]); res.push_back(C[1]);
                    return res;
                };

                std::vector<constraint_type> doubling_left_constrs = make_doubling_constraints(0); // first 6-cell block
                gate_list.push_back(bp.add_gate(doubling_left_constrs));

                std::vector<constraint_type> doubling_right_constrs = make_doubling_constraints(WA/6 - 1); // last 6-cell block
                gate_list.push_back(bp.add_gate(doubling_right_constrs));

                if (WA == 24) { // the two middle 6-cell blocks, if we need them
                    std::vector<constraint_type> doubling_middle_constrs = make_doubling_constraints(1),
                                                 doubling_middle_constrs_2 = make_doubling_constraints(2);
                    doubling_middle_constrs.insert(doubling_middle_constrs.end(), doubling_middle_constrs_2.begin(),
                                                                                  doubling_middle_constrs_2.end());
                    gate_list.push_back(bp.add_gate(doubling_middle_constrs));
                }

                // All the following constraints are for Fp12 elements
                using fp12_constraint = detail::abstract_fp12_element<constraint_type>;

                // LineFunction Doubling case gate

                fp12_constraint X, Y, twoX1, twoY1, F, G, C;
                for(std::size_t i = 0; i < 12; i++) {
                    F[i] = var(component.W(i), -(WA == 12), true);
                    G[i] = var(component.W(i), 1, true);
                    X[i] = constraint_type();
                    Y[i] = constraint_type();
                    twoX1[i] = constraint_type();
                    twoY1[i] = constraint_type();
                }
                X[0] = var(component.W((12+0) % WA), 0, true);
                Y[0] = var(component.W((12+1) % WA), 0, true);
                twoX1[4] = var(component.W((12+3) % WA),0, true) + var(component.W((12+2) % WA),0, true);
                twoX1[5] = var(component.W((12+3) % WA),0, true) - var(component.W((12+2) % WA),0, true);
                twoY1[8] = var(component.W((12+5) % WA),0, true) + var(component.W((12+4) % WA),0, true);
                twoY1[9] = var(component.W((12+5) % WA),0, true) - var(component.W((12+4) % WA),0, true);

                C = 8*twoY1*G - F*F*(6*twoX1*twoX1*X - 3*twoX1*twoX1*twoX1 + 4*twoY1*twoY1 - 8*twoY1*Y);
                std::vector<constraint_type> line_func_double_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    line_func_double_constrs.push_back(C[i]);
                }
                gate_list.push_back(bp.add_gate(line_func_double_constrs));

                // LineFunction Adding case gate
                fp12_constraint twoX2, twoY2;
                // we REUSE X, Y, twoX1, twoX2, F, G from the previous gate and REDEFINE C
                for(std::size_t i = 0; i < 12; i++) {
                    twoX2[i] = constraint_type();
                    twoY2[i] = constraint_type();
                }
                twoX2[4] = var(component.W((12+7) % WA),0, true) + var(component.W((12+6) % WA),0, true);
                twoX2[5] = var(component.W((12+7) % WA),0, true) - var(component.W((12+6) % WA),0, true);
                twoY2[8] = var(component.W((12+9) % WA),0, true) + var(component.W((12+8) % WA),0, true);
                twoY2[9] = var(component.W((12+9) % WA),0, true) - var(component.W((12+8) % WA),0, true);

                C = 2*(twoX2 - twoX1)*G - F*((twoY2 - twoY1)*(2*X - twoX1) - (2*Y - twoY1)*(twoX2 - twoX1));
                std::vector<constraint_type> line_func_add_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    line_func_add_constrs.push_back(C[i]);
                }
                gate_list.push_back(bp.add_gate(line_func_add_constrs));

                return gate_list;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t WA = component.witness_amount();

                std::size_t slot = (WA == 12)? 1 : 7; // location of initial Q data
                for(std::size_t i = 0; i < 4; i++) {
                    bp.add_copy_constraint({var(component.W((2*slot + i) % WA), start_row_index + (2*slot)/WA, false),
                                                instance_input.Q[i]});
                }
                // copy constraints for LineFunction addition gates: P and Q
                std::size_t current_row = start_row_index + ((WA == 12)? 46+1 : 25),
                            row_step = (WA == 12)? 2 : 1;
                std::set<std::size_t> addition_bits = {1,3,6,15,47};
                std::map<std::size_t,std::size_t> skip_blocks = (WA == 12)?
                     std::map<std::size_t,std::size_t>{ {1,0}, {3,1}, {6,0}, {15,1}, {47,1}} :
                     std::map<std::size_t,std::size_t>{ {1,0}, {3,1}, {6,2}, {15,3}, {47,3}};
                // at this moment "slot" points to the cell, where Q storage starts
                for(std::size_t bit_num = 1; bit_num < 64; bit_num++) {
                    bp.add_copy_constraint({var(component.W((12 + 0) % WA), current_row, false), instance_input.P[0]});
                    bp.add_copy_constraint({var(component.W((12 + 1) % WA), current_row, false), instance_input.P[1]});
                    // link the T argument to its source
                    for(std::size_t i = 0; i < 6; i++) {
                        bp.add_copy_constraint({var(component.W((2*slot + i) % WA), start_row_index + (2*slot + i)/WA, false),
                                                var(component.W((12 + 2 + i) % WA), current_row, false)});
                    }
                    slot += 3;
                    current_row += row_step;
                    if (addition_bits.count(bit_num)) {
                        bp.add_copy_constraint({var(component.W((12 + 0) % WA), current_row, false), instance_input.P[0]});
                        bp.add_copy_constraint({var(component.W((12 + 1) % WA), current_row, false), instance_input.P[1]});
                        // link the T argument to its source
                        for(std::size_t i = 0; i < 4; i++) {
                            bp.add_copy_constraint({var(component.W((2*slot + i) % WA), start_row_index + (2*slot + i)/WA, false),
                                                    var(component.W((12 + 2 + i) % WA), current_row, false)});
                        }
                        // account for the slots linked above
                        slot += 2;
                        // skip slots, that correspond to addition subcomponent
                        slot += 12;
                        // additional skip due to alignment
                        slot += 3*skip_blocks[bit_num];
                        // skip the first slot of the addition output block (TODO : might be changed)
                        slot++;
                        // link the Q argument to its source
                        for(std::size_t i = 0; i < 4; i++) {
                            bp.add_copy_constraint({var(component.W((12 + 6 + i) % WA), current_row, false), instance_input.Q[i]});
                        }
                        current_row += row_step;
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                auto apply_selector = [&assignment, &selector_index, &start_row_index](
                    std::size_t gate_id, std::vector<std::size_t> apply_list) {
                    for( std::size_t row : apply_list ) {
                        assignment.enable_selector(selector_index[gate_id], start_row_index + row);
                    }
                };

                if (WA == 12) {
                    // left doubline gate #0
                    std::set<std::size_t> except_rows = {5,6,7,9,10,11,16,17,18,35,36,37};
                    for(std::size_t i = 4; i < 46; i++) {
                        if (!except_rows.count(i)) {
                            assignment.enable_selector(selector_index[0], start_row_index + i);
                        }
                    }
                    // right doubling gate #1
                    except_rows = {1,2,4,5,6,9,10,16,17,18,35,36,37};
                    for(std::size_t i = 0; i < 46; i++) {
                        if (!except_rows.count(i)) {
                            assignment.enable_selector(selector_index[1], start_row_index + i);
                        }
                    }
                } else {
                    // left doubline gate #0
                    std::set<std::size_t> except_rows = {9,10,19,20};
                    for(std::size_t i = 7; i < 25; i++) {
                        if (!except_rows.count(i)) {
                            assignment.enable_selector(selector_index[0], start_row_index + i);
                        }
                    }
                    // right doubling gate #1
                    except_rows = {1,2,3,5,9,10,19,20};
                    for(std::size_t i = 0; i < 25; i++) {
                        if (!except_rows.count(i)) {
                            assignment.enable_selector(selector_index[1], start_row_index + i);
                        }
                    }
                    // middle doubling gate #2
                    except_rows = {3,5,6,9,10,19,20};
                    for(std::size_t i = 2; i < 25; i++) {
                        if (!except_rows.count(i)) {
                            assignment.enable_selector(selector_index[2], start_row_index + i);
                        }
                    }
                }

                using component_type = plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using point_addition_type = typename component_type::point_addition_type;

                point_addition_type point_addition_instance( component._W, component._C, component._PI);

                std::vector<std::size_t> block_start,
                                         block_input,
                                         block_output;
                if (WA == 12) {
                    block_start = {1,5,9,16,35}; // the row!
                    block_input = {4,25,52,94,208};
                    block_output= {19,43,67,112,226};
                } else {
                    block_start = {1,3,5,9,19}; // the row!
                    block_input = {10,31,58,106,226};
                    block_output= {25,49,79,130,250};
                }
                for(std::size_t j = 0; j < block_start.size(); j++) {
                    std::array<var,4> input_P, input_Q;
                    std::size_t input_slot_1 = block_input[j],
                                input_slot_2 = (WA == 12)? 1 : 7;
                    for(std::size_t i = 0; i < 4; i++) {
                        input_P[i] = var(component.W((2*input_slot_1 + i) % WA),start_row_index + (2*input_slot_1)/WA,false);
                        input_Q[i] = var(component.W((2*input_slot_2 + i) % WA),start_row_index + (2*input_slot_2)/WA,false);
                    }
                    typename point_addition_type::input_type point_addition_input = {input_P, input_Q};
                    typename point_addition_type::result_type point_addition_res =
                        generate_circuit(point_addition_instance, bp, assignment, point_addition_input, start_row_index + block_start[j]);
                    std::size_t output_slot = block_output[j];
                    for(std::size_t i = 0; i < 4; i++) {
                        bp.add_copy_constraint({point_addition_res.R[i],
                                            var(component.W((2*output_slot + i) % WA), start_row_index + (2*output_slot)/WA, false)});
                    }
                }

                std::set<std::size_t> addition_bits = {1,3,6,15,47};
                std::size_t dbl_gate = (WA == 12)? 2 : 3,
                            add_gate = (WA == 12)? 3 : 4,
                            row_step = (WA == 12)? 2 : 1,
                            current_row = start_row_index + ((WA == 12)? 46+1 : 25);

                for(std::size_t bit_num = 1; bit_num < 64; bit_num++) {
                    assignment.enable_selector(selector_index[dbl_gate], current_row);
                    current_row += row_step;
                    if(addition_bits.count(bit_num)) {
                        assignment.enable_selector(selector_index[add_gate], current_row);
                        current_row += row_step;
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bls12_miller_loop<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_MILLER_LOOP_HPP
