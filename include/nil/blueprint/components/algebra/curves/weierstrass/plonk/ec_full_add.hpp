//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for full addition of EC points over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_FULL_ADD_ECDSA_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_FULL_ADD_ECDSA_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/detail/plonk/range_check_multi.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/check_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/negation_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition_mod_p.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Parameters: num_chunks = k, bit_size_chunk = b
            // For points P = (x_P,y_P), Q = (x_Q,y_Q), x_P != x_Q, P,Q != O
            // from an elliptic curve over F[p]
            // computes R = (x_R, y_R) = P + Q
            // Expects input as k-chunked values with b bits per chunk
            // p' = 2^(kb) - p
            // Input: xP[0],...,xP[k-1],yP[0],...,yP[k-1],xQ[0],...,xQ[k-1], yQ[0],...,yQ[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1], 0
            // (expects zero constant as input)
            // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType,
                     typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ec_full_add;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ec_full_add<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           NonNativeFieldType,
                           num_chunks,
                           bit_size_chunk>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using range_check_component = range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk>;
                using check_mod_p_component = check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk>;
                using mult_mod_p_component = flexible_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using neg_mod_p_component = negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using add_mod_p_component = addition_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return ec_full_add::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    // NB: this uses a workaround, as manifest cannot process intersecting sets of gates.
                    // We merge only non-intersecting sets of gates which cover all gates in the circuit.
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                      //  .merge_with(range_check_component::get_gate_manifest(witness_amount, lookup_column_amount))
                      //  .merge_with(check_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(mult_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                      //  .merge_with(add_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(neg_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // all requirements come from sub-components, the component itself has no personal requirements
                        std::shared_ptr<manifest_param>(new manifest_range_param(1,7*num_chunks,1)), // we need place for 7k variables
                        false // constant column not needed
                    ).merge_with(range_check_component::get_manifest())
                     .merge_with(check_mod_p_component::get_manifest())
                     .merge_with(mult_mod_p_component::get_manifest())
                     .merge_with(add_mod_p_component::get_manifest())
                     .merge_with(neg_mod_p_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return (7*num_chunks)/witness_amount + ((7*num_chunks) % witness_amount > 0) // to store 7k variables
                           + 7*range_check_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 7*check_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 23*mult_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 20*add_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 6*neg_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           ;
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "non-native field EC point full addition function";

                struct input_type {
                    var xP[num_chunks], yP[num_chunks], xQ[num_chunks], yQ[num_chunks], p[num_chunks], pp[num_chunks], zero;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {zero};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(xP[i]);
                            res.push_back(yP[i]);
                            res.push_back(xQ[i]);
                            res.push_back(yQ[i]);
                            res.push_back(p[i]);
                            res.push_back(pp[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    var xR[num_chunks], yR[num_chunks];

                    result_type(const ec_full_add &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            xR[i] = var(component.W((num_chunks + i) % WA),
                                        start_row_index + (num_chunks + i)/WA, false, var::column_type::witness);
                            yR[i] = var(component.W((2*num_chunks + i) % WA),
                                        start_row_index + (2*num_chunks + i)/WA, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(xR[i]);
                            res.push_back(yR[i]);
                        }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit ec_full_add(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                ec_full_add(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                ec_full_add(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["range_16bit/full"] = 0;

                    return lookup_tables;
                }
           };

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            using plonk_ec_full_add =
                ec_full_add<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    NonNativeFieldType,
                    num_chunks,
                    bit_size_chunk>;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_assignments(
                const plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;
                using var = typename component_type::var;

                using range_check_type = typename component_type::range_check_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;
                using mult_mod_p_type = typename component_type::mult_mod_p_component;
                using add_mod_p_type = typename component_type::add_mod_p_component;
                using neg_mod_p_type = typename component_type::neg_mod_p_component;

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using non_native_value_type = typename NonNativeFieldType::value_type;
                using non_native_integral_type = typename NonNativeFieldType::integral_type;

                const std::size_t WA = component.witness_amount();

                // instances of used subcomponents
                range_check_type range_check_instance( component._W, component._C, component._PI);
                check_mod_p_type check_mod_p_instance( component._W, component._C, component._PI);
                mult_mod_p_type  mult_mod_p_instance( component._W, component._C, component._PI);
                add_mod_p_type   add_mod_p_instance( component._W, component._C, component._PI);
                neg_mod_p_type   neg_mod_p_instance( component._W, component._C, component._PI);

                non_native_integral_type B = non_native_integral_type(1) << bit_size_chunk;
                non_native_value_type xP = 0,
                                      yP = 0,
                                      xQ = 0,
                                      yQ = 0;

                for(std::size_t i = num_chunks; i > 0; i--) {
                    xP *= B;
                    xP += non_native_integral_type(var_value(assignment, instance_input.xP[i-1]).data);
                    yP *= B;
                    yP += non_native_integral_type(var_value(assignment, instance_input.yP[i-1]).data);
                    xQ *= B;
                    xQ += non_native_integral_type(var_value(assignment, instance_input.xQ[i-1]).data);
                    yQ *= B;
                    yQ += non_native_integral_type(var_value(assignment, instance_input.yQ[i-1]).data);
                }

                non_native_value_type lambda, xR, yR,
                                      // indicator variables
                                      zP = (yP == 0)? 0 : yP.inversed(),
                                      zQ = (yQ == 0)? 0 : yQ.inversed(),
                                      zPQ= (xP == xQ)? 0 : (xP - xQ).inversed(),
				      wPQ= ((xP == xQ) && (yP + yQ != 0))? (yP + yQ).inversed() : 0;

                if (yP == 0) {
                    xR = xQ;
                    yR = yQ;
                    // lambda doesn't matter for (xR,yR), but needs to satisfy the constraints
                    lambda = (xP == xQ)? 0 : (yQ - yP)/(xQ - xP);
                } else if (yQ == 0) {
                    xR = xP;
                    yR = yP;
                    // lambda doesn't matter for (xR,yR), but needs to satisfy the constraints
                    lambda = (xP == xQ)? 0 : (yQ - yP)/(xQ - xP);
                } else if ((xP == xQ) && (yP + yQ == 0)) {
                    xR = 0;
                    yR = 0;
                    // lambda doesn't matter for (xR,yR), but needs to satisfy the constraints
                    lambda = 3*xP*xP/(2*yP);
                } else {
                    if (xP == xQ) { // point doubling
                        lambda = 3*xP*xP/(2*yP);
                    } else { // regular addition
                        lambda = (yQ - yP)/(xQ - xP);
                    }
                    xR = lambda*lambda - xP - xQ,
                    yR = lambda*(xP - xR) - yP;
                }

                auto base_B = [&B](non_native_value_type x) {
                    std::array<value_type,num_chunks> res;
                    non_native_integral_type t = non_native_integral_type(x.data);
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        res[i] = t % B;
                        t /= B;
                    }
                    return res;
                };

                std::array<value_type,num_chunks> lambda_B = base_B(lambda),
                                                  xR_B = base_B(xR),
                                                  yR_B = base_B(yR),
                                                  zP_B = base_B(zP),
                                                  zQ_B = base_B(zQ),
                                                  zPQ_B = base_B(zPQ),
                                                  wPQ_B = base_B(wPQ);
                // place to store locations for further reference
                var xP_var[num_chunks], yP_var[num_chunks], xQ_var[num_chunks], yQ_var[num_chunks],
                    lambda_var[num_chunks], xR_var[num_chunks], yR_var[num_chunks], zP_var[num_chunks],
                    zQ_var[num_chunks], zPQ_var[num_chunks], wPQ_var[num_chunks];

                // fill cells with chunks of xP, yP, xQ, yQ, lambda, xR, yR, zP, zQ, zPQ, wPQ consecutively
                for(std::size_t i = 0; i < num_chunks; i++) {
                    xP_var[i] = instance_input.xP[i];
                    yP_var[i] = instance_input.yP[i];
                    xQ_var[i] = instance_input.xQ[i];
                    yQ_var[i] = instance_input.yQ[i];
                    assignment.witness(component.W(i % WA), start_row_index + i/WA) = lambda_B[i];
                    lambda_var[i] = var(component.W(i % WA), start_row_index + i/WA, false);

                    assignment.witness(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA) = xR_B[i];
                    xR_var[i] = var(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA,false);

                    assignment.witness(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA) = yR_B[i];
                    yR_var[i] = var(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA,false);

                    assignment.witness(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA) = zP_B[i];
                    zP_var[i] = var(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA,false);

                    assignment.witness(component.W((4*num_chunks + i) % WA), start_row_index + (4*num_chunks + i)/WA) = zQ_B[i];
                    zQ_var[i] = var(component.W((4*num_chunks + i) % WA), start_row_index + (4*num_chunks + i)/WA,false);

                    assignment.witness(component.W((5*num_chunks + i) % WA), start_row_index + (5*num_chunks + i)/WA) = zPQ_B[i];
                    zPQ_var[i] = var(component.W((5*num_chunks + i) % WA), start_row_index + (5*num_chunks + i)/WA,false);

                    assignment.witness(component.W((6*num_chunks + i) % WA), start_row_index + (6*num_chunks + i)/WA) = wPQ_B[i];
                    wPQ_var[i] = var(component.W((6*num_chunks + i) % WA), start_row_index + (6*num_chunks + i)/WA,false);
                }

                // the number of rows used up to now
                std::size_t current_row_shift = (7*num_chunks)/WA + ((7*num_chunks) % WA > 0);

                auto check_chunked_var = [&assignment, &instance_input, &range_check_instance, &check_mod_p_instance,
                                           &start_row_index, &current_row_shift ] (var x[num_chunks]) {
                    typename range_check_type::input_type range_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        range_check_input.x[i] = x[i];
                    }
                    generate_assignments(range_check_instance, assignment, range_check_input, start_row_index + current_row_shift);
                    current_row_shift += range_check_instance.rows_amount;

                    typename check_mod_p_type::input_type mod_p_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mod_p_check_input.x[i] = x[i];
                        mod_p_check_input.pp[i] = instance_input.pp[i];
                    }
                    mod_p_check_input.zero = instance_input.zero;
                    generate_assignments(check_mod_p_instance, assignment, mod_p_check_input,
                        start_row_index + current_row_shift); // check_mod_p
                    current_row_shift += check_mod_p_instance.rows_amount;
                };
                // perform range checks and mod p checks on all stored variables
                check_chunked_var(lambda_var);
                check_chunked_var(xR_var);
                check_chunked_var(yR_var);
                check_chunked_var(zP_var);
                check_chunked_var(zQ_var);
                check_chunked_var(zPQ_var);
                check_chunked_var(wPQ_var);

                // assignment generation lambda expressions for mod p arithemetic
                auto MultModP = [&instance_input, &mult_mod_p_instance, &assignment, &start_row_index, &current_row_shift]
                                (var x[num_chunks], var y[num_chunks]) {
                    typename mult_mod_p_type::input_type mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mult_input.x[i] = x[i];
                        mult_input.y[i] = y[i];
                        mult_input.p[i] = instance_input.p[i];
                        mult_input.pp[i] = instance_input.pp[i];
                    }
                    typename mult_mod_p_type::result_type res = generate_assignments(mult_mod_p_instance, assignment, mult_input,
                                                               start_row_index + current_row_shift);
                    current_row_shift += mult_mod_p_instance.rows_amount;
                    return res;
                };
                auto AddModP = [&instance_input, &add_mod_p_instance, &assignment, &start_row_index, &current_row_shift]
                               (var x[num_chunks], var y[num_chunks]) {
                    typename add_mod_p_type::input_type add_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        add_input.x[i] = x[i];
                        add_input.y[i] = y[i];
                        add_input.p[i] = instance_input.p[i];
                        add_input.pp[i] = instance_input.pp[i];
                    }
                    add_input.zero = instance_input.zero;
                    typename add_mod_p_type::result_type res = generate_assignments(add_mod_p_instance, assignment, add_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += add_mod_p_instance.rows_amount;
                    return res;
                };
                auto NegModP = [&instance_input, &neg_mod_p_instance, &assignment, &start_row_index, &current_row_shift]
                               (var x[num_chunks]) {
                    typename neg_mod_p_type::input_type neg_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        neg_input.x[i] = x[i];
                        neg_input.p[i] = instance_input.p[i];
                        neg_input.pp[i] = instance_input.pp[i];
                    }
                    neg_input.zero = instance_input.zero;
                    typename neg_mod_p_type::result_type res = generate_assignments(neg_mod_p_instance, assignment, neg_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += neg_mod_p_instance.rows_amount;
                    return res;
                };

                // part 1
                auto t1 = NegModP(xQ_var); // t1 = -xQ
                auto t2 = NegModP(yQ_var); // t2 = -yQ
                auto t3 = NegModP(xP_var); // t3 = -xP
                auto t4 = NegModP(yP_var); // t4 = -yP
                auto t5 = AddModP(xR_var,t1.y); // t5 = xR - xQ
                auto t6 = AddModP(yR_var,t2.y); // t6 = yR - yQ
                auto t7 = AddModP(xR_var,t3.y); // t5 = xR - xP
                auto t8 = AddModP(yR_var,t4.y); // t6 = yR - yP
                auto t9 = AddModP(xP_var,t1.y); // t9 = xP - xQ
                auto t10= MultModP(yP_var,zP_var); // t10 = yP * zP
                auto t11= MultModP(yQ_var,zQ_var); // t11 = yQ * zQ
                auto t12= MultModP(t9.z,zPQ_var); // t12 = (xP - xQ) zPQ = ZPQ
                auto t13= MultModP(t5.z,t10.r); // t13 = (xR - xQ) yP zP
                // copy constrain t5 = t13
                auto t14= MultModP(t6.z,t10.r); // t14 = (yR - yQ) yP zP
                // copy constrain t6 = t14
                auto t15= MultModP(t7.z,t11.r); // t15 = (xR - xP) yQ zQ
                // copy constrain t7 = t15
                auto t16= MultModP(t8.z,t11.r); // t16 = (yR - yP) yQ zQ
                // copy constrain t8 = t16
                auto t17= MultModP(t9.z,t12.r); // t17 = (xP - xQ) ZPQ
                // copy constrain t9 = t17

                // part 2
                auto t18= AddModP(yP_var,yQ_var); // t18 = yP + yQ
                auto t19= MultModP(t18.z,wPQ_var); // t19 = (yP + yQ) wPQ = WPQ
                auto t20= AddModP(t12.r,t19.r); // t20 = ZPQ + WPQ
                auto t21= MultModP(xR_var,t20.z); // t21 = xR(ZPQ + WPQ)
                // copy constrain xR = t21
                auto t22= MultModP(yR_var,t20.z); // t22 = yR(ZPQ + WPQ)
                // copy constrain yR = t22

                // part 3
                auto t23= NegModP(t12.r); // t23 = -ZPQ
                auto t24= MultModP(t18.z,t23.y); // t24 = -(yP + yQ) ZPQ
                auto t25= AddModP(t18.z,t24.r); // t25 = (yP + yQ)(1 - ZPQ)
                auto t26= AddModP(t9.z,t25.z); // t26 = (xP - xQ) + (yP + yQ)(1 - ZPQ)
                auto t27= MultModP(yP_var,yQ_var); // t27 = yP * yQ
                auto t28= MultModP(t26.z,t27.r); // t28 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))
                auto t29= MultModP(lambda_var,lambda_var); // t29 = lambda * lambda
                auto t30= NegModP(t29.r); // t30 = -lambda^2
                auto t31= AddModP(xR_var,t30.y); // t31 = xR - lambda^2
                auto t32= AddModP(t31.z,xP_var); // t32 = xR - lambda^2 + xP
                auto t33= AddModP(t32.z,xQ_var); // t33 = xR - lambda^2 + xP + xQ
                auto t34= AddModP(yR_var,yP_var); // t34 = yR + yP
                auto t35= MultModP(t7.z,lambda_var); // t35 = (xR - xP) lambda
                auto t36= AddModP(t34.z,t35.r); // t36 = yR + yP + (xR - xP)lambda
                auto t37= MultModP(t28.r,t33.z); // t37 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(xR - lambda^2 + xP + xQ)
                // copy constrain t37 = 0
                auto t38= MultModP(t28.r,t36.z); // t38 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(yR + yP + (xR - xP)lambda)
                // copy constrain t38 = 0

                // part 4
                auto t39= MultModP(t9.z,lambda_var); // t39 = (xP - xQ) lambda
                auto t40= AddModP(t39.r,t4.y); // t40 = (xP - xQ) lambda - yP
                auto t41= AddModP(t40.z,yQ_var); // t41 = (xP - xQ) lambda - yP + yQ
                auto t42= MultModP(t9.z,t41.z); // t42 = (xP - xQ)((xP - xQ) lambda - yP + yQ)
                // copy constrain t42 = 0
                auto t43= MultModP(xP_var,t3.y); // t43 = -xP^2
                auto t44= AddModP(t43.r,t43.r); // t44 = -2xP^2
                auto t45= AddModP(t43.r,t44.z); // t45 = -3xP^2
                auto t46= AddModP(yP_var,yP_var); // t46 = 2yP
                auto t47= MultModP(t46.z,lambda_var); // t47 = 2yP lambda
                auto t48= AddModP(t47.r,t45.z); // t48 = 2yP lambda - 3xP^2
                auto t49= MultModP(t48.z,t12.r); // t49 = (2yP lambda - 3xP^2) ZPQ
                // copy constrain t48 = t49

                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input) {

                // never actually called
                return {};
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_ec_full_add<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_circuit(
                const plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {
                using component_type = plonk_ec_full_add<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;
                using var = typename component_type::var;

                using range_check_type = typename component_type::range_check_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;
                using mult_mod_p_type = typename component_type::mult_mod_p_component;
                using add_mod_p_type = typename component_type::add_mod_p_component;
                using neg_mod_p_type = typename component_type::neg_mod_p_component;

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using non_native_value_type = typename NonNativeFieldType::value_type;
                using non_native_integral_type = typename NonNativeFieldType::integral_type;

                const std::size_t WA = component.witness_amount();

                // instances of used subcomponents
                range_check_type range_check_instance( component._W, component._C, component._PI);
                check_mod_p_type check_mod_p_instance( component._W, component._C, component._PI);
                mult_mod_p_type  mult_mod_p_instance( component._W, component._C, component._PI);
                add_mod_p_type   add_mod_p_instance( component._W, component._C, component._PI);
                neg_mod_p_type   neg_mod_p_instance( component._W, component._C, component._PI);

                var xP_var[num_chunks], yP_var[num_chunks], xQ_var[num_chunks], yQ_var[num_chunks],
                    lambda_var[num_chunks], xR_var[num_chunks], yR_var[num_chunks], zP_var[num_chunks],
                    zQ_var[num_chunks], zPQ_var[num_chunks], wPQ_var[num_chunks];
                for(std::size_t i = 0; i < num_chunks; i++) {
                    xP_var[i] = instance_input.xP[i];
                    yP_var[i] = instance_input.yP[i];
                    xQ_var[i] = instance_input.xQ[i];
                    yQ_var[i] = instance_input.yQ[i];
                    lambda_var[i] = var(component.W(i % WA), start_row_index + i/WA, false);
                    xR_var[i] = var(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA,false);
                    yR_var[i] = var(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA,false);
                    zP_var[i] = var(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA,false);
                    zQ_var[i] = var(component.W((4*num_chunks + i) % WA), start_row_index + (4*num_chunks + i)/WA,false);
                    zPQ_var[i] = var(component.W((5*num_chunks + i) % WA), start_row_index + (5*num_chunks + i)/WA,false);
                    wPQ_var[i] = var(component.W((6*num_chunks + i) % WA), start_row_index + (6*num_chunks + i)/WA,false);

                }

                // the number of rows used by data storage
                std::size_t current_row_shift = (7*num_chunks)/WA + ((7*num_chunks) % WA > 0);

                auto check_chunked_var = [&bp, &assignment, &instance_input, &range_check_instance, &check_mod_p_instance,
                                           &start_row_index, &current_row_shift ] (var x[num_chunks]) {
                    typename range_check_type::input_type range_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        range_check_input.x[i] = x[i];
                    }
                    generate_circuit(range_check_instance, bp, assignment, range_check_input, start_row_index + current_row_shift);
                    current_row_shift += range_check_instance.rows_amount;

                    typename check_mod_p_type::input_type mod_p_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mod_p_check_input.x[i] = x[i];
                        mod_p_check_input.pp[i] = instance_input.pp[i];
                    }
                    mod_p_check_input.zero = instance_input.zero;
                    generate_circuit(check_mod_p_instance, bp, assignment, mod_p_check_input,
                        start_row_index + current_row_shift); // check_mod_p
                    current_row_shift += check_mod_p_instance.rows_amount;
                };
                // perform range checks and mod p checks on all stored variables
                check_chunked_var(lambda_var);
                check_chunked_var(xR_var);
                check_chunked_var(yR_var);
                check_chunked_var(zP_var);
                check_chunked_var(zQ_var);
                check_chunked_var(zPQ_var);
                check_chunked_var(wPQ_var);

                // circuit generation lambda expressions for mod p arithemetic
                auto MultModP = [&instance_input, &mult_mod_p_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                (var x[num_chunks], var y[num_chunks]) {
                    typename mult_mod_p_type::input_type mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mult_input.x[i] = x[i];
                        mult_input.y[i] = y[i];
                        mult_input.p[i] = instance_input.p[i];
                        mult_input.pp[i] = instance_input.pp[i];
                    }
                    typename mult_mod_p_type::result_type res = generate_circuit(mult_mod_p_instance, bp, assignment, mult_input,
                                                               start_row_index + current_row_shift);
                    current_row_shift += mult_mod_p_instance.rows_amount;
                    return res;
                };
                auto AddModP = [&instance_input, &add_mod_p_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                               (var x[num_chunks], var y[num_chunks]) {
                    typename add_mod_p_type::input_type add_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        add_input.x[i] = x[i];
                        add_input.y[i] = y[i];
                        add_input.p[i] = instance_input.p[i];
                        add_input.pp[i] = instance_input.pp[i];
                    }
                    add_input.zero = instance_input.zero;
                    typename add_mod_p_type::result_type res = generate_circuit(add_mod_p_instance, bp, assignment, add_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += add_mod_p_instance.rows_amount;
                    return res;
                };
                auto NegModP = [&instance_input, &neg_mod_p_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                               (var x[num_chunks]) {
                    typename neg_mod_p_type::input_type neg_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        neg_input.x[i] = x[i];
                        neg_input.p[i] = instance_input.p[i];
                        neg_input.pp[i] = instance_input.pp[i];
                    }
                    neg_input.zero = instance_input.zero;
                    typename neg_mod_p_type::result_type res = generate_circuit(neg_mod_p_instance, bp, assignment, neg_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += neg_mod_p_instance.rows_amount;
                    return res;
                };

                // Copy constraint generation lambda expression
                auto CopyConstrain = [&bp](var x[num_chunks], var y[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        bp.add_copy_constraint({x[i], y[i]});
                    }
                };
                // Copy constrain to zero lambda expression
                auto ZeroConstrain = [&bp, &instance_input](var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        bp.add_copy_constraint({x[i],instance_input.zero});
                    }
                };

                // part 1
                auto t1 = NegModP(xQ_var);         // t1 = -xQ
                auto t2 = NegModP(yQ_var);         // t2 = -yQ
                auto t3 = NegModP(xP_var);         // t3 = -xP
                auto t4 = NegModP(yP_var);         // t4 = -yP
                auto t5 = AddModP(xR_var,t1.y);    // t5 = xR - xQ
                auto t6 = AddModP(yR_var,t2.y);    // t6 = yR - yQ
                auto t7 = AddModP(xR_var,t3.y);    // t5 = xR - xP
                auto t8 = AddModP(yR_var,t4.y);    // t6 = yR - yP
                auto t9 = AddModP(xP_var,t1.y);    // t9 = xP - xQ
                auto t10= MultModP(yP_var,zP_var); // t10 = yP * zP
                auto t11= MultModP(yQ_var,zQ_var); // t11 = yQ * zQ
                auto t12= MultModP(t9.z,zPQ_var);  // t12 = (xP - xQ) zPQ = ZPQ
                auto t13= MultModP(t5.z,t10.r);    // t13 = (xR - xQ) yP zP
                CopyConstrain(t5.z,t13.r); // xR - xQ = (xR - xQ) yP zP
                auto t14= MultModP(t6.z,t10.r);    // t14 = (yR - yQ) yP zP
                CopyConstrain(t6.z,t14.r); // xR - yQ = (xR - yQ) yP zP
                auto t15= MultModP(t7.z,t11.r);    // t15 = (xR - xP) yQ zQ
                CopyConstrain(t7.z,t15.r); // xR - xP = (xR - xP) yQ zQ
                auto t16= MultModP(t8.z,t11.r);    // t16 = (yR - yP) yQ zQ
                CopyConstrain(t8.z,t16.r); // xR - yP = (xR - yP) yQ zQ
                auto t17= MultModP(t9.z,t12.r);    // t17 = (xP - xQ) ZPQ
                CopyConstrain(t9.z,t17.r); // xP - xQ = (xP - xQ) ZPQ

                // part 2
                auto t18= AddModP(yP_var,yQ_var);  // t18 = yP + yQ
                auto t19= MultModP(t18.z,wPQ_var); // t19 = (yP + yQ) wPQ = WPQ
                auto t20= AddModP(t12.r,t19.r);    // t20 = ZPQ + WPQ
                auto t21= MultModP(xR_var,t20.z);  // t21 = xR(ZPQ + WPQ)
                CopyConstrain(xR_var,t21.r); // xR = xR (ZPQ + WPQ)
                auto t22= MultModP(yR_var,t20.z);  // t22 = yR(ZPQ + WPQ)
                CopyConstrain(yR_var,t22.r); // yR = yR (ZPQ + WPQ)

                // part 3
                auto t23= NegModP(t12.r);          // t23 = -ZPQ
                auto t24= MultModP(t18.z,t23.y);   // t24 = -(yP + yQ) ZPQ
                auto t25= AddModP(t18.z,t24.r);    // t25 = (yP + yQ)(1 - ZPQ)
                auto t26= AddModP(t9.z,t25.z);     // t26 = (xP - xQ) + (yP + yQ)(1 - ZPQ)
                auto t27= MultModP(yP_var,yQ_var); // t27 = yP * yQ
                auto t28= MultModP(t26.z,t27.r);   // t28 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))
                auto t29= MultModP(lambda_var,lambda_var); // t29 = lambda * lambda
                auto t30= NegModP(t29.r);          // t30 = -lambda^2
                auto t31= AddModP(xR_var,t30.y);   // t31 = xR - lambda^2
                auto t32= AddModP(t31.z,xP_var);   // t32 = xR - lambda^2 + xP
                auto t33= AddModP(t32.z,xQ_var);   // t33 = xR - lambda^2 + xP + xQ
                auto t34= AddModP(yR_var,yP_var);  // t34 = yR + yP
                auto t35= MultModP(t7.z,lambda_var); // t35 = (xR - xP) lambda
                auto t36= AddModP(t34.z,t35.r);    // t36 = yR + yP + (xR - xP)lambda
                auto t37= MultModP(t28.r,t33.z);   // t37 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(xR - lambda^2 + xP + xQ)
                ZeroConstrain(t37.r); // yP yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(xR - lambda^2 + xP + xQ) = 0
                auto t38= MultModP(t28.r,t36.z);   // t38 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(yR + yP + (xR - xP)lambda)
                ZeroConstrain(t38.r); // yP yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(yR + yP + (xR - xP)lambda) = 0

                // part 4
                auto t39= MultModP(t9.z,lambda_var); // t39 = (xP - xQ) lambda
                auto t40= AddModP(t39.r,t4.y);       // t40 = (xP - xQ) lambda - yP
                auto t41= AddModP(t40.z,yQ_var);     // t41 = (xP - xQ) lambda - yP + yQ
                auto t42= MultModP(t9.z,t41.z);      // t42 = (xP - xQ)((xP - xQ) lambda - yP + yQ)
                ZeroConstrain(t42.r); // (xP - xQ)((xP - xQ) lambda - yP + yQ) = 0
                auto t43= MultModP(xP_var,t3.y);     // t43 = -xP^2
                auto t44= AddModP(t43.r,t43.r);      // t44 = -2xP^2
                auto t45= AddModP(t43.r,t44.z);      // t45 = -3xP^2
                auto t46= AddModP(yP_var,yP_var);    // t46 = 2yP
                auto t47= MultModP(t46.z,lambda_var); // t47 = 2yP lambda
                auto t48= AddModP(t47.r,t45.z);      // t48 = 2yP lambda - 3xP^2
                auto t49= MultModP(t48.z,t12.r);     // t49 = (2yP lambda - 3xP^2) ZPQ
                CopyConstrain(t48.z,t49.r); // 2yP lambda - 3xP^2 = (2yP lambda - 3xP^2) ZPQ

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index); // does nothing, may be skipped?

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_FULL_ADD_ECDSA_HPP
