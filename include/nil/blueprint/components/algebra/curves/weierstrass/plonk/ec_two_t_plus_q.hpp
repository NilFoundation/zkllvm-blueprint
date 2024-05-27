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
// @file Declaration of interfaces for addition of EC points T,Q as T+Q+T over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_TWO_T_PLUS_Q_ECDSA_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_TWO_T_PLUS_Q_ECDSA_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/detail/plonk/range_check.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/check_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/negation_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition_mod_p.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Parameters: num_chunks = k, bit_size_chunk = b
            // For points T = (x_T,y_T), Q = (x_Q,y_Q), x_T != x_T, T,Q != O
            // from an elliptic curve over F[p]
            // computes R = (x_R, y_R) = T + Q + T
            // Expects input as k-chunked values with b bits per chunk
            // p' = 2^(kb) - p
            // Input: xT[0],...,xT[k-1],yT[0],...,yT[k-1],xQ[0],...,xQ[k-1], yQ[0],...,yQ[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1], 0
            // (expects zero constant as input)
            // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType,
                     typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ec_two_t_plus_q;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ec_two_t_plus_q<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           NonNativeFieldType,
                           num_chunks,
                           bit_size_chunk>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using range_check_component = range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, bit_size_chunk>;
                using check_mod_p_component = check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks, bit_size_chunk>;
                using mult_mod_p_component = flexible_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using neg_mod_p_component = negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using add_mod_p_component = addition_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return ec_two_t_plus_q::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    // NB: this uses a workaround, as manifest cannot process intersecting sets of gates.
                    // We merge only non-intersecting sets of gates which cover all gates in the circuit.
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                    //    .merge_with(range_check_component::get_gate_manifest(witness_amount, lookup_column_amount))
                    //    .merge_with(check_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(mult_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                    //    .merge_with(add_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(neg_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // all requirements come from sub-components, the component itself has no personal requirements
                        std::shared_ptr<manifest_param>(new manifest_range_param(1,5*num_chunks,1)), // we need place for 5k variables
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
                    return (5*num_chunks)/witness_amount + ((5*num_chunks) % witness_amount > 0) // to store 5k variables
                           + 5*range_check_component::get_rows_amount(witness_amount,lookup_column_amount)*num_chunks
                           // NB: awaiting a batched version of range_check to get rid of the *num_chunks here ^^^
                           + 5*check_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 5*mult_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 10*add_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 3*neg_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           ;
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "non-native field EC point T + Q + T function";

                struct input_type {
                    var xT[num_chunks], yT[num_chunks], xQ[num_chunks], yQ[num_chunks], p[num_chunks], pp[num_chunks], zero;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {zero};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(xT[i]);
                            res.push_back(yT[i]);
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

                    result_type(const ec_two_t_plus_q &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            xR[i] = var(component.W((3*num_chunks + i) % WA),
                                        start_row_index + (3*num_chunks + i)/WA, false, var::column_type::witness);
                            yR[i] = var(component.W((4*num_chunks + i) % WA),
                                        start_row_index + (4*num_chunks + i)/WA, false, var::column_type::witness);
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
                explicit ec_two_t_plus_q(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                ec_two_t_plus_q(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                ec_two_t_plus_q(
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
            using plonk_ec_two_t_plus_q =
                ec_two_t_plus_q<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    NonNativeFieldType,
                    num_chunks,
                    bit_size_chunk>;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_assignments(
                const plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;
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
                non_native_value_type xT = 0,
                                      yT = 0,
                                      xQ = 0,
                                      yQ = 0;

                for(std::size_t i = num_chunks; i > 0; i--) {
                    xT *= B;
                    xT += non_native_integral_type(var_value(assignment, instance_input.xT[i-1]).data);
                    yT *= B;
                    yT += non_native_integral_type(var_value(assignment, instance_input.yT[i-1]).data);
                    xQ *= B;
                    xQ += non_native_integral_type(var_value(assignment, instance_input.xQ[i-1]).data);
                    yQ *= B;
                    yQ += non_native_integral_type(var_value(assignment, instance_input.yQ[i-1]).data);
                }

                non_native_value_type lambda = (yQ - yT)/(xQ - xT),
                                      xS = lambda*lambda - xT - xQ,
                                      mu = -lambda - (2*yT)/(xS - xT),
                                      xR = mu*mu - xT - xS,
                                      yR = mu*(xT - xR) - yT;

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
                                                  mu_B = base_B(mu),
                                                  xS_B = base_B(xS),
                                                  xR_B = base_B(xR),
                                                  yR_B = base_B(yR);
                // place to store locations for further reference
                var xT_var[num_chunks], yT_var[num_chunks], xQ_var[num_chunks], yQ_var[num_chunks],
                    lambda_var[num_chunks], mu_var[num_chunks], xS_var[num_chunks], xR_var[num_chunks], yR_var[num_chunks];

                // fill cells with chunks of lambda, mu, xS, xR, yR consecutively
                for(std::size_t i = 0; i < num_chunks; i++) {
                    xT_var[i] = instance_input.xT[i];
                    yT_var[i] = instance_input.yT[i];
                    xQ_var[i] = instance_input.xQ[i];
                    yQ_var[i] = instance_input.yQ[i];
                    assignment.witness(component.W(i % WA), start_row_index + i/WA) = lambda_B[i];
                    lambda_var[i] = var(component.W(i % WA), start_row_index + i/WA, false);

                    assignment.witness(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA) = mu_B[i];
                    mu_var[i] = var(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA, false);

                    assignment.witness(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA) = xS_B[i];
                    xS_var[i] = var(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA,false);

                    assignment.witness(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA) = xR_B[i];
                    xR_var[i] = var(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA,false);

                    assignment.witness(component.W((4*num_chunks + i) % WA), start_row_index + (4*num_chunks + i)/WA) = yR_B[i];
                    yR_var[i] = var(component.W((4*num_chunks + i) % WA), start_row_index + (4*num_chunks + i)/WA,false);
                }

                // the number of rows used up to now
                std::size_t current_row_shift = (5*num_chunks)/WA + ((5*num_chunks) % WA > 0);

                auto check_chunked_var = [&assignment, &instance_input, &range_check_instance, &check_mod_p_instance,
                                           &start_row_index, &current_row_shift ] (var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        typename range_check_type::input_type range_check_input = { x[i] };
                        generate_assignments(range_check_instance, assignment, range_check_input,
                            start_row_index + current_row_shift); // range_check. When it is batched, this will move outside the cycle
                        current_row_shift += range_check_instance.rows_amount;
                    }
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
                check_chunked_var(mu_var);
                check_chunked_var(xS_var);
                check_chunked_var(xR_var);
                check_chunked_var(yR_var);

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

                typename neg_mod_p_type::result_type  t1 = NegModP(xT_var);                 // t1 = -xT
                typename add_mod_p_type::result_type  t2 = AddModP(xQ_var,t1.y);            // t2 = xQ + t1 = xQ - xT
                typename mult_mod_p_type::result_type t3 = MultModP(t2.z,lambda_var);       // t3 = t2 * lambda = (xQ-xT)lambda
                typename add_mod_p_type::result_type  t4 = AddModP(t3.r,yT_var);            // t4 = t3 + yT = (xQ-xP)lambda + yT
                typename add_mod_p_type::result_type  t5 = AddModP(xS_var,xT_var);          // t5 = xS + xT
                typename add_mod_p_type::result_type  t6 = AddModP(t5.z,xQ_var);            // t6 = t5 + xQ = xS + xT + xQ
                typename mult_mod_p_type::result_type t7 = MultModP(lambda_var,lambda_var); // t7 = lambda * lambda
                typename add_mod_p_type::result_type  t8 = AddModP(lambda_var,mu_var);      // t8 = lambda + mu
                typename neg_mod_p_type::result_type  t9 = NegModP(xS_var);                 // t9 = -xS
                typename add_mod_p_type::result_type  t10= AddModP(xT_var,t9.y);            // t10 = xT + t9 = xT - xS
                typename mult_mod_p_type::result_type t11= MultModP(t8.z,t10.z);            // t11 = t8*t10 = (lambda+mu)(xT-xS)
                typename add_mod_p_type::result_type  t12= AddModP(yT_var,yT_var);          // t12 = yT + yT = 2yT
                typename add_mod_p_type::result_type  t13= AddModP(t5.z,xR_var);            // t13 = t5 + xR = xS + xT + xR
                typename mult_mod_p_type::result_type t14= MultModP(mu_var,mu_var);         // t14 = mu * mu
                typename add_mod_p_type::result_type  t15= AddModP(yR_var,yT_var);          // t15 = yR + yT
                typename neg_mod_p_type::result_type  t16= NegModP(xR_var);                 // t16 = -xR
                typename add_mod_p_type::result_type  t17= AddModP(xT_var,t16.y);           // t17 = xT + t16 = xT - xR
                typename mult_mod_p_type::result_type t18= MultModP(mu_var,t17.z);          // t18 = mu * t17 = mu(xT-xR)

                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input) {

                // never actually called
                return {};
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_ec_two_t_plus_q<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_circuit(
                const plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {
                using component_type = plonk_ec_two_t_plus_q<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;
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

                var xT_var[num_chunks], yT_var[num_chunks], xQ_var[num_chunks], yQ_var[num_chunks],
                    lambda_var[num_chunks], mu_var[num_chunks], xS_var[num_chunks], xR_var[num_chunks], yR_var[num_chunks];
                for(std::size_t i = 0; i < num_chunks; i++) {
                    xT_var[i] = instance_input.xT[i];
                    yT_var[i] = instance_input.yT[i];
                    xQ_var[i] = instance_input.xQ[i];
                    yQ_var[i] = instance_input.yQ[i];
                    lambda_var[i] = var(component.W(i % WA), start_row_index + i/WA, false);
                    mu_var[i] = var(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA,false);
                    xS_var[i] = var(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA,false);
                    xR_var[i] = var(component.W((3*num_chunks + i) % WA), start_row_index + (3*num_chunks + i)/WA,false);
                    yR_var[i] = var(component.W((4*num_chunks + i) % WA), start_row_index + (4*num_chunks + i)/WA,false);
                }

                // the number of rows used by data storage
                std::size_t current_row_shift = (5*num_chunks)/WA + ((5*num_chunks) % WA > 0);

                auto check_chunked_var = [&bp, &assignment, &instance_input, &range_check_instance, &check_mod_p_instance,
                                           &start_row_index, &current_row_shift ] (var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        typename range_check_type::input_type range_check_input = { x[i] };
                        generate_circuit(range_check_instance, bp, assignment, range_check_input,
                            start_row_index + current_row_shift); // range_check. When it is batched, this will move outside the cycle
                        current_row_shift += range_check_instance.rows_amount;
                    }
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
                check_chunked_var(mu_var);
                check_chunked_var(xS_var);
                check_chunked_var(xR_var);
                check_chunked_var(yR_var);

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

                typename neg_mod_p_type::result_type  t1 = NegModP(xT_var);                 // t1 = -xT
                typename add_mod_p_type::result_type  t2 = AddModP(xQ_var,t1.y);            // t2 = xQ + t1 = xQ - xT
                typename mult_mod_p_type::result_type t3 = MultModP(t2.z,lambda_var);       // t3 = t2 * lambda = (xQ-xT)lambda
                typename add_mod_p_type::result_type  t4 = AddModP(t3.r,yT_var);            // t4 = t3 + yT = (xQ-xP)lambda + yT
                CopyConstrain(t4.z,yQ_var); // (xQ - xT)lambda + yP = yQ
                typename add_mod_p_type::result_type  t5 = AddModP(xS_var,xT_var);          // t5 = xS + xT
                typename add_mod_p_type::result_type  t6 = AddModP(t5.z,xQ_var);            // t6 = t5 + xQ = xS + xT + xQ
                typename mult_mod_p_type::result_type t7 = MultModP(lambda_var,lambda_var); // t7 = lambda * lambda
                CopyConstrain(t6.z,t7.r); // xS + xT + xQ = lambda^2
                typename add_mod_p_type::result_type  t8 = AddModP(lambda_var,mu_var);      // t8 = lambda + mu
                typename neg_mod_p_type::result_type  t9 = NegModP(xS_var);                 // t9 = -xS
                typename add_mod_p_type::result_type  t10= AddModP(xT_var,t9.y);            // t10 = xT + t9 = xT - xS
                typename mult_mod_p_type::result_type t11= MultModP(t8.z,t10.z);            // t11 = t8*t10 = (lambda+mu)(xT-xS)
                typename add_mod_p_type::result_type  t12= AddModP(yT_var,yT_var);          // t12 = yT + yT = 2yT
                CopyConstrain(t11.r,t12.z); // (lambda+mu)(xT - xS) = 2yT
                typename add_mod_p_type::result_type  t13= AddModP(t5.z,xR_var);            // t13 = t5 + xR = xS + xT + xR
                typename mult_mod_p_type::result_type t14= MultModP(mu_var,mu_var);         // t14 = mu * mu
                CopyConstrain(t13.z,t14.r); // xS + xT + xR = mu^2
                typename add_mod_p_type::result_type  t15= AddModP(yR_var,yT_var);          // t15 = yR + yT
                typename neg_mod_p_type::result_type  t16= NegModP(xR_var);                 // t16 = -xR
                typename add_mod_p_type::result_type  t17= AddModP(xT_var,t16.y);           // t17 = xT + t16 = xT - xR
                typename mult_mod_p_type::result_type t18= MultModP(mu_var,t17.z);          // t18 = mu * t17 = mu(xT-xR)
                CopyConstrain(t15.z,t18.r); // yR + yT = mu(xT - xR)

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index); // does nothing, may be skipped?

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_INCOMPLETE_ADD_ECDSA_HPP
