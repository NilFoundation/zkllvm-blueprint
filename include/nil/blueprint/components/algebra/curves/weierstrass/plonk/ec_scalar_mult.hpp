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
// @file Declaration of interfaces for scalar multiplication of EC points over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_SCALAR_MULT_ECDSA_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_SCALAR_MULT_ECDSA_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/detail/plonk/range_check_multi.hpp>
#include <nil/blueprint/components/detail/plonk/carry_on_addition.hpp>
#include <nil/blueprint/components/detail/plonk/choice_function.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/negation_mod_p.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_double.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_incomplete_add.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_two_t_plus_q.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Parameters: num_chunks = k, bit_size_chunk = b
            // For scalar s and point P = (x,y), P != O, s != 0 (to be corrected?)
            // from an elliptic curve over F[p]
            // computes R = s × P (scalar product for EC point)
            // Expects input as k-chunked values with b bits per chunk
            // Other values: p' = 2^(kb) - p, n = size of EC group, m = (n-1)/2, m' = 2^(kb) - m
            // Input: s[0],...,s[k-1], x[0],...,x[k-1], y[0],...,y[k-1],
            // p[0],...,p[k-1], pp[0], ..., pp[k-1], n[0],...,n[k-1], mp[0],...,mp[k-1], 0
            // (expects zero constant as input)
            // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType,
                     typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ec_scalar_mult;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ec_scalar_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
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
                using carry_on_addition_component = carry_on_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk>;
                using choice_function_component = choice_function<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks>;
                using neg_mod_p_component = negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using ec_double_component = ec_double<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using ec_incomplete_addition_component = ec_incomplete_add<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;
                using ec_two_t_plus_q_component = ec_two_t_plus_q<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return ec_scalar_mult::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    // NB: this uses a workaround, as manifest cannot process intersecting sets of gates.
                    // We merge only non-intersecting sets of gates which cover all gates in the circuit.
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                       // .merge_with(range_check_component::get_gate_manifest(witness_amount, lookup_column_amount))
                       // .merge_with(carry_on_addition_component::get_gate_manifest(witness_amount, lookup_column_amount))
                       // .merge_with(choice_function_component::get_gate_manifest(witness_amount, lookup_column_amount))
                       // .merge_with(neg_mod_p_component::get_gate_manifest(witness_amount, lookup_column_amount))
                       // .merge_with(ec_double_component::get_gate_manifest(witness_amount, lookup_column_amount))
                       // .merge_with(ec_incomplete_addition_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(ec_two_t_plus_q_component::get_gate_manifest(witness_amount, lookup_column_amount))
                       ;
                    return manifest;
                }

                static manifest_type get_manifest() {
                    manifest_type manifest = manifest_type(
                        // all requirements come from sub-components, the component itself has no personal requirements
                        // we need place for the output (2*num_chunks),
                        // the actually used scalar (num_chunks) and its bit decomposition (bit_size_chunk*num_chunks)
                        std::shared_ptr<manifest_param>(new manifest_range_param(1,
                                                        (3 + bit_size_chunk)*num_chunks + (bit_size_chunk*num_chunks % 2),1)),
                        false // constant column not needed
                    ).merge_with(range_check_component::get_manifest())
                     .merge_with(carry_on_addition_component::get_manifest())
                     .merge_with(choice_function_component::get_manifest())
                     .merge_with(neg_mod_p_component::get_manifest())
                     .merge_with(ec_double_component::get_manifest())
                     .merge_with(ec_incomplete_addition_component::get_manifest())
                     .merge_with(ec_two_t_plus_q_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                     const std::size_t L = bit_size_chunk*num_chunks + (bit_size_chunk*num_chunks % 2), // if odd, then +1. L is always even
                                  Q = L/2;
                    // 2*num_chunks : to store the output
                    // num_chunks : to store the actually used scalar
                    // L = bit_size_chunk*num_chunks + (bit_size_chunk*num_chunks % 2) : to store the used scalar bit decomposition
                    std::size_t total_cells = (bit_size_chunk+3)*num_chunks + (bit_size_chunk*num_chunks % 2);
                    std::size_t num_rows = total_cells/witness_amount + (total_cells % witness_amount > 0)
                           + (4*Q-1)*range_check_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + (4*Q)*carry_on_addition_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 6*Q*choice_function_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 2*neg_mod_p_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + Q*ec_double_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + 3*ec_incomplete_addition_component::get_rows_amount(witness_amount,lookup_column_amount)
                           + (Q-1)*ec_two_t_plus_q_component::get_rows_amount(witness_amount,lookup_column_amount)
                           ;
std::cout << "Rows amount = " << num_rows << "\n";
                    return num_rows;
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "non-native field EC point scalar multiplication";

                struct input_type {
                    var s[num_chunks], x[num_chunks], y[num_chunks],
                        p[num_chunks], pp[num_chunks], n[num_chunks], mp[num_chunks], zero;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {zero};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(s[i]);
                            res.push_back(x[i]);
                            res.push_back(y[i]);
                            res.push_back(p[i]);
                            res.push_back(pp[i]);
                            res.push_back(n[i]);
                            res.push_back(mp[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    var xR[num_chunks], yR[num_chunks];

                    result_type(const ec_scalar_mult &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            xR[i] = var(component.W(i % WA),
                                        start_row_index + i/WA, false, var::column_type::witness);
                            yR[i] = var(component.W((num_chunks + i) % WA),
                                        start_row_index + (num_chunks + i)/WA, false, var::column_type::witness);
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
                explicit ec_scalar_mult(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                ec_scalar_mult(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                ec_scalar_mult(
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
            using plonk_ec_scalar_mult =
                ec_scalar_mult<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    NonNativeFieldType,
                    num_chunks,
                    bit_size_chunk>;

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_assignments(
                const plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;
                using var = typename component_type::var;

                using range_check_type = typename component_type::range_check_component;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using choice_function_type = typename component_type::choice_function_component;
                using neg_mod_p_type = typename component_type::neg_mod_p_component;
                using ec_double_type = typename component_type::ec_double_component;
                using ec_incomplete_addition_type = typename component_type::ec_incomplete_addition_component;
                using ec_two_t_plus_q_type = typename component_type::ec_two_t_plus_q_component;

                using value_type = typename BlueprintFieldType::value_type;
                using non_native_value_type = typename NonNativeFieldType::value_type;
                using non_native_integral_type = typename NonNativeFieldType::extended_integral_type;

                const std::size_t WA = component.witness_amount();

                // instances of used subcomponents
                range_check_type            range_check_instance( component._W, component._C, component._PI);
                carry_on_addition_type      carry_on_addition_instance( component._W, component._C, component._PI);
                choice_function_type        choice_function_instance( component._W, component._C, component._PI);
                neg_mod_p_type              neg_mod_p_instance( component._W, component._C, component._PI);
                ec_double_type              ec_double_instance( component._W, component._C, component._PI);
                ec_incomplete_addition_type ec_incomplete_addition_instance( component._W, component._C, component._PI);
                ec_two_t_plus_q_type        ec_two_t_plus_q_instance( component._W, component._C, component._PI);

                non_native_integral_type B = non_native_integral_type(1) << bit_size_chunk,
                                         s = 0,
                                         n = 0,
                                         mp = 0;

                for(std::size_t i = num_chunks; i > 0; i--) {
                    s *= B;
                    s += non_native_integral_type(var_value(assignment, instance_input.s[i-1]).data);
                    n *= B;
                    n += non_native_integral_type(var_value(assignment, instance_input.n[i-1]).data);
                    mp *= B;
                    mp += non_native_integral_type(var_value(assignment, instance_input.mp[i-1]).data);
                }
                non_native_integral_type sp = n - s,
                                         C = (s > (n-1)/2) ? sp : s;

                const std::size_t L = bit_size_chunk*num_chunks + (bit_size_chunk*num_chunks % 2), // if odd, then +1. Thus L is always even
                                  Q = L/2;

                value_type cp[Q], cpp[Q];
                // binary expansion of C, LSB
                for(std::size_t i = 0; i < L; i++) {
                    if (i % 2) { // if i is odd
                        cp[i/2] = C % 2;
                    } else {
                        cpp[i/2] = C % 2;
                    }
                    C /= 2;
                }

                // base B representation of sp
                value_type sp_B[num_chunks];
                for(std::size_t i = 0; i < num_chunks; i++) {
                    sp_B[i] = sp % B;
                    sp /= B;
                }

                // place to store locations for further reference
                var s_var[num_chunks], x_var[num_chunks], y_var[num_chunks], mp_var[num_chunks],
                    sp_var[num_chunks], cp_var[Q], cpp_var[Q];

                for(std::size_t i = 0; i < num_chunks; i++) {
                    s_var[i] = instance_input.s[i];
                    x_var[i] = instance_input.x[i];
                    y_var[i] = instance_input.y[i];
                    mp_var[i] = instance_input.mp[i];
                }

                // fill cells with chunks of sp (skip 2*num_chunks to leave space for xR and yR)
                for(std::size_t i = 0; i < num_chunks; i++) {
                    assignment.witness(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA) = sp_B[i];
                    sp_var[i] = var(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA,false);
                }
                // fill cells with bits of C
                for(std::size_t i = 0; i < Q; i++) {
                    assignment.witness(component.W((3*num_chunks + 2*i) % WA), start_row_index + (3*num_chunks + 2*i)/WA) = cpp[i];
                    cpp_var[i] = var(component.W((3*num_chunks + 2*i) % WA), start_row_index + (3*num_chunks + 2*i)/WA,false);

                    assignment.witness(component.W((3*num_chunks + 2*i+1) % WA), start_row_index + (3*num_chunks + 2*i+1)/WA) = cp[i];
                    cp_var[i] = var(component.W((3*num_chunks + 2*i+1) % WA), start_row_index + (3*num_chunks + 2*i+1)/WA,false);
                }

                // the number of rows used up to now
                std::size_t total_cells = (bit_size_chunk+3)*num_chunks + (bit_size_chunk*num_chunks % 2);
                std::size_t current_row_shift = total_cells/WA + (total_cells % WA > 0);

                // assignment generation lambda expressions
                auto RangeCheck = [&assignment, &instance_input, &range_check_instance, &start_row_index, &current_row_shift]
                                  (var x[num_chunks]) {
                    typename range_check_type::input_type range_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        range_check_input.x[i] = x[i];
                    }
                    generate_assignments(range_check_instance, assignment, range_check_input, start_row_index + current_row_shift);
                    current_row_shift += range_check_instance.rows_amount;
                };
                auto CarryOnAddition = [&carry_on_addition_instance, &assignment, &start_row_index, &current_row_shift]
                                       (var x[num_chunks], var y[num_chunks]) {
                    typename carry_on_addition_type::input_type carry_on_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        carry_on_addition_input.x[i] = x[i];
                        carry_on_addition_input.y[i] = y[i];
                    }
                    typename carry_on_addition_type::result_type res = generate_assignments(carry_on_addition_instance, assignment,
                                                                 carry_on_addition_input, start_row_index + current_row_shift);
                    current_row_shift += carry_on_addition_instance.rows_amount;
                    return res;
                };
                auto ChoiceFunction = [&assignment, &instance_input, &choice_function_instance, &start_row_index, &current_row_shift]
                                      (var q, var x[num_chunks], var y[num_chunks]) {
                    typename choice_function_type::input_type choice_function_input;
                    choice_function_input.q = q;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        choice_function_input.x[i] = x[i];
                        choice_function_input.y[i] = y[i];
                    }
                    typename choice_function_type::result_type res = generate_assignments(choice_function_instance, assignment,
                                                               choice_function_input, start_row_index + current_row_shift);
                    current_row_shift += choice_function_instance.rows_amount;
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
                auto ECDouble = [&instance_input, &ec_double_instance, &assignment, &start_row_index, &current_row_shift]
                                (var x[num_chunks], var y[num_chunks]){
                    typename ec_double_type::input_type ec_double_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_double_input.xQ[i] = x[i];
                        ec_double_input.yQ[i] = y[i];
                        ec_double_input.p[i] = instance_input.p[i];
                        ec_double_input.pp[i] = instance_input.pp[i];
                    }
                    ec_double_input.zero = instance_input.zero;
                    typename ec_double_type::result_type res = generate_assignments(ec_double_instance, assignment, ec_double_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += ec_double_instance.rows_amount;
                    return res;
                };
                auto ECIncompleteAdd = [&instance_input, &ec_incomplete_addition_instance, &assignment, &start_row_index, &current_row_shift]
                                (var xP[num_chunks], var yP[num_chunks], var xQ[num_chunks], var yQ[num_chunks]){
                    typename ec_incomplete_addition_type::input_type ec_incomplete_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_incomplete_addition_input.xP[i] = xP[i];
                        ec_incomplete_addition_input.yP[i] = yP[i];
                        ec_incomplete_addition_input.xQ[i] = xQ[i];
                        ec_incomplete_addition_input.yQ[i] = yQ[i];
                        ec_incomplete_addition_input.p[i] = instance_input.p[i];
                        ec_incomplete_addition_input.pp[i] = instance_input.pp[i];
                    }
                    ec_incomplete_addition_input.zero = instance_input.zero;
                    typename ec_incomplete_addition_type::result_type res = generate_assignments(ec_incomplete_addition_instance,
                                                                           assignment, ec_incomplete_addition_input,
                                                                           start_row_index + current_row_shift);
                    current_row_shift += ec_incomplete_addition_instance.rows_amount;
                    return res;
                };
                auto ECTwoTPlusQ = [&instance_input, &ec_two_t_plus_q_instance, &assignment, &start_row_index, &current_row_shift]
                                (var xT[num_chunks], var yT[num_chunks], var xQ[num_chunks], var yQ[num_chunks]){
                    typename ec_two_t_plus_q_type::input_type ec_two_t_plus_q_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_two_t_plus_q_input.xT[i] = xT[i];
                        ec_two_t_plus_q_input.yT[i] = yT[i];
                        ec_two_t_plus_q_input.xQ[i] = xQ[i];
                        ec_two_t_plus_q_input.yQ[i] = yQ[i];
                        ec_two_t_plus_q_input.p[i] = instance_input.p[i];
                        ec_two_t_plus_q_input.pp[i] = instance_input.pp[i];
                    }
                    ec_two_t_plus_q_input.zero = instance_input.zero;
                    typename ec_two_t_plus_q_type::result_type res = generate_assignments(ec_two_t_plus_q_instance,
                                                                    assignment, ec_two_t_plus_q_input,
                                                                    start_row_index + current_row_shift);
                    current_row_shift += ec_two_t_plus_q_instance.rows_amount;
                    return res;
                };

                auto CopyChunks = [](var from[num_chunks], var to[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        to[i] = from[i];
                    }
                };

                var extend_bit_array[num_chunks];
                for(std::size_t i = 1; i < num_chunks; i++) {
                    extend_bit_array[i] = instance_input.zero;
                }

                var d_var[num_chunks], dp_var[num_chunks], C_var[Q][num_chunks],
                    X_var[Q][num_chunks], Y_var[Q][num_chunks],
                    Xp_var[Q][num_chunks], Yp_var[Q][num_chunks];

                // Part I : adjusting the scalar and the point
                auto t = CarryOnAddition(s_var,mp_var);
                RangeCheck(t.z);
                auto alt_n = CarryOnAddition(s_var,sp_var); // we later constrain the result (alt_n) to be equal to n
                RangeCheck(sp_var);
                auto total_C_var = ChoiceFunction(t.ck,s_var,sp_var); // labeled simply C without indices on the Notion page
                auto y_minus = NegModP(y_var);
                auto y1 = ChoiceFunction(t.ck,y_var,y_minus.y);
                // Assert s × (x,y) = C × (x,y1)
                // Part II : precompute
                auto p2 = ECDouble(x_var,y1.z);
                auto p3 = ECIncompleteAdd(x_var,y1.z,p2.xR,p2.yR);
                auto y_minus1 = ChoiceFunction(t.ck,y_minus.y,y_var);
                auto y_minus3 = NegModP(p3.yR);
                // we now have the points {+/-1, +/-3} × (x, y1)
                // Part III : the main loop
                // Uses a quaternary decomposition C = c_{Q-1} c_{Q-2}...c_0, c_i = 2c_i' + c_i'' where c_i' and c_i'' are bits
                // On every step we add a scalar according to the following table
                // c_i  | c_i' | c_i'' | scalar = 2c_i - 3
                // -----+------+-------+-------
                //  0   |  0   |  0    |   -3
                //  1   |  0   |  1    |   -1
                //  2   |  1   |  0    |    1
                //  3   |  1   |  1    |    3
                //
                // the loop
                for(std::size_t i = Q-1; i > 0; i--) {
                    if (i < Q-1) {
                        auto Pp_temp = ECDouble(X_var[i+1],Y_var[i+1]);
                        CopyChunks(Pp_temp.xR, Xp_var[i+1]);
                        CopyChunks(Pp_temp.yR, Yp_var[i+1]);

                        auto C_p = CarryOnAddition(C_var[i+1],C_var[i+1]);
                        RangeCheck(C_p.z);

                        extend_bit_array[0] = cp_var[i];
                        auto C_pp = CarryOnAddition(C_p.z,extend_bit_array);
                        RangeCheck(C_pp.z);
                        CopyChunks(C_pp.z,C_var[i]);
                    } else {
                        extend_bit_array[0] = cp_var[i];
                        CopyChunks(extend_bit_array,C_var[i]);
                    }
                    auto C_ppp = CarryOnAddition(C_var[i],C_var[i]);
                    RangeCheck(C_ppp.z);
                    extend_bit_array[0] = cpp_var[i];
                    auto C_temp = CarryOnAddition(C_ppp.z,extend_bit_array);
                    CopyChunks(C_temp.z,C_var[i]);
                    RangeCheck(C_var[i]);
                    auto xi_p = ChoiceFunction(cp_var[i],p3.xR,x_var);
                    auto xi_pp = ChoiceFunction(cp_var[i],x_var,p3.xR);
                    auto xi = ChoiceFunction(cpp_var[i],xi_p.z,xi_pp.z);
                    auto eta_p = ChoiceFunction(cp_var[i],y_minus3.y,y1.z);
                    auto eta_pp = ChoiceFunction(cp_var[i],y_minus1.z,p3.yR);
                    auto eta = ChoiceFunction(cpp_var[i],eta_p.z,eta_pp.z);
                    auto P_temp = ECTwoTPlusQ((i < Q-1) ? Xp_var[i+1] : p2.xR,(i < Q-1)? Yp_var[i+1] : p2.yR, xi.z, eta.z);
                    CopyChunks(P_temp.xR,X_var[i]);
                    CopyChunks(P_temp.yR,Y_var[i]);
                }
                // post-loop computations
                auto C_p = CarryOnAddition(C_var[1],C_var[1]);
                RangeCheck(C_p.z);

                extend_bit_array[0] = cp_var[0];
                auto C_pp = CarryOnAddition(C_p.z,extend_bit_array);
                RangeCheck(C_pp.z);

                auto C_ppp = CarryOnAddition(C_pp.z,C_pp.z);
                RangeCheck(C_ppp.z);

                extend_bit_array[0] = cpp_var[0];
                auto C_temp = CarryOnAddition(C_ppp.z,extend_bit_array); // copy constrain result to be equal to total_C_var

                auto eta = ChoiceFunction(cp_var[0],y_minus1.z,y1.z);
                auto Pp_pre = ECDouble(X_var[1],Y_var[1]);
                auto Pp_temp = ECIncompleteAdd(Pp_pre.xR,Pp_pre.yR,x_var,eta.z);
                auto Ppp_temp = ECIncompleteAdd(Pp_temp.xR,Pp_temp.yR,x_var,y_minus1.z);
                // this ^^^ will fail for 0 scalar (needs almost full addition)
                auto X0 = ChoiceFunction(cpp_var[0],Ppp_temp.xR,Pp_temp.xR);
                auto Y0 = ChoiceFunction(cpp_var[0],Ppp_temp.yR,Pp_temp.yR);
                // place X0 and Y0 into xR and yR cells
                for(std::size_t i = 0; i < num_chunks; i++) {
                    assignment.witness(component.W(i % WA), start_row_index + i/WA) =
                        var_value(assignment, X0.z[i]);
                    assignment.witness(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA) =
                        var_value(assignment, Y0.z[i]);
                }
                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type
                    &instance_input) {

                // never actually called
                return {};
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_ec_scalar_mult<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::result_type generate_circuit(
                const plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_ec_scalar_mult<BlueprintFieldType,NonNativeFieldType,num_chunks,bit_size_chunk>;
                using var = typename component_type::var;

                using range_check_type = typename component_type::range_check_component;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using choice_function_type = typename component_type::choice_function_component;
                using neg_mod_p_type = typename component_type::neg_mod_p_component;
                using ec_double_type = typename component_type::ec_double_component;
                using ec_incomplete_addition_type = typename component_type::ec_incomplete_addition_component;
                using ec_two_t_plus_q_type = typename component_type::ec_two_t_plus_q_component;

                using value_type = typename BlueprintFieldType::value_type;
                using non_native_value_type = typename NonNativeFieldType::value_type;
                using non_native_integral_type = typename NonNativeFieldType::integral_type;

                const std::size_t WA = component.witness_amount();

                // instances of used subcomponents
                range_check_type            range_check_instance( component._W, component._C, component._PI);
                carry_on_addition_type      carry_on_addition_instance( component._W, component._C, component._PI);
                choice_function_type        choice_function_instance( component._W, component._C, component._PI);
                neg_mod_p_type              neg_mod_p_instance( component._W, component._C, component._PI);
                ec_double_type              ec_double_instance( component._W, component._C, component._PI);
                ec_incomplete_addition_type ec_incomplete_addition_instance( component._W, component._C, component._PI);
                ec_two_t_plus_q_type        ec_two_t_plus_q_instance( component._W, component._C, component._PI);

                const std::size_t L = bit_size_chunk*num_chunks + (bit_size_chunk*num_chunks % 2), // if odd, then +1. Thus L is always even
                                  Q = L/2;

                var s_var[num_chunks], x_var[num_chunks], y_var[num_chunks], n_var[num_chunks], mp_var[num_chunks],
                    xR_var[num_chunks], yR_var[num_chunks], sp_var[num_chunks], cp_var[Q], cpp_var[Q];

                for(std::size_t i = 0; i < num_chunks; i++) {
                    s_var[i] = instance_input.s[i];
                    x_var[i] = instance_input.x[i];
                    y_var[i] = instance_input.y[i];
                    n_var[i] = instance_input.n[i];
                    mp_var[i] = instance_input.mp[i];
                    xR_var[i] = var(component.W(i % WA), start_row_index + i/WA,false);
                    yR_var[i] = var(component.W((num_chunks + i) % WA), start_row_index + (num_chunks + i)/WA,false);
                    sp_var[i] = var(component.W((2*num_chunks + i) % WA), start_row_index + (2*num_chunks + i)/WA,false);
                }
                for(std::size_t i = 0; i < Q; i++) {
                    cpp_var[i] = var(component.W((3*num_chunks + 2*i) % WA), start_row_index + (3*num_chunks + 2*i)/WA,false);
                    cp_var[i] = var(component.W((3*num_chunks + 2*i+1) % WA), start_row_index + (3*num_chunks + 2*i+1)/WA,false);
                }

                // the number of rows used by data storage
                std::size_t total_cells = (bit_size_chunk+3)*num_chunks + (bit_size_chunk*num_chunks % 2);
                std::size_t current_row_shift = total_cells/WA + (total_cells % WA > 0);

                // assignment generation lambda expressions
                auto RangeCheck = [&instance_input, &range_check_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                  (var x[num_chunks]) {
                    typename range_check_type::input_type range_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        range_check_input.x[i] = x[i];
                    }
                    generate_circuit(range_check_instance, bp, assignment, range_check_input, start_row_index + current_row_shift);
                    current_row_shift += range_check_instance.rows_amount;
                };
                auto CarryOnAddition = [&carry_on_addition_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                       (var x[num_chunks], var y[num_chunks]) {
                    typename carry_on_addition_type::input_type carry_on_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        carry_on_addition_input.x[i] = x[i];
                        carry_on_addition_input.y[i] = y[i];
                    }
                    typename carry_on_addition_type::result_type res = generate_circuit(carry_on_addition_instance, bp, assignment,
                                                                 carry_on_addition_input, start_row_index + current_row_shift);
                    current_row_shift += carry_on_addition_instance.rows_amount;
                    return res;
                };
                auto ChoiceFunction = [&instance_input, &choice_function_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                      (var q, var x[num_chunks], var y[num_chunks]) {
                    typename choice_function_type::input_type choice_function_input;
                    choice_function_input.q = q;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        choice_function_input.x[i] = x[i];
                        choice_function_input.y[i] = y[i];
                    }
                    typename choice_function_type::result_type res = generate_circuit(choice_function_instance, bp, assignment,
                                                               choice_function_input, start_row_index + current_row_shift);
                    current_row_shift += choice_function_instance.rows_amount;
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
                auto ECDouble = [&instance_input, &ec_double_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                (var x[num_chunks], var y[num_chunks]){
                    typename ec_double_type::input_type ec_double_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_double_input.xQ[i] = x[i];
                        ec_double_input.yQ[i] = y[i];
                        ec_double_input.p[i] = instance_input.p[i];
                        ec_double_input.pp[i] = instance_input.pp[i];
                    }
                    ec_double_input.zero = instance_input.zero;
                    typename ec_double_type::result_type res = generate_circuit(ec_double_instance, bp, assignment, ec_double_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += ec_double_instance.rows_amount;
                    return res;
                };
                auto ECIncompleteAdd = [&instance_input, &ec_incomplete_addition_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                (var xP[num_chunks], var yP[num_chunks], var xQ[num_chunks], var yQ[num_chunks]){
                    typename ec_incomplete_addition_type::input_type ec_incomplete_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_incomplete_addition_input.xP[i] = xP[i];
                        ec_incomplete_addition_input.yP[i] = yP[i];
                        ec_incomplete_addition_input.xQ[i] = xQ[i];
                        ec_incomplete_addition_input.yQ[i] = yQ[i];
                        ec_incomplete_addition_input.p[i] = instance_input.p[i];
                        ec_incomplete_addition_input.pp[i] = instance_input.pp[i];
                    }
                    ec_incomplete_addition_input.zero = instance_input.zero;
                    typename ec_incomplete_addition_type::result_type res = generate_circuit(ec_incomplete_addition_instance, bp,
                                                                           assignment, ec_incomplete_addition_input,
                                                                           start_row_index + current_row_shift);
                    current_row_shift += ec_incomplete_addition_instance.rows_amount;
                    return res;
                };
                auto ECTwoTPlusQ = [&instance_input, &ec_two_t_plus_q_instance, &bp, &assignment, &start_row_index, &current_row_shift]
                                (var xT[num_chunks], var yT[num_chunks], var xQ[num_chunks], var yQ[num_chunks]){
                    typename ec_two_t_plus_q_type::input_type ec_two_t_plus_q_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_two_t_plus_q_input.xT[i] = xT[i];
                        ec_two_t_plus_q_input.yT[i] = yT[i];
                        ec_two_t_plus_q_input.xQ[i] = xQ[i];
                        ec_two_t_plus_q_input.yQ[i] = yQ[i];
                        ec_two_t_plus_q_input.p[i] = instance_input.p[i];
                        ec_two_t_plus_q_input.pp[i] = instance_input.pp[i];
                    }
                    ec_two_t_plus_q_input.zero = instance_input.zero;
                    typename ec_two_t_plus_q_type::result_type res = generate_circuit(ec_two_t_plus_q_instance, bp,
                                                                    assignment, ec_two_t_plus_q_input,
                                                                    start_row_index + current_row_shift);
                    current_row_shift += ec_two_t_plus_q_instance.rows_amount;
                    return res;
                };

                auto CopyChunks = [](var from[num_chunks], var to[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        to[i] = from[i];
                    }
                };

                var extend_bit_array[num_chunks];
                for(std::size_t i = 1; i < num_chunks; i++) {
                    extend_bit_array[i] = instance_input.zero;
                }

                // Copy constraint generation lambda expression
                auto CopyConstrain = [&bp](var x[num_chunks], var y[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        bp.add_copy_constraint({x[i], y[i]});
                    }
                };
                auto SingleCopyConstrain = [&bp](var x, var y) {
                    bp.add_copy_constraint({x,y});
                };

                var d_var[num_chunks], dp_var[num_chunks], C_var[Q][num_chunks],
                    X_var[Q][num_chunks], Y_var[Q][num_chunks],
                    Xp_var[Q][num_chunks], Yp_var[Q][num_chunks];

                // Part I : adjusting the scalar and the point
                auto t = CarryOnAddition(s_var,mp_var);
                RangeCheck(t.z);
                auto alt_n = CarryOnAddition(s_var,sp_var);
                CopyConstrain(alt_n.z,n_var);
                SingleCopyConstrain(alt_n.ck,instance_input.zero);
                RangeCheck(sp_var);
                auto total_C_var = ChoiceFunction(t.ck,s_var,sp_var); // labeled simply C without indices on the Notion page
                auto y_minus = NegModP(y_var);
                auto y1 = ChoiceFunction(t.ck,y_var,y_minus.y);
                // Assert s × (x,y) = C × (x,y1)
                // Part II : precompute
                auto p2 = ECDouble(x_var,y1.z);
                auto p3 = ECIncompleteAdd(x_var,y1.z,p2.xR,p2.yR);
                auto y_minus1 = ChoiceFunction(t.ck,y_minus.y,y_var);
                auto y_minus3 = NegModP(p3.yR);
                // Part III : the main loop
                for(std::size_t i = Q-1; i > 0; i--) {
                    if (i < Q-1) {
                        auto Pp_temp = ECDouble(X_var[i+1],Y_var[i+1]);
                        CopyChunks(Pp_temp.xR, Xp_var[i+1]);
                        CopyChunks(Pp_temp.yR, Yp_var[i+1]);

                        auto C_p = CarryOnAddition(C_var[i+1],C_var[i+1]);
                        RangeCheck(C_p.z);
                        SingleCopyConstrain(C_p.ck,instance_input.zero);

                        extend_bit_array[0] = cp_var[i];
                        auto C_pp = CarryOnAddition(C_p.z,extend_bit_array);
                        RangeCheck(C_pp.z);
                        SingleCopyConstrain(C_pp.ck,instance_input.zero);
                        CopyChunks(C_pp.z,C_var[i]);
                    } else {
                        extend_bit_array[0] = cp_var[i];
                        CopyChunks(extend_bit_array,C_var[i]);
                    }
                    auto C_ppp = CarryOnAddition(C_var[i],C_var[i]);
                    RangeCheck(C_ppp.z);
                    SingleCopyConstrain(C_ppp.ck,instance_input.zero);

                    extend_bit_array[0] = cpp_var[i];
                    auto C_temp = CarryOnAddition(C_ppp.z,extend_bit_array);
                    SingleCopyConstrain(C_temp.ck,instance_input.zero);
                    CopyChunks(C_temp.z,C_var[i]);
                    RangeCheck(C_var[i]);

                    auto xi_p = ChoiceFunction(cp_var[i],p3.xR,x_var);
                    auto xi_pp = ChoiceFunction(cp_var[i],x_var,p3.xR);
                    auto xi = ChoiceFunction(cpp_var[i],xi_p.z,xi_pp.z);
                    auto eta_p = ChoiceFunction(cp_var[i],y_minus3.y,y1.z);
                    auto eta_pp = ChoiceFunction(cp_var[i],y_minus1.z,p3.yR);
                    auto eta = ChoiceFunction(cpp_var[i],eta_p.z,eta_pp.z);
                    auto P_temp = ECTwoTPlusQ((i < Q-1) ? Xp_var[i+1] : p2.xR,(i < Q-1)? Yp_var[i+1] : p2.yR, xi.z, eta.z);
                    CopyChunks(P_temp.xR,X_var[i]);
                    CopyChunks(P_temp.yR,Y_var[i]);
                }
                // post-loop computations
                auto C_p = CarryOnAddition(C_var[1],C_var[1]);
                RangeCheck(C_p.z);
                SingleCopyConstrain(C_p.ck,instance_input.zero);

                extend_bit_array[0] = cp_var[0];
                auto C_pp = CarryOnAddition(C_p.z,extend_bit_array);
                RangeCheck(C_pp.z);
                SingleCopyConstrain(C_pp.ck,instance_input.zero);

                auto C_ppp = CarryOnAddition(C_pp.z,C_pp.z);
                RangeCheck(C_ppp.z);
                SingleCopyConstrain(C_ppp.ck,instance_input.zero);

                extend_bit_array[0] = cpp_var[0];
                auto C_temp = CarryOnAddition(C_ppp.z,extend_bit_array);

                CopyConstrain(total_C_var.z,C_temp.z);
                SingleCopyConstrain(C_temp.ck,instance_input.zero);
                auto eta = ChoiceFunction(cp_var[0],y_minus1.z,y1.z);
                auto Pp_pre = ECDouble(X_var[1],Y_var[1]);
                auto Pp_temp = ECIncompleteAdd(Pp_pre.xR,Pp_pre.yR,x_var,eta.z);
                auto Ppp_temp = ECIncompleteAdd(Pp_temp.xR,Pp_temp.yR,x_var,y_minus1.z);
                // this ^^^ will fail for 0 scalar (needs almost full addition)
                auto X0 = ChoiceFunction(cpp_var[0],Ppp_temp.xR,Pp_temp.xR);
                auto Y0 = ChoiceFunction(cpp_var[0],Ppp_temp.yR,Pp_temp.yR);
                CopyConstrain(X0.z,xR_var);
                CopyConstrain(Y0.z,yR_var);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index); // does nothing, may be skipped?

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_SCALAR_MULT_ECDSA_HPP
