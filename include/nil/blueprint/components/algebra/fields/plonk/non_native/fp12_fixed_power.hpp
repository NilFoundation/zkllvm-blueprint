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
// @file Declaration of interfaces for F_p^{12} raising to a fixed power
// t, which is a parameter of the component. We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FIXED_POWER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FIXED_POWER_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp12.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                std::vector<unsigned short int> base4(unsigned long long x) {
                    if (x > 0) {
                        std::vector<unsigned short int> res = {int(x % 4)};
                        x /= 4;
                        while (x > 0) {
                            res.insert(res.begin(), x % 4);
                            x /= 4;
                        }
                        return res;
                    } else {
                        return {0};
                    }
                }
            } // namespace detail

            //
            // Component for raising to a fixed power t in F_p^12
            // Input: x[12]
            // Output: y[12]: y = x^t as elements of F_p^12
            //

            using detail::base4;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class fp12_fixed_power;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class fp12_fixed_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            static std::size_t gates_amount_internal(unsigned long long Power) {
                std::size_t gates = 1; // at least one for power-4 operations
                std::vector<unsigned short int> exp_plan = base4(Power);
                if (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1) {
                    gates++; // a multiplication gate
                }
                gates += (std::count(exp_plan.begin(),exp_plan.end(),3) > 0); // a cubing gate
                gates += (std::count(exp_plan.begin(),exp_plan.end(),2) > 0); // a squaring gate

                return gates;
            }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;


                class gate_manifest_type : public component_gate_manifest {
                    std::array<std::size_t,3> gates_footprint(unsigned long long Power) const {
                        std::vector<unsigned short int> exp_plan = base4(Power);
                        return { (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1),
                                 (std::count(exp_plan.begin(),exp_plan.end(),3) > 0),
                                 (std::count(exp_plan.begin(),exp_plan.end(),2) > 0) };
                    }
                public:
                    std::size_t witness_amount;
                    unsigned long long Power;
                    gate_manifest_type(unsigned long long Power_) : Power(Power_) {}

                    std::uint32_t gates_amount() const override {
                        return fp12_fixed_power::gates_amount_internal(Power);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        unsigned long long o_power = dynamic_cast<const gate_manifest_type*>(other)->Power;

                        std::array<std::size_t,3> gates   = gates_footprint(Power),
                                                  o_gates = gates_footprint(o_power);
                        return (gates < o_gates);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       unsigned long long Power) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type(Power));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(12)),
                        false
                    );
                    return manifest;
                }


                constexpr static std::vector<unsigned short int> get_precomputed_exps(const std::vector<unsigned short int> exps) {
                    std::vector<unsigned short int> precompute = {exps[0]};
                    if ((exps[0] != 3) && (std::count(exps.begin(),exps.end(),3) > 0)) {
                        precompute.insert(precompute.begin(),3);
                    }
                    if ((exps[0] != 2) && (std::count(exps.begin(),exps.end(),2) > 0)) {
                        precompute.insert(precompute.begin(),2);
                    }
                    return precompute;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             unsigned long long power) {
                    std::vector<unsigned short int> exp_plan = base4(power),
                                                    exp_precompute = get_precomputed_exps(exp_plan);
                    std::size_t rows = 0;
                    for(std::size_t i = 0; i < exp_precompute.size(); i++) {
                        rows += 1 + (exp_precompute[i] > 1);
                    }
                    for(std::size_t i = 1; i < exp_plan.size(); i++) {
                        rows += 1 + 2*(exp_plan[i] > 0);
                    }
                    return rows;
                }


                unsigned long long Power;
                const std::vector<unsigned short int> exp_plan = base4(Power),
                                                      exp_precompute = get_precomputed_exps(exp_plan);
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, Power);

                struct input_type {
                    std::array<var,12> x;

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};
                        for(auto & e : x) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const fp12_fixed_power &component, std::uint32_t start_row_index) {
                        std::size_t last_row = start_row_index + component.rows_amount - 1;

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W(i), last_row, false, var::column_type::witness);
                        }
                    }
                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit fp12_fixed_power(ContainerType witness, unsigned long long Power_) :
                    component_type(witness, {}, {}, get_manifest()),
                    Power(Power_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_fixed_power(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, unsigned long long Power_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    Power(Power_) {};

                fp12_fixed_power(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs, unsigned long long Power_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    Power(Power_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fp12_fixed_power =
                fp12_fixed_power<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::vector<unsigned short int> exp_plan = component.exp_plan,
                                                      exp_precompute = component.exp_precompute;

                std::array<value_type,12> x;

                for(std::size_t i = 0; i < 12; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                    assignment.witness(component.W(i),start_row_index) = x[i];
                }

                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                fp12_element X = fp12_element({ {x[0],x[1]}, {x[2],x[3]}, {x[4],x[5]} }, { {x[6],x[7]}, {x[8],x[9]}, {x[10],x[11]} }),
                             Y = X;

                std::size_t row = 0;

                auto fill_row = [&component, &assignment, &start_row_index, &row](fp12_element V) {
                    for(std::size_t i = 0; i < 12; i++) {
                        assignment.witness(component.W(i),start_row_index + row) = V.data[i/6].data[(i % 6)/2].data[i % 2];
                    }
                    row++;
                };

                for(std::size_t i = 0; i < exp_precompute.size(); i++) {
                    fill_row(X); // X
                    if (exp_precompute[i] > 1) {
                        fill_row(X.pow(exp_precompute[i]));
                    }
                }
                Y = X.pow(exp_plan[0]);
                for(std::size_t i = 1; i < exp_plan.size(); i++) {
                    Y = Y.pow(4); fill_row(Y); // every step includes a power-4 operation
                    if (exp_plan[i] > 0) { // for every non-zero digit we need a multiplication too
                        fill_row(X.pow(exp_plan[i]));
                        Y = Y * X.pow(exp_plan[i]); fill_row(Y);
                    }
                }

                return typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                using fp12_constraint = detail::abstract_fp12_element<constraint_type>;

                const std::vector<unsigned short int> exp_plan = component.exp_plan,
                                                      exp_precompute = component.exp_precompute;

                std::vector<std::size_t> gate_list = {}; // at most 4 gate ids

                fp12_constraint X, Y, Z, C;

                // power-4 gate
                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), -1, true);
                    Y[i] = var(component.W(i), 0, true);
                }
                C = (X * X) * (X * X);

                std::vector<constraint_type> pow4_constrs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    pow4_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(pow4_constrs));

                if (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1) {
                    // at least one digit besides the first is non-zero
                    // => we need a multiplication gate
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
                }

                if (std::count(exp_precompute.begin(),exp_precompute.end(),3)) {
                    // we need a cubing gate
                    for(std::size_t i = 0; i < 12; i++) {
                        X[i] = var(component.W(i), -1, true);
                        Y[i] = var(component.W(i), 0, true);
                    }
                    C = X * X * X;

                    std::vector<constraint_type> cube_constrs = {};
                    for(std::size_t i = 0; i < 12; i++) {
                        cube_constrs.push_back(C[i] - Y[i]);
                    }
                    gate_list.push_back(bp.add_gate(cube_constrs));
                }

                if (std::count(exp_precompute.begin(),exp_precompute.end(),2)) {
                    // we need a squaring gate
                    for(std::size_t i = 0; i < 12; i++) {
                        X[i] = var(component.W(i), -1, true);
                        Y[i] = var(component.W(i), 0, true);
                    }
                    C = X * X;

                    std::vector<constraint_type> square_constrs = {};
                    for(std::size_t i = 0; i < 12; i++) {
                        square_constrs.push_back(C[i] - Y[i]);
                    }
                    gate_list.push_back(bp.add_gate(square_constrs));
                }
                return gate_list;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::var;

                const std::vector<unsigned short int> exp_plan = component.exp_plan,
                                                      exp_precompute = component.exp_precompute;

                // for storing relative ids of rows where x^0, x^1, x^2 and x^3 are stored
                std::array<std::size_t,4> row_of_power = {0,1,0,0};

                for(std::size_t small_power = 3; small_power > 0; small_power--) {
                    if (std::count(exp_precompute.begin(),exp_precompute.end(),small_power)) {
                        for(std::size_t i = 0; i < exp_precompute.size(); i++) {
                            if (exp_precompute[i] == small_power) {
                                // this gives a wrong value for small_power = 1, but it is coherent with the next part
                                row_of_power[small_power] = 2*i + 1;
                            }
                        }
                    }
                }

                // copies of initial data
                for(std::size_t j = 1; j < 4; j++) {
                    if (row_of_power[j] > 0) { // => we need a copy of initial data before row_of_power[j]
                        for(std::size_t i = 0; i < 12; i++) {
                            bp.add_copy_constraint({var(component.W(i), start_row_index + row_of_power[j]-1, false), instance_input.x[i]});
                        }
                    }
                }
                row_of_power[1] = 0; // from now on we need the real row number for where x^1 is stored

                std::size_t row = 0;
                for(std::size_t j = 0; j < exp_precompute.size(); j++) {
                    row += 1 + (exp_precompute[j] > 1); // for x² and x³ skip 2 rows, for x just one
                }
                for(std::size_t j = 1; j < exp_plan.size(); j++) {
                    row++; // skip the power-4 value
                    if (exp_plan[j] > 0) { // this row has a copy of some precomputed row
                        for(std::size_t i = 0; i < 12; i++) {
                            bp.add_copy_constraint({var(component.W(i), start_row_index + row_of_power[exp_plan[j]], false),
                                                    var(component.W(i), start_row_index + row, false)});
                        }
                        row += 2;
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                const std::vector<unsigned short int> exp_plan = component.exp_plan,
                                                      exp_precompute = component.exp_precompute;
                std::size_t row = 0;
                for(std::size_t i = 0; i < exp_precompute.size(); i++) {
                    row += 1 + (exp_precompute[i] > 1); // for x² and x³ skip 2 rows, for x just one
                }
                for(std::size_t i = 1; i < exp_plan.size(); i++) {
                    assignment.enable_selector(selector_index[0], start_row_index + row); // power-4 gate
                    row++;
                    if (exp_plan[i] > 0) {
                        assignment.enable_selector(selector_index[1], start_row_index + row); // multiplication gate
                        row += 2;
                    }
                }
                // did we even use a multiplication gate?
                std::size_t gate_id = 1 + (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1);

                // cubing and squaring gates if we need either of them
                for(std::size_t small_power = 3; small_power > 1; small_power--) {
                    if (std::count(exp_precompute.begin(),exp_precompute.end(),small_power)) {
                        std::size_t row_of_power;
                        for(std::size_t i = 0; i < exp_precompute.size(); i++) {
                            if (exp_precompute[i] == small_power) {
                                row_of_power = 2*i + 1;
                            }
                        }
                        assignment.enable_selector(selector_index[gate_id], start_row_index + row_of_power);
                        gate_id++;
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_fixed_power<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_POWER_T_HPP
