//---------------------------------------------------------------------------//
// Copyright (c) 2023 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// @file Declaration of interfaces for F_p^{4} raising to a fixed power
// t, which is a parameter of the component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_FP4_FIXED_POWER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_FP4_FIXED_POWER_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt4/298/params.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/abstract_fp4.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            //
            // Component for raising to a fixed power t in F_p^4
            // Input: x[4]
            // Output: y[4]: y = x^t as elements of F_p^4
            //

            template<typename ArithmetizationType, typename FieldType>
            class mnt4_fp4_fixed_power;

            template<typename BlueprintFieldType>
            class mnt4_fp4_fixed_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;

                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using policy_type = crypto3::algebra::fields::fp4<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;
                using extended_integral_type = typename BlueprintFieldType::extended_integral_type;
                using fp4_element = typename policy_type::value_type;
                using fp4_constraint = detail::abstract_fp4_element<constraint_type, BlueprintFieldType>;

            private:
                static std::vector<std::uint8_t> base4(extended_integral_type x) {
                    if (x > 0) {
                        std::vector<std::uint8_t> res = {std::uint8_t(x % 4)};
                        x /= 4;
                        while (x > 0) {
                            res.insert(res.begin(), std::uint8_t(x % 4));
                            x /= 4;
                        }
                        return res;
                    } else {
                        return {0};
                    }
                }

                static std::size_t gates_amount_internal(extended_integral_type power) {
                    std::size_t gates = 1; // at least one for power-4 operations
                    std::vector<std::uint8_t> exp_plan = base4(power);
                    if (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1) {
                        gates++; // a multiplication gate
                    }
                    gates += (std::count(exp_plan.begin(),exp_plan.end(),3) > 0); // a cubing gate
                    gates += (std::count(exp_plan.begin(),exp_plan.end(),2) > 0); // a squaring gate

                    return gates;
                }

            public:
                using manifest_type = plonk_component_manifest;

                const extended_integral_type power/* = pairing::detail::pairing_params<curve_type>::final_exponent_last_chunk_abs_of_w0*/;

                const std::vector<std::uint8_t> exp_plan, exp_precompute;
                const std::size_t rows_amount;

                class gate_manifest_type : public component_gate_manifest {
                    const extended_integral_type power;
                    std::array<std::size_t,3> gates_footprint(extended_integral_type power) const {
                        std::vector<std::uint8_t> exp_plan = base4(power);
                        return { (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1),
                                 (std::count(exp_plan.begin(),exp_plan.end(),3) > 0),
                                 (std::count(exp_plan.begin(),exp_plan.end(),2) > 0) };
                    }
                public:
                    gate_manifest_type(extended_integral_type power) : power(power) {}

                    std::uint32_t gates_amount() const override {
                        return mnt4_fp4_fixed_power::gates_amount_internal(power);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        extended_integral_type o_power = dynamic_cast<const gate_manifest_type*>(other)->power;

                        std::array<std::size_t, 3>
                            gates   = gates_footprint(power),
                            o_gates = gates_footprint(o_power);
                        return (gates < o_gates);
                    }
                };

                static gate_manifest get_gate_manifest(
                        std::size_t witness_amount,
                        std::size_t lookup_column_amount,
                        extended_integral_type power)
                {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type(power));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(4, 300, 1)),
                        false
                    );
                    return manifest;
                }

                static std::vector<std::uint8_t> get_precomputed_exps(const std::vector<std::uint8_t> exps)
                {
                    std::vector<std::uint8_t> precompute = {exps[0]};
                    if ((exps[0] != 3) && (std::count(exps.begin(),exps.end(),3) > 0)) {
                        precompute.insert(precompute.begin(),3);
                    }
                    if ((exps[0] != 2) && (std::count(exps.begin(),exps.end(),2) > 0)) {
                        precompute.insert(precompute.begin(),2);
                    }
                    return precompute;
                }

                static std::size_t get_rows_amount(extended_integral_type power)
                {
                    std::vector<std::uint8_t>
                        exp_plan = base4(power),
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

                struct input_type {
                    std::array<var, policy_type::arity> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x[0], x[1], x[2], x[3]};
                    }
                };

                struct result_type {
                    std::array<var, policy_type::arity> output;

                    result_type(mnt4_fp4_fixed_power const& component, std::uint32_t start_row_index)
                    {
                        std::size_t last_row = start_row_index + component.rows_amount - 1;

                        for(std::size_t i = 0; i < output.size(); i++) {
                            output[i] = var(component.W(i), last_row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars()
                    {
                        std::vector<std::reference_wrapper<var>> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType> explicit
                mnt4_fp4_fixed_power(
                        ContainerType witness,
                        extended_integral_type power) :
                    component_type(witness, {}, {}, get_manifest()),
                    power(power),
                    exp_plan(base4(power)),
                    exp_precompute(get_precomputed_exps(exp_plan)),
                    rows_amount(get_rows_amount(power))
                { };

                template<typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                mnt4_fp4_fixed_power(
                        WitnessContainerType witness,
                        ConstantContainerType constant,
                        PublicInputContainerType public_input,
                        extended_integral_type power) :
                    component_type(witness, constant, public_input, get_manifest()),
                    power(power),
                    exp_plan(base4(power)),
                    exp_precompute(get_precomputed_exps(exp_plan)),
                    rows_amount(get_rows_amount(power))
                { };

                mnt4_fp4_fixed_power(
                        std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs,
                        extended_integral_type power) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    power(power),
                    exp_plan(base4(power)),
                    exp_precompute(get_precomputed_exps(exp_plan)),
                    rows_amount(get_rows_amount(power))
                { };
            };

            /* */

            template<typename BlueprintFieldType>
            using component_type = mnt4_fp4_fixed_power<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename component_type<BlueprintFieldType>::result_type
            generate_assignments(
                component_type<BlueprintFieldType> const& component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> & assignment,
                typename component_type<BlueprintFieldType>::input_type const& instance_input,
                const std::uint32_t start_row_index)
            {

                using value_type = typename BlueprintFieldType::value_type;
                using policy_type = typename component_type<BlueprintFieldType>::policy_type;

                const std::vector<std::uint8_t>
                    exp_plan = component.exp_plan,
                    exp_precompute = component.exp_precompute;

                std::array<value_type, component_type<BlueprintFieldType>::policy_type::arity> x;

                for(std::size_t i = 0; i < x.size(); i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                }

                using fp4_element = typename component_type<BlueprintFieldType>::fp4_element;
                fp4_element X = fp4_element({ {x[0],x[1]}, {x[2],x[3]},}), Y = X;

                std::size_t row = 0;

                auto fill_row = [&component, &assignment, &start_row_index, &row](fp4_element const& V) {
                    value_type d00 = V.data[0].data[0];
                    value_type d01 = V.data[0].data[1];
                    value_type d10 = V.data[1].data[0];
                    value_type d11 = V.data[1].data[1];
                    assignment.witness(component.W(0),start_row_index + row) = d00;
                    assignment.witness(component.W(1),start_row_index + row) = d01;
                    assignment.witness(component.W(2),start_row_index + row) = d10;
                    assignment.witness(component.W(3),start_row_index + row) = d11;

                    /*
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        assignment.witness(component.W(i),start_row_index + row) = V.data[i/2].data[i % 2];
                    }
                    */
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

                return typename component_type<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                component_type<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> & bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> const& assignment,
                typename component_type<BlueprintFieldType>::input_type const& instance_input)
            {
                using var = typename component_type<BlueprintFieldType>::var;

                const std::vector<std::uint8_t>
                    exp_plan = component.exp_plan,
                    exp_precompute = component.exp_precompute;

                std::vector<std::size_t> gate_list = {}; // at most 4 gate ids


                using policy_type = typename component_type<BlueprintFieldType>::policy_type;
                typename component_type<BlueprintFieldType>::fp4_constraint X, Y, Z, C;

                // power-4 gate
                for(std::size_t i = 0; i < policy_type::arity; i++) {
                    X[i] = var(component.W(i), -1, true);
                    Y[i] = var(component.W(i), 0, true);
                }
                C = (X * X) * (X * X);

                using constraint_type = typename component_type<BlueprintFieldType>::constraint_type;

                std::vector<constraint_type> pow4_constrs = {};
                for(std::size_t i = 0; i < policy_type::arity; i++) {
                    pow4_constrs.push_back(C[i] - Y[i]);
                }
                gate_list.push_back(bp.add_gate(pow4_constrs));

                if (exp_plan.size() - std::count(exp_plan.begin(),exp_plan.end(),0) > 1) {
                    // at least one digit besides the first is non-zero
                    // => we need a multiplication gate
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        X[i] = var(component.W(i), -1, true);
                        Y[i] = var(component.W(i), 0, true);
                        Z[i] = var(component.W(i), 1, true);
                    }
                    C = X * Y;

                    std::vector<constraint_type> mult_constrs = {};
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        mult_constrs.push_back(C[i] - Z[i]);
                    }
                    gate_list.push_back(bp.add_gate(mult_constrs));
                }

                if (std::count(exp_precompute.begin(),exp_precompute.end(),3)) {
                    // we need a cubing gate
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        X[i] = var(component.W(i), -1, true);
                        Y[i] = var(component.W(i), 0, true);
                    }
                    C = X * X * X;

                    std::vector<constraint_type> cube_constrs = {};
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        cube_constrs.push_back(C[i] - Y[i]);
                    }
                    gate_list.push_back(bp.add_gate(cube_constrs));
                }

                if (std::count(exp_precompute.begin(),exp_precompute.end(),2)) {
                    // we need a squaring gate
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        X[i] = var(component.W(i), -1, true);
                        Y[i] = var(component.W(i), 0, true);
                    }
                    C = X * X;

                    std::vector<constraint_type> square_constrs = {};
                    for(std::size_t i = 0; i < policy_type::arity; i++) {
                        square_constrs.push_back(C[i] - Y[i]);
                    }
                    gate_list.push_back(bp.add_gate(square_constrs));
                }

                return gate_list;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                component_type<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename component_type<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index)
            {
                using var = typename component_type<BlueprintFieldType>::var;
                using policy_type = typename component_type<BlueprintFieldType>::policy_type;

                const std::vector<std::uint8_t>
                    exp_plan = component.exp_plan,
                    exp_precompute = component.exp_precompute;

                // for storing relative ids of rows where x^0, x^1, x^2 and x^3 are stored
                std::array<std::size_t, 4> row_of_power = {0,1,0,0};

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
                        for(std::size_t i = 0; i < policy_type::arity; i++) {
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
                        for(std::size_t i = 0; i < policy_type::arity; i++) {
                            bp.add_copy_constraint({
                                var(component.W(i), start_row_index + row_of_power[exp_plan[j]], false),
                                var(component.W(i), start_row_index + row, false)
                            });
                        }
                        row += 2;
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename component_type<BlueprintFieldType>::result_type
            generate_circuit(
                component_type<BlueprintFieldType> const& component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& assignment,
                typename component_type<BlueprintFieldType>::input_type const& instance_input,
                const std::size_t start_row_index)
            {

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);

                const std::vector<std::uint8_t>
                    exp_plan = component.exp_plan,
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

                return typename component_type<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MNT4_FP4_FIXED_POWER_HPP
