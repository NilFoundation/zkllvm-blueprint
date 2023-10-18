//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the GATE_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/gate_component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
            class basic_constraints_verifier;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 1> {

                constexpr static const std::uint32_t ConstantsAmount = 0;

                constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                        const std::vector<std::size_t> &gate_sizes) {

                    std::size_t r = 0;
                    for (std::size_t i = 0; i < gate_sizes.size(); i++) {
                        r += gate_component::get_rows_amount(witness_amount, 0, gate_sizes[i] - 1);
                    }
                    r += std::ceil(gate_sizes.size() * 1.0 / (witness_amount - 1));
                    return r;
                }

                constexpr static const std::size_t gates_amount_internal(std::size_t witness_amount,
                                                                         const std::vector<std::size_t> &gate_sizes) {
                    if (gate_sizes.size() < witness_amount) {
                        return 1;
                    }
                    return 3;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, ConstantsAmount, 1>;

            public:
                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::vector<std::size_t> &gate_sizes) {
                    return rows_amount_internal(witness_amount, gate_sizes);
                }

                const std::vector<std::size_t> gate_sizes;
                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), gate_sizes);
                const std::size_t gates_amount = gates_amount_internal(this->witness_amount(), gate_sizes);

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::vector<std::size_t> gate_sizes;
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_, std::vector<std::size_t> &gate_sizes_) :
                        witness_amount(witness_amount_), gate_sizes(gate_sizes_) {
                    }

                    std::uint32_t gates_amount() const override {
                        return basic_constraints_verifier::gates_amount_internal(witness_amount, gate_sizes);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        std::size_t other_witness_amount =
                            dynamic_cast<const gate_manifest_type *>(other)->witness_amount;
                        return witness_amount < other_witness_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::vector<std::size_t> &gate_sizes) {
                    std::vector<std::size_t>::iterator min_degree = std::min_element(gate_sizes.begin(), gate_sizes.end());
                    std::vector<std::size_t>::iterator max_degree = std::max_element(gate_sizes.begin(), gate_sizes.end()); 
                    if (*min_degree == 1 && *max_degree > *min_degree) {
                        gate_manifest manifest =
                            gate_manifest(gate_manifest_type(witness_amount, gate_sizes))
                                .merge_with(gate_component::get_gate_manifest(witness_amount, lookup_column_amount, *min_degree - 1))
                                .merge_with(gate_component::get_gate_manifest(witness_amount, lookup_column_amount, *max_degree - 1));
                        return manifest;
                    } else {
                        gate_manifest manifest =
                            gate_manifest(gate_manifest_type(witness_amount, gate_sizes))
                                .merge_with(gate_component::get_gate_manifest(witness_amount, lookup_column_amount, *min_degree - 1));
                        return manifest;
                    }
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(3, 15)), false)
                            .merge_with(gate_component::get_manifest());
                    return manifest;
                }

                struct input_type {
                    var theta;
                    std::vector<var> gates;
                    std::vector<var> selectors;

                    std::vector<var> all_vars() const {
                        std::vector<var> vars;
                        vars.push_back(theta);
                        vars.insert(vars.end(), gates.begin(), gates.end());
                        vars.insert(vars.end(), selectors.begin(), selectors.end());
                        return vars;
                    }
                };

                struct result_type {
                    var output;

                    result_type(const basic_constraints_verifier &component, std::uint32_t start_row_index) {
                        output = var(component.W(component.witness_amount() - 1),
                                     start_row_index + component.rows_amount - 1, false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                basic_constraints_verifier(ContainerType witness, std::vector<std::size_t> &gate_sizes_) :
                    component_type(witness, {}, {}, get_manifest()), gate_sizes(gate_sizes_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                basic_constraints_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                           PublicInputContainerType public_input,
                                           std::vector<std::size_t> &gate_sizes_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    gate_sizes(gate_sizes_) {};

                basic_constraints_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::vector<std::size_t> &gate_sizes_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    gate_sizes(gate_sizes_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_basic_constraints_verifier = basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType,
                                                                    ArithmetizationParams>::input_type instance_input,
                    const std::size_t start_row_index) {

                std::size_t n_sl = component.gate_sizes.size();
                std::size_t witness_amount = component.witness_amount();
                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;

                std::size_t row = start_row_index;
                std::vector<var> G;
                std::vector<std::uint32_t> witnesses;
                for (std::uint32_t i = 0; i < witness_amount; i++) {
                    witnesses.push_back(component.W(i));
                }
                std::size_t start = 0;
                for (std::size_t i = 0; i < n_sl; i++) {

                    std::size_t c_size = component.gate_sizes[i];
                    gate_component gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                                  std::array<std::uint32_t, 1>(), c_size - 1);

                    std::vector<var> constraints;
                    constraints.insert(constraints.begin(), instance_input.gates.begin() + start,
                                       instance_input.gates.begin() + start + component.gate_sizes[i]);
                    typename gate_component::input_type gate_input = {instance_input.theta, constraints,
                                                                      instance_input.selectors[i]};

                    typename gate_component::result_type gate_i_result =
                        generate_assignments(gate_instance, assignment, gate_input, row);

                    G.push_back(gate_i_result.output);
                    row += gate_instance.rows_amount;
                    start += component.gate_sizes[i];
                }

                std::size_t r = 0, j = 0;
                for (std::size_t i = 0; i < G.size(); i++) {
                    r = i / (witness_amount - 1);
                    j = i % (witness_amount - 1);
                    assignment.witness(component.W(j), row + r) = var_value(assignment, G[i]);
                }

                std::size_t k = witness_amount - 1;
                typename BlueprintFieldType::value_type sum = 0;
                for (std::size_t rr = 0; rr <= r; rr++) {
                    for (std::size_t i = 0; i < k; i++) {
                        if (k * rr + i >= G.size()) {
                            break;
                        }
                        sum += var_value(assignment, G[k * rr + i]);
                    }
                    assignment.witness(component.W(witness_amount - 1), row + r) = sum;
                }
                row += r;

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input) {

                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::var;

                using term = typename crypto3::zk::snark::plonk_constraint<BlueprintFieldType>::base_type;

                std::size_t witness_amount = component.witness_amount();
                std::size_t n_sl = component.gate_sizes.size();
                std::size_t last_pos = n_sl % witness_amount;

                std::vector<std::size_t> selectors;

                if (n_sl < witness_amount) {
                    term constraint_1 = var(component.W(witness_amount - 1), 0);
                    for (std::size_t j = 0; j < last_pos; j++) {
                        constraint_1 = constraint_1 - var(component.W(j), 0);
                    }
                    selectors.push_back(bp.add_gate({constraint_1}));
                } else {
                    term constraint_1 = var(component.W(witness_amount - 1), 0);
                    for (std::size_t j = 0; j < witness_amount - 1; j++) {
                        constraint_1 = constraint_1 - var(component.W(j), 0);
                    }
                    selectors.push_back(bp.add_gate({constraint_1}));

                    term constraint_2 =
                        var(component.W(witness_amount - 1), 0) - var(component.W(witness_amount - 1), -1);
                    for (std::size_t j = 0; j < witness_amount - 1; j++) {
                        constraint_2 = constraint_2 - var(component.W(j), 0);
                    }
                    selectors.push_back(bp.add_gate({constraint_2}));

                    term constraint_3 =
                        var(component.W(witness_amount - 1), 0) - var(component.W(witness_amount - 1), -1);
                    for (std::size_t j = 0; j < last_pos; j++) {
                        constraint_3 = constraint_3 - var(component.W(j), 0);
                    }
                    selectors.push_back(bp.add_gate({constraint_3}));
                }

                return selectors;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::var;
                std::size_t row = start_row_index;
                std::size_t n_sl = component.gate_sizes.size();
                std::size_t witness_amount = component.witness_amount();

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using gate_component = detail::gate_component<ArithmetizationType>;

                std::vector<std::size_t> row_positions;
                for (std::size_t i = 0; i < n_sl; i++) {
                    std::size_t r = gate_component::get_rows_amount(witness_amount, 0, component.gate_sizes[i] - 1);
                    row += r;
                    row_positions.push_back(row);
                }
                assert(row_positions.size() == n_sl);

                for (std::size_t i = 0; i < n_sl; i++) {
                    std::size_t j = i % witness_amount;
                    std::size_t r = i / (witness_amount - 1);

                    bp.add_copy_constraint({var(component.W(j), row + r, false),
                                            var(component.W(witness_amount - 1), row_positions[i] - 1, false)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType,
                                                                    ArithmetizationParams>::input_type instance_input,
                    const std::size_t start_row_index) {

                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;

                std::size_t row = start_row_index;
                std::size_t n_sl = component.gate_sizes.size();
                std::size_t witness_amount = component.witness_amount();

                std::vector<typename BlueprintFieldType::value_type> G;
                std::vector<std::uint32_t> witnesses;
                for (std::uint32_t i = 0; i < witness_amount; i++) {
                    witnesses.push_back(component.W(i));
                }

                std::size_t start = 0;
                for (std::size_t i = 0; i < n_sl; i++) {

                    gate_component gate_instance =
                        gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                       component.gate_sizes[i] - 1);
                    std::vector<var> constraints;
                    constraints.insert(constraints.begin(), instance_input.gates.begin() + start,
                                       instance_input.gates.begin() + start + component.gate_sizes[i]);
                    typename gate_component::input_type gate_input = {instance_input.theta, constraints,
                                                                      instance_input.selectors[i]};

                    typename gate_component::result_type gate_i_result =
                        generate_circuit(gate_instance, bp, assignment, gate_input, row);
                    row += gate_instance.rows_amount;
                    start += component.gate_sizes[i];
                }

                std::vector<std::size_t> selectors = generate_gates(component, bp, assignment, instance_input);

                std::cout << component.gates_amount << " vs " << selectors.size() << "\n";

                assignment.enable_selector(selectors[0], row);

                if (n_sl >= witness_amount) {
                    row++;
                    std::size_t n = n_sl / witness_amount;
                    while (n--) {
                        assignment.enable_selector(selectors[1], row);
                        row++;
                    }
                    assignment.enable_selector(selectors[2], row);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP