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
// @file Declaration of interfaces for auxiliary components for the PERMUTATION_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERMUTATION_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERMUTATION_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class permutation_verifier;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class permutation_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 6>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 6, 0, 0> {

                constexpr static const std::uint32_t WitnessesAmount = 6;
                constexpr static const std::uint32_t ConstantsAmount = 0;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ConstantsAmount, 0>;

            public:
                using var = typename component_type::var;

                std::size_t rows_amount;
                std::size_t gates_amount = 4;
                const std::size_t m;

                struct input_type {
                    std::vector<var> _input;
                };

                struct result_type {
                    std::array<var, 3> output;

                    result_type(const permutation_verifier &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(4), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(0), start_row_index + component.rows_amount - 1, false)};
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessesAmount << "_" << m;
                    return ss.str();
                }

                template<typename ContainerType>
                permutation_verifier(ContainerType witness, std::size_t m_) : component_type(witness, {}, {}), m(m_) {
                    rows_amount = m_ + 2;
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                permutation_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                     PublicInputContainerType public_input, std::size_t m_) :
                    component_type(witness, constant, public_input),
                    m(m_) {
                    rows_amount = m_ + 2;
                };

                permutation_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t m_) :
                    component_type(witnesses, constants, public_inputs),
                    m(m_) {
                    rows_amount = m_ + 2;
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            using plonk_permutation_verifier = permutation_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::result_type
                generate_assignments(
                    const plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using var = typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::var;

                assert(instance_input._input.size() == 3 * component.m + 7);

                std::size_t m = component.m;

                std::vector<typename BlueprintFieldType::value_type> f, Se, Ssigma;
                for (std::size_t i = 0; i < m; i++) {
                    f.push_back(var_value(assignment, instance_input._input[i]));
                    Se.push_back(var_value(assignment, instance_input._input[m + i]));
                    Ssigma.push_back(var_value(assignment, instance_input._input[2 * m + i]));
                }
                typename BlueprintFieldType::value_type one = BlueprintFieldType::value_type::one();
                typename BlueprintFieldType::value_type fe = one;
                typename BlueprintFieldType::value_type fsigma = one;

                typename BlueprintFieldType::value_type theta_1 =
                    var_value(assignment, instance_input._input[3 * m + 5]);
                typename BlueprintFieldType::value_type theta_2 =
                    var_value(assignment, instance_input._input[3 * m + 6]);

                typename BlueprintFieldType::value_type L0_y = var_value(assignment, instance_input._input[3 * m]);
                typename BlueprintFieldType::value_type Vsigma_y =
                    var_value(assignment, instance_input._input[3 * m + 1]);
                typename BlueprintFieldType::value_type Vsigma_zetay =
                    var_value(assignment, instance_input._input[3 * m + 2]);
                typename BlueprintFieldType::value_type q_last_y =
                    var_value(assignment, instance_input._input[3 * m + 3]);
                typename BlueprintFieldType::value_type q_pad_y =
                    var_value(assignment, instance_input._input[3 * m + 4]);

                for (std::size_t i = 0; i < m; i++) {
                    fe = fe * (f[i] + theta_1 * Se[i] + theta_2);
                    fsigma = fsigma * (f[i] + theta_1 * Ssigma[i] + theta_2);
                    assignment.witness(component.W(0), row + i) = fe;
                    assignment.witness(component.W(1), row + i) = f[i];
                    assignment.witness(component.W(2), row + i) = Se[i];
                    assignment.witness(component.W(4), row + i) = Ssigma[i];
                    assignment.witness(component.W(5), row + i) = fsigma;

                    if (i & 1) {
                        assignment.witness(component.W(3), row + i) = theta_2;
                    } else {
                        assignment.witness(component.W(3), row + i) = theta_1;
                    }
                }
                row += component.m;

                assignment.witness(component.W(0), row) = L0_y * (one - Vsigma_y);
                assignment.witness(component.W(1), row) = q_last_y;
                assignment.witness(component.W(2), row) = q_pad_y;
                assignment.witness(component.W(3), row) = L0_y;
                assignment.witness(component.W(4), row) =
                    (1 - (q_last_y + q_pad_y)) * (Vsigma_zetay * fsigma - Vsigma_y * fe);

                row++;

                assignment.witness(component.W(0), row) = q_last_y * (Vsigma_y * Vsigma_y - Vsigma_y);
                assignment.witness(component.W(1), row) = Vsigma_y;
                assignment.witness(component.W(2), row) = Vsigma_y * Vsigma_y;
                assignment.witness(component.W(3), row) = Vsigma_zetay;

                return typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_gates(
                const plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::input_type
                    instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::var;

                auto constraint_1 =
                    bp.add_constraint(var(component.W(0), 0) - var(component.W(1), 0) -
                                      var(component.W(2), 0) * var(component.W(3), 0) - var(component.W(3), +1));
                auto constraint_2 =
                    bp.add_constraint(var(component.W(5), 0) - var(component.W(1), 0) -
                                      var(component.W(4), 0) * var(component.W(3), 0) - var(component.W(3), +1));

                auto constraint_3 =
                    bp.add_constraint(var(component.W(0), +1) -
                                      var(component.W(0), 0) *
                                          (var(component.W(1), +1) + var(component.W(2), +1) * var(component.W(3), 0) +
                                           var(component.W(3), +1)));
                auto constraint_4 =
                    bp.add_constraint(var(component.W(5), +1) -
                                      var(component.W(5), 0) *
                                          (var(component.W(1), +1) + var(component.W(4), +1) * var(component.W(3), 0) +
                                           var(component.W(3), +1)));

                bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4});

                auto constraint_5 =
                    bp.add_constraint(var(component.W(0), 0) -
                                      var(component.W(0), -1) *
                                          (var(component.W(1), 0) + var(component.W(2), 0) * var(component.W(3), 0) +
                                           var(component.W(3), +1)));
                auto constraint_6 =
                    bp.add_constraint(var(component.W(5), 0) -
                                      var(component.W(5), -1) *
                                          (var(component.W(1), 0) + var(component.W(4), 0) * var(component.W(3), 0) +
                                           var(component.W(3), +1)));

                bp.add_gate(first_selector_index + 1, {constraint_3, constraint_4, constraint_5, constraint_6});

                auto constraint_7 =
                    bp.add_constraint(var(component.W(0), 0) -
                                      var(component.W(0), -1) *
                                          (var(component.W(1), 0) + var(component.W(2), 0) * var(component.W(3), 0) +
                                           var(component.W(3), -1)));
                auto constraint_8 =
                    bp.add_constraint(var(component.W(5), 0) -
                                      var(component.W(5), -1) *
                                          (var(component.W(1), 0) + var(component.W(4), 0) * var(component.W(3), 0) +
                                           var(component.W(3), -1)));
                bp.add_gate(first_selector_index + 2, {constraint_7, constraint_8});

                auto constraint_9 =
                    bp.add_constraint(var(component.W(0), 0) - var(component.W(3), 0) * (1 - var(component.W(1), +1)));
                auto constraint_10 =
                    bp.add_constraint(var(component.W(4), 0) - (1 - var(component.W(1), 0) - var(component.W(2), 0)) *
                                                                   (var(component.W(3), +1) * var(component.W(5), -1) -
                                                                    var(component.W(1), +1) * var(component.W(0), -1)));

                auto constraint_11 =
                    bp.add_constraint(var(component.W(2), +1) - var(component.W(1), +1) * var(component.W(1), +1));
                auto constraint_12 =
                    bp.add_constraint(var(component.W(0), +1) -
                                      var(component.W(1), 0) * (var(component.W(2), +1) - var(component.W(1), +1)));

                bp.add_gate(first_selector_index + 3, {constraint_9, constraint_10, constraint_11, constraint_12});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t m = component.m;

                using var = typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::var;

                for (std::size_t i = 0; i < m; i++) {
                    bp.add_copy_constraint({var(component.W(1), row, false), instance_input._input[i]});
                    bp.add_copy_constraint({var(component.W(2), row, false), instance_input._input[m + i]});
                    // bp.add_copy_constraint({var(component.W(3), row, false), instance_input._input[3 * m + 5 + i &
                    // 1]});
                    bp.add_copy_constraint({var(component.W(4), row, false), instance_input._input[2 * m + i]});
                    row++;
                }
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input._input[3 * m + 3]});
                bp.add_copy_constraint({var(component.W(2), row, false), instance_input._input[3 * m + 4]});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input._input[3 * m]});
                row++;
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input._input[3 * m + 1]});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input._input[3 * m + 2]});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::result_type
                generate_circuit(
                    const plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using var = typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::var;
                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                assignment.enable_selector(first_selector_index, row);
                for (row = start_row_index + 2; row < start_row_index + component.m - 1; row += 2) {
                    assignment.enable_selector(first_selector_index + 1, row);
                }
                if (row == start_row_index + component.m + 1) {
                    assignment.enable_selector(first_selector_index + 2, row - 1);
                }
                assignment.enable_selector(first_selector_index + 3, row + (component.m & 1));

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_permutation_verifier<BlueprintFieldType, ArithmetizationParams, 6>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERMUTATION_ARGUMENT_VERIFIER_HPP