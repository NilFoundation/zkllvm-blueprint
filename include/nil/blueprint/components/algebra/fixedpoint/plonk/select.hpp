#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SELECT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SELECT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            /**
             * Component representing a select operation having inputs x and y, a selector c, and an output z. The
             * selector c must be either 0 or 1, values x and y are field elements. z = x if c == 1 and z
             * = y if c == 0.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same).
             *
             * Input:    x, y ... field elements
             *           c    ... boolean selector (field element): 0 or 1.
             * Output:   z    ... c == true ? x : y
             *
             * The input gets defined via the fix_select::input_type struct and the output gets defined via the
             * fix_select::result_type struct.
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_select;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_select<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_select::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(4)), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var c = var(0, 0, false);
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {c, x, y};
                    }
                };

                struct var_positions {
                    CellPosition c, x, y, z;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (4 col(s), 1 row(s))
                    //
                    //  r\c| 0 | 1 | 2 | 3 |
                    // +---+---+---+---+---+
                    // | 0 | c | x | y | z |

                    var_positions pos;
                    pos.c = CellPosition(this->W(0), start_row_index);
                    pos.x = CellPosition(this->W(1), start_row_index);
                    pos.y = CellPosition(this->W(2), start_row_index);
                    pos.z = CellPosition(this->W(3), start_row_index);
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_select &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(start_row_index);
                        output = var(splat(var_pos.z), false);
                    }

                    result_type(const fix_select &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(start_row_index);
                        output = var(splat(var_pos.z), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_select(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_select(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fix_select(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_select =
                fix_select<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                // getting the values of the inputs at the input location
                auto c_val = var_value(assignment, instance_input.c);
                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);

                BLUEPRINT_RELEASE_ASSERT(c_val == 0 || c_val == 1);
                auto z_val = c_val == 1 ? x_val : y_val;

                const auto var_pos = component.get_var_pos(start_row_index);

                // writing the values of the inputs/output to this gate's internal state variables
                assignment.witness(splat(var_pos.c)) = c_val;
                assignment.witness(splat(var_pos.x)) = x_val;
                assignment.witness(splat(var_pos.y)) = y_val;
                assignment.witness(splat(var_pos.z)) = z_val;

                return typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t start_row_index = 0;

                const auto var_pos = component.get_var_pos(start_row_index);

                auto c = var(splat(var_pos.c));
                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto z = var(splat(var_pos.z));

                // Output: z = c == true ? x : y
                // is equivalent to: z = c * (x - y) + y
                auto constraint_1 = c * (x - y) + y - z;
                auto constraint_2 = c * (c - 1);

                return bp.add_gate({constraint_1, constraint_2});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(start_row_index);

                auto c = var(splat(var_pos.c), false);
                auto x = var(splat(var_pos.x), false);
                auto y = var(splat(var_pos.y), false);

                bp.add_copy_constraint({instance_input.c, c});
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_select<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SELECT_HPP
