#ifndef CRYPTO3_BLUEPRINT_PLONK_TO_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_TO_FIXEDPOINT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/type.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by multiplying the input with the scale

            /**
             * Component representing a to_fixedpoint operation having an integer input x and output y (with delta)
             *
             * This component calculates y = x * delta.
             *
             * Input:    x  ... field element
             * Output:   y  ... field element
             *
             * Argument: m2 ... number of 16-bit limbs after comma
             *
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class int_to_fix;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class int_to_fix<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            private:
                uint8_t m2;    // Post-comma 16-bit limbs

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                /**
                 * returns the number of 16-bit limbs after the decimal separator
                 */
                uint8_t get_m2() const {
                    return m2;
                }

                /**
                 * returns the delta for the rescale operation (2^(16 * m2))
                 */
                uint64_t get_delta() const {
                    return 1ULL << (16 * m2);
                }

                static std::size_t get_witness_columns() {
                    return 2;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return int_to_fix::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns())), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, y;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (2 col(s), 1 row(s))
                    //
                    //  r\c| 0 | 1 |
                    // +---+---+---+
                    // | 0 | x | y |

                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const int_to_fix &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    result_type(const int_to_fix &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit int_to_fix(ContainerType witness, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest()), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                int_to_fix(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest()),
                    m2(M(m2)) {};

                int_to_fix(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs,
                           uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_to_fixedpoint =
                int_to_fix<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto delta = component.get_delta();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = delta * x_val;

                assignment.witness(magic(var_pos.x)) = x_val;
                assignment.witness(magic(var_pos.y)) = y_val;

                return typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            crypto3::zk::snark::plonk_constraint<BlueprintFieldType> get_constraint(
                const plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t start_row_index = 0;
                const auto var_pos = component.get_var_pos(start_row_index);

                using var = typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::var;
                auto delta = component.get_delta();

                auto x = var(magic(var_pos.x));
                auto y = var(magic(var_pos.y));

                auto constraint = y - x * delta;

                return constraint;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraint = get_constraint(component, bp, assignment, instance_input);
                return bp.add_gate(constraint);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::var;

                auto x = var(magic(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_to_fixedpoint<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_TO_FIXEDPOINT_HPP
