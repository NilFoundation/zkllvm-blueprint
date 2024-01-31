#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_SET_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_SET_HPP

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

            // Proves: output = is_equal(index_a, index_b) ? d_eq : d_neq
            // Whereas index_b is a constant and index_a is a witness

            /**
             * Component representing setting a value at a secret index
             *
             * This component calculates output = d_neq + (d_eq - d_neq) * is_equal(index_a, index_b)
             *
             * Input:    d_eq   ... field element
             *           d_neq  ... field element
             *           index_a ... field_element
             *           index_b ... field_element (constant)
             * Output:   output  ... field element
             *
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_cmp_set;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_cmp_set<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                static std::size_t get_witness_columns() {
                    return 6;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;

                value_type index_b;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_cmp_set::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    manifest_type manifest = manifest_type(
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
                    var d_eq = var(0, 0, false);
                    var d_neq = var(0, 0, false);
                    var index_a = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {d_eq, d_neq, index_a};
                    }
                };

                struct var_positions {
                    CellPosition y, d_eq, d_neq, eq, inv, index_a, index_b;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (6 witness col(s), 1 constant col(s), 1 row(s))
                    //
                    //     |          witness                      | constant |
                    //  r\c| 0 |   1  |   2   |  3 |  4  |    5    |    0     |
                    // +---+-----+----------+------+-----+---------+----+----------+
                    // | 0 | y | d_eq | d_neq | eq | inv | index_a | index_b  |

                    var_positions pos;
                    pos.y = CellPosition(this->W(0), start_row_index);
                    pos.d_eq = CellPosition(this->W(1), start_row_index);
                    pos.d_neq = CellPosition(this->W(2), start_row_index);
                    pos.eq = CellPosition(this->W(3), start_row_index);
                    pos.inv = CellPosition(this->W(4), start_row_index);
                    pos.index_a = CellPosition(this->W(5), start_row_index);
                    pos.index_b = CellPosition(this->C(0), start_row_index);
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_cmp_set &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_cmp_set &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_cmp_set(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input, value_type index_b_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    index_b(index_b_) {};

                fix_cmp_set(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs,
                            value_type index_b_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    index_b(index_b_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_cmp_set =
                fix_cmp_set<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto d_eq_val = var_value(assignment, instance_input.d_eq);
                auto d_neq_val = var_value(assignment, instance_input.d_neq);
                auto index_a_val = var_value(assignment, instance_input.index_a);
                auto index_b_val = component.index_b;

                assignment.witness(splat(var_pos.d_eq)) = d_eq_val;
                assignment.witness(splat(var_pos.d_neq)) = d_neq_val;
                assignment.witness(splat(var_pos.index_a)) = index_a_val;

                auto diff = index_a_val - index_b_val;

                if (diff == 0) {
                    // Does not matter what to put into inv
                    assignment.witness(splat(var_pos.inv)) = BlueprintFieldType::value_type::zero();
                    assignment.witness(splat(var_pos.eq)) = BlueprintFieldType::value_type::one();
                    assignment.witness(splat(var_pos.y)) = d_eq_val;
                } else {
                    auto inv_val = diff.inversed();
                    assignment.witness(splat(var_pos.eq)) = BlueprintFieldType::value_type::zero();
                    assignment.witness(splat(var_pos.inv)) = inv_val;
                    assignment.witness(splat(var_pos.y)) = d_neq_val;
                }

                return typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                uint64_t start_row_index = 0;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::var;

                auto y = var(splat(var_pos.y));
                auto d_eq = var(splat(var_pos.d_eq));
                auto d_neq = var(splat(var_pos.d_neq));
                auto eq = var(splat(var_pos.eq));
                auto inv = var(splat(var_pos.inv));
                auto index_a = var(splat(var_pos.index_a));
                auto index_b = var(splat(var_pos.index_b), true, var::column_type::constant);

                auto diff = index_a - index_b;
                auto constraint_1 = diff * eq;
                auto constraint_2 = eq + diff * inv - 1;
                auto constraint_3 = y - (d_eq - d_neq) * eq - d_neq;

                return {constraint_1, constraint_2, constraint_3};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::var;

                auto d_eq = var(splat(var_pos.d_eq), false);
                auto d_neq = var(splat(var_pos.d_neq), false);
                auto index_a = var(splat(var_pos.index_a), false);

                bp.add_copy_constraint({instance_input.d_eq, d_eq});
                bp.add_copy_constraint({instance_input.d_neq, d_neq});
                bp.add_copy_constraint({instance_input.index_a, index_a});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_set<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                assignment.constant(splat(var_pos.index_b)) = component.index_b;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_SET_HPP
