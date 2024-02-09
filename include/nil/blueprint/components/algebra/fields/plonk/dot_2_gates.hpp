#ifndef CRYPTO3_BLUEPRINT_PLONK_DOT_2_GATES_HPP
#define CRYPTO3_BLUEPRINT_PLONK_DOT_2_GATES_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/cell_position.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by proving a dot product in multiple rows.

            /**
             * Component representing a dot operation having inputs x, y and output z. x and y are vectors of
             * field element values where the size of the vectors must be equal.
             *
             * Uses two gates (and two selector columns) for the constraints and one column for the (intermediate) sums
             * of the dot product.
             *
             * Input:    x    ... vector of field elements
             *           y    ... vector of field elements
             *
             * Output:   z    ... x dot y (field element)
             *
             *           dots ... size of the vectors x and y (number of multiplications)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class dot_2_gates;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class dot_2_gates<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            private:
                uint32_t dots;
                uint32_t dots_per_row;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                static std::size_t gates_amount_internal(std::size_t witness_amount, uint32_t dots) {
                    return get_dot_rows(witness_amount, 0, dots) == 1 ? 1 : 2;
                }

            public:
                uint32_t get_dots() const {
                    return dots;
                }

                uint32_t get_dots_per_row() const {
                    return dots_per_row;
                }

                std::pair<std::size_t, std::size_t> dot_position(std::size_t start_row_index, std::size_t dot_index,
                                                                 bool is_x) const {
                    std::size_t row = start_row_index + dot_index / dots_per_row;
                    std::size_t column = 1 + 2 * (dot_index % dots_per_row);
                    if (!is_x) {
                        column++;
                    }
                    return {row, column};
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                private:
                    std::size_t witness_amount;
                    uint32_t dots;

                public:
                    gate_manifest_type(std::size_t witness_amount, uint16_t dots) :
                        witness_amount(witness_amount), dots(dots) {
                    }

                    std::uint32_t gates_amount() const override {
                        return dot_2_gates::gates_amount_internal(witness_amount, dots);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint16_t dots) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, dots));
                    return manifest;
                }

                // Hardcoded to max 15 for now
                static manifest_type get_manifest(uint32_t dots) {
                    manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(3, 15)), false);
                    return manifest;
                }

                static std::size_t get_dot_rows(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                uint32_t dots) {
                    uint32_t dots_per_row = (witness_amount - 1) / 2;    // -1 for sum
                    uint32_t rows = dots / dots_per_row;
                    if (dots % dots_per_row != 0) {
                        rows++;
                    }
                    return rows;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint32_t dots) {
                    uint32_t rows = get_dot_rows(witness_amount, lookup_column_amount, dots);
                    return rows;
                }

                const std::size_t gates_amount = gates_amount_internal(this->witness_amount(), dots);
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, dots);

                struct input_type {
                    std::vector<var> x;
                    std::vector<var> y;
                    var zero = var(0, 0, false);    // for asserting zero for unused constraints

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(x.size() + y.size() + 1);
                        for (auto &elem : x) {
                            result.push_back(elem);
                        }
                        for (auto &elem : y) {
                            result.push_back(elem);
                        }
                        var &zero_ref = zero;
                        result.push_back(zero_ref);
                        return result;
                    }
                };

                struct var_positions {
                    CellPosition dot_0, dot_result;
                    int64_t dot_rows_amount;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (2*b + 1 col(s), a row(s))
                    // dot .. running sum of the dot product
                    // a .. number of rows for calculating the dot product
                    // b .. number of dot products per row
                    //
                    // dot_0 = sum_i x_0_i * y_0_i for i in [0, b-1]
                    // dot_n = dot_n-1 + sum_i x_n_i * y_n_i for i in [0, b-1], for n in [1, a-1]
                    //
                    // Careful: dot_position also calculates rows, cols. Changing the layout here requires adapting
                    // dot_position as well.
                    //
                    //
                    //     |                                   witness                                    |
                    //  r\c|     0     |    1    |    2    |    3    |    4    |..| 2 * b - 1 |   2 * b   |
                    // +---+-----------+---------+---------+---------+---------+--+-----------+-----------+
                    // | 0 |   dot_0   | x_0_0   | y_0_0   | x_0_1   | y_0_1   |..|  x_0_b-1  |  y_0_b-1  |
                    // | 1 |   dot_1   | x_1_0   | y_1_0   | x_1_1   | y_1_1   |..|  x_1_b-1  |  y_1_b-1  |
                    // |.. |    ..     |   ..    |   ..    |   ..    |   ..    |..|    ..     |    ..     |
                    // |a-1|  dot_a-1  | x_a-1_0 | y_a-1_0 | x_a-1_1 | y_a-1_1 |..| x_a-1_b-1 | y_a-1_b-1 |

                    var_positions pos;
                    pos.dot_rows_amount = rows_amount;

                    pos.dot_0 = CellPosition(this->W(0), start_row_index);
                    pos.dot_result =
                        CellPosition(this->W(0), start_row_index + pos.dot_rows_amount - 1);    // is dot_a-1
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const dot_2_gates &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(component.W(0), start_row_index + var_pos.dot_rows_amount - 1, false);
                    }

                    result_type(const dot_2_gates &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(component.W(0), start_row_index + var_pos.dot_rows_amount - 1, false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit dot_2_gates(ContainerType witness, uint32_t dots) :
                    component_type(witness, {}, {}, get_manifest(dots)), dots(dots) {
                    dots_per_row = (this->witness_amount() - 1) / 2;
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                dot_2_gates(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input, uint32_t dots) :
                    component_type(witness, constant, public_input, get_manifest(dots)),
                    dots(dots) {
                    dots_per_row = (this->witness_amount() - 1) / 2;
                };

                dot_2_gates(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs,
                            uint32_t dots) :
                    component_type(witnesses, constants, public_inputs, get_manifest(dots)),
                    dots(dots) {
                    dots_per_row = (this->witness_amount() - 1) / 2;
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_dot_2_gates =
                dot_2_gates<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::var
                get_copy_var(const plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams> &component,
                             std::size_t start_row_index, std::size_t dot_index, bool is_x) {
                auto pos = component.dot_position(start_row_index, dot_index, is_x);
                using var = typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::var;
                return var(component.W(pos.second), static_cast<int>(pos.first), false);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto dots = component.get_dots();
                const auto dots_per_row = component.get_dots_per_row();
                const auto zero = BlueprintFieldType::value_type::zero();

                BLUEPRINT_RELEASE_ASSERT(instance_input.x.size() == dots);
                BLUEPRINT_RELEASE_ASSERT(instance_input.y.size() == dots);

                auto sum = zero;

                for (auto row = 0; row < var_pos.dot_rows_amount; row++) {
                    for (uint32_t i = 0; i < dots_per_row; i++) {
                        auto dot = dots_per_row * row + i;
                        auto x_val = dot < dots ? var_value(assignment, instance_input.x[dot]) : zero;
                        auto y_val = dot < dots ? var_value(assignment, instance_input.y[dot]) : zero;
                        auto mul = x_val * y_val;
                        sum += mul;

                        auto x_pos = component.dot_position(start_row_index, dot, true);
                        auto y_pos = component.dot_position(start_row_index, dot, false);

                        assignment.witness(component.W(x_pos.second), x_pos.first) = x_val;
                        assignment.witness(component.W(y_pos.second), y_pos.first) = y_val;
                    }
                    assignment.witness(var_pos.dot_0.column(), var_pos.dot_0.row() + row) = sum;
                }

                return typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_first_gate(
                const plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t row = 0;
                const auto var_pos = component.get_var_pos(row);

                using var = typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::var;
                // sum = sum_i x_i * y_i

                nil::crypto3::math::expression<var> dot;
                for (uint32_t i = 0; i < component.get_dots_per_row(); i++) {
                    auto x_pos = component.dot_position(row, i, true);
                    auto y_pos = component.dot_position(row, i, false);
                    dot += var(component.W(x_pos.second), x_pos.first) * var(component.W(y_pos.second), y_pos.first);
                }

                auto constraint_1 = dot - var(splat(var_pos.dot_0));

                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_second_gate(
                const plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t row = 0;
                const auto var_pos = component.get_var_pos(row);

                using var = typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::var;
                // sum = prev_sum + sum_i x_i * y_i

                nil::crypto3::math::expression<var> dot;
                for (uint32_t i = 0; i < component.get_dots_per_row(); i++) {
                    auto x_pos = component.dot_position(row, i, true);
                    auto y_pos = component.dot_position(row, i, false);
                    dot += var(component.W(x_pos.second), x_pos.first) * var(component.W(y_pos.second), y_pos.first);
                }

                auto dot_p = var(var_pos.dot_0.column(), var_pos.dot_0.row() - 1);
                auto dot_c = var(splat(var_pos.dot_0));
                auto constraint_1 = dot + dot_p - dot_c;

                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                int64_t row = 0;
                const auto var_pos = component.get_var_pos(row);

                using var = typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::var;

                auto dots = component.get_dots();
                auto dots_per_row = component.get_dots_per_row();

                for (uint32_t i = 0; i < dots; i++) {
                    var x_i = get_copy_var(component, start_row_index, i, true);
                    var y_i = get_copy_var(component, start_row_index, i, false);
                    bp.add_copy_constraint({instance_input.x[i], x_i});
                    bp.add_copy_constraint({instance_input.y[i], y_i});
                }

                // unused dot-slots are constrained to zero
                auto rem = dots % dots_per_row;
                if (rem != 0) {
                    auto row = start_row_index + var_pos.dot_rows_amount - 1;
                    for (auto i = rem; i < dots_per_row; i++) {
                        var x_i = get_copy_var(component, row, i, true);
                        var y_i = get_copy_var(component, row, i, false);
                        bp.add_copy_constraint({instance_input.zero, x_i});
                        bp.add_copy_constraint({instance_input.zero, y_i});
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                std::size_t first_selector = generate_first_gate(component, bp, assignment, instance_input);
                assignment.enable_selector(first_selector, start_row_index);

                if (component.gates_amount == 2) {
                    std::size_t second_selector = generate_second_gate(component, bp, assignment, instance_input);
                    assignment.enable_selector(second_selector, start_row_index + 1,
                                               start_row_index + component.rows_amount - 1);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_dot_2_gates<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_DOT_2_GATES_HPP
