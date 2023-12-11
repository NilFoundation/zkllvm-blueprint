#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ARGMAX_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ARGMAX_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/type.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/range.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing the difference of the inputs. According to ONNX
            // (https://github.com/onnx/onnx/blob/main/docs/Operators.md#ArgMax), the select_last_index attribute
            // decides what should happen during a tie. We set this attribute during initialization of the gadget, and
            // do *not* prove it.
            // This gadget also assumes that index_x < index_y!
            // Index_y is a constant, while index_x is a witness.

            /**
             * Component representing a max and an argmax operation.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same).
             *
             * The delta of z is the same as the delta of x and y.
             *
             * Input:  x       ... field element
             *         y       ... field element
             *         index_x ... field_element
             *         index_y ... field_element (constant)
             * Output: max     ... max(x, y) (field element)
             *         index   ... index_x if x >= / > y, index_y otherwise (field element)
             *                     >= or > is decided by a public bool value during initialization of the gadget (not
             *                     part of trace)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_argmax;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_argmax<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {
            public:
                using value_type = typename BlueprintFieldType::value_type;

            private:
                uint8_t m1;    // Pre-comma 16-bit limbs
                uint8_t m2;    // Post-comma 16-bit limbs

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                uint8_t get_m() const {
                    return m1 + m2;
                }

                uint8_t get_m1() const {
                    return m1;
                }

                uint8_t get_m2() const {
                    return m2;
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return get_rows_amount(witness_amount, 0, m1, m2) == 1 ? 10 + (m1 + m2) : 4 + (m1 + m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                value_type index_y;
                bool select_last_index;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_argmax::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(4 + (m1 + m2), 10 + (m2 + m1))),
                        false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (10 + (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                // Includes the constraints + lookup_gates
                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);
                    var index_x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y, index_x};
                    }
                };

                struct var_positions {
                    CellPosition x, y, index_x, index_y, max, index, flag, eq, inv, s, d0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    var_positions pos;
                    switch (this->rows_amount) {
                        case 1:

                            // trace layout witness (10 + (m+1) col(s), 1 constant col(s), 1 row(s))
                            // requiring an extra limb because of potential overflows during decomposition of
                            // differences
                            //
                            //     |                                    witness            | constant |
                            //  r\c| 0 | 1 | 2 | 3  | 4 | 5    | 6  | 7   | 8 | 9  |..| 9+m|     0    |
                            // +---+---+---+---+---+----+------+----+-----+---+----+--+----+----------+
                            // | 0 | x | y | ix| max| i | flag | eq | inv | s | d0 |..| dm |    iy    |

                            pos.x = CellPosition(this->W(0), start_row_index);
                            pos.y = CellPosition(this->W(1), start_row_index);
                            pos.index_x = CellPosition(this->W(2), start_row_index);
                            pos.max = CellPosition(this->W(3), start_row_index);
                            pos.index = CellPosition(this->W(4), start_row_index);
                            pos.flag = CellPosition(this->W(5), start_row_index);
                            pos.eq = CellPosition(this->W(6), start_row_index);
                            pos.inv = CellPosition(this->W(7), start_row_index);
                            pos.s = CellPosition(this->W(8), start_row_index);
                            pos.d0 = CellPosition(this->W(9 + 0 * (m + 1)), start_row_index);

                            pos.index_y = CellPosition(this->C(0), start_row_index);

                            break;
                        case 2:

                            // trace layout witness (4 + (m1 + m2) col(s), 1 constant col(s), 2 row(s))
                            // (recall that 2 <= m <= 4)
                            // requiring an extra limb because of potential overflows during decomposition of
                            // differences
                            //
                            //     |              witness         |
                            //  r\c| 0  | 1   | 2 | 3  | .. | 3+m |
                            // +---+----+-----+---+----+----+-----+
                            // | 0 | eq | inv | s | d0 | .. | dm  |

                            pos.eq = CellPosition(this->W(0), start_row_index);
                            pos.inv = CellPosition(this->W(1), start_row_index);
                            pos.s = CellPosition(this->W(2), start_row_index);
                            pos.d0 = CellPosition(this->W(3 + 0 * (m + 1)), start_row_index);

                            //     |           witness         | constant |
                            //  r\c| 0 | 1 | 2 | 3  | 4 |   5  |     0    |
                            // +---+---+---+---+----+---+------+----------+
                            // | 1 | x | y | ix| max| i | flag |    iy    |
                            pos.x = CellPosition(this->W(0), start_row_index + 1);
                            pos.y = CellPosition(this->W(1), start_row_index + 1);
                            pos.index_x = CellPosition(this->W(2), start_row_index + 1);
                            pos.max = CellPosition(this->W(3), start_row_index + 1);
                            pos.index = CellPosition(this->W(4), start_row_index + 1);
                            pos.flag = CellPosition(this->W(5), start_row_index + 1);

                            pos.index_y = CellPosition(this->C(0), start_row_index + 1);

                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "rows_amount must be 1 or 2");
                    }
                    return pos;
                }
                struct result_type {
                    var max = var(0, 0, false);
                    var index = var(0, 0, false);

                    result_type(const fix_argmax &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        max = var(splat(var_pos.max), false);
                        index = var(splat(var_pos.index), false);
                    }

                    result_type(const fix_argmax &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        max = var(splat(var_pos.max), false);
                        index = var(splat(var_pos.index), false);
                    }

                    std::vector<var> all_vars() const {
                        return {max, index};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {};
                    auto table = std::shared_ptr<lookup_table_definition>(new range_table());
                    result.push_back(table);
                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables[range_table::FULL_TABLE_NAME] = 0;    // REQUIRED_TABLE
                    return lookup_tables;
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_argmax(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input, uint8_t m1, uint8_t m2, value_type index_y_,
                           bool select_last_index) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), index_y(index_y_), select_last_index(select_last_index) {};

                fix_argmax(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2, value_type index_y_, bool select_last_index) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), index_y(index_y_), select_last_index(select_last_index) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_argmax =
                fix_argmax<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto one = BlueprintFieldType::value_type::one();
                auto m = component.get_m();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);
                auto index_x_val = var_value(assignment, instance_input.index_x);
                auto index_y_val = component.index_y;

                BLUEPRINT_RELEASE_ASSERT(index_x_val < index_y_val);

                assignment.witness(splat(var_pos.x)) = x_val;
                assignment.witness(splat(var_pos.y)) = y_val;
                assignment.witness(splat(var_pos.index_x)) = index_x_val;

                // decomposition of difference
                auto d_val = x_val - y_val;
                std::vector<uint16_t> d0_val;

                bool sign = FixedPointHelper<BlueprintFieldType>::abs(d_val);
                bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(d_val, d0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_);
                // is ok because d0_val is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m);
                assignment.witness(splat(var_pos.s)) = sign ? -one : one;

                // Additional limb due to potential overflow of d_val
                if (d0_val.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(d0_val[m] == 0 || d0_val[m] == 1);
                    assignment.witness(var_pos.d0.column() + m, var_pos.d0.row()) = d0_val[m];
                } else {
                    assignment.witness(var_pos.d0.column() + m, var_pos.d0.row()) = 0;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = d0_val[i];
                }

                // equal, flag and max
                bool eq = d_val == 0;

                assignment.witness(splat(var_pos.eq)) = typename BlueprintFieldType::value_type((uint64_t)eq);

                // if eq:  Does not matter what to put here
                assignment.witness(splat(var_pos.inv)) = eq ? BlueprintFieldType::value_type::zero() : d_val.inversed();

                // Which component to we have
                if (component.select_last_index) {
                    // We have to evaluate x > y
                    bool gt = !eq && !sign;
                    assignment.witness(splat(var_pos.flag)) = typename BlueprintFieldType::value_type((uint64_t)gt);
                    assignment.witness(splat(var_pos.max)) = gt ? x_val : y_val;
                    assignment.witness(splat(var_pos.index)) = gt ? index_x_val : index_y_val;

                } else {
                    // We have to evaluate x >= y
                    bool geq = !sign || eq;
                    assignment.witness(splat(var_pos.flag)) = typename BlueprintFieldType::value_type((uint64_t)geq);
                    assignment.witness(splat(var_pos.max)) = geq ? x_val : y_val;
                    assignment.witness(splat(var_pos.index)) = geq ? index_x_val : index_y_val;
                }

                return typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int first_row = 1 - static_cast<int>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(first_row));

                using var = typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::var;

                auto m = component.get_m();

                auto d0 = nil::crypto3::math::expression(var(splat(var_pos.d0)));
                for (auto i = 1; i < m; i++) {
                    d0 += var(var_pos.d0.column() + i, var_pos.d0.row()) * (1ULL << (16 * i));
                }
                typename BlueprintFieldType::value_type tmp =
                    1ULL << (16 * (m - 1));    // 1ULL << 16m could overflow 64-bit int
                tmp *= 1ULL << 16;
                d0 += var(var_pos.d0.column() + m, var_pos.d0.row()) * tmp;

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto index_x = var(splat(var_pos.index_x));
                auto index_y = var(splat(var_pos.index_y), true, var::column_type::constant);
                auto max = var(splat(var_pos.max));
                auto index = var(splat(var_pos.index));
                auto flag = var(splat(var_pos.flag));
                auto eq = var(splat(var_pos.eq));
                auto inv = var(splat(var_pos.inv));
                auto s = var(splat(var_pos.s));

                auto constraint_1 = x - y - s * d0;
                auto constraint_2 = (s - 1) * (s + 1);
                auto constraint_3 = eq * d0;
                auto constraint_4 = 1 - eq - inv * d0;

                auto inv2 = typename BlueprintFieldType::value_type(2).inversed();

                auto constraint_5 = nil::crypto3::math::expression(flag);
                // Which component to we have
                if (component.select_last_index) {
                    // We have to evaluate x > y
                    constraint_5 = inv2 * (1 + s) * (1 - eq) - constraint_5;
                } else {
                    // We have to evaluate (x >= y) <==> !(x < y)
                    constraint_5 = 1 - inv2 * (1 - s) * (1 - eq) - constraint_5;
                }

                auto constraint_6 = flag * (x - y) + y - max;
                auto constraint_7 = flag * (index_x - index_y) + index_y - index;

                return bp.add_gate(
                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6, constraint_7});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m_ = component.get_m() + 1;

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(m_);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                for (auto i = 0; i < m_; i++) {
                    constraint_type constraint;
                    constraint.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto di = var(var_pos.d0.column() + i, 0);
                    constraint.lookup_input = {di};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(splat(var_pos.x), false);
                var y = var(splat(var_pos.y), false);
                var index_x = var(splat(var_pos.index_x), false);
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
                bp.add_copy_constraint({instance_input.index_x, index_x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, var_pos.d0.row());
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                assignment.constant(splat(var_pos.index_y)) = component.index_y;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ARGMAX_HPP
