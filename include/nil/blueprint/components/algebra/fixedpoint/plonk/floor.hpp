#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_FLOOR_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_FLOOR_HPP

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

            // Works by decomposing the input. We use a constant as an offset for the input to allow the same gadget for
            // the ceil component

            /**
             * Component representing a floor operation.
             *
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x       ... field element
             * Output: y       ... floor(x) (field element)
             *
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_floor;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_floor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                uint64_t get_delta() const {
                    return 1ULL << (16 * this->m2);
                }

                uint8_t get_m1() const {
                    return m1;
                }

                uint8_t get_m2() const {
                    return m2;
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return 3 + M(m1) + M(m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_floor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3 + M(m1) + M(m2))), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

// Includes the constraints + lookup_gates
#ifdef TEST_WITHOUT_LOOKUP_TABLES
                constexpr static const std::size_t gates_amount = 1;
#else
                constexpr static const std::size_t gates_amount = 2;
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, y, s, x0, offset;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (3 + m col(s), 1 constant col(s), 1 row(s))
                    // The constant col is set to 0, but allows to reuse the same gadget for ceil
                    //
                    //     |          witness              | constant |
                    //  r\c| 0 | 1 | 2 | 3  | .. | 3 + m-1 |     0    |
                    // +---+---+---+---+----+----+---------+----------+
                    // | 0 | x | y | s | x0 | .. |   xm-1  |  offset  |

                    auto m = this->get_m();
                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    pos.s = CellPosition(this->W(2), start_row_index);
                    pos.x0 = CellPosition(this->W(3 + 0 * m), start_row_index);    // occupies m cells
                    pos.offset = CellPosition(this->C(0), start_row_index);
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);

                    result_type(const fix_floor &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_floor &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
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

                template<typename ContainerType>
                explicit fix_floor(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_floor(WitnessContainerType witness, ConstantContainerType constant,
                          PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_floor(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                              public_inputs,
                          uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_floor =
                fix_floor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index, std::uint64_t offset = 0) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto one = BlueprintFieldType::value_type::one();
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = m1 + m2;
                auto delta = component.get_delta();
                auto mask = (1ULL << 16) - 1;

                auto x_val = var_value(assignment, instance_input.x);

                assignment.witness(splat(var_pos.x)) = x_val;

                auto x_val_ = x_val + offset;    // offset is zero for floor and Delta-1 for ceil

                uint64_t x_pre_val, x_post_val;
                bool sign = FixedPointHelper<BlueprintFieldType>::split_exp(x_val_, 16 * m2, x_pre_val, x_post_val);

                auto s_val = sign ? -one : one;
                typename BlueprintFieldType::value_type y_val = x_pre_val * delta;
                if (sign) {
                    y_val = -y_val;
                }

                assignment.witness(splat(var_pos.s)) = s_val;
                assignment.witness(splat(var_pos.y)) = y_val;

                auto x0_val = x_post_val & mask;
                assignment.witness(splat(var_pos.x0)) = x0_val;

                if (m2 == 1) {
                    BLUEPRINT_RELEASE_ASSERT((x_post_val >> 16) == 0);
                } else {
                    auto x1_val = (x_post_val >> 16) & mask;
                    assignment.witness(var_pos.x0.column() + 1, var_pos.x0.row()) = x1_val;
                    BLUEPRINT_RELEASE_ASSERT((x_post_val >> 32) == 0);
                }

                auto xi_val = x_pre_val & mask;
                assignment.witness(var_pos.x0.column() + m2, var_pos.x0.row()) = xi_val;
                if (m1 == 1) {
                    BLUEPRINT_RELEASE_ASSERT((x_pre_val >> 16) == 0);
                } else {
                    auto x1i_val = (x_pre_val >> 16) & mask;
                    assignment.witness(var_pos.x0.column() + m2 + 1, var_pos.x0.row()) = x1i_val;
                    BLUEPRINT_RELEASE_ASSERT((x_pre_val >> 32) == 0);
                }

                return typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int first_row = 1 - static_cast<int>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(first_row));

                using var = typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::var;

                auto m = component.get_m();
                auto m2 = component.get_m2();

                auto x_post = nil::crypto3::math::expression(var(splat(var_pos.x0)));
                for (auto i = 1; i < m2; i++) {
                    x_post += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }

                auto x_pre = nil::crypto3::math::expression(var(var_pos.x0.column() + m2, var_pos.x0.row()));
                x_pre *= 1ULL << (16 * m2);
                for (auto i = m2 + 1; i < m; i++) {
                    x_pre += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto s = var(splat(var_pos.s));
                auto offset = var(splat(var_pos.offset), true, var::column_type::constant);

                auto constraint_1 = x + offset - s * x_pre - x_post;
                auto constraint_2 = (s - 1) * (s + 1);
                auto constraint_3 = y - s * x_pre;

                return bp.add_gate({constraint_1, constraint_2, constraint_3});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(m);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                for (auto i = 0; i < m; i++) {
                    constraint_type constraint;
                    constraint.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto di = var(var_pos.x0.column() + i, 0);
                    constraint.lookup_input = {di};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index, std::uint64_t offset = 0) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index, offset);

                return typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_floor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index, std::uint64_t offset) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                assignment.constant(splat(var_pos.offset)) = offset;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_FLOOR_HPP
