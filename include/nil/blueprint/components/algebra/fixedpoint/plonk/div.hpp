#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by proving z = round(\Delta_z * x / y) via 2x\Delta_z + |y| - c = 2zy + 2q and proving 0 <= q < |y|
            // via multiple decompositions and lookup tables for checking the range of the limbs

            /**
             * Component representing a division operation with inputs x and y and output z, where
             * z = x / y.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same). The delta of z is
             * equal to the deltas of y and z.
             *
             * Input:    x  ... field element
             *           y  ... field element
             * Output:   z  ... x / y (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_div;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_div<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using div_by_pos_component = fix_div_by_pos<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                div_by_pos_component div_by_pos;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                div_by_pos_component instantiate_div_by_pos(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = static_cast<std::size_t>(
                        get_rows_amount(this->witness_amount(), 0, m1, m2) == 1 ? 4 + 2 * (m1 + m2) : 2 * (m1 + m2));
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return div_by_pos_component(witness_list, std::array<std::uint32_t, 0>(),
                                                std::array<std::uint32_t, 0>(), m1, m2);
                }

            public:
                const div_by_pos_component &get_div_by_pos_component() const {
                    return div_by_pos;
                }

                uint8_t get_m() const {
                    return div_by_pos.get_m();
                }

                uint8_t get_m1() const {
                    return div_by_pos.get_m1();
                }

                uint8_t get_m2() const {
                    return div_by_pos.get_m2();
                }

                uint64_t get_delta() const {
                    return div_by_pos.get_delta();
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1, uint8_t m2) {
                    return get_rows_amount(witness_amount, lookup_column_amount, m1, m2) == 1 ? 5 + 3 * (m1 + m2) :
                                                                                                5 + (m1 + m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_div::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(
                                                               5 + (M(m2) + M(m1)), 5 + 3 * (m2 + m1))),
                                                           false);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    if (5 + 3 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

// Includes the constraints + lookup_gates
#ifdef TEST_WITHOUT_LOOKUP_TABLES
                constexpr static const std::size_t gates_amount = 1;
#else
                constexpr static const std::size_t gates_amount = 2;
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, div_by_pos.get_m1(), div_by_pos.get_m2());

                using input_type = typename div_by_pos_component::input_type;
                using result_type = typename div_by_pos_component::result_type;

                struct var_positions {
                    CellPosition x, y, z, c, q0, a0, s_y, y0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    var_positions pos;
                    switch (this->rows_amount) {
                        case 1:

                            // trace layout (5 + 3*m col(s), 1 row(s))
                            //
                            //  r\c| 0 | 1 | 2 | 3 | 4  | .. | 4+m-1 | 4+m | .. | 4+2m-1 | 4+2m | 4+2m+1 | .. | 4+3m |
                            // +---+---+---+---+---+----+----+-------+-----+----+--------+------+--------+----+------+
                            // | 0 | x | y | z | c | q0 | .. | qm-1  | a0  | .. |  am-1  | s_y  |  y0    | .. | ym-1 |
                            pos.x = CellPosition(this->W(0), start_row_index);
                            pos.y = CellPosition(this->W(1), start_row_index);
                            pos.z = CellPosition(this->W(2), start_row_index);
                            pos.c = CellPosition(this->W(3), start_row_index);
                            pos.q0 = CellPosition(this->W(4 + 0 * m), start_row_index);    // occupies m cells
                            pos.a0 = CellPosition(this->W(4 + 1 * m), start_row_index);    // occupies m cells
                            pos.s_y = CellPosition(this->W(4 + 2 * m), start_row_index);
                            pos.y0 = CellPosition(this->W(5 + 2 * m), start_row_index);    // occupies m cells
                            break;
                        case 2:

                            // trace layout (5+m col(s), 2 row(s))
                            // recall that m is at most 4.
                            //
                            //  r\c| 0  | .. | m-1  | m  | .. | 2m-1 |
                            // +---+----+----+------+----+----+------+
                            // | 0 | q0 | .. | qm-1 | a0 | .. | am-1 |
                            pos.q0 = CellPosition(this->W(0 + 0 * m), start_row_index);    // occupies m cells
                            pos.a0 = CellPosition(this->W(0 + 1 * m), start_row_index);    // occupies m cells

                            //  r\c| 0 | 1 | 2 | 3 |  4   |   5    | .. | 5+m-1|
                            // +---+---+---+---+---+------+--------+----+------+
                            // | 1 | x | y | z | c | s_y  |  y0    | .. | ym-1 |
                            pos.x = CellPosition(this->W(0), start_row_index + 1);
                            pos.y = CellPosition(this->W(1), start_row_index + 1);
                            pos.z = CellPosition(this->W(2), start_row_index + 1);
                            pos.c = CellPosition(this->W(3), start_row_index + 1);
                            pos.s_y = CellPosition(this->W(4), start_row_index + 1);
                            pos.y0 = CellPosition(this->W(5 + 0 * m), start_row_index + 1);    // occupies m cells
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "rows_amount must be 1 or 2");
                    }
                    return pos;
                }

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
                explicit fix_div(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)),
                    div_by_pos(instantiate_div_by_pos(m1, m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_div(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    div_by_pos(instantiate_div_by_pos(m1, m2)) {};

                fix_div(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    div_by_pos(instantiate_div_by_pos(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_div =
                fix_div<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                auto m = component.get_m();
                auto one = BlueprintFieldType::value_type::one();

                auto div_by_pos_comp = component.get_div_by_pos_component();
                auto result = generate_assignments(div_by_pos_comp, assignment, instance_input, start_row_index);

                auto y_val = var_value(assignment, instance_input.y);
                std::vector<uint16_t> y0_val;

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(y_val, y0_val);
                assignment.witness(splat(var_pos.s_y)) = sign ? -one : one;
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(y0_val.size() >= m);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.y0.column() + i, var_pos.y0.row()) = y0_val[i];
                }

                return result;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::var;
                // 2x\Delta_z + |y| - c = 2zy + 2q and proving 0 <= q < |y|
                auto m = component.get_m();
                auto delta = component.get_delta();

                auto y_abs = nil::crypto3::math::expression<var>(var(splat(var_pos.y0)));
                auto q = nil::crypto3::math::expression<var>(var(splat(var_pos.q0)));
                auto a = nil::crypto3::math::expression<var>(var(splat(var_pos.a0)));

                for (auto i = 1; i < m; i++) {
                    y_abs += var(var_pos.y0.column() + i, var_pos.y0.row()) * (1ULL << (16 * i));
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                    a += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                }
                auto s_y = var(splat(var_pos.s_y));
                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto z = var(splat(var_pos.z));
                auto c = var(splat(var_pos.c));

                auto constraint_1 = 2 * (x * delta - y * z - q) + y_abs - c;
                auto constraint_2 = (c - 1) * c;
                auto constraint_3 = y_abs - q - a - 1;
                auto constraint_4 = y - s_y * y_abs;
                auto constraint_5 = (s_y - 1) * (s_y + 1);

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(3 * m);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                for (auto i = 0; i < m; i++) {
                    constraint_type constraint_q, constraint_a, constraint_y;
                    constraint_q.table_id = table_id;
                    constraint_a.table_id = table_id;
                    constraint_y.table_id = table_id;

                    auto qi = var(var_pos.q0.column() + i, var_pos.q0.row());
                    auto ai = var(var_pos.a0.column() + i, var_pos.a0.row());
                    auto yi = var(var_pos.y0.column() + i, var_pos.y0.row());
                    constraint_q.lookup_input = {qi};
                    constraint_a.lookup_input = {ai};
                    constraint_y.lookup_input = {yi};
                    constraints.push_back(constraint_q);
                    constraints.push_back(constraint_a);
                    constraints.push_back(constraint_y);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                auto last_row = start_row_index + component.rows_amount - 1;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, last_row);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, last_row);
#endif

                // Enable the copy constraints of div_by_pos
                auto div_by_pos_comp = component.get_div_by_pos_component();
                generate_copy_constraints(div_by_pos_comp, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type(
                    div_by_pos_comp, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP
