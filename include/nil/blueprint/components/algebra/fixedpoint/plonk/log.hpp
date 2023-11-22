#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_LOG_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_LOG_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp_ranged.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by proving that the output y = floor(log(x))  The error of the output is at most 2^{-16}.

            /**
             * Component representing a sqrt operation with input x and output y, where y = floor(log(x)).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... log(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_log;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_log<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using exp_component = fix_exp_ranged<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                exp_component exp;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                exp_component instantiate_exp(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = exp_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return exp_component(witness_list, std::array<std::uint32_t, 2>({this->C(0), this->C(1)}),
                                         std::array<std::uint32_t, 0>(), m1, m2);
                }

            public:
                uint8_t get_m() const {
                    return exp.get_m();
                }

                uint8_t get_m1() const {
                    return exp.get_m1();
                }

                uint8_t get_m2() const {
                    return exp.get_m2();
                }

                value_type calc_log(const value_type &x, uint8_t m1, uint8_t m2) const {
                    if (m1 == 1 && m2 == 1) {
                        auto el = FixedPoint<BlueprintFieldType, 1, 1>(x, 16);
                        return el.log().get_value();
                    } else if (m1 == 2 && m2 == 1) {
                        auto el = FixedPoint<BlueprintFieldType, 2, 1>(x, 16);
                        return el.log().get_value();
                    } else if (m1 == 1 && m2 == 2) {
                        auto el = FixedPoint<BlueprintFieldType, 1, 2>(x, 32);
                        return el.log().get_value();
                    } else if (m1 == 2 && m2 == 2) {
                        auto el = FixedPoint<BlueprintFieldType, 2, 2>(x, 32);
                        return el.log().get_value();
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                        return 0;
                    }
                }

                const exp_component &get_exp_component() const {
                    return exp;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_log::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                            .merge_with(exp_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(
                                          std::max(5, 2 * (M(m1) + M(m2))), 5 + 2 * (m2 + m1))),
                                      false)
                            .merge_with(exp_component::get_manifest(m1, m2));
                    return manifest;
                }

                constexpr static std::size_t get_log_rows_amount(std::size_t witness_amount,
                                                                 std::size_t lookup_column_amount, uint8_t m1,
                                                                 uint8_t m2) {
                    if (5 + 2 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    auto exp_rows = exp_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    auto log_rows = get_log_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    return 2 * exp_rows + log_rows;
                }

                constexpr static const std::size_t gates_amount = exp_component::gates_amount + 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, get_m1(), get_m2());
                const std::size_t log_rows_amount = get_log_rows_amount(this->witness_amount(), 0, get_m1(), get_m2());

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, y, exp1_out, exp2_in, exp2_out, a0, b0, c0;
                    int64_t exp1_row, exp2_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    var_positions pos;
                    pos.exp1_row = start_row_index;
                    pos.exp2_row = start_row_index + exp.rows_amount;
                    int64_t row_index = pos.exp2_row + exp.rows_amount;

                    switch (this->log_rows_amount) {
                        case 1:

                            // trace layout (5 + 2*m col(s), 2 constant col(s), 1 row(s))
                            //
                            //               |                witness
                            //     r\c       | 0 | 1 |     2    |    3    |     4    |
                            // +-------------+---+---+----------+---------+----------+ ...
                            // | exp1_row(s) |              <exp_witnesses>
                            // | exp2_row(s) |              <exp_witnesses>
                            // |      0      | x | y | exp1_out | exp2_in | exp2_out |

                            //            witness                |   constant  |
                            //     | 5  |..|5+m-1 |5+m |..|5+2m-1|   0  |   1  |
                            // ... +----+--+------+----+--+------+------+------+
                            //            <exp_witnesses>        | <exp_const> |
                            //     | a0 |..| am-1 | b0 |..| bm-1 |   -  |   -  |

                            pos.x = CellPosition(this->W(0), row_index);
                            pos.y = CellPosition(this->W(1), row_index);
                            pos.exp1_out = CellPosition(this->W(2), row_index);
                            pos.exp2_in = CellPosition(this->W(3), row_index);
                            pos.exp2_out = CellPosition(this->W(4), row_index);
                            pos.a0 = CellPosition(this->W(5 + 0 * m), row_index);    // occupies m cells
                            pos.b0 = CellPosition(this->W(5 + 1 * m), row_index);    // occupies m cells
                            break;
                        case 2:

                            // trace layout (max(5, 2 * m), 2 constant col(s), 2 row(s))
                            //
                            //               |           witness              |   constant  |
                            //      r\c      |  0 |..|  m-1  | m  | .. | 2m-1 |   0  |   1  |
                            // +-------------+----+--+-------+----+----+------+------+------+
                            // | exp1_row(s) |       <exp_witnesses>          | <exp_const> |
                            // | exp1_row(s) |       <exp_witnesses           | <exp_const> |
                            // |      0      | a0 |..| am-1  | b0 | .. | bm-1 |   -  |   -  |

                            //               |              witness                  |   constant  |
                            //      r\c      | 0 | 1 |    2     |    3    |    4     |   0  |   1  |
                            // +-------------+---+---+----------+---------+----------+-------------+
                            // |      1      | x | y | exp1_out | exp2_in | exp2_out |   -  |   -  |

                            pos.a0 = CellPosition(this->W(0 + 0 * m), row_index);    // occupies m cells
                            pos.b0 = CellPosition(this->W(0 + 1 * m), row_index);    // occupies m cells
                            pos.x = CellPosition(this->W(0), row_index + 1);
                            pos.y = CellPosition(this->W(1), row_index + 1);
                            pos.exp1_out = CellPosition(this->W(2), row_index + 1);
                            pos.exp2_in = CellPosition(this->W(3), row_index + 1);
                            pos.exp2_out = CellPosition(this->W(4), row_index + 1);
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "log rows_amount (i.e., without exp) must be 1 or 2");
                    }
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_log &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_log &component, std::size_t start_row_index) {
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
                    // includes the ones for the range component
                    return exp.component_custom_lookup_tables();
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    // includes the ones for the range component
                    return exp.component_lookup_tables();
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_log(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    exp(instantiate_exp(m1, m2)) {};

                fix_log(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    exp(instantiate_exp(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_log =
                fix_log<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto exp_comp = component.get_exp_component();

                // Exp inputs
                typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::exp_component::input_type
                    exp1_input,
                    exp2_input;
                exp1_input.x = var(splat(var_pos.y), false);
                exp2_input.x = var(splat(var_pos.exp2_in), false);

                ////////////////////////////////////////////////////////
                // Build the trace
                ////////////////////////////////////////////////////////

                auto m1 = component.get_m1();
                auto m2 = component.get_m2();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = component.calc_log(x_val, m1, m2);

                auto exp2_in_val = y_val - 1;

                assignment.witness(splat(var_pos.x)) = x_val;
                assignment.witness(splat(var_pos.y)) = y_val;
                assignment.witness(splat(var_pos.exp2_in)) = exp2_in_val;

                // Assign exp gadgets
                auto exp1_out = generate_assignments(exp_comp, assignment, exp1_input, var_pos.exp1_row);
                auto exp2_out = generate_assignments(exp_comp, assignment, exp2_input, var_pos.exp2_row);

                auto exp1_out_val = var_value(assignment, exp1_out.output);
                auto exp2_out_val = var_value(assignment, exp2_out.output);
                assignment.witness(splat(var_pos.exp1_out)) = exp1_out_val;
                assignment.witness(splat(var_pos.exp2_out)) = exp2_out_val;

                // Decompositions
                auto a_val = exp1_out_val - x_val;
                auto b_val = x_val - exp2_out_val - 1;

                std::vector<uint16_t> a0_val;
                std::vector<uint16_t> b0_val;

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(a_val, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(b_val, b0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);

                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                auto m = component.get_m();
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(b0_val.size() >= m);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                    assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = b0_val[i];
                }

                return typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::var;
                auto m = component.get_m();
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                auto a0 = nil::crypto3::math::expression(var(splat(var_pos.a0)));
                auto b0 = nil::crypto3::math::expression(var(splat(var_pos.b0)));
                for (auto i = 1; i < m; i++) {
                    a0 += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                    b0 += var(var_pos.b0.column() + i, var_pos.b0.row()) * (1ULL << (16 * i));
                }

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto exp1_out = var(splat(var_pos.exp1_out));
                auto exp2_in = var(splat(var_pos.exp2_in));
                auto exp2_out = var(splat(var_pos.exp2_out));

                auto constraint_1 = exp1_out - x - a0;
                auto constraint_2 = x - exp2_out - 1 - b0;
                auto constraint_3 = y - 1 - exp2_in;

                return bp.add_gate({constraint_1, constraint_2, constraint_3});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const std::map<std::string, std::size_t> &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(2 * m);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);
                BLUEPRINT_RELEASE_ASSERT(var_pos.a0.row() == var_pos.b0.row());

                for (auto i = 0; i < m; i++) {
                    constraint_type constraint_a, constraint_b;
                    constraint_a.table_id = table_id;
                    constraint_b.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto ai = var(var_pos.a0.column() + i, 0);
                    auto bi = var(var_pos.b0.column() + i, 0);
                    constraint_a.lookup_input = {ai};
                    constraint_b.lookup_input = {bi};
                    constraints.push_back(constraint_a);
                    constraints.push_back(constraint_b);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto exp_comp = component.get_exp_component();

                auto exp1_res = exp_comp.get_result((std::size_t)var_pos.exp1_row);
                auto exp2_res = exp_comp.get_result((std::size_t)var_pos.exp2_row);

                auto x = var(splat(var_pos.x));
                auto exp1_out = var(splat(var_pos.exp1_out));
                auto exp2_out = var(splat(var_pos.exp2_out));

                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({exp1_res.output, exp1_out});
                bp.add_copy_constraint({exp2_res.output, exp2_out});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                auto exp_comp = component.get_exp_component();

                // Exp inputs
                typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::exp_component::input_type
                    exp1_input,
                    exp2_input;
                exp1_input.x = var(splat(var_pos.y), false);
                exp2_input.x = var(splat(var_pos.exp2_in), false);

                // Enable the exp components
                generate_circuit(exp_comp, bp, assignment, exp1_input, var_pos.exp1_row);
                generate_circuit(exp_comp, bp, assignment, exp2_input, var_pos.exp2_row);

                // Enable the log component
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                // Enable the log lookup tables
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, var_pos.a0.row());    // same as b0.row()
#endif

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_log<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_LOG_HPP
