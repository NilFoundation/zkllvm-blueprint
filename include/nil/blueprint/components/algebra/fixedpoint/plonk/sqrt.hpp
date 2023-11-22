#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SQRT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SQRT_HPP

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

            // Works by proving that the output y is in range floor(sqrt(x)) <= y <= ceil(sqrt(x)) and that it was
            // rounded correctly. The error of the output is at most 1 LSB of the fixedpoint representation.

            /**
             * Component representing a sqrt operation with input x and output y, where y = round(sqrt(x)).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... sqrt(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_sqrt;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_sqrt<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

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

                uint64_t get_delta() const {
                    return 1ULL << (16 * m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_sqrt::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(
                                          new manifest_range_param(2 + 2 * (M(m2) + M(m1)), 4 + 4 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (4 + 4 * (M(m2) + M(m1)) <= witness_amount) {
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

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, y, y_sq, r, y0, a0, b0, c0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    var_positions pos;
                    switch (this->rows_amount) {
                        case 1:

                            // trace layout (4 + 4*m col(s), 1 row(s))
                            //
                            //  r\c| 0 | 1 |  2   | 3 | 4  |..| 4+m-1| 4+m|..|4+2m-1|4+2m|..|4+3m-1|4+3m|..|4+4m-1|
                            // +---+---+---+------+---+----+--+------+----+--+------+----+--+------+----+--+------+
                            // | 0 | x | y | y_sq | r | y0 |..| ym-1 | a0 |..| am-1 | b0 |..| bm-1 | c0 |..| cm-1 |

                            pos.x = CellPosition(this->W(0), start_row_index);
                            pos.y = CellPosition(this->W(1), start_row_index);
                            pos.y_sq = CellPosition(this->W(2), start_row_index);
                            pos.r = CellPosition(this->W(3), start_row_index);
                            pos.y0 = CellPosition(this->W(4 + 0 * m), start_row_index);    // occupies m cells
                            pos.a0 = CellPosition(this->W(4 + 1 * m), start_row_index);    // occupies m cells
                            pos.b0 = CellPosition(this->W(4 + 2 * m), start_row_index);    // occupies m cells
                            pos.c0 = CellPosition(this->W(4 + 3 * m), start_row_index);    // occupies m cells
                            break;
                        case 2:

                            // trace layout (2 + 2*m col(s), 2 row(s))
                            //
                            //  r\c|  0  |  1  | 2 | .. | 2+m-1 | 2+m | .. | 2+2m-1 |
                            // +---+------+---+----+----+-------+-----+----+--------+
                            // | 0 | y_sq | r | b0 | .. | bm-1  | c0  | .. | cm-1   |
                            // | 1 | x    | y | y0 | .. | ym-1  | a0  | .. | am-1   |

                            pos.y_sq = CellPosition(this->W(0), start_row_index);
                            pos.r = CellPosition(this->W(1), start_row_index);
                            pos.b0 = CellPosition(this->W(2 + 0 * m), start_row_index);    // occupies m cells
                            pos.c0 = CellPosition(this->W(2 + 1 * m), start_row_index);    // occupies m cells
                            pos.x = CellPosition(this->W(0), start_row_index + 1);
                            pos.y = CellPosition(this->W(1), start_row_index + 1);
                            pos.y0 = CellPosition(this->W(2 + 0 * m), start_row_index + 1);    // occupies m cells
                            pos.a0 = CellPosition(this->W(2 + 1 * m), start_row_index + 1);    // occupies m cells
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "rows_amount must be 1 or 2");
                    }
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_sqrt &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_sqrt &component, std::size_t start_row_index) {
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
                explicit fix_sqrt(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_sqrt(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_sqrt(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_sqrt =
                fix_sqrt<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto x_val = var_value(assignment, instance_input.x);
                auto x_val_delta = x_val * component.get_delta();
                auto y_val = FixedPointHelper<BlueprintFieldType>::sqrt(x_val_delta);
                auto y_val_floor = FixedPointHelper<BlueprintFieldType>::sqrt(x_val_delta, true);

                auto r_bool = y_val != y_val_floor;
                auto r_val = r_bool ? BlueprintFieldType::value_type::one() : BlueprintFieldType::value_type::zero();

                auto y_sq_val = y_val * y_val;

                assignment.witness(splat(var_pos.x)) = x_val;
                assignment.witness(splat(var_pos.y)) = y_val;
                assignment.witness(splat(var_pos.y_sq)) = y_sq_val;
                assignment.witness(splat(var_pos.r)) = r_val;

                // Decompositions
                auto a_val = (x_val_delta - y_sq_val) + r_val * (2 * y_val - 1);
                auto b_val = 2 * y_val - 2 * r_val - a_val;
                auto c_val = 2 * r_val * (x_val_delta - y_sq_val) + y_sq_val + y_val - x_val_delta - r_val;

                std::vector<uint16_t> y0_val;
                std::vector<uint16_t> a0_val;
                std::vector<uint16_t> b0_val;
                std::vector<uint16_t> c0_val;

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(y_val, y0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(a_val, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(b_val, b0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(c_val, c0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);

                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                auto m = component.get_m();
                BLUEPRINT_RELEASE_ASSERT(y0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(b0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(c0_val.size() >= m);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.y0.column() + i, var_pos.y0.row()) = y0_val[i];
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                    assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = b0_val[i];
                    assignment.witness(var_pos.c0.column() + i, var_pos.c0.row()) = c0_val[i];
                }

                return typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::var;
                auto m = component.get_m();
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                auto y0 = nil::crypto3::math::expression(var(splat(var_pos.y0)));
                auto a0 = nil::crypto3::math::expression(var(splat(var_pos.a0)));
                auto b0 = nil::crypto3::math::expression(var(splat(var_pos.b0)));
                auto c0 = nil::crypto3::math::expression(var(splat(var_pos.c0)));
                for (auto i = 1; i < m; i++) {
                    y0 += var(var_pos.y0.column() + i, var_pos.y0.row()) * (1ULL << (16 * i));
                    a0 += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                    b0 += var(var_pos.b0.column() + i, var_pos.b0.row()) * (1ULL << (16 * i));
                    c0 += var(var_pos.c0.column() + i, var_pos.c0.row()) * (1ULL << (16 * i));
                }

                auto x = var(splat(var_pos.x)) * component.get_delta();
                auto y = var(splat(var_pos.y));
                auto y_sq = var(splat(var_pos.y_sq));
                auto r = var(splat(var_pos.r));

                auto constraint_1 = r * (r - 1);
                auto constraint_2 = y - y0;
                auto constraint_3 = (x - y_sq) + 2 * r * y - r - a0;
                auto constraint_4 = 2 * y - r - (x - y_sq) - 2 * r * y - b0;
                auto constraint_5 = 2 * r * (x - y_sq) + y_sq + y - x - r - c0;

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const std::map<std::string, std::size_t> &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);
                if (component.rows_amount == 2) {
                    constraints.reserve(2 * m);
                    // We put just two decompositions into the constraint and activate it twice
                    BLUEPRINT_RELEASE_ASSERT(var_pos.y0.row() == var_pos.a0.row());
                    BLUEPRINT_RELEASE_ASSERT(var_pos.b0.row() == var_pos.c0.row());
                    BLUEPRINT_RELEASE_ASSERT(var_pos.a0.column() == var_pos.c0.column());
                    BLUEPRINT_RELEASE_ASSERT(var_pos.b0.column() == var_pos.y0.column());
                } else {
                    constraints.reserve(4 * m);
                }

                for (auto i = 0; i < m; i++) {
                    constraint_type constraint_y, constraint_a;
                    constraint_y.table_id = table_id;
                    constraint_a.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto yi = var(var_pos.y0.column() + i, 0);
                    auto ai = var(var_pos.a0.column() + i, 0);
                    constraint_y.lookup_input = {yi};
                    constraint_a.lookup_input = {ai};

                    constraints.push_back(constraint_y);
                    constraints.push_back(constraint_a);

                    if (component.rows_amount == 1) {
                        constraint_type constraint_b, constraint_c;
                        constraint_b.table_id = table_id;
                        constraint_c.table_id = table_id;

                        auto bi = var(var_pos.b0.column() + i, 0);
                        auto ci = var(var_pos.c0.column() + i, 0);
                        constraint_b.lookup_input = {bi};
                        constraint_c.lookup_input = {ci};

                        constraints.push_back(constraint_b);
                        constraints.push_back(constraint_c);
                    }
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto x = var(splat(var_pos.x));
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index);
                if (component.rows_amount == 2) {
                    // We put just two decompositions into the constraint and activate it twice
                    assignment.enable_selector(lookup_selector_index, start_row_index + 1);
                }
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SQRT_HPP
