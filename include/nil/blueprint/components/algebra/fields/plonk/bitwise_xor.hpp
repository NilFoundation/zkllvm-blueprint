#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_BITWISE_XOR_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_BITWISE_XOR_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/cell_position.hpp"
#include "nil/blueprint/components/algebra/fields/plonk/non_native/detail/bitwise_helper.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // works via decomposing x and y into 8-bit limbs and one additional sign bit, and looking up the result of
            // the bitwise operation for each 8-bit limb triples in a lookup table. The result is then reassembled from
            // the lookup table result limbs.

            /**
             * Component representing a bitwise XOR operation.
             *
             * Field elements greater than prime half are interpreted as negative numbers, similar to the repesentation
             * of signed integers many in programming languages. The value of a field element gets deomposed into a
             * dedicated sign bit and m 8-bit limbs and the bitwise operation gets applied to each pair of bits.
             *
             * Input:    x ... field element
             *           y ... field element
             * Output:   z ... x ^ y (field element)
             * Constant: m ... number of 8-bit limbs (uint8_t), m in [1,8]
             *           n ... negative part constant (field element), n = prime - 2^8m
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class bitwise_xor;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class bitwise_xor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

            private:
                const uint8_t m;       // number of 8-bit limbs
                const value_type n;    // negative part constant (field element): n = prime - 2^8m

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 8) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                struct var_positions {
                    CellPosition x, y, z, s_x, s_y, x0, x1, y0, y1, z0, z1, n;
                    int64_t start_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->m;
                    var_positions pos;
                    pos.start_row = start_row_index;
                    pos.x = CellPosition(this->W(0), pos.start_row);
                    pos.y = CellPosition(this->W(1), pos.start_row);
                    pos.z = CellPosition(this->W(2), pos.start_row);
                    pos.s_x = CellPosition(this->W(3), pos.start_row);
                    pos.s_y = CellPosition(this->W(4), pos.start_row);
                    pos.x0 = CellPosition(this->W(5 + (0 * m)), pos.start_row);    // occupies m cells
                    pos.x1 = CellPosition(this->W(5 + (0 * m) + 1), pos.start_row);
                    pos.n = CellPosition(this->C(0), pos.start_row);

                    // trace layout constant (1 col(s), 1 row(s))
                    //
                    //     | constant |
                    //  r\c|    0     |
                    // +---+----------+
                    // | 0 |    n     |

                    if (rows_amount == 1) {
                        // trace layout witness (1 col(s), 5 + 3m row(s))
                        //
                        //     |                                    witness                                     |
                        //  r\c| 0 | 1 | 2 |  3  |  4  |  5  | .. | 5+m-1 | 5+m | .. | 5+2m-1| 5+2m| .. | 5+3m-1|
                        // +---+---+---+---+-----+-----+-----+----+-------+-----+----+-------+-----+----+-------+
                        // | 0 | x | y | z | s_x | s_y | x_0 | .. | x_m-1 | y_0 | .. | y_m-1 | z_0 | .. | z_m-1 |
                        pos.y0 = CellPosition(this->W(5 + (1 * m)), pos.start_row);    // occupies m cells
                        pos.y1 = CellPosition(this->W(5 + (1 * m) + 1), pos.start_row);
                        pos.z0 = CellPosition(this->W(5 + (2 * m)), pos.start_row);    // occupies m cells
                        pos.z1 = CellPosition(this->W(5 + (2 * m) + 1), pos.start_row);
                    } else if (rows_amount == 2 && m < 8) {
                        // trace layout witness (2 col(s), r row(s))
                        // where r = max (m + 5, 2m)
                        //
                        //     |                 witness                  |
                        //  r\c| 0 | 1 | 2 |  3  |  4  |  5  | .. | 5+m-1 |
                        // +---+---+---+---+-----+-----+-----+----+-------+
                        // | 0 | x | y | z | s_x | s_y | x_0 | .. | x_m-1 |

                        //     |               witness               |
                        //  r\c|  0  | .. |  m-1  |  m  | .. | 2m-1  |
                        // +---+-----+----+-------+-----+----+-------+
                        // | 1 | y_0 | .. | y_m-1 | z_0 | .. | z_m-1 |
                        pos.y0 = CellPosition(this->W((0 * m)), pos.start_row + 1);    // occupies m cells
                        pos.y1 = CellPosition(this->W((0 * m) + 1), pos.start_row + 1);
                        pos.z0 = CellPosition(this->W((1 * m)), pos.start_row + 1);    // occupies m cells
                        pos.z1 = CellPosition(this->W((1 * m) + 1), pos.start_row + 1);
                    } else if (rows_amount == 2 && m == 8) {
                        // trace layout witness (2 col(s), 15 row(s))
                        //
                        //     |                     witness                      |
                        //  r\c| 0 | 1 | 2 |  3  |  4  |  5  | .. | 5+m-1 | 5 + m |
                        // +---+---+---+---+-----+-----+-----+----+-------+-------+
                        // | 0 | x | y | z | s_x | s_y | x_0 | .. | x_m-1 |  y_0  |

                        //     |               witness               |
                        //  r\c|  0  | .. |  m-2  | m-1 | .. | 2m-2  |
                        // +---+-----+----+-------+-----+----+-------+
                        // | 1 | y_1 | .. | y_m-1 | z_0 | .. | z_m-1 |
                        pos.y0 = CellPosition(this->W(5 + m), pos.start_row);          // occupies 1 cell
                        pos.y1 = CellPosition(this->W((0 * m)), pos.start_row + 1);    // occupies m-1 cells
                        pos.z0 = CellPosition(this->W(m - 1), pos.start_row + 1);      // occupies m cells
                        pos.z1 = CellPosition(this->W(m), pos.start_row + 1);
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    return pos;
                }

            public:
                uint8_t get_m() const {
                    return this->m;
                }

                static std::size_t get_witness_columns(uint8_t m) {
                    if (3 * M(m) + 5 < 15) {
                        return 3 * m + 5;
                    } else if (m >= 4 && m < 8) {
                        return std::max(m + 5, 2 * m);
                    } else if (m == 8) {
                        return 15;
                    }
                    BLUEPRINT_RELEASE_ASSERT(false);
                    return 0;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using bitwise_table = bitwise_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return bitwise_xor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m))), true);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m) {
                    return M(m) < 4 ? 1 : 2;
                }

#ifdef TEST_WITHOUT_LOOKUP_TABLES
                const static std::size_t gates_amount = 1;
#else
                const static std::size_t gates_amount = 2;
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, this->m);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x, y};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const bitwise_xor &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.z), false);
                    }

                    result_type(const bitwise_xor &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.z), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result;
                    auto table = std::shared_ptr<lookup_table_definition>(new bitwise_table());
                    result.push_back(table);
                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables[bitwise_table::XOR_TABLE_NAME] = 0;            // REQUIRED_TABLE
                    lookup_tables[bitwise_table::SMALL_RANGE_TABLE_NAME] = 0;    // REQUIRED_TABLE
                    return lookup_tables;
                }
#endif    // TEST_WITHOUT_LOOKUP_TABLES

                template<typename ContainerType>
                explicit bitwise_xor(ContainerType witness, uint8_t m) :
                    component_type(witness, {}, {}, get_manifest(m)), m(m) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bitwise_xor(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input, uint8_t m) :
                    component_type(witness, constant, public_input, get_manifest(m)),
                    m(m) {};

                bitwise_xor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs,
                            uint8_t m) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m)),
                    m(m) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_bitwise_xor =
                bitwise_xor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::var;
                using value_type = typename BlueprintFieldType::value_type;

                auto m = component.get_m();
                {
                    value_type capacity = value_type::one();
                    for (size_t i = 0; i < m; i++) {
                        capacity = capacity * value_type(1ULL << 8);
                    }
                    BLUEPRINT_RELEASE_ASSERT(capacity < BitwiseHelper<BlueprintFieldType>::P_HALF);
                }

                auto one = value_type::one();
                auto zero = value_type::zero();
                value_type n_val = BitwiseHelper<BlueprintFieldType>::get_n(m);
                assignment.constant(splat(var_pos.n)) = n_val;

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);
                assignment.witness(splat(var_pos.x)) = x_val;
                assignment.witness(splat(var_pos.y)) = y_val;

                std::vector<uint8_t> x0_val;
                std::vector<uint8_t> y0_val;
                value_type s_x_val;
                value_type s_y_val;
                value_type s_z_val;

                s_x_val = BitwiseHelper<BlueprintFieldType>::decompose_bitwise(x_val, x0_val, m);
                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= m);
                s_y_val = BitwiseHelper<BlueprintFieldType>::decompose_bitwise(y_val, y0_val, m);
                BLUEPRINT_RELEASE_ASSERT(y0_val.size() >= m);
                // s_z == (one - s_x * s_y) * (s_x + s_y) == bitwise XOR operation on 1-bit values
                s_z_val = (one - s_x_val * s_y_val) * (s_x_val + s_y_val);

                assignment.witness(splat(var_pos.s_x)) = s_x_val;
                assignment.witness(splat(var_pos.s_y)) = s_y_val;

                std::vector<uint8_t> z0_val;
                value_type z_val = s_z_val == one ? n_val : zero;
                for (size_t i = 0; i < m; i++) {
                    uint8_t result = x0_val[i] ^ y0_val[i];    // bitwise XOR operation on 8-bit limbs
                    z0_val.push_back(result);
                    z_val = z_val + value_type(result) * value_type(1ULL << (8 * i));
                }
                assignment.witness(splat(var_pos.z)) = z_val;

                assignment.witness(splat(var_pos.x0)) = x0_val[0];
                assignment.witness(splat(var_pos.y0)) = y0_val[0];
                assignment.witness(splat(var_pos.z0)) = z0_val[0];
                for (size_t i = 1; i < m; i++) {
                    assignment.witness(var_pos.x1.column() + i - 1, var_pos.x1.row()) = x0_val[i];
                    assignment.witness(var_pos.y1.column() + i - 1, var_pos.y1.row()) = y0_val[i];
                    assignment.witness(var_pos.z1.column() + i - 1, var_pos.z1.row()) = z0_val[i];
                }

                return typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                using var = typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::var;
                using value_type = typename BlueprintFieldType::value_type;
                auto m = component.get_m();
                {
                    value_type capacity = value_type::one();
                    for (size_t i = 0; i < m; i++) {
                        capacity = capacity * value_type(1ULL << 8);
                    }
                    BLUEPRINT_RELEASE_ASSERT(capacity < BitwiseHelper<BlueprintFieldType>::P_HALF);
                }

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto z = var(splat(var_pos.z));
                auto s_x = var(splat(var_pos.s_x));
                auto s_y = var(splat(var_pos.s_y));
                // s_z == (1 - s_x * s_y) * (s_x + s_y) == bitwise XOR operation on 1-bit values
                auto s_z = (1 - s_x * s_y) * (s_x + s_y);
                auto n = var(splat(var_pos.n), true, var::column_type::constant);
                auto x0 = nil::crypto3::math::expression(var(splat(var_pos.x0)));
                auto y0 = nil::crypto3::math::expression(var(splat(var_pos.y0)));
                auto z0 = nil::crypto3::math::expression(var(splat(var_pos.z0)));

                // decomposition of x, y, z
                for (size_t i = 1; i < m; i++) {
                    x0 += var(var_pos.x1.column() + i - 1, var_pos.x1.row()) * (1ULL << (8 * i));
                    y0 += var(var_pos.y1.column() + i - 1, var_pos.y1.row()) * (1ULL << (8 * i));
                    z0 += var(var_pos.z1.column() + i - 1, var_pos.z1.row()) * (1ULL << (8 * i));
                }
                constraints.push_back(n * s_x + x0 - x);
                constraints.push_back(n * s_y + y0 - y);
                constraints.push_back(n * s_z + z0 - z);
                constraints.push_back(s_x * (1 - s_x));
                constraints.push_back(s_y * (1 - s_y));

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::var;

                auto x = var(splat(var_pos.x), false);
                auto y = var(splat(var_pos.y), false);
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
            }

#ifndef TEST_WITHOUT_LOOKUP_TABLES

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using value_type = typename BlueprintFieldType::value_type;
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                using bitwise_table =
                    typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::bitwise_table;

                auto xor_table_id = lookup_tables_indices.at(bitwise_table::XOR_TABLE_NAME);

                auto small_range_table_id = lookup_tables_indices.at(bitwise_table::SMALL_RANGE_TABLE_NAME);

                std::vector<constraint_type> constraints;

                // lookup small range table for x, y
                {
                    auto x0 = var(splat(var_pos.x0));
                    constraint_type constraint;
                    constraint.table_id = small_range_table_id;
                    constraint.lookup_input = {x0};
                    constraints.push_back(constraint);
                }
                {
                    auto y0 = var(splat(var_pos.y0));
                    constraint_type constraint;
                    constraint.table_id = small_range_table_id;
                    constraint.lookup_input = {y0};
                    constraints.push_back(constraint);
                }
                for (size_t i = 1; i < m; i++) {
                    {
                        auto xi = var(var_pos.x1.column() + i - 1, var_pos.x1.row());
                        constraint_type constraint;
                        constraint.table_id = small_range_table_id;
                        constraint.lookup_input = {xi};
                        constraints.push_back(constraint);
                    }
                    {
                        auto yi = var(var_pos.y1.column() + i - 1, var_pos.y1.row());
                        constraint_type constraint;
                        constraint.table_id = small_range_table_id;
                        constraint.lookup_input = {yi};
                        constraints.push_back(constraint);
                    }
                }

                // lookup AND table for x, y, z
                {
                    auto x0 = var(splat(var_pos.x0));
                    auto y0 = var(splat(var_pos.y0));
                    auto z0 = var(splat(var_pos.z0));
                    constraint_type constraint;
                    constraint.table_id = xor_table_id;
                    constraint.lookup_input = {x0 * value_type(1ULL << 8) + y0, z0};
                    constraints.push_back(constraint);
                }
                for (size_t i = 1; i < m; i++) {
                    auto xi = var(var_pos.x1.column() + i - 1, var_pos.x1.row());
                    auto yi = var(var_pos.y1.column() + i - 1, var_pos.y1.row());
                    auto zi = var(var_pos.z1.column() + i - 1, var_pos.z1.row());
                    constraint_type constraint;
                    constraint.table_id = xor_table_id;
                    constraint.lookup_input = {xi * value_type(1ULL << 8) + yi, zi};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

#endif    // TEST_WITHOUT_LOOKUP_TABLES

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index + component.rows_amount - 1);
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bitwise_xor<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_BITWISE_XOR_HPP