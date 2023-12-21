#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_HPP

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

            // Works by decomposing the difference of the input and the ranges.

            /**
             * Component representing a range check for the input x and the constants x_lo and x_hi. The outputs are
             * flags that are 1 if their condition is true and 0 otherwise.
             *
             * The user needs to ensure that the deltas of x, x_lo, and x_hi match (the scale must be the same).
             *
             * Input:    x    ... field element
             * Output:   lt   ... x < x_lo ? 1 : 0 (field element)
             *           in   ... x_lo <= x <= x_hi ? 1 : 0 (field element)
             *           gt   ... x_hi < x ? 1 : 0 (field element)
             * Constant: x_lo ... field element
             *           x_hi ... field element
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_range;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {
            public:
                using value_type = typename BlueprintFieldType::value_type;

            private:
                uint8_t m1;    // Pre-comma 16-bit limbs
                uint8_t m2;    // Post-comma 16-bit limbs

                value_type x_lo;
                value_type x_hi;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                static void check_range(const value_type &low, const value_type &high) {
                    // check low <= high
                    auto low_abs = low;
                    auto high_abs = high;
                    bool sign_low = FixedPointHelper<BlueprintFieldType>::abs(low_abs);
                    bool sign_high = FixedPointHelper<BlueprintFieldType>::abs(high_abs);
                    bool greater = (!sign_low && sign_high) || (sign_low && sign_high && (low_abs < high_abs)) ||
                                   (!sign_low && !sign_high && (low_abs > high_abs));
                    BLUEPRINT_RELEASE_ASSERT(!greater);
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

                value_type get_x_lo() const {
                    return x_lo;
                }

                value_type get_x_hi() const {
                    return x_hi;
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return get_rows_amount(witness_amount, 0, M(m1), M(m2)) == 1 ? 10 + 2 * (m1 + m2 + 1) : 10;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_range::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(10, 10 + 2 * (m2 + m1 + 1))), false);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    if (10 + 2 * (M(m2) + M(m1) + 1) <= witness_amount) {
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
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, in, lt, gt, z_a, z_b, inv_a, inv_b, s_a, s_b, a0, b0, x_l, x_h;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    var_positions pos;
                    switch (this->rows_amount) {
                        case 1:

                            // trace layout witness (10 + 2*(m+1) col(s), 1 row(s))
                            // requiring an extra limb because of potential overflows during decomposition of
                            // differences
                            //
                            //     |                                    witness                     10+     10+     |
                            //  r\c| 0 | 1 | 2 | 3 | 4  | 5  | 6    | 7    | 8  | 9  | 10 |..|10+m| m+1|..| 2(m+1)-1|
                            // +---+---+---+---+---+----+----+------+------+----+----+----+--+----+----+--+---------+
                            // | 0 | x | in| lt| gt| z_a| z_b| inv_a| inv_b| s_a| s_b| a0 |..| am | b0 |..| bm      |

                            pos.x = CellPosition(this->W(0), start_row_index);
                            pos.in = CellPosition(this->W(1), start_row_index);
                            pos.lt = CellPosition(this->W(2), start_row_index);
                            pos.gt = CellPosition(this->W(3), start_row_index);
                            pos.z_a = CellPosition(this->W(4), start_row_index);
                            pos.z_b = CellPosition(this->W(5), start_row_index);
                            pos.inv_a = CellPosition(this->W(6), start_row_index);
                            pos.inv_b = CellPosition(this->W(7), start_row_index);
                            pos.s_a = CellPosition(this->W(8), start_row_index);
                            pos.s_b = CellPosition(this->W(9), start_row_index);
                            pos.a0 = CellPosition(this->W(10 + 0 * (m + 1)), start_row_index);
                            pos.b0 = CellPosition(this->W(10 + 1 * (m + 1)), start_row_index);

                            // trace layout constant (2 col(s), 1 row(s))
                            //
                            //     | constant  |
                            //  r\c|  0  |  1  |
                            // +---+-----+-----+
                            // | 0 | x_l | x_h |

                            pos.x_l = CellPosition(this->C(0), start_row_index);
                            pos.x_h = CellPosition(this->C(1), start_row_index);
                            break;
                        case 2:

                            // trace layout witness (10 col(s), 2 row(s)), constant (2 col(s), 1 row(s))
                            // (recall that 2 <= m <= 4)
                            // requiring an extra limb because of potential overflows during decomposition of
                            // differences
                            //
                            //     |              witness               |
                            //  r\c| 0  | .. | m  | m+1 | .. | 2(m+1)-1 |
                            // +---+----+----+----+-----+----+----------+
                            // | 0 | a0 | .. | am | b0  | .. | bm       |

                            pos.a0 = CellPosition(this->W(0 + 0 * (m + 1)), start_row_index);
                            pos.b0 = CellPosition(this->W(0 + 1 * (m + 1)), start_row_index);

                            //     |                         witness                          | constant  |
                            //  r\c| 0 | 1  | 2  | 3  | 4   | 5   | 6     | 7     | 8   | 9   |  0  |  1  |
                            // +---+---+----+----+----+-----+-----+-------+-------+-----+-----+-----+-----+
                            // | 1 | x | in | lt | gt | z_a | z_b | inv_a | inv_b | s_a | s_b | x_l | x_h |

                            pos.x = CellPosition(this->W(0), start_row_index + 1);
                            pos.in = CellPosition(this->W(1), start_row_index + 1);
                            pos.lt = CellPosition(this->W(2), start_row_index + 1);
                            pos.gt = CellPosition(this->W(3), start_row_index + 1);
                            pos.z_a = CellPosition(this->W(4), start_row_index + 1);
                            pos.z_b = CellPosition(this->W(5), start_row_index + 1);
                            pos.inv_a = CellPosition(this->W(6), start_row_index + 1);
                            pos.inv_b = CellPosition(this->W(7), start_row_index + 1);
                            pos.s_a = CellPosition(this->W(8), start_row_index + 1);
                            pos.s_b = CellPosition(this->W(9), start_row_index + 1);
                            pos.x_l = CellPosition(this->C(0), start_row_index + 1);
                            pos.x_h = CellPosition(this->C(1), start_row_index + 1);
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "rows_amount must be 1 or 2");
                    }
                    return pos;
                }
                struct result_type {
                    var in = var(0, 0, false);
                    var lt = var(0, 0, false);
                    var gt = var(0, 0, false);

                    result_type(const fix_range &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        in = var(splat(var_pos.in), false);
                        lt = var(splat(var_pos.lt), false);
                        gt = var(splat(var_pos.gt), false);
                    }

                    result_type(const fix_range &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        in = var(splat(var_pos.in), false);
                        lt = var(splat(var_pos.lt), false);
                        gt = var(splat(var_pos.gt), false);
                    }

                    std::vector<var> all_vars() const {
                        return {in, lt, gt};
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
                fix_range(WitnessContainerType witness, ConstantContainerType constant,
                          PublicInputContainerType public_input, uint8_t m1, uint8_t m2, const value_type &low,
                          const value_type &high) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), x_lo(low), x_hi(high) {
                    check_range(low, high);
                };

                fix_range(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                              public_inputs,
                          uint8_t m1, uint8_t m2, const value_type &low, const value_type &high) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), x_lo(low), x_hi(high) {
                    check_range(low, high);
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_range =
                fix_range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto one = BlueprintFieldType::value_type::one();
                const auto zero = BlueprintFieldType::value_type::zero();
                auto m = component.get_m();

                auto x_val = var_value(assignment, instance_input.x);

                assignment.witness(splat(var_pos.x)) = x_val;

                auto a_val = x_val - component.get_x_lo();
                auto b_val = component.get_x_hi() - x_val;

                std::vector<uint16_t> a0_val;
                std::vector<uint16_t> b0_val;

                bool sign_a = FixedPointHelper<BlueprintFieldType>::abs(a_val);
                bool sign_b = FixedPointHelper<BlueprintFieldType>::abs(b_val);
                bool sign_a_ = FixedPointHelper<BlueprintFieldType>::decompose(a_val, a0_val);
                bool sign_b_ = FixedPointHelper<BlueprintFieldType>::decompose(b_val, b0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_a_);
                BLUEPRINT_RELEASE_ASSERT(!sign_b_);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(b0_val.size() >= m);

                assignment.witness(splat(var_pos.in)) = (!sign_a && !sign_b) ? one : zero;
                assignment.witness(splat(var_pos.lt)) = sign_a ? one : zero;
                assignment.witness(splat(var_pos.gt)) = sign_b ? one : zero;
                BLUEPRINT_RELEASE_ASSERT(!sign_a || !sign_b);

                bool eq_a = a_val == 0;
                bool eq_b = b_val == 0;
                assignment.witness(splat(var_pos.z_a)) = eq_a ? one : zero;
                assignment.witness(splat(var_pos.z_b)) = eq_b ? one : zero;

                // if eq: Does not matter what to put here
                assignment.witness(splat(var_pos.inv_a)) = eq_a ? zero : a_val.inversed();
                assignment.witness(splat(var_pos.inv_b)) = eq_b ? zero : b_val.inversed();

                assignment.witness(splat(var_pos.s_a)) = sign_a ? -one : one;
                assignment.witness(splat(var_pos.s_b)) = sign_b ? -one : one;

                // Additional limb due to potential overflow of diff
                // FixedPointHelper::decompose creates a vector whose size is a multiple of 4.
                // Furthermore, the size of the vector might be larger than required (e.g. if 4 limbs would suffice the
                // vectour could be of size 8)
                if (a0_val.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(a0_val[m] == 0 || a0_val[m] == 1);
                    assignment.witness(var_pos.a0.column() + m, var_pos.a0.row()) = a0_val[m];
                } else {
                    assignment.witness(var_pos.a0.column() + m, var_pos.a0.row()) = 0;
                }
                if (b0_val.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(b0_val[m] == 0 || b0_val[m] == 1);
                    assignment.witness(var_pos.b0.column() + m, var_pos.b0.row()) = b0_val[m];
                } else {
                    assignment.witness(var_pos.b0.column() + m, var_pos.b0.row()) = 0;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                    assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = b0_val[i];
                }

                return typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int first_row = 1 - static_cast<int>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(first_row));

                using var = typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::var;

                auto m = component.get_m();

                auto a0 = nil::crypto3::math::expression(var(splat(var_pos.a0)));
                auto b0 = nil::crypto3::math::expression(var(splat(var_pos.b0)));
                for (auto i = 1; i < m; i++) {
                    a0 += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                    b0 += var(var_pos.b0.column() + i, var_pos.b0.row()) * (1ULL << (16 * i));
                }
                typename BlueprintFieldType::value_type tmp =
                    1ULL << (16 * (m - 1));    // 1ULL << 16m could overflow 64-bit int
                tmp *= 1ULL << 16;
                a0 += var(var_pos.a0.column() + m, var_pos.a0.row()) * tmp;
                b0 += var(var_pos.b0.column() + m, var_pos.b0.row()) * tmp;

                auto x = var(splat(var_pos.x));
                auto in = var(splat(var_pos.in));
                auto lt = var(splat(var_pos.lt));
                auto gt = var(splat(var_pos.gt));
                auto z_a = var(splat(var_pos.z_a));
                auto z_b = var(splat(var_pos.z_b));
                auto inv_a = var(splat(var_pos.inv_a));
                auto inv_b = var(splat(var_pos.inv_b));
                auto s_a = var(splat(var_pos.s_a));
                auto s_b = var(splat(var_pos.s_b));
                auto x_l = var(splat(var_pos.x_l), true, var::column_type::constant);
                auto x_h = var(splat(var_pos.x_h), true, var::column_type::constant);

                auto inv2 = typename BlueprintFieldType::value_type(2).inversed();

                auto constraint_1 = x - x_l - s_a * a0;
                auto constraint_2 = x_h - x - s_b * b0;
                auto constraint_3 = (s_a - 1) * (s_a + 1);
                auto constraint_4 = (s_b - 1) * (s_b + 1);
                auto constraint_5 = z_a * a0;
                auto constraint_6 = z_b * b0;
                auto constraint_7 = 1 - z_a - inv_a * a0;
                auto constraint_8 = 1 - z_b - inv_b * b0;
                auto constraint_9 = lt - inv2 * (1 - s_a) * (1 - z_a);
                auto constraint_10 = gt - inv2 * (1 - s_b) * (1 - z_b);
                auto constraint_11 = in - (1 - lt) * (1 - gt);

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                    constraint_7, constraint_8, constraint_9, constraint_10, constraint_11});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m_ = component.get_m() + 1;

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(2 * m_);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);
                BLUEPRINT_RELEASE_ASSERT(var_pos.a0.row() == var_pos.b0.row());

                for (auto i = 0; i < m_; i++) {
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
                const plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::var;
                var x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, var_pos.a0.row());    // same as b0.row()
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                assignment.constant(splat(var_pos.x_l)) = component.get_x_lo();
                assignment.constant(splat(var_pos.x_h)) = component.get_x_hi();
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_HPP
