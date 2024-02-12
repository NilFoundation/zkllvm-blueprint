#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SINH_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SINH_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/type.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/range.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/hyperbolic.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing x into up to three limbs and using the identities sinh(a+b) = sinh(a)cosh(b) +
            // cosh(a)sinh(b) and cosh(a+b) = cosh(a)cosh(b) + sinh(a)sinh(b) multiple times, followed by one custom
            // rescale operation. The evaluations of sinh and cosh are retrieved via pre-computed lookup tables.
            // Large evaluations of sinh and cosh are clipped to the largest and smallest possible values of the current
            // fixedpoint representation.

            /**
             * Component representing a sinh operation with input x and output y, where y = sinh(x).
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x ... field element
             * Output: y ... sinh(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_sinh;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_sinh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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
                struct var_positions {
                    CellPosition x, y, s_x, x0, s_d, d0, q0, sinh0, cosh0, cosh1;
                    int64_t start_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m1 = this->m1;
                    auto m2 = this->m2;
                    auto m = m1 + m2;
                    var_positions pos;

                    pos.start_row = start_row_index;

                    if (2 == m2) {
                        // trace layout (7 + m col(s), 2 row(s))
                        //
                        //     |                             witness                             |
                        //  r\c| 0 |  1  | 2  | .. | 1+m |  2+m  | 3 + m | 4 + m | 5 + m | 6 + m |
                        // +---+---+-----+----+----+-----+-------+-------+-------+-------+-------+
                        // | 0 | x | s_x | x0 | .. | x_m |  q_0  |  q_1  |  q_2  |  q_3  |   -   |
                        // | 1 | y | s_d | d0 | .. | d_m | sinh0 | sinh1 | sinh2 | cosh0 | cosh1 |

                        pos.x = CellPosition(this->W(0), pos.start_row);
                        pos.s_x = CellPosition(this->W(1), pos.start_row);
                        pos.x0 = CellPosition(this->W(2 + 0 * m), pos.start_row);    // occupies m cells
                        pos.q0 = CellPosition(this->W(2 + 1 * m), pos.start_row);    // occupies 4 cells

                        pos.y = CellPosition(this->W(0), pos.start_row + 1);
                        pos.s_d = CellPosition(this->W(1), pos.start_row + 1);
                        pos.d0 = CellPosition(this->W(2 + 0 * m), pos.start_row + 1);       // occupies m cells
                        pos.sinh0 = CellPosition(this->W(2 + 1 * m), pos.start_row + 1);    // occupies 3 cells
                        pos.cosh0 = CellPosition(this->W(5 + 1 * m), pos.start_row + 1);
                        pos.cosh1 = CellPosition(this->W(6 + 1 * m), pos.start_row + 1);

                    } else if (1 == m2) {
                        // trace layout (9 + 2m col(s), 1 row(s))
                        //
                        //     |                                       witness                                        |
                        //  r\c| 0 | 1 |  2  | 3  |..| 2+m  | 3+m | 4+m|..| 3+2m |4+2m| 5+2m  | 6+2m  | 7+2m  | 8+2m  |
                        // +---+---+---+-----+----+--+------+-----+----+--+------+----+-------+-------+-------+-------+
                        // | 0 | x | y | s_x | x0 |..| xm-1 | s_d | d0 |..| dm-1 | q0 | sinh0 | sinh1 | cosh0 | cosh1 |

                        pos.x = CellPosition(this->W(0), pos.start_row);
                        pos.y = CellPosition(this->W(1), pos.start_row);
                        pos.s_x = CellPosition(this->W(2), pos.start_row);
                        pos.x0 = CellPosition(this->W(3 + 0 * m), pos.start_row);    // occupies m cells
                        pos.s_d = CellPosition(this->W(3 + 1 * m), pos.start_row);
                        pos.d0 = CellPosition(this->W(4 + 1 * m), pos.start_row);    // occupies m cells
                        pos.q0 = CellPosition(this->W(4 + 2 * m), pos.start_row);
                        pos.sinh0 = CellPosition(this->W(5 + 2 * m), pos.start_row);    // occupies 2 cells
                        pos.cosh0 = CellPosition(this->W(7 + 2 * m), pos.start_row);
                        pos.cosh1 = CellPosition(this->W(8 + 2 * m), pos.start_row);
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return pos;
                }

            public:
                uint64_t get_delta() const {
                    return 1ULL << (16 * this->m2);
                }

                uint8_t get_m2() const {
                    return this->m2;
                }

                uint8_t get_m1() const {
                    return this->m1;
                }

                uint8_t get_m() const {
                    return this->m1 + this->m2;
                }

                static std::size_t get_witness_columns(uint8_t m1, uint8_t m2) {
                    return M(m2) == 1 ? 9 + 2 * (M(m1) + m2) : 7 + m1 + m2;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                void initialize_assignment(
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const std::uint32_t start_row_index) const {
                    auto num_cols = this->get_witness_columns(m1, m2);
                    auto num_rows = this->rows_amount;
                    for (std::size_t i = 0; i < num_cols; ++i) {
                        for (std::size_t j = 0; j < num_rows; ++j) {
                            assignment.witness(this->W(i), start_row_index + j) = value_type::zero();
                        }
                    }
                }

            public:
                const value_type h;
                value_type get_h() const {
                    return h;
                }

                value_type fixedpoint_max() const {
                    if (2 == get_m()) {
                        return value_type(4294967295ULL);    // 2^32 - 1
                    } else if (3 == get_m()) {
                        return value_type(281474976710655ULL);    // 2^48 - 1
                    } else if (4 == get_m()) {
                        return value_type(18446744073709551615ULL);    // 2^64 - 1
                    }
                    BLUEPRINT_RELEASE_ASSERT(false);
                    return value_type(0);
                }

            private:
                static value_type get_h(uint8_t m1, uint8_t m2) {
                    if (1 == m1) {
                        return 1 == m2 ? value_type(772243ULL) : value_type(50609756021ULL);
                    } else if (2 == m1) {
                        return 1 == m2 ? value_type(1499061ULL) : value_type(98242467570ULL);
                    }
                    BLUEPRINT_RELEASE_ASSERT(false);
                    return value_type(0);
                }

            public:
                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_sinh::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1, uint8_t m2 = 0) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m1, m2))),
                        false);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    return static_cast<std::size_t>(m2);
                }

#ifdef TEST_WITHOUT_LOOKUP_TABLES
                constexpr static const std::size_t gates_amount = 1;
#else
                constexpr static const std::size_t gates_amount = 2;
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, this->m1, this->m2);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_sinh &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_sinh &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {
                        std::shared_ptr<lookup_table_definition>(new range_table())};

                    if (m2 == 1) {
                        auto table = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_hyperb_16_table<BlueprintFieldType>());
                        result.push_back(table);
                    } else if (m2 == 2) {
                        auto table = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_hyperb_32_table<BlueprintFieldType>());
                        result.push_back(table);
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables[range_table::FULL_TABLE_NAME] = 0;    // REQUIRED_TABLE

                    if (m2 == 1) {
                        lookup_tables[fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_SINH_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_SINH_B] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_COSH_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_COSH_B] =
                            0;    // REQUIRED_TABLE
                    } else if (m2 == 2) {
                        lookup_tables[fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_SINH_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_SINH_B] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_SINH_C] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_COSH_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_COSH_B] =
                            0;    // REQUIRED_TABLE
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    return lookup_tables;
                }
#endif    // TEST_WITHOUT_LOOKUP_TABLES

                template<typename ContainerType>
                explicit fix_sinh(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)), h(get_h(m1, m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_sinh(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), h(get_h(m1, m2)) {};

                fix_sinh(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), h(get_h(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_sinh =
                fix_sinh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                component.initialize_assignment(assignment, start_row_index);

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using value_type = typename BlueprintFieldType::value_type;

                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto one = value_type::one();
                auto zero = value_type::zero();
                auto delta = value_type(component.get_delta());

                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(splat(var_pos.x)) = x_val;

                std::vector<uint16_t> x0_val;
                value_type s_x_val, s_d_val;
                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(x_val, x0_val);
                s_x_val = sign ? -one : one;

                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= (m2 + 1));
                assignment.witness(splat(var_pos.s_x)) = s_x_val;
                for (size_t i = 0; i < m; i++) {
                    assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                }

                {
                    auto x_abs = x_val;
                    FixedPointHelper<BlueprintFieldType>::abs(x_abs);
                    const auto h_val = component.get_h();
                    std::vector<uint16_t> d0_val;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(h_val - x_abs, d0_val);
                    s_d_val = sign ? one : zero;    // if sign of d == one --> out of range [-h, h].
                    assignment.witness(splat(var_pos.s_d)) = s_d_val;
                    BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m);
                    for (auto i = 0; i < m; i++) {
                        assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = d0_val[i];
                    }
                }

                auto sinh_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_sinh_a_16() :
                                              FixedPointTables<BlueprintFieldType>::get_sinh_a_32();
                auto sinh_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_sinh_b_16() :
                                              FixedPointTables<BlueprintFieldType>::get_sinh_b_32();
                auto cosh_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_cosh_a_16() :
                                              FixedPointTables<BlueprintFieldType>::get_cosh_a_32();
                auto cosh_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_cosh_b_16() :
                                              FixedPointTables<BlueprintFieldType>::get_cosh_b_32();
                auto sinh_c_table = FixedPointTables<BlueprintFieldType>::get_sinh_c_32();

                // x0 .. smallest limb, x1 .. 2nd smallest limb, x2 .. 3rd smallest limb (2 or 3 limbs in total)
                // sinh0 holds the looked-up value of the one and only pre-comma limb, so sinh(a) = sinh0 where a is the
                // largest limb of the input. a = x0_val[m2], ..
                auto sinh0_val = sinh_a_table[x0_val[m2 - 0]];                     // 0 .. a
                auto sinh1_val = sinh_b_table[x0_val[m2 - 1]];                     // 1 .. b
                auto sinh2_val = m2 == 1 ? zero : sinh_c_table[x0_val[m2 - 2]];    // 2 .. c
                auto cosh0_val = cosh_a_table[x0_val[m2 - 0]];                     // 0 .. a
                auto cosh1_val = cosh_b_table[x0_val[m2 - 1]];                     // 1 .. b
                auto cosh2_val = delta;                                            // 2 .. c

                assignment.witness(splat(var_pos.sinh0)) = sinh0_val;
                assignment.witness(var_pos.sinh0.column() + 1, var_pos.sinh0.row()) = sinh1_val;
                if (m2 == 2) {
                    assignment.witness(var_pos.sinh0.column() + 2, var_pos.sinh0.row()) = sinh2_val;
                }
                assignment.witness(splat(var_pos.cosh0)) = cosh0_val;
                assignment.witness(splat(var_pos.cosh1)) = cosh1_val;

                if (s_d_val == one) {
                    assignment.witness(splat(var_pos.y)) = s_x_val * component.fixedpoint_max();
                    return typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
                }

                // sinh(-a)    = -sinh(a)
                // sinh(a+b)   = sinh(a)cosh(b) + cosh(a)sinh(b)
                // sinh(a+b+c) = sinh(a+b)cosh(c) + cosh(a+b)sinh(c)
                //            = cosh(c) * (sinh(a)cosh(b) + cosh(a)sinh(b))
                //            + sinh(c) * (cosh(a)cosh(b) + sinh(a)sinh(b))
                // sinh(a) .. sinh0, sinh(b) .. sinh1, sinh(c) .. sinh2
                // cosh(a) .. cosh0, cosh(b) .. cosh1, cosh(c) .. cosh2
                value_type computation = m2 == 1 ?
                                             s_x_val * (sinh0_val * cosh1_val + cosh0_val * sinh1_val) :
                                             s_x_val * (cosh2_val * (sinh0_val * cosh1_val + cosh0_val * sinh1_val) +
                                                        sinh2_val * (cosh0_val * cosh1_val + sinh0_val * sinh1_val));

                auto actual_delta = m2 == 1 ? delta : delta * delta;

                auto tmp = FixedPointHelper<BlueprintFieldType>::round_div_mod(computation, actual_delta);
                auto y_val = tmp.quotient;
                auto q_val = tmp.remainder;

                assignment.witness(splat(var_pos.y)) = y_val;

                if (m2 == 1) {
                    assignment.witness(splat(var_pos.q0)) = q_val;
                } else {    // m2 == 2
                    std::vector<uint16_t> q0_val;
                    bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(q_val, q0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign_);
                    BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= (4));
                    for (size_t i = 0; i < 4; i++) {
                        assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                    }
                }

                return typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                using var = typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::var;
                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto delta = typename BlueprintFieldType::value_type(component.get_delta());
                auto h = component.get_h();
                auto max = component.fixedpoint_max();
                auto x = var(splat(var_pos.x));
                auto s_x = var(splat(var_pos.s_x));
                auto s_d = var(splat(var_pos.s_d));
                auto x0 = nil::crypto3::math::expression<var>(var(splat(var_pos.x0)));
                auto d = nil::crypto3::math::expression<var>(var(splat(var_pos.d0)));

                // decomposition of x
                for (size_t i = 1; i < m; i++) {
                    x0 += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                    d += var(var_pos.d0.column() + i, var_pos.d0.row()) * (1ULL << (16 * i));
                }

                // decomposition constraints for x, d
                auto constraint_1 = x - s_x * x0;
                auto constraint_2 = (h - x0) + s_d * d - (1 - s_d) * d;

                // sign of x and d
                auto constraint_3 = (s_x - 1) * (s_x + 1);
                auto constraint_4 = s_d * (1 - s_d);

                auto y = var(splat(var_pos.y));
                auto sinh0 = var(splat(var_pos.sinh0));                               // 0 .. a
                auto sinh1 = var(var_pos.sinh0.column() + 1, var_pos.sinh0.row());    // 1 .. b
                auto cosh0 = var(splat(var_pos.cosh0));                               // 0 .. a
                auto cosh1 = var(splat(var_pos.cosh1));                               // 1 .. b
                auto sinh2 = var(var_pos.sinh0.column() + 2, var_pos.sinh0.row());    // 2 .. c
                auto cosh2 = delta;                                                   // 2 .. c
                auto q = nil::crypto3::math::expression<var>(var(splat(var_pos.q0)));
                for (size_t i = 1; i < m2 * m2; i++) {
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                }

                // sinh(a) .. sinh0, sinh(b) .. sinh1, sinh(c) .. sinh2
                // cosh(a) .. cosh0, cosh(b) .. cosh1, cosh(c) .. cosh2
                auto computation =
                    m2 == 1 ? s_x * (sinh0 * cosh1 + cosh0 * sinh1) :
                              s_x * (cosh2 * (sinh0 * cosh1 + cosh0 * sinh1) + sinh2 * (cosh0 * cosh1 + sinh0 * sinh1));
                auto actual_delta = m2 == 1 ? delta : delta * delta;

                // "custom" rescale
                auto constraint_5 = (1 - s_d) * (2 * (computation - y * actual_delta - q) + actual_delta);
                auto constraint_6 = s_d * (y - s_x * max);

                return {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::var;

                auto x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m2 = component.get_m2();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::range_table;

                auto range_table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);
                auto sinh_a_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_SINH_A) :
                              lookup_tables_indices.at(fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_SINH_A);
                auto sinh_b_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_SINH_B) :
                              lookup_tables_indices.at(fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_SINH_B);
                auto cosh_a_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_COSH_A) :
                              lookup_tables_indices.at(fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_COSH_A);
                auto cosh_b_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_hyperb_16_table<BlueprintFieldType>::FULL_COSH_B) :
                              lookup_tables_indices.at(fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_COSH_B);

                std::vector<constraint_type> constraints;

                // lookup decomposition of q
                for (size_t i = 0; i < m2 * m2; i++) {
                    constraint_type constraint;
                    constraint.table_id = range_table_id;
                    auto qi = var(var_pos.q0.column() + i, var_pos.q0.row());
                    constraint.lookup_input = {qi};
                    constraints.push_back(constraint);
                }

                // lookup sinh, cosh
                // x0 .. smallest limb, x1 .. 2nd smallest limb, x2 .. 3rd smallest limb (2 or 3 limbs in total)
                // sinh0 holds the looked-up value of the one and only pre-comma limb, so sinh(a) = sinh0 where a is the
                // largest limb of the input. a = x0_val[m2], ..
                auto x0 = var(var_pos.x0.column() + m2 - 0, var_pos.x0.row());
                auto x1 = var(var_pos.x0.column() + m2 - 1, var_pos.x0.row());
                auto x2 = var(var_pos.x0.column() + m2 - 2, var_pos.x0.row());    // invalid if m2 == 1
                auto sinh0 = var(var_pos.sinh0.column() + 0, var_pos.sinh0.row());
                auto sinh1 = var(var_pos.sinh0.column() + 1, var_pos.sinh0.row());
                auto sinh2 = var(var_pos.sinh0.column() + 2, var_pos.sinh0.row());    // invalid if m2 == 1
                {
                    constraint_type constraint;
                    constraint.table_id = sinh_a_table_id;
                    constraint.lookup_input = {x0, sinh0};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = cosh_a_table_id;
                    constraint.lookup_input = {x0, var(splat(var_pos.cosh0))};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = sinh_b_table_id;
                    constraint.lookup_input = {x1, sinh1};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = cosh_b_table_id;
                    constraint.lookup_input = {x1, var(splat(var_pos.cosh1))};
                    constraints.push_back(constraint);
                }
                if (m2 == 2) {
                    constraint_type constraint;
                    auto sinh_c_table_id =
                        lookup_tables_indices.at(fixedpoint_hyperb_32_table<BlueprintFieldType>::FULL_SINH_C);
                    constraint.table_id = sinh_c_table_id;
                    constraint.lookup_input = {x2, sinh2};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index + component.rows_amount - 1);
#endif
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_sinh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SINH_HPP
