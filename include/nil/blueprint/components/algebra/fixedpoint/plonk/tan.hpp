#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TAN_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TAN_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/rem.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/trigonometric.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing x into up to three limbs and using the identities sin(a+b) = sin(a)cos(b) +
            // cos(a)sin(b) and cos(a+b) = cos(a)cos(b) - sin(a)sin(b) multiple times, followed by a custom rescale
            // and division operation. The evaluations of sin and cos are retrieved via pre-computed lookup tables.
            // In case m1 >= 2, a rem operation (mod 2*pi) brings x into a range where one pre-comma limb is sufficient
            // for computing tan(x).

            /**
             * Component representing a tan operation with input x and output y, where y = tan(x).
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x ... field element
             * Output: y ... tan(x) (field element)
             * Constant: two_pi ... 2*pi (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_tan;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_tan<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using rem_component =
                    fix_rem<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                uint8_t m1;    // Pre-comma 16-bit limbs
                uint8_t m2;    // Post-comma 16-bit limbs
                rem_component rem;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                static std::size_t gates_amount_internal(uint8_t m1, uint8_t m2) {
#ifdef TEST_WITHOUT_LOOKUP_TABLES
                    return m2 == 2 ? 2 : 1;
#else
                    return m2 == 2 ? 4 : 2;
#endif
                }

            public:
                struct var_positions {
                    CellPosition x, s_x, x0, q0, a0, y0, b0, c, sin0, cos0, cos1, two_pi, sin, cos, tan, s_y;
                    typename rem_component::var_positions rem_pos;
                    int64_t start_row, rem_row, tan_row, div_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m1 = this->m1;
                    auto m2 = this->m2;
                    var_positions pos;

                    pos.start_row = start_row_index;
                    pos.rem_row = pos.start_row;
                    pos.tan_row = pos.rem_row;

                    if (m1 == 2) {
                        pos.tan_row += rem.rows_amount;
                        pos.rem_pos = rem.get_var_pos(pos.rem_row);
                        pos.two_pi = CellPosition(this->C(0), pos.tan_row);
                    }
                    pos.div_row = pos.tan_row + 1;

                    // trace layout constant (1 col(s), 1 row(s))
                    //
                    //     | constant |
                    //  r\c|    0     |
                    // +---+----------+
                    // |tan|  two_pi  |

                    if (m2 == 1) {
                        // trace layout witness (10 col(s), 3 + rem_rows row(s))
                        //                      (2 if m1=1, 4 if m1=2 row(s))
                        //
                        // rem does not exist, or has two rows (m1 must be 2 for rem to exist)
                        // sin and cos are sin(x) * delta and cos(x) * delta respectively, the division eliminates the
                        // delta.
                        //
                        // This design uses the concepts from the components sin, cos, and div, where the component rem
                        // and the vars x, s_x, x0, x1, sin0, sin1, cos0, cos1, sin, cos belong to the components sin
                        // and cos, and the vars c, q0, q1, a0, a1, s_y, y0, y1 belong to the component div. Note that y
                        // is the divisor which is cos. Recall that sin and cos are not rescaled.
                        //
                        // y == cos might be 1 or -1, in the representation of times delta, making it consume three
                        // limbs --> therefore y0, y1, y2.
                        //
                        //       |                          witness                           |
                        //   r\c |  0  |  1  |  2  | 3  |  4   |  5   |  6   |  7   | 8  | 9  |
                        // +-----+-----+-----+-----+----+------+------+------+------+----+----+
                        // | rem |                       <rem_witness>                        |
                        // | tan |  x  | s_x | x0  | x1 | sin0 | sin1 | cos0 | cos1 | c  | s_y|
                        // | div | sin | cos | tan | q0 |  q1  |  a0  |  a1  |  y0  | y1 | y2 |

                        pos.x = CellPosition(this->W(0), pos.tan_row);
                        pos.s_x = CellPosition(this->W(1), pos.tan_row);
                        pos.x0 = CellPosition(this->W(2), pos.tan_row);      // occupies 2 cells
                        pos.sin0 = CellPosition(this->W(4), pos.tan_row);    // occupies 2 cells
                        pos.cos0 = CellPosition(this->W(6), pos.tan_row);
                        pos.cos1 = CellPosition(this->W(7), pos.tan_row);
                        pos.c = CellPosition(this->W(8), pos.tan_row);
                        pos.s_y = CellPosition(this->W(9), pos.tan_row);

                        pos.sin = CellPosition(this->W(0), pos.div_row);
                        pos.cos = CellPosition(this->W(1), pos.div_row);
                        pos.tan = CellPosition(this->W(2), pos.div_row);
                        pos.q0 = CellPosition(this->W(3), pos.div_row);    // occupies 2 cells
                        pos.a0 = CellPosition(this->W(5), pos.div_row);    // occupies 2 cells
                        pos.y0 = CellPosition(this->W(7), pos.div_row);    // occupies 3 cells
                    } else if (m2 == 2) {
                        // trace layout witness (10 or 11 col(s), 3 + rem_rows row(s))
                        //                      (10 if m1=1, 11 if m1=2 col(s))
                        //                      (3 if m1=1, 5 if m1=2 row(s))
                        //
                        // rem does not exist, or has two rows (m1 must be 2 for rem to exist) and 11 cols
                        // sin is sin(x) * delta^3, cos is cos(x) * delta^2, the custom division eliminates the deltas
                        // and doesn't take the denominator times delta.
                        //
                        // This design uses the concepts from the components sin, cos, and div, where the component rem
                        // and the vars x, s_x, x0, x1, x2, sin0, sin1, sin2, cos0, cos1, sin, cos belong to the
                        // components sin and cos, and the vars c, q0, q1, q2, q3, a0, a1, a2, a3, s_y, y0, y1, y2, y3,
                        // y4 belong to the component div. Note that y is the divisor which is cos. sin is not rescaled,
                        // while cos is rescaled by delta, where b0 and b1 serve as the remainder for the proof.
                        //
                        // y == cos might be 1 or -1, in the representation of times delta^2, making it consume five
                        // limbs --> therefore y0, y1, y2, y3, y4.
                        //
                        //        |                            witness                            |
                        //    r\c |  0  |  1  |  2  | 3  |  4  |  5   |  6   |  7   |  8   |  9   |
                        // +------+-----+-----+-----+----+-----+------+------+------+------+------+
                        // | rem  |                         <rem_witness>                         |
                        // | tan  |  x  | s_x | x0  | x1 | x2  | sin0 | sin1 | sin2 | cos0 | cos1 |
                        // | div0 | sin | cos | b0  | b1 |  c  | s_y  |  a0  |  a1  |  a2  |  a3  |
                        // | div1 | tan | y0  | y1  | y2 | y3  |  y4  |  q0  |  q1  |  q2  |  q3  |

                        pos.x = CellPosition(this->W(0), pos.tan_row);
                        pos.s_x = CellPosition(this->W(1), pos.tan_row);
                        pos.x0 = CellPosition(this->W(2), pos.tan_row);      // occupies 3 cells
                        pos.sin0 = CellPosition(this->W(5), pos.tan_row);    // occupies 3 cells
                        pos.cos0 = CellPosition(this->W(8), pos.tan_row);
                        pos.cos1 = CellPosition(this->W(9), pos.tan_row);

                        pos.sin = CellPosition(this->W(0), pos.div_row);
                        pos.cos = CellPosition(this->W(1), pos.div_row);
                        pos.b0 = CellPosition(this->W(2), pos.div_row);    // occupies 2 cells
                        pos.c = CellPosition(this->W(4), pos.div_row);
                        pos.s_y = CellPosition(this->W(5), pos.div_row);
                        pos.a0 = CellPosition(this->W(6), pos.div_row);    // occupies 4 cells

                        pos.tan = CellPosition(this->W(0), pos.div_row + 1);
                        pos.y0 = CellPosition(this->W(1), pos.div_row + 1);    // occupies 5 cells
                        pos.q0 = CellPosition(this->W(6), pos.div_row + 1);    // occupies 4 cells
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false && "m2 must be 1 or 2");
                    }

                    return pos;
                }

            private:
                rem_component instantiate_rem() const {
                    auto m1 = this->m1;
                    auto m2 = this->m2;
                    value_type scaler = 1;
                    if (is_32_16()) {
                        scaler = value_type(1ULL << 16);
                    }
                    std::vector<std::uint32_t> witness_list;
                    std::size_t witness_columns;
                    if (m1 == 1) {
                        witness_columns = rem_component::get_witness_columns(this->witness_amount(), m1, 1);
                    } else {
                        witness_columns = rem_component::get_witness_columns(this->witness_amount(), m1, 2);
                    }
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    std::vector<std::uint32_t> constant_list = {this->C(0)};
                    // if m1=1: a rem_component is constructed but never used.
                    return rem_component(witness_list, constant_list, std::array<std::uint32_t, 0>(), m1, 2, scaler);
                }

            public:
                const rem_component &get_rem_component() const {
                    return rem;
                }

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
                    if (m1 == 2 && m2 == 2) {
                        return 11;
                    }
                    return 10;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                value_type two_pi;

                class gate_manifest_type : public component_gate_manifest {
                    // variable gates amount computation inspired by
                    // include/nil/blueprint/components/algebra/fields/plonk/non_native/comparison_checked.hpp
                public:
                    uint8_t m1;
                    uint8_t m2;

                    gate_manifest_type(uint8_t m1, uint8_t m2) : m1(m1), m2(m2) {
                    }

                    std::uint32_t gates_amount() const override {
                        return fix_tan::gates_amount_internal(this->m1, this->m2);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1, uint8_t m2) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(m1, m2));
                    if (m1 == 2) {
                        manifest.merge_with(
                            rem_component::get_gate_manifest(witness_amount, lookup_column_amount, 2, 2));
                    }
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m1, m2))),
                        true);
                    if (m1 == 2) {
                        manifest.merge_with(rem_component::get_manifest(2, 2));
                    }
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    size_t rows_amount = M(m2) == 2 ? 3 : 2;
                    if (M(m1) == 2) {
                        rows_amount +=
                            rem_component::get_rows_amount(get_witness_columns(m1, m2), lookup_column_amount, m1, 2);
                    }
                    return rows_amount;
                }

                constexpr static value_type get_two_pi() {
                    return value_type(26986075409ULL);
                }

                /**
                 * Returns true if the component uses the 32.16 fixed point data type.
                 */
                bool is_32_16() const {
                    return this->m1 == 2 && this->m2 == 1;
                }

                const std::size_t gates_amount = gates_amount_internal(this->m1, this->m2);
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, this->m1, this->m2);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_tan &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.tan), false);
                    }

                    result_type(const fix_tan &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.tan), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                result_type get_result(std::uint32_t start_row_index) const {
                    return result_type(*this, static_cast<size_t>(start_row_index));
                }

                result_type get_result(std::size_t start_row_index) const {
                    return result_type(*this, static_cast<size_t>(start_row_index));
                }

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = rem.component_custom_lookup_tables();

                    if (m2 == 1) {
                        auto table = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_trigon_16_table<BlueprintFieldType>());
                        result.push_back(table);
                    } else if (m2 == 2) {
                        auto table = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_trigon_32_table<BlueprintFieldType>());
                        result.push_back(table);
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables = rem.component_lookup_tables();

                    if (m2 == 1) {
                        lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_SIN_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_SIN_B] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_COS_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_COS_B] =
                            0;    // REQUIRED_TABLE
                    } else if (m2 == 2) {
                        lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_B] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_C] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_COS_A] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_COS_B] =
                            0;    // REQUIRED_TABLE
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    return lookup_tables;
                }
#endif    // TEST_WITHOUT_LOOKUP_TABLES

                template<typename ContainerType>
                explicit fix_tan(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)), rem(instantiate_rem()),
                    two_pi(get_two_pi()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_tan(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), rem(instantiate_rem()), two_pi(get_two_pi()) {};

                fix_tan(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), rem(instantiate_rem()), two_pi(get_two_pi()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_tan =
                fix_tan<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;
                using value_type = typename BlueprintFieldType::value_type;

                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto one = value_type::one();
                auto zero = value_type::zero();
                auto delta = value_type(component.get_delta());

                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(splat(var_pos.x)) = x_val;

                std::vector<uint16_t> x0_val;
                value_type s_x_val;
                // if two pre-comma limbs are used, x is reduced mod 2*pi
                if (m1 == 2) {
                    assignment.constant(splat(var_pos.two_pi)) = component.two_pi;
                    auto rem_component = component.get_rem_component();
                    typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::rem_component::input_type
                        rem_input;
                    rem_input.x = var(splat(var_pos.x), false);
                    rem_input.y = var(splat(var_pos.two_pi), false, var::column_type::constant);
                    generate_assignments(rem_component, assignment, rem_input, var_pos.rem_row);
                    int64_t z_offset = m2 == 1 ? 1 : 0;
                    for (int64_t i = 0; i < m2 + 1; i++) {    // copy decomposition of z to sin
                        auto rem_zi_val = var_value(assignment, var(var_pos.rem_pos.z0.column() + z_offset + i,
                                                                    var_pos.rem_pos.z0.row(), false));
                        // we know the value of rem_z_val is in [0, 2^16) because of the decomposition step
                        auto rem_zi_val_uint16 =
                            static_cast<uint16_t>(FixedPointHelper<BlueprintFieldType>::field_to_double(rem_zi_val));
                        x0_val.push_back(rem_zi_val_uint16);
                    }
                    // sign of y is sign of z in rem
                    s_x_val = var_value(assignment, var(splat(var_pos.rem_pos.s_y), false));
                } else {    // if one pre-comma limb is used, x gets decomposed into up to three limbs
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(x_val, x0_val);
                    s_x_val = sign ? -one : one;
                }

                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= (m2 + 1));
                assignment.witness(splat(var_pos.s_x)) = s_x_val;
                for (size_t i = 0; i < m2 + 1; i++) {
                    assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                }

                // TODO optimize
                auto sin_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_sin_a_16() :
                                             FixedPointTables<BlueprintFieldType>::get_sin_a_32();
                auto sin_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_sin_b_16() :
                                             FixedPointTables<BlueprintFieldType>::get_sin_b_32();
                auto cos_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_cos_a_16() :
                                             FixedPointTables<BlueprintFieldType>::get_cos_a_32();
                auto cos_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_cos_b_16() :
                                             FixedPointTables<BlueprintFieldType>::get_cos_b_32();
                auto sin_c_table = FixedPointTables<BlueprintFieldType>::get_sin_c_32();

                // x0 .. smallest limb, x1 .. 2nd smallest limb, x2 .. 3rd smallest limb (2 or 3 limbs in total)
                // sin0 holds the looked-up value of the one and only pre-comma limb, so sin(a) = sin0 where a is the
                // largest limb of the input. a = x0_val[m2], ..
                auto sin0_val = sin_a_table[x0_val[m2 - 0]];                     // 0 .. a
                auto sin1_val = sin_b_table[x0_val[m2 - 1]];                     // 1 .. b
                auto sin2_val = m2 == 1 ? zero : sin_c_table[x0_val[m2 - 2]];    // 2 .. c
                auto cos0_val = cos_a_table[x0_val[m2 - 0]];                     // 0 .. a
                auto cos1_val = cos_b_table[x0_val[m2 - 1]];                     // 1 .. b
                auto cos2_val = delta;                                           // 2 .. c

                assignment.witness(splat(var_pos.sin0)) = sin0_val;
                assignment.witness(var_pos.sin0.column() + 1, var_pos.sin0.row()) = sin1_val;
                if (m2 == 2) {
                    assignment.witness(var_pos.sin0.column() + 2, var_pos.sin0.row()) = sin2_val;
                }
                assignment.witness(splat(var_pos.cos0)) = cos0_val;
                assignment.witness(splat(var_pos.cos1)) = cos1_val;

                // sin(-a)    = -sin(a)
                // sin(a+b)   = sin(a)cos(b) + cos(a)sin(b)
                // sin(a+b+c) = sin(a+b)cos(c) + cos(a+b)sin(c)
                //            = cos(c) * (sin(a)cos(b) + cos(a)sin(b))
                //            + sin(c) * (cos(a)cos(b) - sin(a)sin(b))
                // sin(a) .. sin0, sin(b) .. sin1, sin(c) .. sin2
                // cos(a) .. cos0, cos(b) .. cos1, cos(c) .. cos2
                value_type computation_sin = m2 == 1 ?
                                                 s_x_val * (sin0_val * cos1_val + cos0_val * sin1_val) :
                                                 s_x_val * (cos2_val * (sin0_val * cos1_val + cos0_val * sin1_val) +
                                                            sin2_val * (cos0_val * cos1_val - sin0_val * sin1_val));

                // cos(-a)    = cos(a)
                // sin(a+b)   = sin(a)cos(b) + cos(a)sin(b)
                // sin(a+b+c) = sin(a+b)cos(c) + cos(a+b)sin(c)
                //            = cos(c) * (sin(a)cos(b) + cos(a)sin(b))
                //            + sin(c) * (cos(a)cos(b) - sin(a)sin(b))
                // sin(a) .. sin0, sin(b) .. sin1, sin(c) .. sin2
                // cos(a) .. cos0, cos(b) .. cos1, cos(c) .. cos2
                value_type computation_cos = m2 == 1 ? (cos0_val * cos1_val - sin0_val * sin1_val) :
                                                       (cos2_val * (cos0_val * cos1_val - sin0_val * sin1_val) -
                                                        sin2_val * (sin0_val * cos1_val + cos0_val * sin1_val));

                // BEGIN TAN LOGIC

                value_type tan_input_sin = computation_sin;
                value_type tan_input_cos = computation_cos;

                // PREPARE SIN AND COS FOR DIVISION (including custom rescale for cos for m2=2)
                // sin(x) * delta / cos(x) * delta = sin(x) / cos(x)
                // need to multiply result with delta (either mul sin(x) with delta or div cos(x) by delta)
                if (m2 == 1) {
                    // multiply sin(x) with delta
                    tan_input_sin *= delta;
                } else { /* m2 == 2 */
                    // divide cos(x) by delta
                    auto tmp = FixedPointHelper<BlueprintFieldType>::round_div_mod(computation_cos, delta);
                    tan_input_cos = tmp.quotient;
                    auto b_val = tmp.remainder;    // we know delta is 2^32, so q_val can be split into two limbs
                    std::vector<uint16_t> b0_val;
                    bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(b_val, b0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign_);
                    for (size_t i = 0; i < 2; i++) {
                        assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = b0_val[i];
                    }
                }
                assignment.witness(splat(var_pos.sin)) = tan_input_sin;
                assignment.witness(splat(var_pos.cos)) = tan_input_cos;
                // END PREPARE SIN AND COS

                // BEGIN CUSTOM DIVISION (no rescale required, as sin(x) and cos(x) are properly scaled already)
                // decomposition of y (== cos(x))
                std::vector<uint16_t> y0_val;
                auto y0_size = m2 == 2 ? 5 : 3;
                bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(tan_input_cos, y0_val);
                while (y0_val.size() < y0_size) {
                    y0_val.push_back(0);
                }
                BLUEPRINT_RELEASE_ASSERT(y0_val.size() >= y0_size);
                assignment.witness(splat(var_pos.s_y)) = sign_ ? -one : one;
                for (auto i = 0; i < y0_size; i++) {
                    assignment.witness(var_pos.y0.column() + i, var_pos.y0.row()) = y0_val[i];
                }
                // end decomposition of y
                // begin division by positive
                auto tmp = FixedPointHelper<BlueprintFieldType>::round_div_mod(tan_input_sin, tan_input_cos);
                auto tan_val = tmp.quotient;
                assignment.witness(splat(var_pos.tan)) = tan_val;

                std::vector<uint16_t> q0_val;
                std::vector<uint16_t> a0_val;
                auto q0_size = m2 == 2 ? 4 : 2;
                auto a0_size = q0_size;

                value_type tan_input_cos_abs = tan_input_cos;
                FixedPointHelper<BlueprintFieldType>::abs(tan_input_cos_abs);
                auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp.remainder, q0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(tan_input_cos_abs - tmp.remainder - 1, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= q0_size);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= a0_size);

                auto y_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(tan_input_cos_abs);
                assignment.witness(splat(var_pos.c)) = value_type(y_.limbs()[0] & 1);

                for (auto i = 0; i < q0_size; i++) {
                    assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                }
                // end division by positive
                // END CUSTOM DIVISION
                // END TAN LOGIC

                return typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_first_gate(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t first_row = -1;
                const int64_t second_row = 0;
                const auto var_pos = component.get_var_pos(0);
                using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = component.get_m();

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;

                auto delta = typename BlueprintFieldType::value_type(component.get_delta());
                auto x = var(var_pos.x.column(), first_row);
                auto s_x = var(var_pos.s_x.column(), first_row);
                auto x0 = nil::crypto3::math::expression(var(var_pos.x0.column(), first_row));

                // decomposition of x
                for (size_t i = 1; i < m2 + 1; i++) {
                    x0 += var(var_pos.x0.column() + i, first_row) * (1ULL << (16 * i));
                }

                // decomposition constraint for x, only applies if m1=1 (decomp of x mod 2*pi is constrained in rem)
                if (m1 == 1) {
                    constraints.push_back(x - s_x * x0);
                    constraints.push_back((s_x - 1) * (s_x + 1));
                }

                auto sin = var(var_pos.sin.column(), second_row);
                auto cos = var(var_pos.cos.column(), second_row);
                auto sin0 = var(var_pos.sin0.column() + 0, first_row);    // 0 .. a
                auto sin1 = var(var_pos.sin0.column() + 1, first_row);    // 1 .. b
                auto cos0 = var(var_pos.cos0.column(), first_row);        // 0 .. a
                auto cos1 = var(var_pos.cos1.column(), first_row);        // 1 .. b
                auto sin2 = var(var_pos.sin0.column() + 2, first_row);    // 2 .. c
                auto cos2 = delta;                                        // 2 .. c

                // sin(a) .. sin0, sin(b) .. sin1, sin(c) .. sin2
                // cos(a) .. cos0, cos(b) .. cos1, cos(c) .. cos2
                auto computation_sin =
                    m2 == 1 ? s_x * (sin0 * cos1 + cos0 * sin1) :
                              s_x * (cos2 * (sin0 * cos1 + cos0 * sin1) + sin2 * (cos0 * cos1 - sin0 * sin1));
                auto computation_cos = m2 == 1 ?
                                           (cos0 * cos1 - sin0 * sin1) :
                                           (cos2 * (cos0 * cos1 - sin0 * sin1) - sin2 * (sin0 * cos1 + cos0 * sin1));

                if (m2 == 1) {
                    constraints.push_back(sin - computation_sin * delta);
                    constraints.push_back(cos - computation_cos);
                } else { /* m2 == 2 */
                    constraints.push_back(sin - computation_sin);
                    auto b0 = var(var_pos.b0.column() + 0, second_row);
                    auto b1 = var(var_pos.b0.column() + 1, second_row);
                    auto b = b0 + b1 * (1ULL << 16);
                    constraints.push_back(2 * (computation_cos - cos * delta - b) + delta);    // "custom" rescale
                }

                // division happens in first gate for m2 == 1 and in second gate for m2 == 2
                if (m2 == 1) {
                    auto tan = var(var_pos.tan.column(), second_row);
                    auto y_abs = nil::crypto3::math::expression(var(var_pos.y0.column(), second_row));
                    auto q = nil::crypto3::math::expression(var(var_pos.q0.column(), second_row));
                    auto a = nil::crypto3::math::expression(var(var_pos.a0.column(), second_row));
                    auto a_size = 2;
                    auto q_size = a_size;
                    for (auto i = 1; i < a_size; i++) {
                        y_abs += var(var_pos.y0.column() + i, second_row) * (1ULL << (16 * i));
                        q += var(var_pos.q0.column() + i, second_row) * (1ULL << (16 * i));
                        a += var(var_pos.a0.column() + i, second_row) * (1ULL << (16 * i));
                    }
                    y_abs += var(var_pos.y0.column() + a_size, second_row) * (1ULL << (16 * a_size));
                    auto s_y = var(var_pos.s_y.column(), first_row);
                    auto c = var(var_pos.c.column(), first_row);

                    constraints.push_back(2 * (sin - cos * tan - q) + y_abs - c);
                    constraints.push_back((c - 1) * c);
                    constraints.push_back(y_abs - q - a - 1);
                    constraints.push_back(cos - s_y * y_abs);
                    constraints.push_back((s_y - 1) * (s_y + 1));
                }

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_second_gate(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t first_row = -1;
                const int64_t second_row = 0;
                const auto var_pos = component.get_var_pos(0);
                using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;
                using value_type = typename BlueprintFieldType::value_type;
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();

                BLUEPRINT_RELEASE_ASSERT(m2 == 2);

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;

                auto sin = var(var_pos.sin.column(), first_row);
                auto cos = var(var_pos.cos.column(), first_row);
                auto tan = var(var_pos.tan.column(), second_row);
                auto y_abs = nil::crypto3::math::expression(var(var_pos.y0.column(), second_row));
                auto q = nil::crypto3::math::expression(var(var_pos.q0.column(), second_row));
                auto a = nil::crypto3::math::expression(var(var_pos.a0.column(), first_row));
                auto a_size = 4;
                auto q_size = a_size;
                for (auto i = 1; i < a_size; i++) {
                    y_abs += var(var_pos.y0.column() + i, second_row) * (1ULL << (16 * i));
                    q += var(var_pos.q0.column() + i, second_row) * (1ULL << (16 * i));
                    a += var(var_pos.a0.column() + i, first_row) * (1ULL << (16 * i));
                }
                BLUEPRINT_RELEASE_ASSERT(a_size == 4);
                y_abs += var(var_pos.y0.column() + a_size, second_row) * value_type((1ULL << (16 * 2))) *
                         value_type((1ULL << (16 * 2)));

                auto s_y = var(var_pos.s_y.column(), first_row);
                auto c = var(var_pos.c.column(), first_row);

                constraints.push_back(2 * (sin - cos * tan - q) + y_abs - c);
                constraints.push_back((c - 1) * c);
                constraints.push_back(y_abs - q - a - 1);
                constraints.push_back(cos - s_y * y_abs);
                constraints.push_back((s_y - 1) * (s_y + 1));

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();

                auto x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
                if (m1 == 1) {
                    return;
                }
                // if m1==2: copy decomposition of x mod 2*pi from rem to sin
                int64_t z_offset = m2 == 1 ? 1 : 0;
                for (int64_t i = 0; i < m2 + 1; i++) {    // copy decomposition of z to sin
                    auto rem_zi = var(var_pos.rem_pos.z0.column() + z_offset + i, var_pos.rem_pos.z0.row(), false);
                    auto sin_xi = var(var_pos.x0.column() + i, var_pos.x0.row(), false);
                    bp.add_copy_constraint({rem_zi, sin_xi});
                }
                // sign of y is sign of z in rem
                auto rem_s_z = var(splat(var_pos.rem_pos.s_y), false);
                auto sin_s_x = var(splat(var_pos.s_x), false);
                bp.add_copy_constraint({rem_s_z, sin_s_x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_first_lookup_gates(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t first_row = -1;
                const int64_t second_row = 0;
                const auto var_pos = component.get_var_pos(0);
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::range_table;

                auto range_table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);
                auto sin_a_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_SIN_A) :
                              lookup_tables_indices.at(fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_A);
                auto sin_b_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_SIN_B) :
                              lookup_tables_indices.at(fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_B);
                auto cos_a_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_COS_A) :
                              lookup_tables_indices.at(fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_COS_A);
                auto cos_b_table_id =
                    m2 == 1 ? lookup_tables_indices.at(fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_COS_B) :
                              lookup_tables_indices.at(fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_COS_B);

                std::vector<constraint_type> constraints;

                // if m1 == 1 x gets decomposed by tan, if m1 == 2 x gets decomposed by rem
                if (m1 == 1) {
                    for (size_t i = 0; i < m2 + 1; i++) {
                        auto xi = var(var_pos.x0.column() + i, first_row);
                        constraint_type constraint;
                        constraint.table_id = range_table_id;
                        constraint.lookup_input = {xi};
                        constraints.push_back(constraint);
                    }
                }

                // lookup sin, cos
                // x0 .. smallest limb, x1 .. 2nd smallest limb, x2 .. 3rd smallest limb (2 or 3 limbs in total)
                // sin0 holds the looked-up value of the one and only pre-comma limb, so sin(a) = sin0 where a is the
                // largest limb of the input. a = x0_val[m2], ..
                auto x0 = var(var_pos.x0.column() + m2 - 0, first_row);
                auto x1 = var(var_pos.x0.column() + m2 - 1, first_row);
                auto x2 = var(var_pos.x0.column() + m2 - 2, first_row);    // invalid if m2 == 1
                auto sin0 = var(var_pos.sin0.column() + 0, first_row);
                auto sin1 = var(var_pos.sin0.column() + 1, first_row);
                auto sin2 = var(var_pos.sin0.column() + 2, first_row);    // invalid if m2 == 1
                auto cos0 = var(var_pos.cos0.column(), first_row);
                auto cos1 = var(var_pos.cos1.column(), first_row);
                {
                    constraint_type constraint;
                    constraint.table_id = sin_a_table_id;
                    constraint.lookup_input = {x0, sin0};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = cos_a_table_id;
                    constraint.lookup_input = {x0, cos0};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = sin_b_table_id;
                    constraint.lookup_input = {x1, sin1};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = cos_b_table_id;
                    constraint.lookup_input = {x1, cos1};
                    constraints.push_back(constraint);
                }
                if (m2 == 2) {
                    constraint_type constraint;
                    auto sin_c_table_id =
                        lookup_tables_indices.at(fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_C);
                    constraint.table_id = sin_c_table_id;
                    constraint.lookup_input = {x2, sin2};
                    constraints.push_back(constraint);
                }

                // lookup a (is in the same row for m1 == 1 and m1 == 2)
                for (size_t i = 0; i < 2 * m2; i++) {
                    auto ai = var(var_pos.a0.column() + i, second_row);
                    constraint_type constraint;
                    constraint.table_id = range_table_id;
                    constraint.lookup_input = {ai};
                    constraints.push_back(constraint);
                }

                // lookup q and y if m2 == 1
                if (m2 == 1) {
                    for (size_t i = 0; i < 2 * m2; i++) {
                        auto qi = var(var_pos.q0.column() + i, second_row);
                        constraint_type constraint;
                        constraint.table_id = range_table_id;
                        constraint.lookup_input = {qi};
                        constraints.push_back(constraint);
                    }
                    for (size_t i = 0; i < 2 * m2 + 1; i++) {
                        auto yi = var(var_pos.y0.column() + i, second_row);
                        constraint_type constraint;
                        constraint.table_id = range_table_id;
                        constraint.lookup_input = {yi};
                        constraints.push_back(constraint);
                    }
                }

                // lookup b if m2 == 2
                if (m2 == 2) {
                    for (size_t i = 0; i < m2; i++) {
                        auto bi = var(var_pos.b0.column() + i, second_row);
                        constraint_type constraint;
                        constraint.table_id = range_table_id;
                        constraint.lookup_input = {bi};
                        constraints.push_back(constraint);
                    }
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_second_lookup_gates(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t row = 0;
                const auto var_pos = component.get_var_pos(0);
                auto m2 = component.get_m2();
                BLUEPRINT_RELEASE_ASSERT(m2 == 2);

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::range_table;

                auto range_table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                std::vector<constraint_type> constraints;

                // lookup q and y
                for (size_t i = 0; i < 2 * m2; i++) {
                    auto qi = var(var_pos.q0.column() + i, row);
                    constraint_type constraint;
                    constraint.table_id = range_table_id;
                    constraint.lookup_input = {qi};
                    constraints.push_back(constraint);
                }
                for (size_t i = 0; i < 2 * m2 + 1; i++) {
                    auto yi = var(var_pos.y0.column() + i, row);
                    constraint_type constraint;
                    constraint.table_id = range_table_id;
                    constraint.lookup_input = {yi};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                if (component.get_m1() == 2) {    // if m1=2, rem exists
                    typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::rem_component::input_type
                        rem_input;

                    using var = typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::var;

                    rem_input.x = var(splat(var_pos.x), false);
                    rem_input.y = var(splat(var_pos.two_pi), false, var::column_type::constant);

                    generate_circuit(component.get_rem_component(), bp, assignment, rem_input, var_pos.rem_row);
                }

                std::size_t first_selector_index = generate_first_gate(component, bp, assignment, instance_input);
                assignment.enable_selector(first_selector_index, var_pos.tan_row + 1);    // enable on first div row

                if (component.get_m2() == 2) {
                    std::size_t second_selector_index = generate_second_gate(component, bp, assignment, instance_input);
                    assignment.enable_selector(second_selector_index,
                                               start_row_index + component.rows_amount -
                                                   1);    // enable on last comp row
                }

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t first_lookup_selector_index =
                    generate_first_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(first_lookup_selector_index,
                                           var_pos.tan_row + 1);    // enable on first div row
                if (component.get_m2() == 2) {
                    std::size_t second_lookup_selector_index =
                        generate_second_lookup_gates(component, bp, assignment, instance_input);
                    assignment.enable_selector(second_lookup_selector_index,
                                               start_row_index + component.rows_amount -
                                                   1);    // enable on last comp row
                }
#endif
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_tan<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TAN_HPP
