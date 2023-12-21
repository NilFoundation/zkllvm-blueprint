#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SIN_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SIN_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/rem.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/trigonometric.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing x into up to three limbs and using the identities sin(a+b) = sin(a)cos(b) +
            // cos(a)sin(b) and cos(a+b) = cos(a)cos(b) - sin(a)sin(b) multiple times, followed by one custom rescale
            // operation. The evaluations of sin and cos are retrieved via pre-computed lookup tables. In case m1 >= 2,
            // a rem operation (mod 2*pi) brings x into a range where one pre-comma limb is sufficient for computing
            // sin(x).

            /**
             * Component representing a sin operation with input x and output y, where y = sin(x).
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x ... field element
             * Output: y ... sin(x) (field element)
             * Constant: two_pi ... 2*pi (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_sin;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_sin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

            public:
                struct var_positions {
                    CellPosition x, y, s_x, x0, q0, sin0, cos0, cos1, two_pi;
                    typename rem_component::var_positions rem_pos;
                    int64_t start_row, rem_row, sin_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (7 + m2 * (2 + m2) col(s), 1 + rem_rows row(s))
                    //              (10 if m2=1, 15 if m2=2 col(s))
                    //              (11 col(s), 3 row(s) for 32.16 fixed point because rem requires m2=2)
                    //
                    // rem only exists if m1=2; rem_rows = 0 if m1=1
                    // two_pi only exists if rem exists
                    // t = 0 if m2 = 1
                    // t = 3 if m2 = 2
                    //
                    //     |                                         witness                                         |
                    //  r\c| 0 | 1 |  2  | 3  | .. | 3+m2|4+m2|..|4+m2+t| 5+m2+t| .. |5+2*m2+t | 6+2*m2+t | 7+2*m2+t |
                    // +---+---+---+-----+----+----+-----+----+--+------+-------+----+---------+----------+----------+
                    // |rem| <rem_witness>                                                                           |
                    // |sin| x | y | s_x | x0 | .. | xm2 | q0 |..|  qt  | sin0  | .. |  sinm2  |   cos0   |   cos1   |
                    //
                    //     | constant |
                    //  r\c|    0     |
                    // +---+----------+
                    // |sin|  two_pi  |

                    auto m1 = this->m1;
                    auto m2 = this->m2;
                    auto t = m2 * m2 - 1;
                    var_positions pos;

                    pos.start_row = start_row_index;
                    pos.rem_row = pos.start_row;
                    pos.sin_row = pos.rem_row;

                    if (m1 == 2) {
                        pos.sin_row += rem.rows_amount;
                        pos.rem_pos = rem.get_var_pos(pos.rem_row);
                        pos.two_pi = CellPosition(this->C(0), pos.sin_row);
                    }

                    pos.x = CellPosition(this->W(0), pos.sin_row);
                    pos.y = CellPosition(this->W(1), pos.sin_row);
                    pos.s_x = CellPosition(this->W(2), pos.sin_row);
                    pos.x0 = CellPosition(this->W(3 + 0 * (m2 + 1)), pos.sin_row);    // occupies m2 + 1 cells
                    pos.q0 = CellPosition(this->W(3 + 1 * (m2 + 1)), pos.sin_row);    // occupies t+1 cells
                    pos.sin0 = CellPosition(this->W(5 + m2 + t), pos.sin_row);        // occupies m2 + 1 cells
                    pos.cos0 = CellPosition(this->W(6 + 2 * m2 + t), pos.sin_row);
                    pos.cos1 = CellPosition(this->W(7 + 2 * m2 + t), pos.sin_row);
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
                    auto witness_columns = rem_component::get_witness_columns(this->witness_amount(), m1, 2);
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
                    if (m1 == 2 && m2 == 1) {
                        return 11;
                    }
                    return M(m2) == 1 ? 10 : 15;
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
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_sin::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    if (m1 == 2) {
                        manifest = manifest.merge_with(
                            rem_component::get_gate_manifest(witness_amount, lookup_column_amount, 2, 2));
                    }
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m1, m2))),
                        true);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    if (M(m1) == 2 && M(m2) == 1) {
                        return 1 +
                               rem_component::get_rows_amount(get_witness_columns(m1, m2), lookup_column_amount, m1, 2);
                    }
                    return M(m1) == 2 ? 1 + rem_component::get_rows_amount(get_witness_columns(m1, m2),
                                                                           lookup_column_amount, m1, m2) :
                                        1;
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

#ifdef TEST_WITHOUT_LOOKUP_TABLES
                constexpr static const std::size_t gates_amount = 1;
#else
                constexpr static const std::size_t gates_amount = 2;
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, this->m1, this->m2);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_sin &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_sin &component, std::size_t start_row_index) {
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
                explicit fix_sin(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)), rem(instantiate_rem()),
                    two_pi(get_two_pi()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_sin(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), rem(instantiate_rem()), two_pi(get_two_pi()) {};

                fix_sin(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), rem(instantiate_rem()), two_pi(get_two_pi()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_sin =
                fix_sin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
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
                value_type computation = m2 == 1 ? s_x_val * (sin0_val * cos1_val + cos0_val * sin1_val) :
                                                   s_x_val * (cos2_val * (sin0_val * cos1_val + cos0_val * sin1_val) +
                                                              sin2_val * (cos0_val * cos1_val - sin0_val * sin1_val));

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

                return typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto delta = typename BlueprintFieldType::value_type(component.get_delta());
                auto x = var(splat(var_pos.x));
                auto s_x = var(splat(var_pos.s_x));
                auto x0 = nil::crypto3::math::expression(var(splat(var_pos.x0)));

                // decomposition of x
                for (size_t i = 1; i < m2 + 1; i++) {
                    x0 += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }

                // decomposition constraint for x, only applies if m1=1 (decomp of x mod 2*pi is constrained in rem)
                auto constraint_1 = x - s_x * x0;

                // sign of x, only applies if m1=1 as mentioned above
                auto constraint_2 = (s_x - 1) * (s_x + 1);

                auto y = var(splat(var_pos.y));
                auto sin0 = var(splat(var_pos.sin0));                              // 0 .. a
                auto sin1 = var(var_pos.sin0.column() + 1, var_pos.sin0.row());    // 1 .. b
                auto cos0 = var(splat(var_pos.cos0));                              // 0 .. a
                auto cos1 = var(splat(var_pos.cos1));                              // 1 .. b
                auto sin2 = var(var_pos.sin0.column() + 2, var_pos.sin0.row());    // 2 .. c
                auto cos2 = delta;                                                 // 2 .. c
                auto q = nil::crypto3::math::expression(var(splat(var_pos.q0)));
                for (size_t i = 1; i < m2 * m2; i++) {
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                }

                // sin(a) .. sin0, sin(b) .. sin1, sin(c) .. sin2
                // cos(a) .. cos0, cos(b) .. cos1, cos(c) .. cos2
                auto computation = m2 == 1 ?
                                       s_x * (sin0 * cos1 + cos0 * sin1) :
                                       s_x * (cos2 * (sin0 * cos1 + cos0 * sin1) + sin2 * (cos0 * cos1 - sin0 * sin1));
                auto actual_delta = m2 == 1 ? delta : delta * delta;

                auto constraint_3 = 2 * (computation - y * actual_delta - q) + actual_delta;    // "custom" rescale

                if (m1 == 1) {
                    return {constraint_1, constraint_2, constraint_3};
                } else {    // m1 == 2
                    return {constraint_3};
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
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
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m2 = component.get_m2();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::range_table;

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

                // lookup decomposition of q
                for (size_t i = 0; i < m2 * m2; i++) {
                    constraint_type constraint;
                    constraint.table_id = range_table_id;
                    auto qi = var(var_pos.q0.column() + i, var_pos.q0.row());
                    constraint.lookup_input = {qi};
                    constraints.push_back(constraint);
                }

                // lookup sin, cos
                // x0 .. smallest limb, x1 .. 2nd smallest limb, x2 .. 3rd smallest limb (2 or 3 limbs in total)
                // sin0 holds the looked-up value of the one and only pre-comma limb, so sin(a) = sin0 where a is the
                // largest limb of the input. a = x0_val[m2], ..
                auto x0 = var(var_pos.x0.column() + m2 - 0, var_pos.x0.row());
                auto x1 = var(var_pos.x0.column() + m2 - 1, var_pos.x0.row());
                auto x2 = var(var_pos.x0.column() + m2 - 2, var_pos.x0.row());    // invalid if m2 == 1
                auto sin0 = var(var_pos.sin0.column() + 0, var_pos.sin0.row());
                auto sin1 = var(var_pos.sin0.column() + 1, var_pos.sin0.row());
                auto sin2 = var(var_pos.sin0.column() + 2, var_pos.sin0.row());    // invalid if m2 == 1
                {
                    constraint_type constraint;
                    constraint.table_id = sin_a_table_id;
                    constraint.lookup_input = {x0, sin0};
                    constraints.push_back(constraint);
                }
                {
                    constraint_type constraint;
                    constraint.table_id = cos_a_table_id;
                    constraint.lookup_input = {x0, var(splat(var_pos.cos0))};
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
                    constraint.lookup_input = {x1, var(splat(var_pos.cos1))};
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

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                if (component.get_m1() == 2) {    // if m1=2, rem exists
                    typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::rem_component::input_type
                        rem_input;

                    using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;

                    rem_input.x = var(splat(var_pos.x), false);
                    rem_input.y = var(splat(var_pos.two_pi), false, var::column_type::constant);

                    generate_circuit(component.get_rem_component(), bp, assignment, rem_input, var_pos.rem_row);
                }

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index + component.rows_amount - 1);
#endif
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SIN_HPP
