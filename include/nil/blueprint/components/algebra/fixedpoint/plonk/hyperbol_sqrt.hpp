#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASINH_SQRT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASINH_SQRT_HPP

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
             * Component representing a sqrt operation with input x and output y, where y = x + round(sqrt(x^2 +- 1)).
             *
             * Used to compute x + sqrt(x^2 +- 1) which is then used as an input to log for computing asinh and acosh
             * via approximation formulas:
             *     asinh(x) = log(x + sqrt(x^2 + 1))
             *     acosh(x) = log(x + sqrt(x^2 - 1))
             *
             * The delta of y is always 2^32 and rescaling happens in fix_hyperbol_log in case m2 is 1.
             *
             * Input:    x  ... field element
             * Output:   y  ... x + round(sqrt(x^2 +- 1)) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_hyperbol_sqrt;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_hyperbol_sqrt<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

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

                static constexpr uint64_t get_internal_delta() {
                    return 1ULL << (32);
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    // component uses m2=2 internally
                    return 3 + 3 * (M(m1) + 2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                value_type get_h() const {
                    if (m1 == 1 && m2 == 2) {
                        return value_type(((uint64_t)(1ULL << (16 * (m1 + 2)))) / 2 - (1ULL << 17));
                    } else if (m1 == 1 && m2 == 1) {
                        return value_type(((uint64_t)(1ULL << (16 * (m1 + 2)))) / 2 - 1);
                    } else {
                        return value_type(((uint64_t)(-1)) / 2 - 1);
                    }
                }

            private:
                value_type one_for_formula;    // is 1 for asinh and -1 for acosh
            public:
                value_type get_one_for_formula() const {
                    return one_for_formula;
                }

                enum class hyperbolic_type { ASINH, ACOSH };

                static value_type init_one(hyperbolic_type tp) {
                    if (tp == hyperbolic_type::ASINH) {
                        return value_type(get_internal_delta());
                    } else if (tp == hyperbolic_type::ACOSH) {
                        return -value_type(get_internal_delta());
                    }
                    BLUEPRINT_RELEASE_ASSERT(false);
                    return value_type(0);
                }

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_hyperbol_sqrt::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(
                                          new manifest_single_value_param(get_witness_columns(0, m1, m2))),
                                      false);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    return 2;
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

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, y, y_sq, r, y0, a0, b0, c0, x0, d0, s_x, res, one_f_frml;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m1 = this->get_m1();
                    var_positions pos;

                    // trace layout (3 + 3*m col(s), 2 row(s))
                    //
                    //     |                                  witness                                   | constant |
                    //  r\c|  0   | 1 | 2  | .. | 2+m-1 | 2+m | .. | 2+2m-1 | 2+2m | .. | 2+3m-1 | 2+3m |    0     |
                    // +---+------+---+----+----+-------+-----+----+--------+------+----+--------+------+----------+
                    // | 0 | y_sq | r | b0 | .. | bm-1  | c0  | .. |  cm-1  |  x0  | .. |  xm-1  | s_x  |one_f_frml|
                    // | 1 | x    |res| y0 | .. | ym-1  | a0  | .. |  am-1  |  d0  | .. |  dm-1  |  y   |    -     |

                    pos.y_sq = CellPosition(this->W(0), start_row_index);
                    pos.r = CellPosition(this->W(1), start_row_index);
                    pos.b0 = CellPosition(this->W(2 + 0 * (m1 + 2)), start_row_index);    // occupies m1 + 2 cells
                    pos.c0 = CellPosition(this->W(2 + 1 * (m1 + 2)), start_row_index);    // occupies m1 + 2 cells
                    pos.x0 = CellPosition(this->W(2 + 2 * (m1 + 2)), start_row_index);    // occupies m1 + 2 cells
                    pos.s_x = CellPosition(this->W(2 + 3 * (m1 + 2)), start_row_index);
                    pos.x = CellPosition(this->W(0), start_row_index + 1);
                    pos.res = CellPosition(this->W(1), start_row_index + 1);
                    pos.y0 = CellPosition(this->W(2 + 0 * (m1 + 2)), start_row_index + 1);    // occupies m1 + 2 cells
                    pos.a0 = CellPosition(this->W(2 + 1 * (m1 + 2)), start_row_index + 1);    // occupies m1 + 2 cells
                    pos.d0 = CellPosition(this->W(2 + 2 * (m1 + 2)), start_row_index + 1);    // occupies m1 + 2 cells
                    pos.y = CellPosition(this->W(2 + 3 * (m1 + 2)), start_row_index + 1);
                    pos.one_f_frml = CellPosition(this->C(0), start_row_index);
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_hyperbol_sqrt &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.res), false);
                    }

                    result_type(const fix_hyperbol_sqrt &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.res), false);
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

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_hyperbol_sqrt(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input, uint8_t m1, uint8_t m2, hyperbolic_type tp) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), one_for_formula(init_one(tp)) {};

                fix_hyperbol_sqrt(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2, hyperbolic_type tp) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)), one_for_formula(init_one(tp)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using fixplonk_fixedpoint_hyperbol_sqrt = fix_hyperbol_sqrt<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType,
                                                                     ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {
                using value_type = typename BlueprintFieldType::value_type;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto m1 = component.get_m1();
                const auto m2 = component.get_m2();
                const auto m2_internal = 2;
                const auto m_internal = m1 + m2_internal;
                value_type delta = value_type(component.get_delta());
                value_type delta_internal = value_type(component.get_internal_delta());

                std::vector<uint16_t> x0_val;
                std::vector<uint16_t> d0_val;
                value_type s_x_val, x_abs_val;
                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(splat(var_pos.x)) = x_val;
                if (m2 == 1) {
                    x_val *= delta;    // delta is 2^16 if m2 == 1
                }
                {
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(x_val, x0_val);
                    s_x_val = sign ? -value_type::one() : value_type::one();
                    x_abs_val = sign ? -x_val : x_val;
                    assignment.witness(splat(var_pos.s_x)) = s_x_val;
                    value_type d_val = component.get_h() - x_abs_val;
                    sign = FixedPointHelper<BlueprintFieldType>::decompose(d_val, d0_val);
                    if (sign) {
                        BLUEPRINT_RELEASE_ASSERT(
                            false &&
                            "input for asinh/acosh is too large. abs(input) must be smaller than (FixedPoint::max / 2) "
                            "- 1 except for 16.32 where it must be (FixedPoint::max / 2) - 2^17");
                    }
                    for (auto i = 0; i < m_internal; i++) {
                        assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                        assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = d0_val[i];
                    }
                }
                value_type one_for_formula = component.get_one_for_formula();
                assignment.constant(splat(var_pos.one_f_frml)) = one_for_formula;
                auto sqrt_in = x_val * x_val + one_for_formula * delta_internal;    // x^2 +- 1
                auto y_val = FixedPointHelper<BlueprintFieldType>::sqrt(sqrt_in);
                auto y_val_floor = FixedPointHelper<BlueprintFieldType>::sqrt(sqrt_in, true);

                auto r_bool = y_val != y_val_floor;
                auto r_val = r_bool ? value_type::one() : value_type::zero();

                auto y_sq_val = y_val * y_val;

                assignment.witness(splat(var_pos.y)) = y_val;
                assignment.witness(splat(var_pos.y_sq)) = y_sq_val;
                assignment.witness(splat(var_pos.r)) = r_val;

                // Decompositions
                auto a_val = (sqrt_in - y_sq_val) + r_val * (2 * y_val - 1);
                auto b_val = 2 * y_val - 2 * r_val - a_val;
                auto c_val = 2 * r_val * (sqrt_in - y_sq_val) + y_sq_val + y_val - sqrt_in - r_val;

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
                BLUEPRINT_RELEASE_ASSERT(y0_val.size() >= static_cast<std::size_t>(m_internal));
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= static_cast<std::size_t>(m_internal));
                BLUEPRINT_RELEASE_ASSERT(b0_val.size() >= static_cast<std::size_t>(m_internal));
                BLUEPRINT_RELEASE_ASSERT(c0_val.size() >= static_cast<std::size_t>(m_internal));

                for (auto i = 0; i < m_internal; i++) {
                    assignment.witness(var_pos.y0.column() + i, var_pos.y0.row()) = y0_val[i];
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                    assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = b0_val[i];
                    assignment.witness(var_pos.c0.column() + i, var_pos.c0.row()) = c0_val[i];
                }

                value_type res_val = x_val + y_val;
                assignment.witness(splat(var_pos.res)) = res_val;

                return
                    typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::var;
                const auto m1 = component.get_m1();
                const auto m2 = component.get_m2();
                const auto m2_internal = 2;
                const auto m_internal = m1 + m2_internal;
                using value_type = typename BlueprintFieldType::value_type;
                value_type delta = value_type(component.get_delta());
                value_type delta_internal = value_type(component.get_internal_delta());
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                auto y0 = nil::crypto3::math::expression<var>(var(splat(var_pos.y0)));
                auto a0 = nil::crypto3::math::expression<var>(var(splat(var_pos.a0)));
                auto b0 = nil::crypto3::math::expression<var>(var(splat(var_pos.b0)));
                auto c0 = nil::crypto3::math::expression<var>(var(splat(var_pos.c0)));
                auto d0 = nil::crypto3::math::expression<var>(var(splat(var_pos.d0)));
                auto x0 = nil::crypto3::math::expression<var>(var(splat(var_pos.x0)));
                for (auto i = 1; i < m_internal; i++) {
                    y0 += var(var_pos.y0.column() + i, var_pos.y0.row()) * (1ULL << (16 * i));
                    a0 += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                    b0 += var(var_pos.b0.column() + i, var_pos.b0.row()) * (1ULL << (16 * i));
                    c0 += var(var_pos.c0.column() + i, var_pos.c0.row()) * (1ULL << (16 * i));
                    d0 += var(var_pos.d0.column() + i, var_pos.d0.row()) * (1ULL << (16 * i));
                    x0 += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }

                auto one_f_frml = var(splat(var_pos.one_f_frml), true, var::column_type::constant);
                auto x = var(splat(var_pos.x));
                auto x_internal = m2 == 1 ? x * delta : x;
                auto h = component.get_h();
                auto x_sqrt = x_internal * x_internal + one_f_frml * delta_internal;
                auto y = var(splat(var_pos.y));
                auto y_sq = var(splat(var_pos.y_sq));
                auto r = var(splat(var_pos.r));
                auto res = var(splat(var_pos.res));
                auto s_x = var(splat(var_pos.s_x));

                auto constraint_1 = r * (r - 1);
                auto constraint_2 = y - y0;
                auto constraint_3 = (x_sqrt - y_sq) + 2 * r * y - r - a0;
                auto constraint_4 = 2 * y - r - (x_sqrt - y_sq) - 2 * r * y - b0;
                auto constraint_5 = 2 * r * (x_sqrt - y_sq) + y_sq + y - x_sqrt - r - c0;
                auto constraint_6 = res - x_internal - y;
                auto constraint_7 = s_x * x0 - x_internal;
                auto constraint_8 = (s_x - 1) * (s_x + 1);
                auto constraint_9 = d0 - (h - x0);

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                    constraint_7, constraint_8, constraint_9});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                const auto m1 = component.get_m1();
                const auto m2_internal = 2;
                const auto m_internal = m1 + m2_internal;

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                constraints.reserve(3 * m_internal);
                // We put just two decompositions into the constraint and activate it twice
                BLUEPRINT_RELEASE_ASSERT(var_pos.y0.row() == var_pos.a0.row());
                BLUEPRINT_RELEASE_ASSERT(var_pos.b0.row() == var_pos.c0.row());
                BLUEPRINT_RELEASE_ASSERT(var_pos.a0.column() == var_pos.c0.column());
                BLUEPRINT_RELEASE_ASSERT(var_pos.b0.column() == var_pos.y0.column());
                BLUEPRINT_RELEASE_ASSERT(var_pos.x0.column() == var_pos.d0.column());
                BLUEPRINT_RELEASE_ASSERT(var_pos.x0.row() == var_pos.b0.row());
                BLUEPRINT_RELEASE_ASSERT(var_pos.d0.row() == var_pos.y0.row());

                for (auto i = 0; i < m_internal; i++) {
                    constraint_type constraint_y, constraint_a, constraint_d;
                    constraint_y.table_id = table_id;
                    constraint_a.table_id = table_id;
                    constraint_d.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto yi = var(var_pos.y0.column() + i, 0);
                    auto ai = var(var_pos.a0.column() + i, 0);
                    auto di = var(var_pos.d0.column() + i, 0);
                    constraint_y.lookup_input = {yi};
                    constraint_a.lookup_input = {ai};
                    constraint_d.lookup_input = {di};

                    constraints.push_back(constraint_y);
                    constraints.push_back(constraint_a);
                    constraints.push_back(constraint_d);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType,
                                                                     ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index);
                // We put just two decompositions into the constraint and activate it twice
                assignment.enable_selector(lookup_selector_index, start_row_index + 1);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return
                    typename fixplonk_fixedpoint_hyperbol_sqrt<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASINH_SQRT_HPP
