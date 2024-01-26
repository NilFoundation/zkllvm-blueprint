#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATANH_DIV_BY_POSITIVE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATANH_DIV_BY_POSITIVE_HPP

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

            // Works by proving z = round(delta_z * x / y) via 2*x*delta_z + y - c = 2zy + 2q and proving 0 <= q < y
            // via multiple decompositions and lookup tables for checking the range of the limbs

            /**
             * This is a subcomponent of atanh and not supposed to be used independently.
             *
             * Performs a range check on x s.t. x in (-1, 1) and computes the fraction (1 + x)/(1 - x) that always
             * evaluates to a positive fixedpoint value.
             *
             * Precisely, this component checks abs(x) <= (delta - 2) instead of x in (-1, 1).
             *
             * Input:    x  ... field element
             * Output:   z  ... (1 + x)/(1 - x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_atanh_div_by_pos;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_atanh_div_by_pos<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return 6 + 4 * M(m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                value_type get_h() const {
                    return (m1 == 1 && m2 == 2) ? value_type(get_delta() - (1ULL << 17)) : value_type(get_delta() - 2);
                }

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_atanh_div_by_pos::gates_amount;
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
                    return 1;
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
                    CellPosition x, s_x, a0, x0, z, c, q0, d0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    var_positions pos;

                    // trace layout (6 + 4*m2 col(s), 2 row(s))
                    //
                    //  r\c| 0 | 1 |  2  | 3 | 4 | 4+m2 | 5+m2 |5+2*m2 | 6+2*m2 | 5+3*m2 | 6+3*m2 | 5+4*m2 |
                    // +---+---+---+-----+---+---+------+------+-------+--------+--------+--------+--------+
                    // | 0 | x | z | s_x | c | a0..am2  |   q0..qm2    |   x0 .. xm2-1   |   d0 .. dm2-1   |

                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.z = CellPosition(this->W(1), start_row_index);
                    pos.s_x = CellPosition(this->W(2), start_row_index);
                    pos.c = CellPosition(this->W(3), start_row_index);
                    pos.a0 = CellPosition(this->W(4 + 0 * (m2 + 1)), start_row_index);             // occupies m cells
                    pos.q0 = CellPosition(this->W(4 + 1 * (m2 + 1)), start_row_index);             // occupies m cells
                    pos.x0 = CellPosition(this->W(4 + 2 * (m2 + 1) + 0 * m2), start_row_index);    // occupies m2 cells
                    pos.d0 = CellPosition(this->W(4 + 2 * (m2 + 1) + 1 * m2), start_row_index);    // occupies m2 cells

                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_atanh_div_by_pos &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.z), false);
                    }

                    result_type(const fix_atanh_div_by_pos &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.z), false);
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
                explicit fix_atanh_div_by_pos(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_atanh_div_by_pos(WitnessContainerType witness, ConstantContainerType constant,
                                     PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_atanh_div_by_pos(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_atanh_div_by_pos = fix_atanh_div_by_pos<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType,
                                                                     ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using value_type = typename BlueprintFieldType::value_type;
                const uint8_t m1 = component.get_m1();
                const uint8_t m2 = component.get_m2();
                const value_type delta = value_type(component.get_delta());
                const value_type h = component.get_h();
                const value_type one = value_type::one();

                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(splat(var_pos.x)) = x_val;

                std::vector<uint16_t> x0_val;
                value_type s_x_val;
                {
                    auto sign = FixedPointHelper<BlueprintFieldType>::decompose(x_val, x0_val);
                    BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= m2);
                    s_x_val = sign ? -one : one;
                    for (auto i = 0; i < m2; i++) {
                        assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                    }
                    assignment.witness(splat(var_pos.s_x)) = s_x_val;
                }
                std::vector<uint16_t> d0_val;
                {
                    auto sign = FixedPointHelper<BlueprintFieldType>::decompose(h - s_x_val * x_val, d0_val);
                    BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m2);
                    BLUEPRINT_RELEASE_ASSERT(!sign && "input to atanh is not in the range (-1, 1)");
                    for (auto i = 0; i < m2; i++) {
                        assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = d0_val[i];
                    }
                }
                // x_val is in (-1, 1).

                value_type dividend = delta + x_val;    // always positive
                value_type divisor = delta - x_val;     // always positive
                DivMod<BlueprintFieldType> tmp_div =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(dividend * delta, divisor);
                auto z_val = tmp_div.quotient;
                assignment.witness(splat(var_pos.z)) = z_val;
                {
                    std::vector<uint16_t> checker_decomp;
                    uint64_t upper = 0;
                    auto m = m1 + m2;
                    if (2 == m) {
                        upper = 4294967295ULL;    // 2^32 - 1
                    } else if (3 == m) {
                        upper = 281474976710655ULL;    // 2^48 - 1
                    } else if (4 == m) {
                        upper = 18446744073709551615ULL;    // 2^64 - 1
                    }
                    value_type checker = value_type(upper) - z_val;
                    auto sign = FixedPointHelper<BlueprintFieldType>::decompose(checker, checker_decomp);
                    BLUEPRINT_RELEASE_ASSERT(!sign && "result is too large, input range check not tight enough");
                }

                std::vector<uint16_t> q0_val;
                std::vector<uint16_t> a0_val;

                auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp_div.remainder, q0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(divisor - tmp_div.remainder - 1, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= (m2 + 1));
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= (m2 + 1));

                auto divisor_tmp_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(divisor);
                assignment.witness(splat(var_pos.c)) = value_type(divisor_tmp_.limbs()[0] & 1);

                for (auto i = 0; i < (m2 + 1); i++) {    // divisor is < 2 --> one pre-comma limb is enough
                    assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                }

                return
                    typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::var;
                // 2x\Delta_z + y - c = 2zy + 2q and proving 0 <= q < y
                auto m2 = component.get_m2();
                auto delta = component.get_delta();
                auto h = component.get_h();

                auto q0 = nil::crypto3::math::expression(var(splat(var_pos.q0)));
                auto a0 = nil::crypto3::math::expression(var(splat(var_pos.a0)));
                for (auto i = 1; i < (m2 + 1); i++) {
                    q0 += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                    a0 += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                }

                auto x0 = nil::crypto3::math::expression(var(splat(var_pos.x0)));
                auto d0 = nil::crypto3::math::expression(var(splat(var_pos.d0)));
                for (auto i = 1; i < m2; i++) {
                    x0 += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                    d0 += var(var_pos.d0.column() + i, var_pos.d0.row()) * (1ULL << (16 * i));
                }

                auto x = var(splat(var_pos.x));
                auto s_x = var(splat(var_pos.s_x));
                auto z = var(splat(var_pos.z));
                auto c = var(splat(var_pos.c));

                auto dividend = delta + x;
                auto divisor = delta - x;

                // decomp and range check constraints
                auto constraint_1 = x - s_x * x0;
                auto constraint_2 = (s_x - 1) * (s_x + 1);
                auto constraint_3 = d0 - h + x0;

                // div by pos constraints
                auto constraint_4 = 2 * (dividend * delta - divisor * z - q0) + divisor - c;
                auto constraint_5 = (c - 1) * c;
                auto constraint_6 = divisor - q0 - a0 - 1;

                return bp.add_gate(
                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m2 = component.get_m2();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                for (auto i = 0; i < (m2 + 1); i++) {
                    constraint_type constraint_q0, constraint_a0;
                    constraint_q0.table_id = table_id;
                    constraint_a0.table_id = table_id;

                    auto qi = var(var_pos.q0.column() + i, var_pos.q0.row());
                    auto ai = var(var_pos.a0.column() + i, var_pos.a0.row());
                    constraint_q0.lookup_input = {qi};
                    constraint_a0.lookup_input = {ai};
                    constraints.push_back(constraint_q0);
                    constraints.push_back(constraint_a0);
                }

                for (auto i = 0; i < m2; i++) {
                    constraint_type constraint_x0, constraint_d0;
                    constraint_x0.table_id = table_id;
                    constraint_d0.table_id = table_id;

                    auto xi = var(var_pos.x0.column() + i, var_pos.x0.row());
                    auto di = var(var_pos.d0.column() + i, var_pos.d0.row());
                    constraint_x0.lookup_input = {xi};
                    constraint_d0.lookup_input = {di};
                    constraints.push_back(constraint_x0);
                    constraints.push_back(constraint_d0);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType,
                                                                     ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index + component.rows_amount - 1);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return
                    typename plonk_fixedpoint_atanh_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATANH_DIV_BY_POSITIVE_HPP
