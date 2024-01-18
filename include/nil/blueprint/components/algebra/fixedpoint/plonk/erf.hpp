#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ERF_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ERF_HPP

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

            // Works by decomposing the input, computing erf(x) for positive x, and using erf(-x) == -erf(x). erf(x)
            // is computed using an approximation formula that gets implemented using custom rescale and division
            // operations. The input x is checked to be in the range [-h, h] and if it is not, the output is set to -1
            // or 1, respectively, where h is 3.625.

            // The approximation formula is
            //
            // erf(x) = 1 - (1/(g(x))^16) + epsilon(x)
            //
            // where
            //
            // g(x) = 1 + a1 * x + a2 * x^2 + a3 * x^3 + a4 * x^4 + a5 * x^5 + a6 * x^6
            //
            // and
            //
            // | epsilon(x) | <= 3*10^(-7)
            //
            // for 0 <= x < inf

            /**
             * Component representing an erf operation using an approximation formula.
             *
             * The delta of y is equal to the delta of x.
             *
             * The error is <= 3*10^(-7) when using 32 after comma bits (FixedPoint .32) and <= 8*10^(-6) when
             * using 16 after comma bits (FixedPoint .16) for all x in the full FixedPoint domain.
             *
             * Input:    x  ... field element
             * Output:   y  ... erf(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_erf;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_erf<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                uint64_t get_internal_delta() const {
                    return 1ULL << (16 * 2);
                }

                static std::size_t get_num_witness_variables(uint8_t m1, uint8_t m2) {
                    return 44;
                }

                static std::size_t get_witness_columns(uint8_t m1, uint8_t m2) {
                    // Always 15.
                    std::size_t var_count = get_num_witness_variables(m1, m2);
                    std::size_t row_count = get_rows_amount(15, 0, m1, m2);
                    return var_count % row_count == 0 ? var_count / row_count : var_count / row_count + 1;
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
                /**
                 * Returns the constants for the polynomial in the divisor of the approximation of erf(x).
                 * let g(x) = 1 + a1*x + a2*x^2 + a3*x^3 + a4*x^4 + a5*x^5 + a6*x^6
                 * erf(x) ~ 1 - 1/(g(x))^16
                 * where
                 * a1 = 0.0705230784
                 * a2 = 0.0422820123
                 * a3 = 0.0092705272
                 * a4 = 0.0001520143
                 * a5 = 0.0002765672
                 * a6 = 0.0000430638
                 */
                static constexpr const value_type get_a(size_t i) {
                    switch (i) {
                        case 1:
                            return value_type(302894315ULL);
                        case 2:
                            return value_type(181599860ULL);
                        case 3:
                            return value_type(39816611ULL);
                        case 4:
                            return value_type(652896ULL);
                        case 5:
                            return value_type(1187847ULL);
                        case 6:
                            return value_type(184958ULL);
                        default:
                            break;
                    }
                    BLUEPRINT_RELEASE_ASSERT(false);
                    return value_type::zero();
                }

                static constexpr const value_type get_h() {
                    return value_type(15569256448ULL);    // == 3.625
                }

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_erf::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
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
                    // Always 3.
                    std::size_t var_count = get_num_witness_variables(m1, m2);
                    return var_count % 15 == 0 ? var_count / 15 : var_count / 15 + 1;
                }

#ifdef TEST_WITHOUT_LOOKUP_TABLES
                static constexpr const std::size_t gates_amount = 2;
#else
                static constexpr const std::size_t gates_amount = 4;
#endif

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                struct input_type {
                    var input = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {input};
                    }
                };

                struct var_positions {
                    // y ~ erf(x), x decomposed into x0 (x0 occupies 2+m1 cells) and s_x, xpn means x^n, gpn means g^n,
                    // g is the polynomial of the approximation, c is the correction term for the division, r0 to r7 are
                    // the remainders for the rescale operations (each rn occupies 2 cells), q0 is the remainder of the
                    // division, b0 is a0 in the div_by_pos component (q0 and b0 occupy 2+m1 cells each), d0 (occupies
                    // 2+m1 cells) and s_d are used for performing a range check on the absolute value of the input |x|.
                    CellPosition x, y, s_x, s_d, x0, d0, xp2, xp3, g, gp2, gp4, gp8, gp16, c, r0, r1, r2, r4, r5, r6,
                        r7, q0, b0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    auto m1 = this->get_m1();
                    auto m2 = this->get_m2();
                    var_positions pos;

                    // trace layout (15 col(s), 3 row(s))
                    //
                    //  r\c|  0  |  1  |  2  |  3  |  4  | 5  | 6  | 7  | 8  | 9  | 10 | 11 | 12 | 13 | 14 |
                    // +---+-----+-----+-----+-----+-----+----+----+----+----+----+----+----+----+----+----+
                    // | 0 |  x  | xp2 | xp3 |  g  |  -  |    r0   |         x0        |         d0        |
                    // | 1 | s_x | s_d | gp2 |     r1    |         r2        |    r4   |         b0        |
                    // | 2 |  y  |  c  | gp4 | gp8 | gp16|    r5   |    r6   |    r7   |         q0        |

                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.xp2 = CellPosition(this->W(1), start_row_index);
                    pos.xp3 = CellPosition(this->W(2), start_row_index);
                    pos.g = CellPosition(this->W(3), start_row_index);
                    pos.r0 = CellPosition(this->W(5 + 0 * 2), start_row_index);    // occupies 2 cells
                    pos.x0 = CellPosition(this->W(7 + 0 * 4), start_row_index);    // occupies 4 cells
                    pos.d0 = CellPosition(this->W(7 + 1 * 4), start_row_index);    // occupies 4 cells

                    pos.s_x = CellPosition(this->W(0), start_row_index + 1);
                    pos.s_d = CellPosition(this->W(1), start_row_index + 1);
                    pos.gp2 = CellPosition(this->W(2), start_row_index + 1);
                    pos.r1 = CellPosition(this->W(3 + 0 * 2), start_row_index + 1);     // occupies 2 cells
                    pos.r2 = CellPosition(this->W(5 + 0 * 4), start_row_index + 1);     // occupies 4 cells
                    pos.r4 = CellPosition(this->W(9 + 0 * 2), start_row_index + 1);     // occupies 2 cells
                    pos.b0 = CellPosition(this->W(11 + 0 * 4), start_row_index + 1);    // occupies 4 cells

                    pos.y = CellPosition(this->W(0), start_row_index + 2);
                    pos.c = CellPosition(this->W(1), start_row_index + 2);
                    pos.gp4 = CellPosition(this->W(2), start_row_index + 2);
                    pos.gp8 = CellPosition(this->W(3), start_row_index + 2);
                    pos.gp16 = CellPosition(this->W(4), start_row_index + 2);
                    pos.r5 = CellPosition(this->W(5 + 0 * 2), start_row_index + 2);     // occupies 2 cells
                    pos.r6 = CellPosition(this->W(5 + 1 * 2), start_row_index + 2);     // occupies 2 cells
                    pos.r7 = CellPosition(this->W(5 + 2 * 2), start_row_index + 2);     // occupies 2 cells
                    pos.q0 = CellPosition(this->W(11 + 0 * 4), start_row_index + 2);    // occupies 4 cells

                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_erf &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_erf &component, std::size_t start_row_index) {
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
                explicit fix_erf(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_erf(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_erf(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_erf =
                fix_erf<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                component.initialize_assignment(assignment, start_row_index);

                using value_type = typename BlueprintFieldType::value_type;
                const auto one = value_type::one();
                const auto zero = value_type::zero();
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto m1 = component.get_m1();
                const auto m2 = component.get_m2();
                const auto delta = value_type(component.get_internal_delta());    // "big" delta (32 bit)
                value_type target_delta = delta;
                if (1 == m2) {
                    target_delta = value_type(component.get_delta());
                }

                auto x_input_val = var_value(assignment, instance_input.input);
                assignment.witness(splat(var_pos.x)) = x_input_val;
                std::vector<uint16_t> x0_val;

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(x_input_val, x0_val);
                auto s_x_val = sign ? -one : one;
                assignment.witness(splat(var_pos.s_x)) = s_x_val;
                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= m1 + m2);

                auto x_val = sign ? -x_input_val : x_input_val;
                if (1 == m2) {
                    x_val *= value_type(component.get_delta());    // "small" delta (16 bit)
                    x0_val.insert(x0_val.begin(), 0);
                }
                if (1 == m1) {
                    x0_val.insert(x0_val.end(), 0);    // ensure that x0_val has at least 4 elems
                }
                // x_val now uses the "big" delta

                for (auto i = 0; i < 4; i++) {
                    assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                }

                {
                    const auto h_val = component.get_h();
                    std::vector<uint16_t> d0_val;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(h_val - x_val, d0_val);
                    auto s_d_val = sign ? one : zero;    // if sign of d == one --> out of range [-h, h].
                    assignment.witness(splat(var_pos.s_d)) = s_d_val;
                    BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= 4);
                    for (auto i = 0; i < 4; i++) {
                        assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = d0_val[i];
                    }
                    if (s_d_val == one) {
                        // out of range, just set the result to sign of x and return
                        // assumption: all undefined cells were initialized with zero (lookup constraints!)
                        assignment.witness(splat(var_pos.y)) = s_x_val * target_delta;
                        return typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::result_type(
                            component, start_row_index);
                    }
                }

                auto mul_rescale = [&delta, &assignment](const value_type &expr, const CellPosition &result_pos,
                                                         const CellPosition &remainder_pos,
                                                         uint8_t num_deltas = 1) -> value_type {
                    value_type actual_delta = value_type::one();
                    for (auto i = 0; i < num_deltas; i++) {
                        actual_delta *= delta;
                    }
                    DivMod<BlueprintFieldType> res =
                        FixedPointHelper<BlueprintFieldType>::round_div_mod(expr, actual_delta);

                    value_type result_val = res.quotient;
                    value_type remainder_val = res.remainder;

                    assignment.witness(splat(result_pos)) = result_val;

                    std::vector<uint16_t> remainder_val_decomp;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(remainder_val, remainder_val_decomp);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    BLUEPRINT_RELEASE_ASSERT(remainder_val_decomp.size() >= 2 * num_deltas);
                    for (auto i = 0; i < 2 * num_deltas; i++) {
                        assignment.witness(remainder_pos.column() + i, remainder_pos.row()) = remainder_val_decomp[i];
                    }

                    return result_val;
                };

                value_type xp2_val = mul_rescale(x_val * x_val, var_pos.xp2, var_pos.r0);
                value_type xp3_val = mul_rescale(xp2_val * x_val, var_pos.xp3, var_pos.r1);

                value_type g_val = mul_rescale(delta * delta * delta +                         // 1 +
                                                   component.get_a(1) * x_val * delta +        // a1 * x^1 +
                                                   component.get_a(2) * xp2_val * delta +      // a2 * x^2 +
                                                   component.get_a(3) * xp3_val * delta +      // a3 * x^3 +
                                                   component.get_a(4) * xp2_val * xp2_val +    // a4 * x^4 +
                                                   component.get_a(5) * xp3_val * xp2_val +    // a5 * x^5 +
                                                   component.get_a(6) * xp3_val * xp3_val,     // a6 * x^6
                                               var_pos.g, var_pos.r2, 2);

                value_type gp2_val = mul_rescale(g_val * g_val, var_pos.gp2, var_pos.r4);
                value_type gp4_val = mul_rescale(gp2_val * gp2_val, var_pos.gp4, var_pos.r5);
                value_type gp8_val = mul_rescale(gp4_val * gp4_val, var_pos.gp8, var_pos.r6);
                value_type gp16_val = mul_rescale(gp8_val * gp8_val, var_pos.gp16, var_pos.r7);

                // compute 1/g(x)^16
                value_type y_val;
                {
                    DivMod<BlueprintFieldType> tmp_div =
                        FixedPointHelper<BlueprintFieldType>::round_div_mod(delta * target_delta, gp16_val);
                    value_type gp16_inv_val = tmp_div.quotient;

                    std::vector<uint16_t> q0_val;
                    std::vector<uint16_t> b0_val;

                    auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp_div.remainder, q0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    sign = FixedPointHelper<BlueprintFieldType>::decompose(gp16_val - tmp_div.remainder - 1, b0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= 4);
                    BLUEPRINT_RELEASE_ASSERT(b0_val.size() >= 4);

                    auto y_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(gp16_val);
                    assignment.witness(splat(var_pos.c)) = typename BlueprintFieldType::value_type(y_.limbs()[0] & 1);

                    for (auto i = 0; i < 4; i++) {
                        assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                        assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = b0_val[i];
                    }

                    // erf(x) = 1 - 1/g(x)^16
                    y_val = s_x_val * (target_delta - gp16_inv_val);
                    assignment.witness(splat(var_pos.y)) = y_val;
                }

                return typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_first_gate(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t start_row_index = 1 - 2;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(
                    start_row_index));    // only vars in the first and second row are valid for this gate

                using var = typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::var;

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;

                const auto m = component.get_m();
                const auto m1 = component.get_m1();
                const auto m2 = component.get_m2();
                const auto delta = typename BlueprintFieldType::value_type(component.get_internal_delta());

                // this below is an empty expression, didn't know how to declare that
                auto x_inp = nil::crypto3::math::expression(var(splat(var_pos.x0)) - var(splat(var_pos.x0)));
                if (2 == m2) {
                    x_inp = nil::crypto3::math::expression(var(splat(var_pos.x0)));
                }

                auto x_abs = nil::crypto3::math::expression(var(splat(var_pos.x0)));
                auto d = nil::crypto3::math::expression(var(splat(var_pos.d0)));
                auto x = nil::crypto3::math::expression(var(splat(var_pos.x)));
                auto s_x = nil::crypto3::math::expression(var(splat(var_pos.s_x)));
                auto s_d = nil::crypto3::math::expression(var(splat(var_pos.s_d)));
                auto xp2 = nil::crypto3::math::expression(var(splat(var_pos.xp2)));
                auto xp3 = nil::crypto3::math::expression(var(splat(var_pos.xp3)));
                auto gp2 = nil::crypto3::math::expression(var(splat(var_pos.gp2)));
                auto g = nil::crypto3::math::expression(var(splat(var_pos.g)));
                for (auto i = 1; i < 4; i++) {
                    x_abs += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                    x_inp += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * (i + m2 - 2)));
                    d += var(var_pos.d0.column() + i, var_pos.d0.row()) * (1ULL << (16 * i));
                }

                auto r0 = nil::crypto3::math::expression(var(splat(var_pos.r0)));
                auto r1 = nil::crypto3::math::expression(var(splat(var_pos.r1)));
                auto r2 = nil::crypto3::math::expression(var(splat(var_pos.r2)));
                auto r4 = nil::crypto3::math::expression(var(splat(var_pos.r4)));
                for (auto i = 1; i < 2; i++) {
                    r0 += var(var_pos.r0.column() + i, var_pos.r0.row()) * (1ULL << (16 * i));
                    r1 += var(var_pos.r1.column() + i, var_pos.r1.row()) * (1ULL << (16 * i));
                    r4 += var(var_pos.r4.column() + i, var_pos.r4.row()) * (1ULL << (16 * i));
                }
                for (auto i = 1; i < 4; i++) {
                    r2 += var(var_pos.r2.column() + i, var_pos.r2.row()) * (1ULL << (16 * i));
                }

                auto h = component.get_h();

                // constraint construction
                auto cnstrnt_decomp_x = x - s_x * x_inp;
                auto cnstrnt_s_x = (s_x - 1) * (s_x + 1);
                auto cnstrnt_decomp_d = (h - x_abs) + s_d * d - (1 - s_d) * d;
                auto cnstrnt_s_d = s_d * (1 - s_d);
                auto cnstrnt_mul_resc_xp2 = (1 - s_d) * (2 * (x_abs * x_abs - xp2 * delta - r0) + delta);
                auto cnstrnt_mul_resc_xp3 = (1 - s_d) * (2 * (xp2 * x_abs - xp3 * delta - r1) + delta);

                auto g_computation = delta * delta * delta +                 // 1 +
                                     component.get_a(1) * x_abs * delta +    // a1 * x^1 +
                                     component.get_a(2) * xp2 * delta +      // a2 * x^2 +
                                     component.get_a(3) * xp3 * delta +      // a3 * x^3 +
                                     component.get_a(4) * xp2 * xp2 +        // a4 * x^4 +
                                     component.get_a(5) * xp3 * xp2 +        // a5 * x^5 +
                                     component.get_a(6) * xp3 * xp3;         // a6 * x^6

                auto cnstrnt_mul_resc_g = (1 - s_d) * (2 * (g_computation - g * delta * delta - r2) + delta * delta);

                auto cnstrnt_mul_resc_gp2 = (1 - s_d) * (2 * (g * g - gp2 * delta - r4) + delta);

                if (1 == m2) {
                    // enforce the additional limb to be zero
                    constraints.push_back(var(splat(var_pos.x0)));
                }

                constraints.push_back(cnstrnt_decomp_x);
                constraints.push_back(cnstrnt_s_x);
                constraints.push_back(cnstrnt_decomp_d);
                constraints.push_back(cnstrnt_s_d);
                constraints.push_back(cnstrnt_mul_resc_xp2);
                constraints.push_back(cnstrnt_mul_resc_xp3);
                constraints.push_back(cnstrnt_mul_resc_g);
                constraints.push_back(cnstrnt_mul_resc_gp2);

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_second_gate(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(
                    start_row_index));    // only vars in the second and third row are valid for this gate

                using var = typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::var;

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;

                const auto m = component.get_m();
                const auto m1 = component.get_m1();
                const auto m2 = component.get_m2();
                const auto delta = typename BlueprintFieldType::value_type(component.get_internal_delta());
                const auto target_delta = typename BlueprintFieldType::value_type(component.get_delta());

                auto q = nil::crypto3::math::expression(var(splat(var_pos.q0)));
                auto b = nil::crypto3::math::expression(var(splat(var_pos.b0)));
                auto s_x = nil::crypto3::math::expression(var(splat(var_pos.s_x)));
                auto s_d = nil::crypto3::math::expression(var(splat(var_pos.s_d)));
                auto y = nil::crypto3::math::expression(var(splat(var_pos.y)));
                auto c = nil::crypto3::math::expression(var(splat(var_pos.c)));
                auto gp2 = nil::crypto3::math::expression(var(splat(var_pos.gp2)));
                auto gp4 = nil::crypto3::math::expression(var(splat(var_pos.gp4)));
                auto gp8 = nil::crypto3::math::expression(var(splat(var_pos.gp8)));
                auto gp16 = nil::crypto3::math::expression(var(splat(var_pos.gp16)));
                for (auto i = 1; i < 4; i++) {
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                    b += var(var_pos.b0.column() + i, var_pos.b0.row()) * (1ULL << (16 * i));
                }
                auto r5 = nil::crypto3::math::expression(var(splat(var_pos.r5)));
                auto r6 = nil::crypto3::math::expression(var(splat(var_pos.r6)));
                auto r7 = nil::crypto3::math::expression(var(splat(var_pos.r7)));
                for (auto i = 1; i < 2; i++) {
                    r5 += var(var_pos.r5.column() + i, var_pos.r5.row()) * (1ULL << (16 * i));
                    r6 += var(var_pos.r6.column() + i, var_pos.r6.row()) * (1ULL << (16 * i));
                    r7 += var(var_pos.r7.column() + i, var_pos.r7.row()) * (1ULL << (16 * i));
                }

                auto cnstrnt_mul_resc_gp4 = (1 - s_d) * (2 * (gp2 * gp2 - gp4 * delta - r5) + delta);
                auto cnstrnt_mul_resc_gp8 = (1 - s_d) * (2 * (gp4 * gp4 - gp8 * delta - r6) + delta);
                auto cnstrnt_mul_resc_gp16 = (1 - s_d) * (2 * (gp8 * gp8 - gp16 * delta - r7) + delta);
                auto cnstrnt_div_gp16_1 =
                    (1 - s_d) * (2 * (delta * target_delta - gp16 * (target_delta - s_x * y) - q) + gp16 - c);
                auto cnstrnt_div_gp16_2 = (c - 1) * c;
                auto cnstrnt_div_gp16_3 = (1 - s_d) * (gp16 - q - b - 1);
                auto cnstrnt_oor = s_d * (y - s_x * target_delta);    // out of range [-h, h] --> map to -1 or 1

                constraints.push_back(cnstrnt_mul_resc_gp4);
                constraints.push_back(cnstrnt_mul_resc_gp8);
                constraints.push_back(cnstrnt_mul_resc_gp16);
                constraints.push_back(cnstrnt_div_gp16_1);
                constraints.push_back(cnstrnt_div_gp16_2);
                constraints.push_back(cnstrnt_div_gp16_3);
                constraints.push_back(cnstrnt_oor);

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_first_lookup_gate(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                // lookup constraint for rows 0, 1, 2 for variables rn, x0, d0, b0, q0

                for (size_t i = 5; i < 15; i++) {
                    constraint_type cnstrnt;
                    cnstrnt.table_id = table_id;
                    cnstrnt.lookup_input = {var(component.W(i), 0)};
                    constraints.push_back(cnstrnt);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_second_lookup_gate(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                // lookup constraint for row 1 for variable r1

                for (size_t i = 3; i < 5; i++) {
                    constraint_type cnstrnt;
                    cnstrnt.table_id = table_id;
                    cnstrnt.lookup_input = {var(component.W(i), 0)};
                    constraints.push_back(cnstrnt);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.input, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index_first = generate_first_gate(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index_first, start_row_index + 2 - 1);
                std::size_t selector_index_second = generate_second_gate(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index_second, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index_first =
                    generate_first_lookup_gate(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index_first, start_row_index,
                                           start_row_index + component.rows_amount - 1);

                std::size_t lookup_selector_index_second =
                    generate_second_lookup_gate(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index_second, start_row_index + 1);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_erf<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ERF_HPP
