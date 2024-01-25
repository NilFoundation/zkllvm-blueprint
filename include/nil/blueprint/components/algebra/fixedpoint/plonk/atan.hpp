#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATAN_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATAN_HPP

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

            // Works by evaluating a taylor series with corrections for intervals outside of 0 <= x <= 0.7

            /**
             * Component representing a atan operation with input x and output y, where y = atan(x).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... atan(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_atan;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_atan<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

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

                value_type calc_atan(const value_type &x, uint8_t m1, uint8_t m2) const {
                    if (m1 == 1 && m2 == 1) {
                        auto el = FixedPoint<BlueprintFieldType, 1, 1>(x, 16);
                        return el.atan().get_value();
                    } else if (m1 == 2 && m2 == 1) {
                        auto el = FixedPoint<BlueprintFieldType, 2, 1>(x, 16);
                        return el.atan().get_value();
                    } else if (m1 == 1 && m2 == 2) {
                        auto el = FixedPoint<BlueprintFieldType, 1, 2>(x, 32);
                        return el.atan().get_value();
                    } else if (m1 == 2 && m2 == 2) {
                        auto el = FixedPoint<BlueprintFieldType, 2, 2>(x, 32);
                        return el.atan().get_value();
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                        return 0;
                    }
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_atan::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    auto value = M(m1) == 1 ? 12 : 13;
                    value = M(m2) == 2 ? 15 : value;
                    manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(value)), false);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    return 6;
                }

// Includes the constraints + lookup_gates
#ifdef TEST_WITHOUT_LOOKUP_TABLES
                constexpr static const std::size_t gates_amount = 6;
#else
                constexpr static const std::size_t gates_amount = 9;
#endif    // TEST_WITHOUT_LOOKUP_TABLES

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, sx, gt1, s1, eq1, inv1, a0, b0;
                    CellPosition y1, abs, ainv, c1, c0, d0, pad1;
                    CellPosition x1, gt2, num, denom, s2, eq2, inv2, z1, e0, f0;
                    CellPosition y2, num1, denom1, x3, gt3, z2, c2, g0, h0;
                    CellPosition p2, p3, p33, p5, p55, p20, p30, p330, p50, p550;
                    CellPosition y, t1, t3, t5, f1, f2, f3, i1, i2;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m2 = this->get_m2();
                    auto m = this->get_m();
                    var_positions pos;

                    // trace layout (between 11 and 15 columns, 6 row(s))
                    //
                    // First row calculates the abs value (a0..am-1) and compares it to 1 (gt1)
                    // Second row takes the inverse of abs if gt1=1, otherwise it takes the abs value
                    // Third row compares the output of the second row to 0.7 (gt2), and prepares the division for the
                    // next row Fourth row calculates the a division and takes the result if gt2=1, otherwise it takes
                    // the result of the second row Fifth row calculates the taylor polynomial Sixth row calculates the
                    // output from the flags sx, gt1, gt2, and the taylor polynomial
                    //
                    // pad1 is just here to allow the same lookup table gate in row0, row1, and row3 (lookup is always
                    // true for gt3)
                    //
                    //       |                witness
                    //   r\c | 0  |  1   |   2    |   3   |  4  |  ..  |  ..  |  ..  |  ..  |  .. | .. |  ..  |  ..  |
                    //   ..  | .. |
                    // +-----+----+------+--------+-------+-----+------+------+------+------+-----+----+------+------+------+----|
                    // |  0  | x  | sx   | gt1    | s1    | eq1 | inv1 | a0   |  ..  | am-1 | b0  | .. | bm   |
                    // |  1  | y1 | abs  | ainv   | c1    |  -  |  -   | c0   |  ..  | cm-1 | d0  | .. | dm-1 | pad1 |
                    // |  2  | x1 | gt2  | num    | denom | s2  | eq2  | inv2 | z1   | e0   |  .. | em | f0   |  ..  |
                    // |  3  | y2 | num1 | denom1 | x3    | c2  | z2   | gt3  | g0   |  ..  | gm-1 | h0  | .. | hm-1 |
                    // |  4  | p2 | p3   | p33    | p5    | p55 | p20  | ..   | p30  |  ..  | p50 | .. | p55  | ..   |
                    // p550 | .. |
                    // | 5 | y | t1 | t3 | t5 | f1 | f2 | f3 | i1 | i2 |

                    // columns:
                    // 0: 7 + 2 * m
                    // 1: 4 + 2 * m
                    // 2: 9 + m + m2
                    // 3: 7 + 2 * m
                    // 4: 5 + 5 * m2
                    // 5: 9

                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.sx = CellPosition(this->W(1), start_row_index);
                    pos.gt1 = CellPosition(this->W(2), start_row_index);
                    pos.s1 = CellPosition(this->W(3), start_row_index);
                    pos.eq1 = CellPosition(this->W(4), start_row_index);
                    pos.inv1 = CellPosition(this->W(5), start_row_index);
                    pos.a0 = CellPosition(this->W(6 + 0 * m), start_row_index);    // occupies m cells
                    pos.b0 = CellPosition(this->W(6 + 1 * m), start_row_index);    // occupies m + 1 cells

                    pos.y1 = CellPosition(this->W(0), start_row_index + 1);
                    pos.abs = CellPosition(this->W(1), start_row_index + 1);
                    pos.ainv = CellPosition(this->W(2), start_row_index + 1);
                    pos.c1 = CellPosition(this->W(3), start_row_index + 1);
                    pos.c0 = CellPosition(this->W(6 + 0 * m), start_row_index + 1);    // occupies m cells
                    pos.d0 = CellPosition(this->W(6 + 1 * m), start_row_index + 1);    // occupies m cells
                    pos.pad1 = CellPosition(this->W(6 + 2 * m), start_row_index + 1);

                    pos.x1 = CellPosition(this->W(0), start_row_index + 2);
                    pos.gt2 = CellPosition(this->W(1), start_row_index + 2);
                    pos.num = CellPosition(this->W(2), start_row_index + 2);
                    pos.denom = CellPosition(this->W(3), start_row_index + 2);
                    pos.s2 = CellPosition(this->W(4), start_row_index + 2);
                    pos.eq2 = CellPosition(this->W(5), start_row_index + 2);
                    pos.inv2 = CellPosition(this->W(6), start_row_index + 2);
                    pos.z1 = CellPosition(this->W(7), start_row_index + 2);
                    pos.e0 = CellPosition(this->W(8 + 0 * (m + 1)), start_row_index + 2);    // occupies m + 1 cells
                    pos.f0 = CellPosition(this->W(8 + 1 * (m + 1)), start_row_index + 2);    // occupies m2 cells

                    pos.y2 = CellPosition(this->W(0), start_row_index + 3);
                    pos.num1 = CellPosition(this->W(1), start_row_index + 3);
                    pos.denom1 = CellPosition(this->W(2), start_row_index + 3);
                    pos.x3 = CellPosition(this->W(3), start_row_index + 3);
                    pos.c2 = CellPosition(this->W(4), start_row_index + 3);
                    pos.z2 = CellPosition(this->W(5), start_row_index + 3);
                    pos.gt3 = CellPosition(this->W(6), start_row_index + 3);
                    pos.g0 = CellPosition(this->W(7 + 0 * m), start_row_index + 3);    // occupies m cells
                    pos.h0 = CellPosition(this->W(7 + 1 * m), start_row_index + 3);    // occupies m2 cells

                    pos.p2 = CellPosition(this->W(0), start_row_index + 4);
                    pos.p3 = CellPosition(this->W(1), start_row_index + 4);
                    pos.p33 = CellPosition(this->W(2), start_row_index + 4);
                    pos.p5 = CellPosition(this->W(3), start_row_index + 4);
                    pos.p55 = CellPosition(this->W(4), start_row_index + 4);
                    pos.p20 = CellPosition(this->W(5 + 0 * m2), start_row_index + 4);     // occupies m2 cells
                    pos.p30 = CellPosition(this->W(5 + 1 * m2), start_row_index + 4);     // occupies m2 cells
                    pos.p330 = CellPosition(this->W(5 + 2 * m2), start_row_index + 4);    // occupies m2 cells
                    pos.p50 = CellPosition(this->W(5 + 3 * m2), start_row_index + 4);     // occupies m2 cells
                    pos.p550 = CellPosition(this->W(5 + 4 * m2), start_row_index + 4);    // occupies m2 cells

                    pos.y = CellPosition(this->W(0), start_row_index + 5);
                    pos.t1 = CellPosition(this->W(1), start_row_index + 5);
                    pos.t3 = CellPosition(this->W(2), start_row_index + 5);
                    pos.t5 = CellPosition(this->W(3), start_row_index + 5);
                    pos.f1 = CellPosition(this->W(4), start_row_index + 5);
                    pos.f2 = CellPosition(this->W(5), start_row_index + 5);
                    pos.f3 = CellPosition(this->W(6), start_row_index + 5);
                    pos.i1 = CellPosition(this->W(5), start_row_index + 5);
                    pos.i2 = CellPosition(this->W(6), start_row_index + 5);

                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_atan &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_atan &component, std::size_t start_row_index) {
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

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_atan(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_atan(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_atan =
                fix_atan<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename BlueprintFieldType::value_type generate_assignments_row0(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                // Basically combines abs and abs > 1

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                const auto one = BlueprintFieldType::value_type::one();
                const auto zero = BlueprintFieldType::value_type::zero();
                auto m = component.get_m();

                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(splat(var_pos.x)) = x_val;

                // abs
                std::vector<uint16_t> x0_val;
                auto sign = FixedPointHelper<BlueprintFieldType>::abs(x_val);
                assignment.witness(splat(var_pos.sx)) = sign ? -one : one;

                // decompose
                bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(x_val, x0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_);
                // is ok because x0_val is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= m);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = x0_val[i];
                }

                // abs > 1
                auto d_val = x_val - component.get_delta();
                std::vector<uint16_t> d0_val;
                sign = FixedPointHelper<BlueprintFieldType>::abs(d_val);
                sign_ = FixedPointHelper<BlueprintFieldType>::decompose(d_val, d0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_);
                // is ok because d0_val is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m);
                bool eq = d_val == 0;
                BLUEPRINT_RELEASE_ASSERT(eq && !sign || !eq);    // sign must be false if equal is true
                auto eq_val = typename BlueprintFieldType::value_type(static_cast<uint64_t>(eq));
                auto gt_val = typename BlueprintFieldType::value_type((uint64_t)(!eq && !sign));
                assignment.witness(splat(var_pos.eq1)) = eq_val;
                assignment.witness(splat(var_pos.gt1)) = gt_val;
                assignment.witness(splat(var_pos.s1)) = sign ? -one : one;

                // if eq:  Does not matter what to put here
                assignment.witness(splat(var_pos.inv1)) = eq ? zero : d_val.inversed();

                // Additional limb due to potential overflow of diff
                // FixedPointHelper::decompose creates a vector whose size is a multiple of 4.
                // Furthermore, the size of the vector might be larger than required (e.g. if 4 limbs would suffice the
                // vector could be of size 8)
                if (d0_val.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(d0_val[m] == 0 || d0_val[m] == 1);
                    assignment.witness(var_pos.b0.column() + m, var_pos.b0.row()) = d0_val[m];
                } else {
                    assignment.witness(var_pos.b0.column() + m, var_pos.b0.row()) = zero;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.b0.column() + i, var_pos.b0.row()) = d0_val[i];
                }

                return x_val;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_row1(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions &var_pos,
                typename BlueprintFieldType::value_type &abs) {

                // Basically a div_by_pos gadget, where x is hardcoded to be one.

                auto m = component.get_m();
                auto delta = component.get_delta();

                bool gt = abs > delta;

                auto x_val = typename BlueprintFieldType::value_type(delta) * delta;
                // Set the divisor to 1 if no division should happen to prevent division by zero
                auto y_val = gt ? abs : delta;

                DivMod<BlueprintFieldType> tmp_div = FixedPointHelper<BlueprintFieldType>::round_div_mod(x_val, y_val);
                auto z_val = tmp_div.quotient;

                assignment.witness(splat(var_pos.abs)) = y_val;
                assignment.witness(splat(var_pos.ainv)) = z_val;

                std::vector<uint16_t> q0_val;
                std::vector<uint16_t> a0_val;

                auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp_div.remainder, q0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(y_val - tmp_div.remainder - 1, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);

                auto y_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(y_val);
                assignment.witness(splat(var_pos.c1)) = typename BlueprintFieldType::value_type(y_.limbs()[0] & 1);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.c0.column() + i, var_pos.c0.row()) = q0_val[i];
                    assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = a0_val[i];
                }

                // We pad to have the same lookup gate as for row0
                assignment.witness(splat(var_pos.pad1)) = BlueprintFieldType::value_type::zero();

                // Finally, output depending on gt1
                assignment.witness(splat(var_pos.y1)) = gt ? z_val : abs;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_row2(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                // Basically a comparison of the input x > 0.7 and preparing the values for a division in hte next row

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto m = component.get_m();
                auto m2 = component.get_m2();
                auto delta = component.get_delta();
                const auto one = BlueprintFieldType::value_type::one();
                const auto zero = BlueprintFieldType::value_type::zero();

                // constants
                uint64_t sqrt3_3 = 0;
                uint64_t zero_7 = 0;

                if (m2 == 1) {
                    zero_7 = 45875;
                    sqrt3_3 = 37837;
                } else if (m2 == 2) {
                    zero_7 = 3006477107;
                    sqrt3_3 = 2479700525;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }

                // x_val > 0.7
                auto x_val = assignment.witness(splat(var_pos.y1));
                assignment.witness(splat(var_pos.x1)) = x_val;

                auto d_val = x_val - zero_7;
                std::vector<uint16_t> d0_val;
                bool sign = FixedPointHelper<BlueprintFieldType>::abs(d_val);
                bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(d_val, d0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_);
                // is ok because d0_val is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m);
                bool eq = d_val == 0;
                BLUEPRINT_RELEASE_ASSERT(eq && !sign || !eq);    // sign must be false if equal is true
                auto eq_val = typename BlueprintFieldType::value_type(static_cast<uint64_t>(eq));
                auto gt_val = typename BlueprintFieldType::value_type((uint64_t)(!eq && !sign));
                assignment.witness(splat(var_pos.eq2)) = eq_val;
                assignment.witness(splat(var_pos.gt2)) = gt_val;
                assignment.witness(splat(var_pos.s2)) = sign ? -one : one;

                // if eq:  Does not matter what to put here
                assignment.witness(splat(var_pos.inv2)) = eq ? zero : d_val.inversed();

                // Additional limb due to potential overflow of diff
                // FixedPointHelper::decompose creates a vector whose size is a multiple of 4.
                // Furthermore, the size of the vector might be larger than required (e.g. if 4 limbs would suffice the
                // vector could be of size 8)
                if (d0_val.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(d0_val[m] == 0 || d0_val[m] == 1);
                    assignment.witness(var_pos.e0.column() + m, var_pos.e0.row()) = d0_val[m];
                } else {
                    assignment.witness(var_pos.e0.column() + m, var_pos.e0.row()) = zero;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.e0.column() + i, var_pos.e0.row()) = d0_val[i];
                }

                // prepare the division
                auto num_val = (x_val - sqrt3_3) * delta;
                assignment.witness(splat(var_pos.num)) = num_val;

                // mul rescale
                auto tmp = x_val * sqrt3_3;
                auto res = FixedPointHelper<BlueprintFieldType>::round_div_mod(tmp, delta);

                auto z_val = res.quotient;
                auto q_val = res.remainder;
                assignment.witness(splat(var_pos.z1)) = z_val;

                if (component.get_m2() == 1) {
                    assignment.witness(splat(var_pos.f0)) = q_val;
                } else {
                    std::vector<uint16_t> q0_val;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(q_val, q0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    // is ok because q0_val is at least of size 4 and the biggest we have is 32.32
                    BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= m2);
                    for (auto i = 0; i < m2; i++) {
                        assignment.witness(var_pos.f0.column() + i, var_pos.f0.row()) = q0_val[i];
                    }
                }

                // Set the divisor to 1 if no division should happen to prevent division by zero
                auto denom_val = gt_val == one ? z_val + delta : delta;
                assignment.witness(splat(var_pos.denom)) = denom_val;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_row3(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                // Basically a div_by_positive gadget, and setting an output based on previous flags

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto m = component.get_m();
                auto zero = BlueprintFieldType::value_type::zero();
                auto one = BlueprintFieldType::value_type::one();

                auto x_val = assignment.witness(splat(var_pos.num));
                auto y_val = assignment.witness(splat(var_pos.denom));
                auto gt_val = assignment.witness(splat(var_pos.gt2));
                auto x = assignment.witness(splat(var_pos.x1));

                DivMod<BlueprintFieldType> tmp_div = FixedPointHelper<BlueprintFieldType>::round_div_mod(x_val, y_val);
                auto z_val = tmp_div.quotient;

                assignment.witness(splat(var_pos.num1)) = x_val;
                assignment.witness(splat(var_pos.denom1)) = y_val;
                assignment.witness(splat(var_pos.z2)) = z_val;
                assignment.witness(splat(var_pos.gt3)) = gt_val;
                assignment.witness(splat(var_pos.x3)) = x;

                std::vector<uint16_t> q0_val;
                std::vector<uint16_t> a0_val;

                FixedPointHelper<BlueprintFieldType>::abs(y_val);    // For gadgets using this gadget
                auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp_div.remainder, q0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(y_val - tmp_div.remainder - 1, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);

                auto y_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(y_val);
                assignment.witness(splat(var_pos.c2)) = typename BlueprintFieldType::value_type(y_.limbs()[0] & 1);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.g0.column() + i, var_pos.g0.row()) = q0_val[i];
                    assignment.witness(var_pos.h0.column() + i, var_pos.h0.row()) = a0_val[i];
                }

                // Finally, output depending on gt2
                BLUEPRINT_RELEASE_ASSERT(gt_val == one || gt_val == zero);
                assignment.witness(splat(var_pos.y2)) = gt_val == one ? z_val : x;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_row4(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                // Basically a taylor polynomial

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto delta = component.get_delta();
                auto m2 = component.get_m2();

                auto x_val = assignment.witness(splat(var_pos.y2));

                DivMod<BlueprintFieldType> res_x2 =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(x_val * x_val, delta);
                DivMod<BlueprintFieldType> res_x3 =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(res_x2.quotient * x_val, delta);
                DivMod<BlueprintFieldType> res_x5 =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(res_x2.quotient * res_x3.quotient, delta);

                DivMod<BlueprintFieldType> res_x33 = FixedPointHelper<BlueprintFieldType>::round_div_mod(
                    res_x3.quotient * static_cast<int64_t>(delta / 3.), delta);
                DivMod<BlueprintFieldType> res_x55 = FixedPointHelper<BlueprintFieldType>::round_div_mod(
                    res_x5.quotient * static_cast<int64_t>(delta / 5.), delta);

                assignment.witness(splat(var_pos.p2)) = res_x2.quotient;
                assignment.witness(splat(var_pos.p3)) = res_x3.quotient;
                assignment.witness(splat(var_pos.p33)) = res_x33.quotient;
                assignment.witness(splat(var_pos.p5)) = res_x5.quotient;
                assignment.witness(splat(var_pos.p55)) = res_x55.quotient;

                if (component.get_m2() == 1) {
                    assignment.witness(splat(var_pos.p20)) = res_x2.remainder;
                    assignment.witness(splat(var_pos.p30)) = res_x3.remainder;
                    assignment.witness(splat(var_pos.p330)) = res_x33.remainder;
                    assignment.witness(splat(var_pos.p50)) = res_x5.remainder;
                    assignment.witness(splat(var_pos.p550)) = res_x55.remainder;
                } else {
                    std::vector<uint16_t> q20_val;
                    std::vector<uint16_t> q30_val;
                    std::vector<uint16_t> q330_val;
                    std::vector<uint16_t> q50_val;
                    std::vector<uint16_t> q550_val;

                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(res_x2.remainder, q20_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    sign = FixedPointHelper<BlueprintFieldType>::decompose(res_x3.remainder, q30_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    sign = FixedPointHelper<BlueprintFieldType>::decompose(res_x33.remainder, q330_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    sign = FixedPointHelper<BlueprintFieldType>::decompose(res_x5.remainder, q50_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    sign = FixedPointHelper<BlueprintFieldType>::decompose(res_x55.remainder, q550_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    // is ok because q0_val is at least of size 4 and the biggest we have is 32.32
                    BLUEPRINT_RELEASE_ASSERT(q20_val.size() >= m2);
                    BLUEPRINT_RELEASE_ASSERT(q30_val.size() >= m2);
                    BLUEPRINT_RELEASE_ASSERT(q330_val.size() >= m2);
                    BLUEPRINT_RELEASE_ASSERT(q50_val.size() >= m2);
                    BLUEPRINT_RELEASE_ASSERT(q550_val.size() >= m2);
                    for (auto i = 0; i < m2; i++) {
                        assignment.witness(var_pos.p20.column() + i, var_pos.p20.row()) = q20_val[i];
                        assignment.witness(var_pos.p30.column() + i, var_pos.p30.row()) = q30_val[i];
                        assignment.witness(var_pos.p330.column() + i, var_pos.p330.row()) = q330_val[i];
                        assignment.witness(var_pos.p50.column() + i, var_pos.p50.row()) = q50_val[i];
                        assignment.witness(var_pos.p550.column() + i, var_pos.p550.row()) = q550_val[i];
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_row5(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                // Combine taylor with the corrections from the previous rows

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto m2 = component.get_m2();
                auto zero = BlueprintFieldType::value_type::zero();
                auto one = BlueprintFieldType::value_type::one();

                auto x_val = assignment.witness(splat(var_pos.y2));
                auto x33_val = assignment.witness(splat(var_pos.p33));
                auto x55_val = assignment.witness(splat(var_pos.p55));
                auto shift_val = assignment.witness(splat(var_pos.gt2));
                auto invert_val = assignment.witness(splat(var_pos.gt1));
                auto sign_val = assignment.witness(splat(var_pos.sx));

                assignment.witness(splat(var_pos.t1)) = x_val;
                assignment.witness(splat(var_pos.t3)) = x33_val;
                assignment.witness(splat(var_pos.t5)) = x55_val;
                assignment.witness(splat(var_pos.f1)) = shift_val;
                assignment.witness(splat(var_pos.f2)) = invert_val;
                assignment.witness(splat(var_pos.f3)) = sign_val;

                BLUEPRINT_RELEASE_ASSERT(shift_val == one || shift_val == zero);
                BLUEPRINT_RELEASE_ASSERT(invert_val == one || invert_val == zero);
                BLUEPRINT_RELEASE_ASSERT(sign_val == one || sign_val == -one);

                uint64_t pi_2 = 0;
                uint64_t pi_6 = 0;
                if (m2 == 1) {
                    pi_2 = 102944;
                    pi_6 = 34315;
                } else if (m2 == 2) {
                    pi_2 = 6746518852;
                    pi_6 = 2248839617;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }

                auto poly_val = x_val - x33_val + x55_val;
                if (shift_val == one) {
                    poly_val += pi_6;
                }
                assignment.witness(splat(var_pos.i1)) = poly_val;

                if (invert_val == one) {
                    poly_val = pi_2 - poly_val;
                }
                assignment.witness(splat(var_pos.i2)) = poly_val;

                if (sign_val == -one) {
                    poly_val = -poly_val;
                }
                assignment.witness(splat(var_pos.y)) = poly_val;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto abs = generate_assignments_row0(component, assignment, instance_input, var_pos);
                generate_assignments_row1(component, assignment, var_pos, abs);
                generate_assignments_row2(component, assignment, var_pos);
                generate_assignments_row3(component, assignment, var_pos);
                generate_assignments_row4(component, assignment, var_pos);
                generate_assignments_row5(component, assignment, var_pos);

                return typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gate0(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto delta = component.get_delta();
                auto m = component.get_m();

                auto a = nil::crypto3::math::expression(var(var_pos.a0.column(), 0, false));
                auto b = nil::crypto3::math::expression(var(var_pos.b0.column(), 0, false));
                for (auto i = 1; i < m; i++) {
                    a += var(var_pos.a0.column() + i, 0) * (1ULL << (16 * i));
                    b += var(var_pos.b0.column() + i, 0) * (1ULL << (16 * i));
                }
                // 1ULL << 16m could overflow 64-bit int
                typename BlueprintFieldType::value_type tmp = 1ULL << (16 * (m - 1));
                tmp *= 1ULL << 16;
                b += var(var_pos.b0.column() + m, 0) * tmp;

                auto x = var(var_pos.x.column(), 0, false);
                auto sx = var(var_pos.sx.column(), 0, false);
                auto gt1 = var(var_pos.gt1.column(), 0, false);
                auto s1 = var(var_pos.s1.column(), 0, false);
                auto eq1 = var(var_pos.eq1.column(), 0, false);
                auto inv1 = var(var_pos.inv1.column(), 0, false);

                auto inv_of_2 = typename BlueprintFieldType::value_type(2).inversed();

                // abs
                auto constraint_1 = x - sx * a;
                auto constraint_2 = (sx - 1) * (sx + 1);
                // abs > 1
                auto d = a - delta;
                auto constraint_3 = d - s1 * b;
                auto constraint_4 = (s1 - 1) * (s1 + 1);
                auto constraint_5 = eq1 * b;
                auto constraint_6 = 1 - eq1 - inv1 * b;
                auto constraint_7 = gt1 - inv_of_2 * (1 + s1) * (1 - eq1);

                return bp.add_gate(
                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6, constraint_7});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gate1(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto delta = component.get_delta();
                auto m = component.get_m();

                auto c = nil::crypto3::math::expression(var(var_pos.c0.column(), 0, false));
                auto d = nil::crypto3::math::expression(var(var_pos.d0.column(), 0, false));
                auto abs_val =
                    nil::crypto3::math::expression(var(var_pos.a0.column(), -1, false));    // abs from prev row
                for (auto i = 1; i < m; i++) {
                    c += var(var_pos.c0.column() + i, 0) * (1ULL << (16 * i));
                    d += var(var_pos.d0.column() + i, 0) * (1ULL << (16 * i));
                    abs_val += var(var_pos.a0.column() + i, -1) * (1ULL << (16 * i));
                }

                auto y1 = var(var_pos.y1.column(), 0, false);
                auto abs = var(var_pos.abs.column(), 0, false);
                auto ainv = var(var_pos.ainv.column(), 0, false);
                auto c1 = var(var_pos.c1.column(), 0, false);
                // auto pad1 = var(var_pos.pad1.column(), 0, false); // Enforced by lookup table
                auto gt = var(var_pos.gt1.column(), -1, false);

                auto x_val = typename BlueprintFieldType::value_type(delta) * delta;

                auto constraint_1 = gt * (abs_val - delta) + delta - abs;
                auto constraint_2 = 2 * (x_val - abs * ainv - c) + abs - c1;
                auto constraint_3 = (c1 - 1) * c1;
                auto constraint_4 = abs - c - d - 1;
                auto constraint_5 = gt * (ainv - abs_val) + abs_val - y1;

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gate2(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto delta = component.get_delta();
                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto e = nil::crypto3::math::expression(var(var_pos.e0.column(), 0, false));
                auto f = nil::crypto3::math::expression(var(var_pos.f0.column(), 0, false));
                for (auto i = 1; i < m2; i++) {
                    f += var(var_pos.f0.column() + i, 0) * (1ULL << (16 * i));
                }
                for (auto i = 1; i < m; i++) {
                    e += var(var_pos.e0.column() + i, 0) * (1ULL << (16 * i));
                }
                // 1ULL << 16m could overflow 64-bit int
                typename BlueprintFieldType::value_type tmp = 1ULL << (16 * (m - 1));
                tmp *= 1ULL << 16;
                e += var(var_pos.e0.column() + m, 0) * tmp;

                // constants
                uint64_t sqrt3_3 = 0;
                uint64_t zero_7 = 0;

                if (m2 == 1) {
                    zero_7 = 45875;
                    sqrt3_3 = 37837;
                } else if (m2 == 2) {
                    zero_7 = 3006477107;
                    sqrt3_3 = 2479700525;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }

                auto x1 = var(var_pos.x1.column(), 0, false);
                auto gt2 = var(var_pos.gt2.column(), 0, false);
                auto s2 = var(var_pos.s2.column(), 0, false);
                auto eq2 = var(var_pos.eq2.column(), 0, false);
                auto inv2 = var(var_pos.inv2.column(), 0, false);
                auto num = var(var_pos.num.column(), 0, false);
                auto denom = var(var_pos.denom.column(), 0, false);
                auto z1 = var(var_pos.z1.column(), 0, false);

                auto inv_of_2 = typename BlueprintFieldType::value_type(2).inversed();

                // x > 0.7
                auto d = x1 - zero_7;
                auto constraint_1 = d - s2 * e;
                auto constraint_2 = (s2 - 1) * (s2 + 1);
                auto constraint_3 = eq2 * e;
                auto constraint_4 = 1 - eq2 - inv2 * e;
                auto constraint_5 = gt2 - inv_of_2 * (1 + s2) * (1 - eq2);
                // num and denom
                auto constraint_6 = num - (x1 - sqrt3_3) * delta;
                auto constraint_7 = 2 * (x1 * sqrt3_3 - z1 * delta - f) + delta;
                auto constraint_8 = gt2 * z1 + delta - denom;

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                    constraint_7, constraint_8});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gate3(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions
                    &var_pos) {

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                auto delta = component.get_delta();
                auto m = component.get_m();

                auto g = nil::crypto3::math::expression(var(var_pos.g0.column(), 0, false));
                auto h = nil::crypto3::math::expression(var(var_pos.h0.column(), 0, false));
                for (auto i = 1; i < m; i++) {
                    g += var(var_pos.g0.column() + i, 0) * (1ULL << (16 * i));
                    h += var(var_pos.h0.column() + i, 0) * (1ULL << (16 * i));
                }

                auto y2 = var(var_pos.y2.column(), 0, false);
                auto num = var(var_pos.num1.column(), 0, false);
                auto denom = var(var_pos.denom1.column(), 0, false);
                auto z2 = var(var_pos.z2.column(), 0, false);
                auto c2 = var(var_pos.c2.column(), 0, false);
                auto gt3 = var(var_pos.gt3.column(), 0, false);
                auto x3 = var(var_pos.x3.column(), 0, false);

                // auto constraint_1 = gt * (abs_val - delta) + delta - abs;
                // auto constraint_2 = 2 * (x_val - abs * ainv - c) + abs - c1;
                // auto constraint_3 = (c1 - 1) * c1;
                // auto constraint_4 = abs - c - d - 1;
                // auto constraint_5 = gt * (ainv - abs_val) + abs_val - y1;

                return bp.add_gate({});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                // row0
                var x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});

                // row2
                var x1 = var(splat(var_pos.x1), false);
                var y1 = var(splat(var_pos.y1), false);
                bp.add_copy_constraint({x1, y1});

                // row3
                var num = var(splat(var_pos.num), false);
                var num1 = var(splat(var_pos.num1), false);
                var denom = var(splat(var_pos.denom), false);
                var denom1 = var(splat(var_pos.denom1), false);
                var x3 = var(splat(var_pos.x3), false);
                var gt2 = var(splat(var_pos.gt2), false);
                var gt3 = var(splat(var_pos.gt3), false);
                bp.add_copy_constraint({num, num1});
                bp.add_copy_constraint({denom, denom1});
                bp.add_copy_constraint({x1, x3});
                bp.add_copy_constraint({gt2, gt3});

                // TODO
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                std::size_t selector_index = generate_gate0(component, bp, var_pos);
                assignment.enable_selector(selector_index, start_row_index);

                selector_index = generate_gate1(component, bp, var_pos);
                assignment.enable_selector(selector_index, start_row_index + 1);

                selector_index = generate_gate2(component, bp, var_pos);
                assignment.enable_selector(selector_index, start_row_index + 2);

                selector_index = generate_gate3(component, bp, var_pos);
                assignment.enable_selector(selector_index, start_row_index + 3);

                // TODO

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                // TODO
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATAN_HPP
