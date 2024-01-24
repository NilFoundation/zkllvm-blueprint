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
                    auto value = M(m1) == 1 ? 11 : 13;
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
                    CellPosition x1, gt2, num, denom, s2, eq2, inv2, e0, f0;
                    CellPosition y2, num1, denom1, z, c2, g0, h0, pad2;
                    CellPosition p2, p3, p33, p5, p55, p20, p30, p330, p50, p550;
                    CellPosition y, t1, t3, t5, f1, f2, f3;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m2 = this->get_m2();
                    auto m = this->get_m();
                    var_positions pos;

                    // trace layout (between 11 and 15 columns, 6 row(s))
                    //
                    // First row calculates the abs value (a0..am-1) and compares it to 1 (gt1)
                    // Second row takes the inverse of abs if gt1=1, otherwise it takes the abs value
                    // Third row compares the output of the second row to 0.7 (gt2), and prepares the division for the next row
                    // Fourth row calculates the a division and takes the result if gt2=1, otherwise it takes the result of the second row
                    // Fifth row calculates the taylor polynomial
                    // Sixth row calculates the output from the flags sx, gt1, gt2, and the taylor polynomial
                    //
                    // pad1 and pad2 are just here to allow the same lookup table gate in row0, row1, and row3
                    //
                    //       |                witness
                    //   r\c | 0  |  1   |   2    |   3   |  4  |  ..  |  ..  |  ..  |  ..  |  .. | .. |  ..  |  ..  |  ..  | .. |
                    // +-----+----+------+--------+-------+-----+------+------+------+------+-----+----+------+------+------+----|
                    // |  0  | x  | sx   | gt1    | s1    | eq1 | inv1 | a0   |  ..  | am-1 | b0  | .. | bm   |                    7 + 2 * m
                    // |  1  | y1 | abs  | ainv   | c1    |  -  |  -   | c0   |  ..  | cm-1 | d0  | .. | dm-1 | pad1 |             4 + 2 * m
                    // |  2  | x1 | gt2  | num    | denom | s2  | eq2  | inv2 | e0   |  ..  | em  | f0 |  ..  |                    8 + m + m2
                    // |  3  | y2 | num1 | denom1 | z     | c2  |  -   | g0   |  ..  | gm-1 | h0  | .. | hm-1 | pad2 |             5 + 2 * m
                    // |  4  | p2 | p3   | p33    | p5    | p55 | p20  | ..   | p30  |  ..  | p50 | .. | p55  | ..   | p550 | .. | 5 + 5 * m2
                    // |  5  | y  | t1   | t3     | t5    | f1  | f2   | f3   |                                                    7

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
                    pos.e0 = CellPosition(this->W(7 + 0 * (m + 1)), start_row_index + 2);    // occupies m + 1 cells
                    pos.f0 = CellPosition(this->W(7 + 1 * (m + 1)), start_row_index + 2);    // occupies m2 cells

                    pos.y2 = CellPosition(this->W(0), start_row_index + 3);
                    pos.num1 = CellPosition(this->W(1), start_row_index + 3);
                    pos.denom1 = CellPosition(this->W(2), start_row_index + 3);
                    pos.z = CellPosition(this->W(3), start_row_index + 3);
                    pos.c2 = CellPosition(this->W(4), start_row_index + 3);
                    pos.g0 = CellPosition(this->W(6 + 0 * m), start_row_index + 3);    // occupies m cells
                    pos.h0 = CellPosition(this->W(6 + 1 * m), start_row_index + 3);    // occupies m2 cells
                    pos.pad2 = CellPosition(this->W(6 + 2 * m), start_row_index + 3);

                    pos.p2 = CellPosition(this->W(0), start_row_index + 4);
                    pos.p3 = CellPosition(this->W(1), start_row_index + 4);
                    pos.p33 = CellPosition(this->W(2), start_row_index + 4);
                    pos.p5 = CellPosition(this->W(3), start_row_index + 4);
                    pos.p55 = CellPosition(this->W(4), start_row_index + 4);
                    pos.p20 = CellPosition(this->W(5 + 0 * m2), start_row_index + 4); // occupies m2 cells
                    pos.p30 = CellPosition(this->W(5 + 1 * m2), start_row_index + 4); // occupies m2 cells
                    pos.p330 = CellPosition(this->W(5 + 2 * m2), start_row_index + 4); // occupies m2 cells
                    pos.p50 = CellPosition(this->W(5 + 3 * m2), start_row_index + 4); // occupies m2 cells
                    pos.p550 = CellPosition(this->W(5 + 4 * m2), start_row_index + 4); // occupies m2 cells

                    pos.y = CellPosition(this->W(0), start_row_index + 5);
                    pos.t1 = CellPosition(this->W(1), start_row_index + 5);
                    pos.t3 = CellPosition(this->W(2), start_row_index + 5);
                    pos.t5 = CellPosition(this->W(3), start_row_index + 5);
                    pos.f1 = CellPosition(this->W(4), start_row_index + 5);
                    pos.f2 = CellPosition(this->W(5), start_row_index + 5);
                    pos.f3 = CellPosition(this->W(6), start_row_index + 5);

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
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions& var_pos) {

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
                auto d_val = x_val - one;
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
                const typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::var_positions& var_pos, typename BlueprintFieldType::value_type& abs) {

                // Basically a div_by_pos gadget, where x is hardcoded to be one.

                auto m = component.get_m();
                auto delta = component.get_delta();

                auto x_val = typename BlueprintFieldType::value_type(delta) * delta;

                DivMod<BlueprintFieldType> tmp_div =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(x_val, abs);
                auto z_val = tmp_div.quotient;

                assignment.witness(splat(var_pos.abs)) = abs;
                assignment.witness(splat(var_pos.ainv)) = z_val;

                std::vector<uint16_t> q0_val;
                std::vector<uint16_t> a0_val;

                auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp_div.remainder, q0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(abs - tmp_div.remainder - 1, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);

                auto y_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(abs);
                assignment.witness(splat(var_pos.c1)) = typename BlueprintFieldType::value_type(y_.limbs()[0] & 1);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.c0.column() + i, var_pos.c0.row()) = q0_val[i];
                    assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = a0_val[i];
                }

                // We pad to have the same lookup gate as for row0
                assignment.witness(splat(var_pos.pad1)) = BlueprintFieldType::value_type::zero();

                // Finally, output depending on gt1
                assignment.witness(splat(var_pos.y1)) = abs > BlueprintFieldType::value_type::one() ? z_val : abs;
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

                // TODO

                return typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
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

                // TODO

                return typename plonk_fixedpoint_atan<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATAN_HPP
