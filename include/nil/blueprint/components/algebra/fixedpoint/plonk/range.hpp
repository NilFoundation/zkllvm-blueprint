#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/type.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x as fixedpoint numbers with \Delta_x
            // Constant inputs: Two fixedpoint ranges(x_lo, x_hi) with \Delta_x
            // Output: three flags with values \in {0,1} indicating whether x is in range. Concretely lt = x < x_lo, gt
            // = x > x_hi, in = x_lo <= x <= x_hi

            // // Works by decomposing the difference of the input and the ranges.

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

                value_type get_x_lo() const {
                    return x_lo;
                }

                value_type get_x_hi() const {
                    return x_hi;
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return get_rows_amount(witness_amount, 0, M(m1), M(m2)) == 1 ? 12 + 2 * (m1 + m2) : 10;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_range::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(
                                          new manifest_range_param(10, 12 + 2 * (m2 + m1), 2 + 2 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (12 + 2 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct result_type {
                    var in = var(0, 0, false);
                    var lt = var(0, 0, false);
                    var gt = var(0, 0, false);

                    result_type(const fix_range &component, std::uint32_t start_row_index) {
                        auto row = start_row_index + component.rows_amount - 1;
                        in = var(component.W(1), row, false, var::column_type::witness);
                        lt = var(component.W(2), row, false, var::column_type::witness);
                        gt = var(component.W(3), row, false, var::column_type::witness);
                    }

                    result_type(const fix_range &component, std::size_t start_row_index) {
                        auto row = start_row_index + component.rows_amount - 1;
                        in = var(component.W(1), row, false, var::column_type::witness);
                        lt = var(component.W(2), row, false, var::column_type::witness);
                        gt = var(component.W(3), row, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {in, lt, gt};
                    }
                };

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

                const std::size_t j = start_row_index;
                auto second_row = j + component.rows_amount - 1;
                auto m = component.get_m();

                auto x = var_value(assignment, instance_input.x);

                // if one row:
                // | x | in | lt | gt | z_a | z_b | inv_a | inv_b | s_a | s_b | a_0 | ... | b_0 | ...
                // else;
                // first row: | a_0 | ... | b_0 | ...
                // second row: | x | in | lt | gt | z_a | z_b | inv_a | inv_b | s_a | s_b |

                assignment.witness(component.W(0), second_row) = x;

                auto diff_a = x - component.get_x_lo();
                auto diff_b = component.get_x_hi() - x;

                std::vector<uint16_t> decomp_a;
                std::vector<uint16_t> decomp_b;

                bool sign_a = FixedPointHelper<BlueprintFieldType>::abs(diff_a);
                bool sign_b = FixedPointHelper<BlueprintFieldType>::abs(diff_b);
                bool sign_a_ = FixedPointHelper<BlueprintFieldType>::decompose(diff_a, decomp_a);
                bool sign_b_ = FixedPointHelper<BlueprintFieldType>::decompose(diff_b, decomp_b);
                BLUEPRINT_RELEASE_ASSERT(!sign_a_);
                BLUEPRINT_RELEASE_ASSERT(!sign_b_);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(decomp_a.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(decomp_b.size() >= m);

                assignment.witness(component.W(1), second_row) =
                    typename BlueprintFieldType::value_type((uint64_t)(!sign_a && !sign_b));
                assignment.witness(component.W(2), second_row) =
                    typename BlueprintFieldType::value_type((uint64_t)sign_a);
                assignment.witness(component.W(3), second_row) =
                    typename BlueprintFieldType::value_type((uint64_t)sign_b);

                bool eq_a = diff_a == 0;
                bool eq_b = diff_b == 0;
                assignment.witness(component.W(4), second_row) =
                    typename BlueprintFieldType::value_type((uint64_t)eq_a);
                assignment.witness(component.W(5), second_row) =
                    typename BlueprintFieldType::value_type((uint64_t)eq_b);

                // if eq: Does not matter what to put here
                assignment.witness(component.W(6), second_row) =
                    eq_a ? BlueprintFieldType::value_type::zero() : diff_a.inversed();
                assignment.witness(component.W(7), second_row) =
                    eq_b ? BlueprintFieldType::value_type::zero() : diff_b.inversed();

                assignment.witness(component.W(8), second_row) =
                    sign_a ? -BlueprintFieldType::value_type::one() : BlueprintFieldType::value_type::one();

                assignment.witness(component.W(9), second_row) =
                    sign_b ? -BlueprintFieldType::value_type::one() : BlueprintFieldType::value_type::one();

                auto decomp_a_start = component.rows_amount == 1 ? 10 : 0;
                auto decomp_b_start = decomp_a_start + m + 1;

                // Additional limb due to potential overflow of diff
                if (decomp_a.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(decomp_a[m] == 0 || decomp_a[m] == 1);
                    assignment.witness(component.W(decomp_a_start + m), j) = decomp_a[m];
                } else {
                    assignment.witness(component.W(decomp_a_start + m), j) = 0;
                }
                if (decomp_b.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(decomp_b[m] == 0 || decomp_b[m] == 1);
                    assignment.witness(component.W(decomp_b_start + m), j) = decomp_b[m];
                } else {
                    assignment.witness(component.W(decomp_b_start + m), j) = 0;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(component.W(decomp_a_start + i), j) = decomp_a[i];
                    assignment.witness(component.W(decomp_b_start + i), j) = decomp_b[i];
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

                using var = typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::var;

                auto m = component.get_m();
                int first_row = 1 - (int)component.rows_amount;
                auto decomp_a_start = component.rows_amount == 1 ? 10 : 0;
                auto decomp_b_start = decomp_a_start + m + 1;

                auto diff_a = nil::crypto3::math::expression(var(component.W(decomp_a_start), first_row));
                auto diff_b = nil::crypto3::math::expression(var(component.W(decomp_b_start), first_row));
                for (auto i = 1; i < m; i++) {
                    diff_a += var(component.W(decomp_a_start + i), first_row) * (1ULL << (16 * i));
                    diff_b += var(component.W(decomp_b_start + i), first_row) * (1ULL << (16 * i));
                }
                typename BlueprintFieldType::value_type tmp =
                    1ULL << (16 * (m - 1));    // 1ULL << 16m could overflow 64-bit int
                tmp *= 1ULL << 16;
                diff_a += var(component.W(decomp_a_start + m), first_row) * tmp;
                diff_b += var(component.W(decomp_b_start + m), first_row) * tmp;

                auto constraint_1 = var(component.W(0), 0) - var(component.C(0), 0, true, var::column_type::constant) -
                                    diff_a * var(component.W(8), 0);

                auto constraint_2 = var(component.C(1), 0, true, var::column_type::constant) - var(component.W(0), 0) -
                                    diff_b * var(component.W(9), 0);

                auto constraint_3 = (var(component.W(8), 0) - 1) * (var(component.W(8), 0) + 1);

                auto constraint_4 = (var(component.W(9), 0) - 1) * (var(component.W(9), 0) + 1);

                auto constraint_5 = var(component.W(4), 0) * diff_a;

                auto constraint_6 = var(component.W(5), 0) * diff_b;

                auto constraint_7 = 1 - var(component.W(4), 0) - var(component.W(6), 0) * diff_a;

                auto constraint_8 = 1 - var(component.W(5), 0) - var(component.W(7), 0) * diff_b;

                auto inv2 = typename BlueprintFieldType::value_type(2).inversed();

                auto constraint_9 =
                    var(component.W(2), 0) - inv2 * (1 - var(component.W(8), 0)) * (1 - var(component.W(4), 0));

                auto constraint_10 =
                    var(component.W(3), 0) - inv2 * (1 - var(component.W(9), 0)) * (1 - var(component.W(5), 0));

                auto constraint_11 =
                    var(component.W(1), 0) - (1 - var(component.W(2), 0)) * (1 - var(component.W(3), 0));

                // TACEO_TODO extend for lookup constraint
                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                    constraint_7, constraint_8, constraint_9, constraint_10, constraint_11});
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

                using var = typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index + component.rows_amount - 1;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
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

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

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

                auto row = start_row_index + component.rows_amount - 1;
                assignment.constant(component.C(0), row) = component.get_x_lo();
                assignment.constant(component.C(1), row) = component.get_x_hi();
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_HPP
