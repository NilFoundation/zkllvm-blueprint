#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_REM_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_REM_HPP

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

            // Input: x, y as fixedpoint numbers with \Delta_x = \Delta_y
            // Output: z = x mod y with \Delta_z = \Delta_x = \Delta_y and sign(z) = sign(y)

            // Works by proving x = y + q * z  by having 4 decompositions of y, q, z, and y - z - 1.

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_rem;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_rem<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_rem::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(
                                          3 + 2 * (M(m2) + M(m1)), 5 + 4 * (m2 + m1), 2 + 2 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (5 + 4 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_rem &component, std::uint32_t start_row_index) {
                        auto row = start_row_index + component.rows_amount - 1;
                        output = var(component.W(2), row, false, var::column_type::witness);
                    }

                    result_type(const fix_rem &component, std::size_t start_row_index) {
                        auto row = start_row_index + component.rows_amount - 1;
                        output = var(component.W(2), row, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_rem(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_rem(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_rem(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_rem =
                fix_rem<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;
                auto second_row = j + component.rows_amount - 1;
                auto m = component.get_m();

                auto x = var_value(assignment, instance_input.x);
                auto y = var_value(assignment, instance_input.y);

                DivMod<BlueprintFieldType> res = FixedPointHelper<BlueprintFieldType>::div_mod(x, y);
                if (y > FixedPointHelper<BlueprintFieldType>::P_HALF && res.remainder != 0) {
                    // sign(other.value) == sign(divmod_remainder)
                    res.remainder += y;
                    res.quotient -= 1;
                }

                // if one row:
                // | x | y | z | s_y | s_q | y0 | ... | z0 | ... |q0 | ... | yz_0 | ...
                // else;
                // first row: | s_y | s_q | q0 | ... | yz_0 | ...
                // second row: | x | y | z  | y0 | ... | z0 | ...
                assignment.witness(component.W(0), second_row) = x;
                assignment.witness(component.W(1), second_row) = y;
                assignment.witness(component.W(2), second_row) = res.remainder;

                std::vector<uint16_t> decomp_y;
                std::vector<uint16_t> decomp_z;
                std::vector<uint16_t> decomp_q;
                std::vector<uint16_t> decomp_yz;

                auto y_abs = y;
                bool sign_y = FixedPointHelper<BlueprintFieldType>::abs(y_abs);
                bool sign_y_ = FixedPointHelper<BlueprintFieldType>::decompose(y_abs, decomp_y);
                BLUEPRINT_RELEASE_ASSERT(!sign_y_);

                auto sign_col = component.rows_amount == 1 ? 3 : 0;
                if (sign_y) {
                    assignment.witness(component.W(sign_col), j) = -BlueprintFieldType::value_type::one();

                } else {
                    assignment.witness(component.W(sign_col), j) = BlueprintFieldType::value_type::one();
                }

                bool sign_q = FixedPointHelper<BlueprintFieldType>::decompose(res.quotient, decomp_q);
                if (sign_q) {
                    assignment.witness(component.W(sign_col + 1), j) = -BlueprintFieldType::value_type::one();

                } else {
                    assignment.witness(component.W(sign_col + 1), j) = BlueprintFieldType::value_type::one();
                }

                auto z_abs = res.remainder;
                bool sign_z = FixedPointHelper<BlueprintFieldType>::abs(z_abs);
                BLUEPRINT_RELEASE_ASSERT((z_abs == 0) || (sign_z == sign_y));
                bool sign_z_ = FixedPointHelper<BlueprintFieldType>::decompose(z_abs, decomp_z);
                BLUEPRINT_RELEASE_ASSERT(!sign_z_);

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(y_abs - z_abs - 1, decomp_yz);
                BLUEPRINT_RELEASE_ASSERT(!sign);

                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(decomp_y.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(decomp_z.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(decomp_q.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(decomp_yz.size() >= m);

                auto y_start = component.rows_amount == 1 ? 5 : 3;
                auto z_start = y_start + m;
                auto q_start = component.rows_amount == 1 ? z_start + m : 2;
                auto yz_start = q_start + m;

                for (auto i = 0; i < m; i++) {
                    assignment.witness(component.W(y_start + i), second_row) = decomp_y[i];
                    assignment.witness(component.W(z_start + i), second_row) = decomp_z[i];
                    assignment.witness(component.W(q_start + i), j) = decomp_q[i];
                    assignment.witness(component.W(yz_start + i), j) = decomp_yz[i];
                }

                return typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::var;
                auto m = component.get_m();

                int first_row = 1 - (int)component.rows_amount;
                auto sign_col = component.rows_amount == 1 ? 3 : 0;
                auto y_start = component.rows_amount == 1 ? 5 : 3;
                auto z_start = y_start + m;
                auto q_start = component.rows_amount == 1 ? z_start + m : 2;
                auto yz_start = q_start + m;

                auto y = nil::crypto3::math::expression(var(component.W(y_start), 0));
                auto z = nil::crypto3::math::expression(var(component.W(z_start), 0));
                auto q = nil::crypto3::math::expression(var(component.W(q_start), first_row));
                auto yz = nil::crypto3::math::expression(var(component.W(yz_start), first_row));
                for (auto i = 1; i < m; i++) {
                    y += var(component.W(y_start + i), 0) * (1ULL << (16 * i));
                    z += var(component.W(z_start + i), 0) * (1ULL << (16 * i));
                    q += var(component.W(q_start + i), first_row) * (1ULL << (16 * i));
                    yz += var(component.W(yz_start + i), first_row) * (1ULL << (16 * i));
                }

                auto constraint_1 = var(component.W(0), 0) -
                                    var(component.W(sign_col + 1), first_row) * q * var(component.W(1), 0) -
                                    var(component.W(2), 0);

                auto constraint_2 = var(component.W(1), 0) - y * var(component.W(sign_col), first_row);

                auto constraint_3 = var(component.W(2), 0) - z * var(component.W(sign_col), first_row);

                auto constraint_4 = y - z - yz - 1;

                auto constraint_5 =
                    (var(component.W(sign_col), first_row) - 1) * (var(component.W(sign_col), first_row) + 1);

                auto constraint_6 =
                    (var(component.W(sign_col + 1), first_row) - 1) * (var(component.W(sign_col + 1), first_row) + 1);

                // TACEO_TODO extend for lookup constraint
                return bp.add_gate(
                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index + component.rows_amount - 1;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                var component_y = var(component.W(1), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
                bp.add_copy_constraint({component_y, instance_input.y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_REM_HPP
