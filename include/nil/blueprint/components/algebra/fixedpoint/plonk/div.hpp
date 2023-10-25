#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP

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
            // Output: z = round(\Delta_z * x / y) with \Delta_z = \Delta_x = \Delta_y

            // Works by proving z = round(\Delta_z * x / y) via 2x\Delta_z + |y| - c = 2zy + 2q and proving 0 <= q < |y|
            // via multiple decompositions and lookup tables for checking the range of the limbs

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_div;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_div<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_div::gates_amount;
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
                                          5 + (M(m2) + M(m1)), 5 + 3 * (m2 + m1), 3 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (5 + 3 * (M(m2) + M(m1)) <= witness_amount) {
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
                    result_type(const fix_div &component, std::uint32_t start_row_index) {
                        auto row = start_row_index + component.rows_amount - 1;
                        output = var(component.W(2), row, false, var::column_type::witness);
                    }

                    result_type(const fix_div &component, std::size_t start_row_index) {
                        auto row = start_row_index + component.rows_amount - 1;
                        output = var(component.W(2), row, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_div(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_div(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_div(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_div =
                fix_div<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;
                auto second_row = j + component.rows_amount - 1;
                auto m = component.get_m();

                typename BlueprintFieldType::value_type tmp =
                    var_value(assignment, instance_input.x) * component.get_delta();

                auto y = var_value(assignment, instance_input.y);

                DivMod<BlueprintFieldType> res = FixedPointHelper<BlueprintFieldType>::round_div_mod(tmp, y);

                // if one row:
                // | x | y | z | c | s_y | y0 | ... | q0 | ... | yq_0 | ...
                // else;
                // first row: | q0 | ... | yq_0 | ...
                // second row: | x | y | z | c | s_y | y0 | ...
                assignment.witness(component.W(0), second_row) = var_value(assignment, instance_input.x);
                assignment.witness(component.W(1), second_row) = y;
                assignment.witness(component.W(2), second_row) = res.quotient;

                std::vector<uint16_t> decomp_y;
                std::vector<uint16_t> decomp_q;
                std::vector<uint16_t> decomp_yq;

                bool sign = FixedPointHelper<BlueprintFieldType>::abs(y);
                assignment.witness(component.W(4), second_row) =
                    sign ? -BlueprintFieldType::value_type::one() : BlueprintFieldType::value_type::one();

                sign = FixedPointHelper<BlueprintFieldType>::decompose(y, decomp_y);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(res.remainder, decomp_q);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(y - res.remainder - 1, decomp_yq);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(decomp_y.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(decomp_q.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(decomp_yq.size() >= m);

                assignment.witness(component.W(3), second_row) =
                    typename BlueprintFieldType::value_type(decomp_y[0] & 1);

                auto y_start = 5;
                auto q_start = component.rows_amount == 1 ? y_start + m : 0;
                auto yq_start = q_start + m;

                for (auto i = 0; i < m; i++) {
                    assignment.witness(component.W(y_start + i), second_row) = decomp_y[i];
                    assignment.witness(component.W(q_start + i), j) = decomp_q[i];
                    assignment.witness(component.W(yq_start + i), j) = decomp_yq[i];
                }

                return typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::var;
                // 2x\Delta_z + |y| - c = 2zy + 2q and proving 0 <= q < |y|
                auto m = component.get_m();
                auto delta = component.get_delta();

                int first_row = 1 - (int)component.rows_amount;
                auto y_start = 5;
                auto q_start = component.rows_amount == 1 ? y_start + m : 0;
                auto yq_start = q_start + m;

                auto y = nil::crypto3::math::expression(var(component.W(y_start), 0));
                auto q = nil::crypto3::math::expression(var(component.W(q_start), first_row));
                auto yq = nil::crypto3::math::expression(var(component.W(yq_start), first_row));
                for (auto i = 1; i < m; i++) {
                    y += var(component.W(y_start + i), 0) * (1ULL << (16 * i));
                    q += var(component.W(q_start + i), first_row) * (1ULL << (16 * i));
                    yq += var(component.W(yq_start + i), first_row) * (1ULL << (16 * i));
                }

                auto constraint_1 =
                    2 * (var(component.W(0), 0) * delta - var(component.W(1), 0) * var(component.W(2), 0) - q) + y -
                    var(component.W(3), 0);

                auto constraint_2 = var(component.W(1), 0) - y * var(component.W(4), 0);

                auto constraint_3 = y - q - yq - 1;

                auto constraint_4 = (var(component.W(3), 0) - 1) * var(component.W(3), 0);

                auto constraint_5 = (var(component.W(4), 0) - 1) * (var(component.W(4), 0) + 1);

                // TACEO_TODO extend for lookup constraint
                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index + component.rows_amount - 1;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                var component_y = var(component.W(1), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
                bp.add_copy_constraint({component_y, instance_input.y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP
