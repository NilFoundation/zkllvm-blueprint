#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_HPP

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
            // Output: three flags with values \in {0,1} indicating equality, less than, or greater than

            // Works by decomposing the difference of the inputs.

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_cmp;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_cmp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                static std::size_t get_witness_columns(uint8_t m1, uint8_t m2) {
                    return 8 + M(m2) + M(m1);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_cmp::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m1, m2))), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var eq = var(0, 0, false);
                    var lt = var(0, 0, false);
                    var gt = var(0, 0, false);

                    result_type(const fix_cmp &component, std::uint32_t start_row_index) {
                        eq = var(component.W(2), start_row_index, false, var::column_type::witness);
                        lt = var(component.W(3), start_row_index, false, var::column_type::witness);
                        gt = var(component.W(4), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const fix_cmp &component, std::size_t start_row_index) {
                        eq = var(component.W(2), start_row_index, false, var::column_type::witness);
                        lt = var(component.W(3), start_row_index, false, var::column_type::witness);
                        gt = var(component.W(4), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {eq, lt, gt};
                    }
                };

                template<typename ContainerType>
                explicit fix_cmp(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_cmp(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_cmp(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_cmp =
                fix_cmp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;
                auto m = component.get_m();

                auto x = var_value(assignment, instance_input.x);
                auto y = var_value(assignment, instance_input.y);

                auto diff = x - y;

                // Take m+1 limbs due to potential overflow
                // | x | y | eq | lt | gt | s | inv | y0 | ...
                assignment.witness(component.W(0), j) = x;
                assignment.witness(component.W(1), j) = y;

                std::vector<uint16_t> decomp;

                bool sign = FixedPointHelper<BlueprintFieldType>::abs(diff);
                bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(diff, decomp);
                BLUEPRINT_RELEASE_ASSERT(!sign_);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(decomp.size() >= m);
                bool eq = diff == 0;
                assignment.witness(component.W(2), j) = typename BlueprintFieldType::value_type((uint64_t)eq);
                assignment.witness(component.W(3), j) = typename BlueprintFieldType::value_type((uint64_t)sign);
                assignment.witness(component.W(4), j) =
                    typename BlueprintFieldType::value_type((uint64_t)(!eq && !sign));

                assignment.witness(component.W(5), j) =
                    sign ? -BlueprintFieldType::value_type::one() : BlueprintFieldType::value_type::one();

                // if eq:  Does not matter what to put here
                assignment.witness(component.W(6), j) = eq ? BlueprintFieldType::value_type::zero() : diff.inversed();

                // Additional limb due to potential overflow of diff
                if (decomp.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(decomp[m] == 0 || decomp[m] == 1);
                    assignment.witness(component.W(7 + m), j) = decomp[m];
                } else {
                    assignment.witness(component.W(7 + m), j) = 0;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(component.W(7 + i), j) = decomp[i];
                }

                return typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::var;
                auto m = component.get_m();

                auto diff = nil::crypto3::math::expression(var(component.W(7), 0));
                for (auto i = 1; i < m; i++) {
                    diff += var(component.W(7 + i), 0) * (1ULL << (16 * i));
                }
                typename BlueprintFieldType::value_type tmp =
                    1ULL << (16 * (m - 1));    // 1ULL << 16m could overflow 64-bit int
                tmp *= 1ULL << 16;
                diff += var(component.W(7 + m), 0) * tmp;

                auto constraint_1 = var(component.W(0), 0) - var(component.W(1), 0) - var(component.W(5), 0) * diff;

                auto constraint_2 = (var(component.W(5), 0) - 1) * (var(component.W(5), 0) + 1);

                auto constraint_3 = var(component.W(2), 0) * diff;

                auto constraint_4 = 1 - var(component.W(2), 0) - var(component.W(6), 0) * diff;

                auto inv2 = typename BlueprintFieldType::value_type(2).inversed();

                auto constraint_5 =
                    var(component.W(3), 0) - inv2 * (1 - var(component.W(5), 0)) * (1 - var(component.W(2), 0));

                auto constraint_6 =
                    var(component.W(4), 0) - inv2 * (1 + var(component.W(5), 0)) * (1 - var(component.W(2), 0));

                // TACEO_TODO extend for lookup constraint
                return {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                var component_y = var(component.W(1), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
                bp.add_copy_constraint({component_y, instance_input.y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_HPP
