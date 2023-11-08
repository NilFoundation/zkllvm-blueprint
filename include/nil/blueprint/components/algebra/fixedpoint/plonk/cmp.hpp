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

            // Works by decomposing the difference of the inputs.

            /**
             * Component representing a compare operation.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same).
             * 
             * The outputs are flags with values in {0, 1} that describe the relation between x and y. 
             *
             * Input:  x ... field element
             *         y ... field element
             * Output: eq ... 1 if x = y, 0 otherwise (field element)
             *         lt ... 1 if x < y, 0 otherwise (field element)
             *         gt ... 1 if x > y, 0 otherwise (field element)
             */
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
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m1, m2))),
                        false);
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

                struct var_positions {
                    CellPosition x, y, eq, lt, gt, s, inv, d0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (7 + m+1 col(s), 1 row(s))
                    // requiring an extra limb because of potential overflows during decomposition of
                    // differences
                    //
                    //     |                     witness                      |
                    //  r\c| 0 | 1 | 2  | 3  | 4  | 5 |  6  | 7  | .. | 7 + m |
                    // +---+---+---+----+----+----+---+-----+----+----+-------+
                    // | 0 | x | y | eq | lt | gt | s | inv | d0 | .. | dm    |

                    auto m = this->get_m();
                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    pos.eq = CellPosition(this->W(2), start_row_index);
                    pos.lt = CellPosition(this->W(3), start_row_index);
                    pos.gt = CellPosition(this->W(4), start_row_index);
                    pos.s = CellPosition(this->W(5), start_row_index);
                    pos.inv = CellPosition(this->W(6), start_row_index);
                    pos.d0 = CellPosition(this->W(7 + 0 * (m + 1)), start_row_index);    // occupies m + 1 cells
                    return pos;
                }

                struct result_type {
                    var eq = var(0, 0, false);
                    var lt = var(0, 0, false);
                    var gt = var(0, 0, false);

                    result_type(const fix_cmp &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        eq = var(magic(var_pos.eq), false);
                        lt = var(magic(var_pos.lt), false);
                        gt = var(magic(var_pos.gt), false);
                    }

                    result_type(const fix_cmp &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        eq = var(magic(var_pos.eq), false);
                        lt = var(magic(var_pos.lt), false);
                        gt = var(magic(var_pos.gt), false);
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

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                auto m = component.get_m();
                auto one = BlueprintFieldType::value_type::one();
                auto zero = BlueprintFieldType::value_type::zero();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);
                auto d_val = x_val - y_val;

                assignment.witness(magic(var_pos.x)) = x_val;
                assignment.witness(magic(var_pos.y)) = y_val;

                std::vector<uint16_t> d0_val;

                bool sign = FixedPointHelper<BlueprintFieldType>::abs(d_val);
                bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(d_val, d0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_);
                // is ok because d0_val is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m);
                bool eq = d_val == 0;
                BLUEPRINT_RELEASE_ASSERT(eq && !sign || !eq);    // sign must be false if equal is true
                auto eq_val = typename BlueprintFieldType::value_type(static_cast<uint64_t>(eq));
                auto lt_val = typename BlueprintFieldType::value_type(static_cast<uint64_t>(sign));
                auto gt_val = typename BlueprintFieldType::value_type((uint64_t)(!eq && !sign));
                assignment.witness(magic(var_pos.eq)) = eq_val;
                assignment.witness(magic(var_pos.lt)) = lt_val;
                assignment.witness(magic(var_pos.gt)) = gt_val;
                assignment.witness(magic(var_pos.s)) = sign ? -one : one;

                // if eq:  Does not matter what to put here
                assignment.witness(magic(var_pos.inv)) = eq ? zero : d_val.inversed();

                // Additional limb due to potential overflow of diff
                // FixedPointHelper::decompose creates a vector whose size is a multiple of 4.
                // Furthermore, the size of the vector might be larger than required (e.g. if 4 limbs would suffice the
                // vectour could be of size 8)
                if (d0_val.size() > m) {
                    BLUEPRINT_RELEASE_ASSERT(d0_val[m] == 0 || d0_val[m] == 1);
                    assignment.witness(var_pos.d0.column() + m, var_pos.d0.row()) = d0_val[m];
                } else {
                    assignment.witness(var_pos.d0.column() + m, var_pos.d0.row()) = zero;
                }

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.d0.column() + i, var_pos.d0.row()) = d0_val[i];
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

                int64_t start_row_index = 1 - component.rows_amount;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::var;
                auto m = component.get_m();

                auto d = nil::crypto3::math::expression(var(magic(var_pos.d0)));
                for (auto i = 1; i < m; i++) {
                    d += var(var_pos.d0.column() + i, var_pos.d0.row()) * (1ULL << (16 * i));
                }
                typename BlueprintFieldType::value_type tmp =
                    1ULL << (16 * (m - 1));    // 1ULL << 16m could overflow 64-bit int
                tmp *= 1ULL << 16;
                d += var(var_pos.d0.column() + m, var_pos.d0.row()) * tmp;

                auto x = var(magic(var_pos.x));
                auto y = var(magic(var_pos.y));
                auto eq = var(magic(var_pos.eq));
                auto lt = var(magic(var_pos.lt));
                auto gt = var(magic(var_pos.gt));
                auto s = var(magic(var_pos.s));
                auto inv = var(magic(var_pos.inv));
                auto inv2 = typename BlueprintFieldType::value_type(2).inversed();

                auto constraint_1 = x - y - s * d;
                auto constraint_2 = (s - 1) * (s + 1);
                auto constraint_3 = eq * d;
                auto constraint_4 = 1 - eq - inv * d;
                auto constraint_5 = lt - inv2 * (1 - s) * (1 - eq);
                auto constraint_6 = gt - inv2 * (1 + s) * (1 - eq);

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
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_cmp<BlueprintFieldType, ArithmetizationParams>::var;
                var x = var(magic(var_pos.x), false);
                var y = var(magic(var_pos.y), false);
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
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
