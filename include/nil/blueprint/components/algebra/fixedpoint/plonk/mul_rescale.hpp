#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_HPP

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

            // Works by proving z = round(x*y/\Delta) via 2xy + \Delta = 2z\Delta + 2q and proving 0 <= q < \Delta via a
            // lookup table

            /**
             * Component representing a multiplication operation.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same).
             *
             * The delta of z is the same as the delta of x and y.
             *
             * Input:  x ... field element
             *         y ... field element
             * Output: z ... x * y (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_mul_rescale;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_mul_rescale<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            private:
                uint8_t m2;    // Post-comma 16-bit limbs

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                uint8_t get_m2() const {
                    return m2;
                }

                uint64_t get_delta() const {
                    return 1ULL << (16 * m2);
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
                        return fix_mul_rescale::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3 + M(m2))), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                // Includes the constraints + lookup_gates
                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct var_positions {
                    CellPosition x, y, z, q0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (3 + m2 col(s), 1 row(s))
                    //
                    //  r\c| 0 | 1 | 2 | 3  | .. | 3 + m2-1 |
                    // +---+---+---+---+----+----+----------+
                    // | 0 | x | y | z | q0 | .. | qm2-1    |

                    auto m2 = this->get_m2();
                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    pos.z = CellPosition(this->W(2), start_row_index);
                    pos.q0 = CellPosition(this->W(3 + 0 * m2), start_row_index);    // occupies m2 cells
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_mul_rescale &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.z), false);
                    }

                    result_type(const fix_mul_rescale &component, std::size_t start_row_index) {
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
                explicit fix_mul_rescale(ContainerType witness, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m2)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_mul_rescale(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m2)),
                    m2(M(m2)) {};

                fix_mul_rescale(std::initializer_list<typename component_type::witness_container_type::value_type>
                                    witnesses,
                                std::initializer_list<typename component_type::constant_container_type::value_type>
                                    constants,
                                std::initializer_list<typename component_type::public_input_container_type::value_type>
                                    public_inputs,
                                uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m2)),
                    m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_mul_rescale =
                fix_mul_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);

                typename BlueprintFieldType::value_type tmp = x_val * y_val;
                DivMod<BlueprintFieldType> res =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(tmp, component.get_delta());

                auto z_val = res.quotient;
                auto q_val = res.remainder;

                assignment.witness(splat(var_pos.x)) = x_val;
                assignment.witness(splat(var_pos.y)) = y_val;
                assignment.witness(splat(var_pos.z)) = z_val;

                if (component.get_m2() == 1) {
                    assignment.witness(splat(var_pos.q0)) = q_val;
                } else {
                    std::vector<uint16_t> q0_val;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(q_val, q0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    // is ok because q0_val is at least of size 4 and the biggest we have is 32.32
                    BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= component.get_m2());
                    for (auto i = 0; i < component.get_m2(); i++) {
                        assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                    }
                }

                return typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                uint64_t start_row_index = 0;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::var;
                // 2xy + delta = 2z delta + 2q and proving 0 <= q < delta via a lookup table. delta is a multiple of
                // 2^16, hence q could be decomposed into 16-bit limbs
                auto delta = component.get_delta();

                auto q = nil::crypto3::math::expression(var(splat(var_pos.q0)));
                for (auto i = 1; i < component.get_m2(); i++) {
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                }

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto z = var(splat(var_pos.z));

                auto constraint_1 = 2 * (x * y - z * delta - q) + delta;    // see the definition of rescale

                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                int64_t start_row_index = 0;
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m2 = component.get_m2();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(m2);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                for (auto i = 0; i < m2; i++) {
                    constraint_type constraint;
                    constraint.table_id = table_id;

                    auto qi = var(var_pos.q0.column() + i, var_pos.q0.row());
                    constraint.lookup_input = {qi};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(splat(var_pos.x), false);
                var y = var(splat(var_pos.y), false);
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_HPP
