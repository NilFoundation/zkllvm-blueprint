#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_BOOLEAN_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_BOOLEAN_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/boolean.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_boolean;

            /**
             * This component exists for fun, demo, and experimental reasons (because its lookup table is small).
             * (and doesn't actually use fixed point representation, just the values 0 and 1 of the underlying field)
             */
            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_boolean<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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
            private:
            public:
                uint64_t get_delta() const {
                    return 1ULL << (16 * this->m2);
                }

                uint8_t get_m2() const {
                    return this->m2;
                }

                uint8_t get_m1() const {
                    return this->m1;
                }

                uint8_t get_m() const {
                    return this->m1 + this->m2;
                }

                constexpr static std::size_t get_witness_columns(uint8_t m2) {
                    return 7;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_boolean::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m2) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m2))),
                        false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

// Includes the constraints + lookup_gates
#ifdef TEST_WITHOUT_LOOKUP_TABLES
                constexpr static const std::size_t gates_amount = 1;
#else
                constexpr static const std::size_t gates_amount = 2;
#endif    // TEST_WITHOUT_LOOKUP_TABLES
                const std::size_t rows_amount = get_rows_amount(this->m1, this->m2);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var and_ = var(0, 0, false);
                    var or_ = var(0, 0, false);
                    var xor_ = var(0, 0, false);
                    var a_inv_ = var(0, 0, false);
                    var b_inv_ = var(0, 0, false);

                    result_type(const fix_boolean &component, std::uint32_t start_row_index) {
                        and_ = var(component.W(2), start_row_index, false);
                        or_ = var(component.W(3), start_row_index, false);
                        xor_ = var(component.W(4), start_row_index, false);
                        a_inv_ = var(component.W(5), start_row_index, false);
                        b_inv_ = var(component.W(6), start_row_index, false);
                    }

                    result_type(const fix_boolean &component, std::size_t start_row_index) {
                        and_ = var(component.W(2), start_row_index, false);
                        or_ = var(component.W(3), start_row_index, false);
                        xor_ = var(component.W(4), start_row_index, false);
                        a_inv_ = var(component.W(5), start_row_index, false);
                        b_inv_ = var(component.W(6), start_row_index, false);
                    }

                    std::vector<var> all_vars() const {
                        return {and_, or_, xor_, a_inv_, b_inv_};
                    }
                };

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {};
                    auto table =
                        std::shared_ptr<lookup_table_definition>(new fixedpoint_boolean_table<BlueprintFieldType>());
                    result.push_back(table);

                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables = {};
                    lookup_tables[fixedpoint_boolean_table<BlueprintFieldType>::FULL_AND] = 0;        // REQUIRED_TABLE
                    lookup_tables[fixedpoint_boolean_table<BlueprintFieldType>::FULL_OR] = 0;         // REQUIRED_TABLE
                    lookup_tables[fixedpoint_boolean_table<BlueprintFieldType>::FULL_XOR] = 0;        // REQUIRED_TABLE
                    lookup_tables[fixedpoint_boolean_table<BlueprintFieldType>::FULL_INVERSE] = 0;    // REQUIRED_TABLE

                    return lookup_tables;
                }
#endif    // TEST_WITHOUT_LOOKUP_TABLES

                template<typename ContainerType>
                explicit fix_boolean(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_boolean(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_boolean(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_boolean =
                fix_boolean<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                auto one = value_type::one();
                auto zero = value_type::zero();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);
                auto and_val = x_val * y_val;
                auto or_val = x_val == one ? x_val : y_val;
                auto xor_val = x_val == y_val ? zero : one;
                auto a_inv_val = x_val == one ? zero : one;
                auto b_inv_val = y_val == one ? zero : one;

                assignment.witness(component.W(0), start_row_index) = x_val;
                assignment.witness(component.W(1), start_row_index) = y_val;
                assignment.witness(component.W(2), start_row_index) = and_val;
                assignment.witness(component.W(3), start_row_index) = or_val;
                assignment.witness(component.W(4), start_row_index) = xor_val;
                assignment.witness(component.W(5), start_row_index) = a_inv_val;
                assignment.witness(component.W(6), start_row_index) = b_inv_val;

                return typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                using var = typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::var;
                auto a = var(component.W(0), start_row_index);

                auto constraint_1 = a * (a - 1);    // dummy constraint to have at least one for keeping our structure
                return {constraint_1};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                using var = typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::var;
                var x = var(component.W(0), start_row_index, false);
                var y = var(component.W(1), start_row_index, false);
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                auto m2 = component.get_m2();

                const auto &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                auto boolean_table_id_and =
                    lookup_tables_indices.at(fixedpoint_boolean_table<BlueprintFieldType>::FULL_AND);
                auto boolean_table_id_or =
                    lookup_tables_indices.at(fixedpoint_boolean_table<BlueprintFieldType>::FULL_OR);
                auto boolean_table_id_xor =
                    lookup_tables_indices.at(fixedpoint_boolean_table<BlueprintFieldType>::FULL_XOR);
                auto boolean_table_id_inv =
                    lookup_tables_indices.at(fixedpoint_boolean_table<BlueprintFieldType>::FULL_INVERSE);

                auto x = var(component.W(0), start_row_index);
                auto y = var(component.W(1), start_row_index);
                auto and_ = var(component.W(2), start_row_index);
                auto or_ = var(component.W(3), start_row_index);
                auto xor_ = var(component.W(4), start_row_index);
                auto a_inv_ = var(component.W(5), start_row_index);
                auto b_inv_ = var(component.W(6), start_row_index);

                std::vector<constraint_type> constraints;
                {    // and
                    constraint_type constraint;
                    constraint.table_id = boolean_table_id_and;
                    constraint.lookup_input = {x, y, and_};
                    constraints.push_back(constraint);
                }
                {    // or
                    constraint_type constraint;
                    constraint.table_id = boolean_table_id_or;
                    constraint.lookup_input = {x, y, or_};
                    constraints.push_back(constraint);
                }
                {    // xor
                    constraint_type constraint;
                    constraint.table_id = boolean_table_id_xor;
                    constraint.lookup_input = {x, y, xor_};
                    constraints.push_back(constraint);
                }
                {    // a_inv
                    constraint_type constraint;
                    constraint.table_id = boolean_table_id_inv;
                    constraint.lookup_input = {x, a_inv_};
                    constraints.push_back(constraint);
                }
                {    // b_inv
                    constraint_type constraint;
                    constraint.table_id = boolean_table_id_inv;
                    constraint.lookup_input = {y, b_inv_};
                    constraints.push_back(constraint);
                }
                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index + component.rows_amount - 1);
#endif
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_boolean<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_BOOLEAN_HPP
