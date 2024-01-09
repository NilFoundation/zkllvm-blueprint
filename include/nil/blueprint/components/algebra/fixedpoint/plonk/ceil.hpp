#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CEIL_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CEIL_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/floor.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing the input. We use a constant as an offset for the input to allow the same gadget for
            // the floor component

            /**
             * Component representing a ceil operation.
             *
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x       ... field element
             * Output: y       ... ceil(x) (field element)
             *
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_ceil;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_ceil<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {
            public:
                using value_type = typename BlueprintFieldType::value_type;
                using floor_component =
                    fix_floor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                floor_component floor;
                uint64_t offset;

                floor_component instantiate_floor(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = floor_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return floor_component(witness_list, std::array<std::uint32_t, 1>({this->C(0)}),
                                           std::array<std::uint32_t, 0>(), m1, m2);
                }

            public:
                uint8_t get_m() const {
                    return floor.get_m();
                }

                uint64_t get_delta() const {
                    return floor.get_delta();
                }

                uint8_t get_m1() const {
                    return floor.get_m1();
                }

                uint8_t get_m2() const {
                    return floor.get_m2();
                }

                const floor_component &get_floor_component() const {
                    return floor;
                }

                uint64_t get_offset() const {
                    return offset;
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return floor_component::get_witness_columns(witness_amount, m1, m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_ceil::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    gate_manifest manifest = floor_component::get_gate_manifest(witness_amount, lookup_column_amount);
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest = floor_component::get_manifest(m1, m2);
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    return floor_component::get_rows_amount(witness_amount, lookup_column_amount);
                }

                // Includes the constraints + lookup_gates
                constexpr static const std::size_t gates_amount = floor_component::gates_amount;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                using input_type = typename floor_component::input_type;
                using result_type = typename floor_component::result_type;
                using var_positions = typename floor_component::var_positions;

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    return floor.component_custom_lookup_tables();
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    return floor.component_lookup_tables();
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_ceil(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    floor(instantiate_floor(m1, m2)), offset(floor.get_delta() - 1) {};

                fix_ceil(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    floor(instantiate_floor(m1, m2)), offset(floor.get_delta() - 1) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_ceil =
                fix_ceil<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_ceil<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_ceil<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_ceil<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {
                auto floor = component.get_floor_component();
                return generate_assignments(floor, assignment, instance_input, start_row_index, component.get_offset());
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_ceil<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_ceil<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_ceil<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                auto floor = component.get_floor_component();
                return generate_circuit(floor, bp, assignment, instance_input, start_row_index, component.get_offset());
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CEIL_HPP
