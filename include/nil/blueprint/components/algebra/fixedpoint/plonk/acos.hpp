#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ACOS_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ACOS_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/asin.hpp"

namespace nil {
    namespace blueprint {
        namespace components {
            // Works by evaluating acos(x) = pi/2 - asin(x)
            // The range of 1 <= x <= 1 is enforced by the asin component

            /**
             * Component representing a asin operation with input x and output y, where y = acos(x).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... acos(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_acos;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_acos<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using asin_component =
                    fix_asin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                asin_component asin;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                static std::size_t gates_amount_internal(uint8_t m1, uint8_t m2) {
                    asin_component::gates_amount_internal(m1, m2);
                }

                asin_component instantiate_asin(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = asin_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return asin_component(witness_list, std::vector({this->C(0), this->C(1)}),
                                          std::array<std::uint32_t, 0>(), m1, m2);
                }

            public:
                uint8_t get_m() const {
                    return asin.get_m();
                }

                uint8_t get_m1() const {
                    return asin.get_m1();
                }

                uint8_t get_m2() const {
                    return asin.get_m2();
                }

                uint64_t get_delta() const {
                    return asin.get_delta();
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return asin_component::get_witness_columns(witness_amount, m1, m2);
                }

                // trace layout is from asin:
                // witness (atan col(s)), constant (2 col(s))
                //
                //                |               witness                |     constant      |
                //       r\c      | 0 | 1 |    2   |     3     |  4 | .. |  0     |    1     |
                // +--------------+---+------+-------+---------+---------+--------+----------|
                // | atan_rows    |             <atan_witness>           |   <atan_const>    |
                // | sqrt_row(s)  |             <sqrt_witness>           |   <sqrt_const>    |
                // | div_row(s)   |              <div_witness>           |   <div_const>     |
                // |     0        | x | y | sqrt_in | atan_out | q0 | .. | add_off | mul_off |

                const asin_component &get_asin_component() const {
                    return asin;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                using gate_manifest_type = typename asin_component::gate_manifest_type;

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1, uint8_t m2) {
                    return asin_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2);
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    return asin_component::get_manifest(m1, m2);
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    return asin_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, get_m1(), get_m2());

                using input_type = typename asin_component::input_type;
                using result_type = typename asin_component::result_type;

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    // just the range table
                    return asin.component_custom_lookup_tables();
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    // just the range table
                    return asin.component_lookup_tables();
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_acos(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    asin(instantiate_asin(m1, m2)) {
                    ;
                };

                fix_acos(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    asin(instantiate_asin(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_acos =
                fix_acos<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                auto asin_component = component.get_asin_component();
                const auto var_pos = asin_component.get_var_pos(start_row_index);

                // assign asin
                auto asin_res = generate_assignments(asin_component, assignment, instance_input, start_row_index);

                // overwrite result
                auto m2 = component.get_m2();
                uint64_t pi_2 = 0;
                if (m2 == 1) {
                    pi_2 = 102944;
                } else if (m2 == 2) {
                    pi_2 = 6746518852;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }
                auto res = assignment.witness(splat(var_pos.y));
                assignment.witness(splat(var_pos.y)) = pi_2 - res;

                return asin_res;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                auto asin_component = component.get_asin_component();

                auto asin_res = generate_circuit(asin_component, bp, assignment, instance_input, start_row_index);

                // Overwrite the constants
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return asin_res;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_acos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                auto asin_component = component.get_asin_component();
                const auto var_pos = asin_component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto m2 = component.get_m2();
                uint64_t pi_2 = 0;
                if (m2 == 1) {
                    pi_2 = 102944;
                } else if (m2 == 2) {
                    pi_2 = 6746518852;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }

                assignment.constant(splat(var_pos.add_off)) = pi_2;
                assignment.constant(splat(var_pos.mul_off)) = -BlueprintFieldType::value_type::one();
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ACOS_HPP
