#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASINH_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASINH_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/hyperbol_sqrt.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/hyperbol_log.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // uses the identity asinh(x) = log(x - sqrt(x^2 + 1))

            /**
             * Component representing an asinh operation with input x and output y, where y =
             * asinh(x).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... asinh(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_asinh;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_asinh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using hyperbol_sqrt_component = fix_hyperbol_sqrt<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

                using hyperbol_log_component = fix_hyperbol_log<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                hyperbol_sqrt_component asinh_sqrt;
                hyperbol_log_component log;
                uint8_t m1;
                uint8_t m2;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                hyperbol_sqrt_component instantiate_asinh_sqrt(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = hyperbol_sqrt_component::get_witness_columns(0, m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return hyperbol_sqrt_component(witness_list, std::array<std::uint32_t, 1>({this->C(0)}),
                                                   std::array<std::uint32_t, 0>(), m1, m2,
                                                   hyperbol_sqrt_component::hyperbolic_type::ASINH);
                }

                hyperbol_log_component instantiate_log(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = hyperbol_log_component::get_witness_columns(this->witness_amount(), m1);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return hyperbol_log_component(witness_list, std::array<std::uint32_t, 0>(),
                                                  std::array<std::uint32_t, 0>(), m1, m2);
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
                    return 1ULL << (16 * this->m2);
                }

                const hyperbol_sqrt_component &get_hyperbol_sqrt_component() const {
                    return asinh_sqrt;
                }

                const hyperbol_log_component &get_hyperbol_log_component() const {
                    return log;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    return hyperbol_sqrt_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2)
                        .merge_with(
                            hyperbol_log_component::get_gate_manifest(witness_amount, lookup_column_amount, m1));
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    return hyperbol_sqrt_component::get_manifest(m1, m2).merge_with(
                        hyperbol_log_component::get_manifest(m1));
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    auto asinh_sqrt_rows =
                        hyperbol_sqrt_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    auto log_rows =
                        hyperbol_log_component::get_rows_amount(witness_amount, lookup_column_amount, m1);
                    return asinh_sqrt_rows + log_rows;
                }

                constexpr static const std::size_t gates_amount = 0;

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, get_m1(), get_m2());

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct var_positions {
                    int64_t asinh_sqrt_row, log_row;
                    CellPosition two_const;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {
                    var_positions pos;
                    pos.asinh_sqrt_row = start_row_index;
                    pos.log_row = pos.asinh_sqrt_row + asinh_sqrt.rows_amount;
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_asinh &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        typename hyperbol_log_component::result_type log_res(component.get_hyperbol_log_component(),
                                                                             static_cast<std::size_t>(var_pos.log_row));
                        output = log_res.output;
                    }

                    result_type(const fix_asinh &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        typename hyperbol_log_component::result_type log_res(component.get_hyperbol_log_component(),
                                                                             static_cast<std::size_t>(var_pos.log_row));
                        output = log_res.output;
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result;
                    for (auto elem : asinh_sqrt.component_custom_lookup_tables()) {
                        result.push_back(elem);
                    }
                    for (auto elem : log.component_custom_lookup_tables()) {
                        result.push_back(elem);
                    }
                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> result = asinh_sqrt.component_lookup_tables();
                    result.merge(log.component_lookup_tables());
                    return result;
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_asinh(WitnessContainerType witness, ConstantContainerType constant,
                          PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    asinh_sqrt(instantiate_asinh_sqrt(m1, m2)), log(instantiate_log(m1, m2)), m1(m1), m2(m2) {};

                fix_asinh(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                              public_inputs,
                          uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    asinh_sqrt(instantiate_asinh_sqrt(m1, m2)), log(instantiate_log(m1, m2)), m1(m1), m2(m2) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_asinh =
                fix_asinh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using value_type = typename BlueprintFieldType::value_type;
                using var = typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::var;

                auto asinh_sqrt_comp = component.get_hyperbol_sqrt_component();
                auto log_comp = component.get_hyperbol_log_component();

                typename plonk_fixedpoint_asinh<
                    BlueprintFieldType, ArithmetizationParams>::hyperbol_sqrt_component::input_type asinh_sqrt_input;
                asinh_sqrt_input.x = instance_input.x;

                auto asinh_sqrt_res =
                    generate_assignments(asinh_sqrt_comp, assignment, asinh_sqrt_input, var_pos.asinh_sqrt_row);

                typename plonk_fixedpoint_asinh<BlueprintFieldType,
                                                ArithmetizationParams>::hyperbol_log_component::input_type log_input;
                log_input.x = asinh_sqrt_res.output;

                generate_assignments(log_comp, assignment, log_input, var_pos.log_row);

                return typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::var;
                auto asinh_sqrt_comp = component.get_hyperbol_sqrt_component();
                auto log_comp = component.get_hyperbol_log_component();

                typename plonk_fixedpoint_asinh<
                    BlueprintFieldType, ArithmetizationParams>::hyperbol_sqrt_component::input_type asinh_sqrt_input;
                asinh_sqrt_input.x = instance_input.x;

                generate_circuit(asinh_sqrt_comp, bp, assignment, asinh_sqrt_input, var_pos.asinh_sqrt_row);

                typename plonk_fixedpoint_asinh<BlueprintFieldType,
                                                ArithmetizationParams>::hyperbol_sqrt_component::result_type
                    asinh_sqrt_res(asinh_sqrt_comp, static_cast<std::size_t>(var_pos.asinh_sqrt_row));
                typename plonk_fixedpoint_asinh<BlueprintFieldType,
                                                ArithmetizationParams>::hyperbol_log_component::input_type log_input;
                log_input.x = asinh_sqrt_res.output;

                generate_circuit(log_comp, bp, assignment, log_input, var_pos.log_row);

                return typename plonk_fixedpoint_asinh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASINH_HPP
