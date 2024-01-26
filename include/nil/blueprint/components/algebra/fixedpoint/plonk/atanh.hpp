#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATANH_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATANH_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/atanh_div_by_pos.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/log.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // uses the identity atanh(x) = 1/2 * log((1+x)/(1-x))

            /**
             * Component representing an atanh operation with input x and output y, where y =
             * atanh(x).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... atanh(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_atanh;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_atanh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using atanh_div_by_pos_component = fix_atanh_div_by_pos<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

                using log_component =
                    fix_log<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

                using div_by_pos_component = fix_div_by_pos<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                atanh_div_by_pos_component atanh_div;
                log_component log;
                div_by_pos_component div;
                uint8_t m1;
                uint8_t m2;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                atanh_div_by_pos_component instantiate_atanh_div(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = atanh_div_by_pos_component::get_witness_columns(0, m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return atanh_div_by_pos_component(witness_list, std::array<std::uint32_t, 0>(),
                                                      std::array<std::uint32_t, 0>(), m1, m2);
                }

                log_component instantiate_log(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = log_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return log_component(witness_list, std::array<std::uint32_t, 2>({this->C(0), this->C(1)}),
                                         std::array<std::uint32_t, 0>(), m1, m2);
                }

                div_by_pos_component instantiate_div(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = div_by_pos_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return div_by_pos_component(witness_list, std::array<std::uint32_t, 0>(),
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

                value_type calc_log(const value_type &x, uint8_t m1, uint8_t m2) const {
                    if (m1 == 1 && m2 == 1) {
                        auto el = FixedPoint<BlueprintFieldType, 1, 1>(x, 16);
                        return el.log().get_value();
                    } else if (m1 == 2 && m2 == 1) {
                        auto el = FixedPoint<BlueprintFieldType, 2, 1>(x, 16);
                        return el.log().get_value();
                    } else if (m1 == 1 && m2 == 2) {
                        auto el = FixedPoint<BlueprintFieldType, 1, 2>(x, 32);
                        return el.log().get_value();
                    } else if (m1 == 2 && m2 == 2) {
                        auto el = FixedPoint<BlueprintFieldType, 2, 2>(x, 32);
                        return el.log().get_value();
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                        return 0;
                    }
                }

                const atanh_div_by_pos_component &get_atanh_div_component() const {
                    return atanh_div;
                }

                const log_component &get_log_component() const {
                    return log;
                }

                const div_by_pos_component &get_div_component() const {
                    return div;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
                    return atanh_div_by_pos_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2)
                        .merge_with(log_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2))
                        .merge_with(
                            div_by_pos_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2));
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    return atanh_div_by_pos_component::get_manifest(m1, m2)
                        .merge_with(log_component::get_manifest(m1, m2))
                        .merge_with(div_by_pos_component::get_manifest(m1, m2));
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    auto atanh_div_rows =
                        atanh_div_by_pos_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    auto log_rows = log_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    auto div_rows = div_by_pos_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    return atanh_div_rows + log_rows + div_rows;
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
                    int64_t atanh_div_row, log_row, div_row;
                    CellPosition two_const;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {
                    var_positions pos;
                    pos.atanh_div_row = start_row_index;
                    pos.log_row = pos.atanh_div_row + atanh_div.rows_amount;
                    pos.div_row = pos.log_row + log.rows_amount;
                    pos.two_const = CellPosition(this->C(0), pos.div_row);
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_atanh &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        typename div_by_pos_component::result_type div_res(component.get_div_component(),
                                                                           static_cast<std::size_t>(var_pos.div_row));
                        output = div_res.output;
                    }

                    result_type(const fix_atanh &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        typename div_by_pos_component::result_type div_res(component.get_div_component(),
                                                                           static_cast<std::size_t>(var_pos.div_row));
                        output = div_res.output;
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result;
                    for (auto elem : atanh_div.component_custom_lookup_tables()) {
                        result.push_back(elem);
                    }
                    for (auto elem : log.component_custom_lookup_tables()) {
                        result.push_back(elem);
                    }
                    for (auto elem : div.component_custom_lookup_tables()) {
                        result.push_back(elem);
                    }
                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> result = atanh_div.component_lookup_tables();
                    result.merge(log.component_lookup_tables());
                    result.merge(div.component_lookup_tables());
                    return result;
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_atanh(WitnessContainerType witness, ConstantContainerType constant,
                          PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    atanh_div(instantiate_atanh_div(m1, m2)), log(instantiate_log(m1, m2)),
                    div(instantiate_div(m1, m2)), m1(m1), m2(m2) {};

                fix_atanh(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                              public_inputs,
                          uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    atanh_div(instantiate_atanh_div(m1, m2)), log(instantiate_log(m1, m2)),
                    div(instantiate_div(m1, m2)), m1(m1), m2(m2) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_atanh =
                fix_atanh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using value_type = typename BlueprintFieldType::value_type;
                using var = typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::var;

                assignment.constant(splat(var_pos.two_const)) = value_type(component.get_delta() * 2);

                auto atanh_div_comp = component.get_atanh_div_component();
                auto log_comp = component.get_log_component();
                auto div_comp = component.get_div_component();

                typename plonk_fixedpoint_atanh<
                    BlueprintFieldType, ArithmetizationParams>::atanh_div_by_pos_component::input_type atanh_div_input;
                atanh_div_input.x = instance_input.x;

                auto atanh_div_res =
                    generate_assignments(atanh_div_comp, assignment, atanh_div_input, var_pos.atanh_div_row);

                typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::log_component::input_type
                    log_input;
                log_input.x = atanh_div_res.output;

                auto log_res = generate_assignments(log_comp, assignment, log_input, var_pos.log_row);
                typename plonk_fixedpoint_atanh<BlueprintFieldType,
                                                ArithmetizationParams>::div_by_pos_component::input_type div_input;
                div_input.x = log_res.output;
                div_input.y = var(splat(var_pos.two_const), false, var::column_type::constant);

                auto div_res = generate_assignments(div_comp, assignment, div_input, var_pos.div_row);

                return typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::var;
                auto atanh_div_comp = component.get_atanh_div_component();
                auto log_comp = component.get_log_component();
                auto div_comp = component.get_div_component();

                typename plonk_fixedpoint_atanh<
                    BlueprintFieldType, ArithmetizationParams>::atanh_div_by_pos_component::input_type atanh_div_input;
                atanh_div_input.x = instance_input.x;

                generate_circuit(atanh_div_comp, bp, assignment, atanh_div_input, var_pos.atanh_div_row);

                typename plonk_fixedpoint_atanh<BlueprintFieldType,
                                                ArithmetizationParams>::atanh_div_by_pos_component::result_type
                    atanh_div_res(atanh_div_comp, static_cast<std::size_t>(var_pos.atanh_div_row));
                typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::log_component::input_type
                    log_input;
                log_input.x = atanh_div_res.output;

                generate_circuit(log_comp, bp, assignment, log_input, var_pos.log_row);

                typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::log_component::result_type
                    log_res(log_comp, static_cast<std::size_t>(var_pos.log_row));

                typename plonk_fixedpoint_atanh<BlueprintFieldType,
                                                ArithmetizationParams>::div_by_pos_component::input_type div_input;
                div_input.x = log_res.output;
                div_input.y = var(splat(var_pos.two_const), false, var::column_type::constant);

                generate_circuit(div_comp, bp, assignment, div_input, var_pos.div_row);

                return typename plonk_fixedpoint_atanh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ATANH_HPP
