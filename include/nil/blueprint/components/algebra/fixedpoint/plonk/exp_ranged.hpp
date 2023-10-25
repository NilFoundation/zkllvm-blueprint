#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP

#include "nil/blueprint/components/algebra/fixedpoint/tables.hpp"

#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/range.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x as fixedpoint numbers with \Delta_x
            // Output: y as fixedpoint number with huge scale!
            // Additionally clips output to  a predefined min/max range if the values are to small/large

            // Uses the range gadget for clipping, and modifies the constraints of the exp gadget accordingly

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_exp_ranged;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_exp_ranged<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                 BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using exp_component =
                    fix_exp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using range_component =
                    fix_range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                const value_type lo;
                const value_type hi;
                const value_type exp_min;
                const value_type exp_max;

                exp_component exp;
                range_component range;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                static value_type calc_max(uint8_t m1, uint8_t m2) {
                    if (m1 == 1 && m2 == 1) {
                        auto max = FixedPoint<BlueprintFieldType, 1, 1>::max();
                        return max.get_value();
                    } else if (m1 == 2 && m2 == 1) {
                        auto max = FixedPoint<BlueprintFieldType, 2, 1>::max();
                        return max.get_value();
                    } else if (m1 == 1 && m2 == 2) {
                        auto max = FixedPoint<BlueprintFieldType, 1, 2>::max();
                        return max.get_value();
                    } else if (m1 == 2 && m2 == 2) {
                        auto max = FixedPoint<BlueprintFieldType, 2, 2>::max();
                        return max.get_value();
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                        return 0;
                    }
                }

                exp_component instantiate_exp(uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = exp_component::get_witness_columns(m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return exp_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                         m2);
                }

                range_component instantiate_range(uint8_t m1, uint8_t m2, const value_type &low,
                                                  const value_type &high) const {
                    std::vector<std::uint32_t> witness_list;

                    auto witness_columns = range_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return range_component(witness_list, std::array<std::uint32_t, 2>({this->C(0), this->C(1)}),
                                           std::array<std::uint32_t, 0>(), m1, m2, low, high);
                }

            public:
                const exp_component &get_exp_component() const {
                    return exp;
                }

                const range_component &get_range_component() const {
                    return range;
                }

                const value_type get_exp_min() const {
                    return exp_min;
                }

                const value_type get_exp_max() const {
                    return exp_max;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 2;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        exp_component::get_gate_manifest(witness_amount, lookup_column_amount)
                            .merge_with(range_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        exp_component::get_manifest(m2).merge_with(range_component::get_manifest(m1, m2));
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    return range_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2) +
                           exp_component::get_rows_amount(witness_amount, lookup_column_amount);
                }

                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, range.get_m1(), range.get_m2());

                using input_type = typename exp_component::input_type;
                using result_type = typename exp_component::result_type;

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_exp_ranged(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    lo(FixedPointTables<BlueprintFieldType>::get_lowest_exp_input(m2)),
                    hi(FixedPointTables<BlueprintFieldType>::get_highest_valid_exp_input(m1, m2)), exp_min(0),
                    exp_max(calc_max(m1, m2)), exp(instantiate_exp(m2)), range(instantiate_range(m1, m2, lo, hi)) {
                    ;
                };

                fix_exp_ranged(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    lo(FixedPointTables<BlueprintFieldType>::get_lowest_exp_input(m2)),
                    hi(FixedPointTables<BlueprintFieldType>::get_highest_valid_exp_input(m1, m2)), exp_min(0),
                    exp_max(calc_max(m1, m2)), exp(instantiate_exp(m2)),
                    range(instantiate_range(m1, m2, lo, hi)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_exp_ranged =
                fix_exp_ranged<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                               BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                // First, we put the range gadget into the trace
                // Then, we add the exp gadget into new rows

                typename plonk_fixedpoint_exp_ranged<BlueprintFieldType,
                                                     ArithmetizationParams>::range_component::input_type range_input;
                range_input.x = instance_input.x;

                auto range_comp = component.get_range_component();
                auto range_result = generate_assignments(range_comp, assignment, range_input, start_row_index);

                auto range_rows = range_comp.rows_amount;
                auto exp_row = start_row_index + range_rows;

                auto exp_comp = component.get_exp_component();
                auto exp_result = generate_assignments(exp_comp, assignment, instance_input, exp_row, false);

                // update output if out of range!
                if (var_value(assignment, range_result.lt) == BlueprintFieldType::value_type::one()) {
                    assignment.witness(exp_result.output.index, exp_row) = component.get_exp_min();
                } else if (var_value(assignment, range_result.gt) == BlueprintFieldType::value_type::one()) {
                    assignment.witness(exp_result.output.index, exp_row) = component.get_exp_max();
                }

                return exp_result;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_exp_gates(
                const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::var;

                auto exp_comp = component.get_exp_component();
                auto range_comp = component.get_range_component();

                typename plonk_fixedpoint_range<BlueprintFieldType, ArithmetizationParams>::result_type range_output(
                    range_comp, (std::uint32_t)0);

                typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type exp_output(
                    exp_comp, (std::uint32_t)0);

                auto constraints = get_constraints(exp_comp, bp, assignment, instance_input);

                auto in = var(range_output.in.index, -1);
                auto lt = var(range_output.lt.index, -1);
                auto gt = var(range_output.gt.index, -1);
                auto y = var(exp_output.output.index, 0);
                auto min = var(component.C(0), 0, true, var::column_type::constant);
                auto max = var(component.C(1), 0, true, var::column_type::constant);

                constraints[0] *= in;
                constraints[2] *= in;
                constraints[2] += (1 - in) * (lt * min + gt * max - y);

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                typename plonk_fixedpoint_exp_ranged<BlueprintFieldType,
                                                     ArithmetizationParams>::range_component::input_type range_input;
                range_input.x = instance_input.x;

                // Enable the range component
                auto range_comp = component.get_range_component();
                std::size_t range_selector = generate_gates(range_comp, bp, assignment, range_input);
                assignment.enable_selector(range_selector, start_row_index + range_comp.rows_amount - 1);
                generate_copy_constraints(range_comp, bp, assignment, range_input, start_row_index);
                generate_assignments_constant(range_comp, assignment, range_input, start_row_index);

                auto exp_row = start_row_index + range_comp.rows_amount;

                // We slightly modify the exp component
                std::size_t exp_selector = generate_exp_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(exp_selector, exp_row);

                // Enable the copy constraints of exp
                auto exp_comp = component.get_exp_component();
                generate_copy_constraints(exp_comp, bp, assignment, instance_input, exp_row);

                // Finally, we have to put the min/max values into the constant columns
                generate_assignments_constant(component, assignment, instance_input, exp_row);

                return typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::result_type(
                    exp_comp, exp_row);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t row_index) {

                assignment.constant(component.C(0), row_index) = component.get_exp_min();
                assignment.constant(component.C(1), row_index) = component.get_exp_max();
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP
