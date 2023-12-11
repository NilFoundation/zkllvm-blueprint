#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/range.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Uses the range gadget for clipping, and modifies the constraints of the exp gadget accordingly

            /**
             * Component representing an exp operation with clipping.
             *
             * Clipping means that the output is set to the highest/lowest allowed value in case of being too
             * large/small.
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x ... field element
             * Output: y ... e^x (field element)
             */
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
                uint8_t get_m() const {
                    return range.get_m();
                }

                uint8_t get_m1() const {
                    return range.get_m1();
                }

                uint8_t get_m2() const {
                    return range.get_m2();
                }

                uint64_t get_delta() const {
                    return range.get_delta();
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return std::max(exp_component::get_witness_columns(m2),
                                    range_component::get_witness_columns(witness_amount, m1, m2));
                }

                struct var_positions {
                    CellPosition exp_min, exp_max;
                    typename range_component::var_positions range_pos;
                    typename exp_component::var_positions exp_pos;
                    int64_t start_row, range_row, exp_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout witness (a col(s)), constant (2 col(s))
                    // where a = max(range_cols, exp_cols)
                    // number of rows: range_row(s) + exp_row
                    //
                    //                |      witness     |     constant      |
                    //       r\c      | 0 |  ..  | a - 1 |    0    |    1    |
                    // +--------------+---+------+-------+---------+---------+
                    // | range_row(s) | <range_witness>  | <range_const>     |
                    // | exp_row      | <exp_witness>    | exp_min | exp_max |

                    var_positions pos;
                    pos.start_row = start_row_index;
                    pos.range_row = start_row_index;
                    pos.exp_row = start_row_index + this->range.rows_amount;

                    pos.range_pos = this->range.get_var_pos(pos.range_row);
                    pos.exp_pos = this->exp.get_var_pos(pos.exp_row);
                    pos.exp_min = CellPosition(this->C(0), pos.exp_row);
                    pos.exp_max = CellPosition(this->C(1), pos.exp_row);
                    return pos;
                }

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
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_exp_ranged::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1 = 0, uint8_t m2 = 0) {
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

                // Includes the constraints + lookup_gates
                constexpr static const std::size_t gates_amount =
                    exp_component::gates_amount + range_component::gates_amount;
                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, range.get_m1(), range.get_m2());

                using input_type = typename exp_component::input_type;
                using result_type = typename exp_component::result_type;

                result_type get_result(std::uint32_t start_row_index) const {
                    const auto var_pos = get_var_pos(static_cast<int64_t>(start_row_index));
                    return result_type(exp, static_cast<size_t>(var_pos.exp_row));
                }

                result_type get_result(std::size_t start_row_index) const {
                    const auto var_pos = get_var_pos(static_cast<int64_t>(start_row_index));
                    return result_type(exp, static_cast<size_t>(var_pos.exp_row));
                }

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    // includes the ones for the range component
                    return exp.component_custom_lookup_tables();
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    // includes the ones for the range component
                    return exp.component_lookup_tables();
                }
#endif

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
                    exp_max(calc_max(m1, m2)), exp(instantiate_exp(m2)), range(instantiate_range(m1, m2, lo, hi)) {};
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

                const auto one = BlueprintFieldType::value_type::one();
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                // First, we put the range gadget into the trace
                // Then, we add the exp gadget into new rows

                typename plonk_fixedpoint_exp_ranged<BlueprintFieldType,
                                                     ArithmetizationParams>::range_component::input_type range_input;
                range_input.x = instance_input.x;

                auto range_comp = component.get_range_component();
                auto range_result = generate_assignments(range_comp, assignment, range_input, var_pos.range_row);

                auto exp_comp = component.get_exp_component();
                auto exp_result = generate_assignments(exp_comp, assignment, instance_input, var_pos.exp_row, false);

                // update output if out of range!
                if (var_value(assignment, range_result.lt) == one) {
                    assignment.witness(splat(var_pos.exp_pos.y)) = component.get_exp_min();
                } else if (var_value(assignment, range_result.gt) == one) {
                    assignment.witness(splat(var_pos.exp_pos.y)) = component.get_exp_max();
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

                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::var;

                auto exp_comp = component.get_exp_component();

                auto constraints = get_constraints(exp_comp, bp, assignment, instance_input);

                auto in = var(splat(var_pos.range_pos.in));
                auto lt = var(splat(var_pos.range_pos.lt));
                auto gt = var(splat(var_pos.range_pos.gt));
                auto y = var(splat(var_pos.exp_pos.y));
                auto exp_min = var(splat(var_pos.exp_min), true, var::column_type::constant);
                auto exp_max = var(splat(var_pos.exp_max), true, var::column_type::constant);

                constraints[0] *= in;
                constraints[2] *= in;
                constraints[2] += (1 - in) * (lt * exp_min + gt * exp_max - y);

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
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                typename plonk_fixedpoint_exp_ranged<BlueprintFieldType,
                                                     ArithmetizationParams>::range_component::input_type range_input;
                range_input.x = instance_input.x;

                // Enable the range component
                auto range_comp = component.get_range_component();
                generate_circuit(range_comp, bp, assignment, range_input, var_pos.range_row);

                // We slightly modify the exp component
                std::size_t exp_selector = generate_exp_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(exp_selector, var_pos.exp_row);

                auto exp_comp = component.get_exp_component();
// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                // Enable the lookup gates for exp
                std::size_t lookup_selector_index = generate_lookup_gates(exp_comp, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, var_pos.exp_row);
#endif

                // Enable the copy constraints of exp
                generate_copy_constraints(exp_comp, bp, assignment, instance_input, var_pos.exp_row);

                // Finally, we have to put the min/max values into the constant columns
                generate_assignments_constant(component, assignment, instance_input, var_pos.start_row);

                return component.get_result(start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                assignment.constant(splat(var_pos.exp_min)) = component.get_exp_min();
                assignment.constant(splat(var_pos.exp_max)) = component.get_exp_max();
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP
