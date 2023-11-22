#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_MIN_MAX_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_MIN_MAX_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/cmp.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing the difference of the inputs using the cmp gadget

            /**
             * Component representing a compare operation.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same).
             *
             * The outputs are flags with values in {0, 1} that describe the relation between x and y, as well as the
             * minimum and maximum value of x and y.
             *
             * Input:  x   ... field element
             *         y   ... field element
             * Output: eq  ... 1 if x = y, 0 otherwise (field element)
             *         lt  ... 1 if x < y, 0 otherwise (field element)
             *         gt  ... 1 if x > y, 0 otherwise (field element)
             *         min ... min(x, y) (field element)
             *         max ... max(x, y) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_cmp_min_max;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_cmp_min_max<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using cmp_component =
                    fix_cmp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                cmp_component cmp;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                cmp_component instantiate_cmp(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = cmp_component::get_witness_columns(m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < 5; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    // we include min/max after gt and before s,inv,y0... in the trace
                    for (auto i = 5; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i + 2));
                    }
                    return cmp_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                         m1, m2);
                }

            public:
                const cmp_component &get_cmp_component() const {
                    return cmp;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_cmp_min_max::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                                                        // I include the number of witness for cmp before the merge,
                                                        // since merge chooses max and we put everything in one row
                                                        std::shared_ptr<manifest_param>(new manifest_single_value_param(
                                                            2 + cmp_component::get_witness_columns(m1, m2))),
                                                        false)
                                                        .merge_with(cmp_component::get_manifest(m1, m2));
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                // Includes the constraints + lookup_gates
                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                using input_type = typename cmp_component::input_type;

                struct var_positions {
                    CellPosition x, y, eq, lt, gt, min, max, s, inv, d0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (9 + m+1 col(s), 1 row(s))
                    // requiring an extra limb because of potential overflows during decomposition of
                    // differences
                    //
                    // Changing the layout here requires changing the mapping in instantiate_cmp as well.
                    //
                    //     |                           witness                            |
                    //  r\c| 0 | 1 | 2  | 3  | 4  |  5  |  6  | 7 |  8  | 9  | .. | 9 + m |
                    // +---+---+---+----+----+----+-----+-----+---+-----+----+----+-------+
                    // | 0 | x | y | eq | lt | gt | min | max | s | inv | d0 | .. | dm    |

                    auto m = cmp.get_m();
                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    pos.eq = CellPosition(this->W(2), start_row_index);
                    pos.lt = CellPosition(this->W(3), start_row_index);
                    pos.gt = CellPosition(this->W(4), start_row_index);
                    pos.min = CellPosition(this->W(5), start_row_index);
                    pos.max = CellPosition(this->W(6), start_row_index);
                    pos.s = CellPosition(this->W(7), start_row_index);
                    pos.inv = CellPosition(this->W(8), start_row_index);
                    pos.d0 = CellPosition(this->W(9 + 0 * (m + 1)), start_row_index);    // occupies m + 1 cells
                    return pos;
                }

                struct result_type {
                    var eq = var(0, 0, false);
                    var lt = var(0, 0, false);
                    var gt = var(0, 0, false);
                    var min = var(0, 0, false);
                    var max = var(0, 0, false);
                    result_type(const fix_cmp_min_max &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        eq = var(splat(var_pos.eq), false);
                        lt = var(splat(var_pos.lt), false);
                        gt = var(splat(var_pos.gt), false);
                        min = var(splat(var_pos.min), false);
                        max = var(splat(var_pos.max), false);
                    }

                    result_type(const fix_cmp_min_max &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        eq = var(splat(var_pos.eq), false);
                        lt = var(splat(var_pos.lt), false);
                        gt = var(splat(var_pos.gt), false);
                        min = var(splat(var_pos.min), false);
                        max = var(splat(var_pos.max), false);
                    }

                    std::vector<var> all_vars() const {
                        return {eq, lt, gt, min, max};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    return cmp.component_custom_lookup_tables();
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    return cmp.component_lookup_tables();
                }
#endif

                template<typename ContainerType>
                explicit fix_cmp_min_max(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), cmp(instantiate_cmp(m1, m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_cmp_min_max(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    cmp(instantiate_cmp(m1, m2)) {};

                fix_cmp_min_max(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    cmp(instantiate_cmp(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_cmp_min_max =
                fix_cmp_min_max<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto cmp_comp = component.get_cmp_component();
                auto result = generate_assignments(cmp_comp, assignment, instance_input, start_row_index);
                auto one = BlueprintFieldType::value_type::one();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);

                if (var_value(assignment, result.eq) == one) {
                    assignment.witness(splat(var_pos.min)) = x_val;
                    assignment.witness(splat(var_pos.max)) = x_val;
                } else if (var_value(assignment, result.lt) == one) {
                    assignment.witness(splat(var_pos.min)) = x_val;
                    assignment.witness(splat(var_pos.max)) = y_val;
                } else {
                    assignment.witness(splat(var_pos.min)) = y_val;
                    assignment.witness(splat(var_pos.max)) = x_val;
                }

                return typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::var;

                auto cmp_comp = component.get_cmp_component();
                auto constraints = get_constraints(cmp_comp, bp, assignment, instance_input);

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto min = var(splat(var_pos.min));
                auto max = var(splat(var_pos.max));
                auto s = var(splat(var_pos.s));
                auto inv2 = typename BlueprintFieldType::value_type(2).inversed();

                auto constraint_1 = min - inv2 * (s * (y - x) + x + y);
                auto constraint_2 = max - inv2 * (s * (x - y) + x + y);

                constraints.reserve(constraints.size() + 2);
                constraints.push_back(constraint_1);
                constraints.push_back(constraint_2);

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                auto cmp_comp = component.get_cmp_component();
                generate_copy_constraints(cmp_comp, bp, assignment, instance_input, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                auto cmp_comp = component.get_cmp_component();
                std::size_t lookup_selector_index = generate_lookup_gates(cmp_comp, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_cmp_min_max<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_MIN_MAX_HPP
