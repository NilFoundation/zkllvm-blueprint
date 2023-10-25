#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/rescale.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x as fixedpoint numbers with \Delta_x
            // Output: y as fixedpoint number with \Delta_y = \Delta_y

            // Works by decomposing to the pre-comma part and, depending on \Delta_x, one or two 16-bit post-comma parts
            // and fusing lookup tables: y = exp(x) = exp(x_pre) * exp(x_post1) * exp(x_post2)
            // followed by a rescale

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_exp;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_exp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using rescale_component =
                    fix_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                uint8_t m2;    // Post-comma 16-bit limbs
                rescale_component rescale;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                rescale_component instantiate_rescale(uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = rescale_component::get_witness_columns(m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    witness_list.push_back(this->W(4 + 2 * m2));    // y_mul = input
                    witness_list.push_back(this->W(1));             // z = output
                    for (auto i = 2; i < witness_columns; i++) {
                        witness_list.push_back(this->W(4 + 2 * m2 + i));
                    }
                    return rescale_component(witness_list, std::array<std::uint32_t, 0>(),
                                             std::array<std::uint32_t, 0>(), m2);
                }

            public:
                const rescale_component &get_rescale_component() const {
                    return rescale;
                }

                uint8_t get_m2() const {
                    return rescale.get_m2();
                }

                uint64_t get_delta() const {
                    return rescale.get_delta();
                }

                static std::size_t get_witness_columns(uint8_t m2) {
                    return 4 + 2 * M(m2) + rescale_component::get_witness_columns(m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_exp::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m2))),
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

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_exp &component, std::uint32_t start_row_index) {
                        output = var(component.W(1), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const fix_exp &component, std::size_t start_row_index) {
                        output = var(component.W(1), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_exp(ContainerType witness, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m2)), m2(M(m2)), rescale(instantiate_rescale(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_exp(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m2)),
                    m2(M(m2)), rescale(instantiate_rescale(m2)) {};

                fix_exp(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m2)),
                    m2(M(m2)), rescale(instantiate_rescale(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_exp =
                fix_exp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index, bool assert_on_out_of_range = true) {

                const std::size_t j = start_row_index;
                auto m2 = component.get_m2();

                // | x | y | x_pre | y_pre | x_post1 | y_post1 |
                // if m2 == 2: add | x_post2 | y_post2 |
                // Then rescale: | y_mul | q0 | ... | where y of this component is actually the output of rescale (z)

                auto x = var_value(assignment, instance_input.x);
                assignment.witness(component.W(0), j) = x;

                uint64_t pre, post;
                bool sign = FixedPointHelper<BlueprintFieldType>::split_exp(x, 16 * m2, pre, post);

                int32_t table_half = FixedPointTables<BlueprintFieldType>::ExpALen / 2;
                int64_t input_a = sign ? table_half - (int64_t)pre : table_half + pre;

                auto exp_a = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_exp_a_16() :
                                       FixedPointTables<BlueprintFieldType>::get_exp_a_32();
                auto exp_b = FixedPointTables<BlueprintFieldType>::get_exp_b();

                auto output_a = exp_a[0];
                if (input_a >= 0 && input_a < exp_a.size()) {
                    output_a = exp_a[input_a];
                    assignment.witness(component.W(2), j) = input_a;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(!assert_on_out_of_range);
                    assignment.witness(component.W(2), j) = 0;
                }
                assignment.witness(component.W(3), j) = output_a;

                auto y_mul_col = 8;
                if (m2 == 2) {
                    auto exp_c = FixedPointTables<BlueprintFieldType>::get_exp_c();
                    uint32_t input_b = post >> 16;
                    uint32_t input_c = post & ((1ULL << 16) - 1);
                    BLUEPRINT_RELEASE_ASSERT(input_b >= 0 && input_b < exp_b.size());
                    BLUEPRINT_RELEASE_ASSERT(input_c >= 0 && input_c < exp_c.size());
                    auto output_b = exp_b[input_b];
                    auto output_c = exp_c[input_c];
                    auto res = output_a * output_b * output_c;
                    assignment.witness(component.W(y_mul_col), j) = res;
                    assignment.witness(component.W(4), j) = input_b;
                    assignment.witness(component.W(5), j) = output_b;
                    assignment.witness(component.W(6), j) = input_c;
                    assignment.witness(component.W(7), j) = output_c;
                } else {
                    y_mul_col = 6;
                    BLUEPRINT_RELEASE_ASSERT(post >= 0 && post < exp_b.size());
                    auto output_b = exp_b[post];
                    auto res = output_a * output_b;
                    assignment.witness(component.W(y_mul_col), j) = res;
                    assignment.witness(component.W(4), j) = post;
                    assignment.witness(component.W(5), j) = output_b;
                }

                // Assign rescale
                using var = typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::var;
                typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::rescale_component::input_type
                    rescale_input;
                rescale_input.x = var(component.W(y_mul_col), j);
                auto rescale_comp = component.get_rescale_component();
                generate_assignments(rescale_comp, assignment, rescale_input, j);

                return typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::var;
                auto m2 = component.get_m2();
                auto delta = component.get_delta();
                uint32_t table_half = FixedPointTables<BlueprintFieldType>::ExpALen / 2;

                auto exp_in = var(component.W(0), 0);
                auto tab_a_in = var(component.W(2), 0);
                auto tab_a_out = var(component.W(3), 0);
                auto tab_b_in = var(component.W(4), 0);
                auto tab_b_out = var(component.W(5), 0);

                auto constraint_1 = delta * (tab_a_in - table_half) - exp_in;
                auto constraint_2 = nil::crypto3::math::expression(tab_a_out * tab_b_out);

                auto y_mul_col = 8;
                if (m2 == 2) {
                    auto tab_c_in = var(component.W(6), 0);
                    auto tab_c_out = var(component.W(7), 0);
                    constraint_1 += (1ULL << 16) * tab_b_in + tab_c_in;
                    constraint_2 *= tab_c_out;
                } else {
                    y_mul_col = 6;
                    constraint_1 += tab_b_in;
                }
                auto y_mul = var(component.W(y_mul_col), 0);
                constraint_2 -= y_mul;

                // Constrain rescale
                typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::rescale_component::input_type
                    rescale_input;
                rescale_input.x = var(component.W(y_mul_col), 0);
                auto rescale_comp = component.get_rescale_component();
                auto constraint_3 = get_constraint(rescale_comp, bp, assignment, rescale_input);

                // TACEO_TODO extend for lookup constraint
                return {constraint_1, constraint_2, constraint_3};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_HPP
