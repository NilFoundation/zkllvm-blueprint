#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TO_INT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TO_INT_HPP

#include <cstdint>
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

            // Works by decomposing the input and composing the necessary part. If the input is negative and we have an
            // unsigned typ, we add the MAX+1.

            /**
             * Component representing a cast_to_integer operation.
             *
             * Input:  x       ... field element
             * Output: y       ... Integer(x) (field element)
             *
             */

            // TACEO_TODO: Plan is:
            // uint8_t and int8_t: 8-bit lookups!
            // We split everything into u16 as usual, except for x[m2] (i.e., the output) which we split into 2 u8s.
            // This results in 1 extra column.
            //
            // to_bool (separate gadget):
            // !is_zero()

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_to_int;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_to_int<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {
            public:
                using value_type = typename BlueprintFieldType::value_type;

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
                enum OutputType { U8 = 0, U16, U32, U64, I8, I16, I32, I64 };

                template<typename Integer>
                static OutputType get_type() {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }
                template<typename Integer>
                static OutputType get_offset() {
                    BLUEPRINT_RELEASE_ASSERT(false);
                }
#define macro_get_type(type, enum_type)  \
    template<>                           \
    static OutputType get_type<type>() { \
        return OutputType::enum_type;    \
    }
                macro_get_type(uint8_t, U8);
                macro_get_type(uint16_t, U16);
                macro_get_type(uint32_t, U32);
                macro_get_type(uint64_t, U64);
                macro_get_type(int8_t, I8);
                macro_get_type(int16_t, I16);
                macro_get_type(int32_t, I32);
                macro_get_type(int64_t, I64);
#undef macro_get_type

                bool is_signed() const {
                    return out_type >= OutputType::I8;
                }

                bool is_unsigned() const {
                    return out_type < OutputType::I8;
                }

                uint64_t get_offset() const {
                    switch (out_type) {
                        case U8: {
                            return (uint64_t)std::numeric_limits<uint8_t>::max();
                        }
                        case U16: {
                            return (uint64_t)std::numeric_limits<uint16_t>::max();
                        }
                        case U32: {
                            return (uint64_t)std::numeric_limits<uint32_t>::max();
                        }
                        case U64: {
                            return (uint64_t)std::numeric_limits<uint64_t>::max();
                        }
                        default: {
                            BLUEPRINT_RELEASE_ASSERT(false);
                            return 0;
                        }
                    }
                }

                OutputType out_type;

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
                    return 1ULL << (16 * m2);
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2,
                                                       OutputType out) {
                    if (out == OutputType::U8 || out == OutputType::I8) {
                        return 4 + M(m1) + M(m2);
                    } else {
                        return 3 + M(m1) + M(m2);
                    }
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
                        return fix_to_int::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2, uint8_t out) {
                    auto cols = 3 + M(m1) + M(m2);
                    if (out == OutputType::U8 || out == OutputType::I8) {
                        cols += 1;
                    }
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(cols)), false);
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

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct var_positions {
                    CellPosition x, y, s, x0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (3 + m col(s) for 16/32/64 bit ouput, 4 + m col(s) for 8 bit output, 1 row(s))
                    //
                    //     |          witness            |
                    //  r\c| 0 | 1 | 2 | 3  | .. | 3 + m |
                    // +---+---+---+---+----+----+---------+
                    // | 0 | x | y | s | x0 | .. |   xm  |

                    auto m = this->get_m();
                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    pos.s = CellPosition(this->W(2), start_row_index);
                    pos.x0 = CellPosition(this->W(3 + 0 * m), start_row_index);    // occupies m or m+1 cells
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);

                    result_type(const fix_to_int &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_to_int &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling the lookup tables for faster testing
// TACEO_TODO add uint8_t lookup table if required
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
                explicit fix_to_int(ContainerType witness, uint8_t m1, uint8_t m2, OutputType out) :
                    component_type(witness, {}, {}, get_manifest(m1, m2, out)), m1(M(m1)), m2(M(m2)), out_type(out) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_to_int(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input, uint8_t m1, uint8_t m2, OutputType out) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2, out)),
                    m1(M(m1)), m2(M(m2)), out_type(out) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_to_int(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input, uint8_t m1, uint8_t m2, uint8_t out) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2, out)),
                    m1(M(m1)), m2(M(m2)), out_type(out) {};

                fix_to_int(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2, OutputType out) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2, out)),
                    m1(M(m1)), m2(M(m2)), out_type(out) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_to_int =
                fix_to_int<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                if (component.out_type ==
                        plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U8 ||
                    component.out_type ==
                        plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I8) {
                    BLUEPRINT_RELEASE_ASSERT(false && "Not yet implemented");
                }

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                const auto one = BlueprintFieldType::value_type::one();
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = m1 + m2;

                auto x_val = var_value(assignment, instance_input.x);

                assignment.witness(splat(var_pos.x)) = x_val;

                // uint64_t x_pre_val, x_post_val;
                // bool sign = FixedPointHelper<BlueprintFieldType>::split(x_val, 16 * m2, x_pre_val, x_post_val);

                std::vector<uint16_t> x0_val;
                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(x_val, x0_val);
                // is ok because x0_val is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= m);

                auto s_val = sign ? -one : one;
                typename BlueprintFieldType::value_type y_val;

                // Take the output depending on the output type
                switch (component.out_type) {
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U8:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I8:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U16:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I16: {
                        y_val = x0_val[m2];
                        break;
                    }
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U32:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I32:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U64:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I64: {
                        y_val = x0_val[m2] + x0_val[m2 + 1] * (1ULL << 16);
                        break;
                    }
                    default:
                        BLUEPRINT_RELEASE_ASSERT(false);
                }

                if (sign) {
                    y_val = -y_val;
                    if (component.is_unsigned()) {
                        y_val += component.get_offset();
                        y_val += one;
                    }
                }

                assignment.witness(splat(var_pos.s)) = s_val;
                assignment.witness(splat(var_pos.y)) = y_val;

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                }

                return typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int first_row = 1 - static_cast<int>(component.rows_amount);
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(first_row));

                using var = typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::var;

                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto delta = component.get_delta();

                auto x_post = nil::crypto3::math::expression(var(splat(var_pos.x0)));
                for (auto i = 1; i < m2; i++) {
                    x_post += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }

                auto x_pre = nil::crypto3::math::expression(var(var_pos.x0.column() + m2, var_pos.x0.row()));
                for (auto i = 1; i < m1; i++) {
                    x_pre += var(var_pos.x0.column() + m2 + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }

                nil::crypto3::math::expression<var> composed;

                // Take the output depending on the output type
                switch (component.out_type) {
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U8:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I8:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U16:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I16: {
                        composed = nil::crypto3::math::expression(var(var_pos.x0.column() + m2, var_pos.x0.row()));
                        break;
                    }
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U32:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I32:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U64:
                    case plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I64: {
                        composed = x_pre;
                        break;
                    }
                    default:
                        BLUEPRINT_RELEASE_ASSERT(false);
                }

                auto x = var(splat(var_pos.x));
                auto y = var(splat(var_pos.y));
                auto s = var(splat(var_pos.s));

                auto constraint_1 = x - s * (x_pre * delta + x_post);
                auto constraint_2 = (s - 1) * (s + 1);
                auto constraint_3 = y - s * composed;
                if (component.is_unsigned()) {
                    auto inv2 = typename BlueprintFieldType::value_type(2).inversed();
                    constraint_3 -=
                        (1 - s) * (typename BlueprintFieldType::value_type(component.get_offset()) + 1) * inv2;
                }

                return bp.add_gate({constraint_1, constraint_2, constraint_3});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const std::map<std::string, std::size_t> &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(m);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);

                for (auto i = 0; i < m; i++) {
                    constraint_type constraint;
                    constraint.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto di = var(var_pos.x0.column() + i, 0);
                    constraint.lookup_input = {di};
                    constraints.push_back(constraint);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(splat(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                if (component.out_type ==
                        plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::U8 ||
                    component.out_type ==
                        plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::OutputType::I8) {
                    BLUEPRINT_RELEASE_ASSERT(false && "Not yet implemented");
                }

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, start_row_index);
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_to_int<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TO_INT_HPP
