#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TESTER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TESTER_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/argmax.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/argmin.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/gather_acc.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/cmp.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/cmp_extended.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/cmp_min_max.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/select.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/range.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/min.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/max.hpp"
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include "nil/blueprint/components/algebra/fixedpoint/plonk/mul_rescale.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/mul_rescale_const.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/div.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/rem.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/rescale.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/neg.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/to_fixedpoint.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp_ranged.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/dot_rescale_1_gate.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/dot_rescale_2_gates.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/log.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/sqrt.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/sqrt_floor.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/tanh.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/sin.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/cos.hpp"
#include <nil/blueprint/components/algebra/fixedpoint/plonk/sign_abs.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            enum FixedPointComponents {
                ADD,
                ARGMAX,
                ARGMIN,
                CMP,
                CMP_EXTENDED,
                CMP_MIN_MAX,
                COS,
                DIV_BY_POS,
                DIV,
                DOT_RESCALE1,
                DOT_RESCALE2,
                EXP,
                EXP_RANGED,
                GATHER_ACC,
                LOG,
                MAX,
                MIN,
                MUL_RESCALE,
                MUL_RESCALE_CONST,
                NEG,
                RANGE,
                REM,
                RESCALE,
                SELECT,
                SIGN_ABS,
                SIN,
                SQRT,
                SQRT_FLOOR,
                SUB,
                TANH,
                TO_FIXEDPOINT
            };

            static constexpr uint8_t TESTER_MAX_CONSTANT_COLS = 2;

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_tester;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_tester<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, TESTER_MAX_CONSTANT_COLS, 0> {
            public:
                using value_type = typename BlueprintFieldType::value_type;

                struct testcase {
                    FixedPointComponents component;
                    std::vector<value_type> inputs;
                    std::vector<value_type> outputs;
                    std::vector<value_type> constants;
                    uint8_t m1;
                    uint8_t m2;
                    std::uint32_t size;
                };

            private:
                std::vector<testcase> testcases;

            public:
                const std::vector<testcase> &get_testcases() const {
                    return testcases;
                }

                static std::size_t io_rows_for_dot(std::size_t witness_amount, std::uint32_t dots) {
                    auto inputs_outputs = 2 * dots + 2;
                    auto rows = inputs_outputs / witness_amount;
                    rows += inputs_outputs % witness_amount == 0 ? 0 : 1;
                    return rows;
                }

                static std::tuple<std::size_t, std::size_t> split(std::size_t witness_amount,
                                                                  std::size_t start_row_index, std::size_t index) {
                    auto row = start_row_index + index / witness_amount;
                    auto column = index % witness_amount;
                    return std::make_tuple(column, row);
                }

///////////////////////////////////////////////////////////////////////////////
//  macro
#define macro_rows_amount(name, ...)                                                     \
    name<ArithmetizationType, BlueprintFieldType, NonNativePolicyType>::get_rows_amount( \
        witness_amount, lookup_column_amount, ##__VA_ARGS__);
                ///////////////////////////////////////////////////////////////////////////////

                static std::size_t get_component_rows_amount(FixedPointComponents component, std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2,
                                                             std::uint32_t size = 0) {
                    using ArithmetizationType =
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                    auto input_output_rows = 1;
                    auto component_rows = 0;

                    switch (component) {
                        case FixedPointComponents::ADD:
                            component_rows = macro_rows_amount(addition);
                            break;
                        case FixedPointComponents::ARGMAX:
                            component_rows = macro_rows_amount(fix_argmax, m1, m2);
                            break;
                        case FixedPointComponents::ARGMIN:
                            component_rows = macro_rows_amount(fix_argmin, m1, m2);
                            break;
                        case FixedPointComponents::CMP:
                            component_rows = macro_rows_amount(fix_cmp);
                            break;
                        case FixedPointComponents::CMP_EXTENDED:
                            component_rows = macro_rows_amount(fix_cmp_extended);
                            break;
                        case FixedPointComponents::CMP_MIN_MAX:
                            component_rows = macro_rows_amount(fix_cmp_min_max);
                            break;
                        case FixedPointComponents::COS:
                            component_rows = macro_rows_amount(fix_cos, m1, m2);
                            break;
                        case FixedPointComponents::DIV_BY_POS:
                            component_rows = macro_rows_amount(fix_div_by_pos, m1, m2);
                            break;
                        case FixedPointComponents::DIV:
                            component_rows = macro_rows_amount(fix_div, m1, m2);
                            break;
                        case FixedPointComponents::DOT_RESCALE1:
                            input_output_rows = io_rows_for_dot(witness_amount, size);
                            component_rows = macro_rows_amount(fix_dot_rescale_1_gate, size, m2);
                            break;
                        case FixedPointComponents::DOT_RESCALE2:
                            input_output_rows = io_rows_for_dot(witness_amount, size);
                            component_rows = macro_rows_amount(fix_dot_rescale_2_gates, size, m2);
                            break;
                        case FixedPointComponents::EXP:
                            component_rows = macro_rows_amount(fix_exp);
                            break;
                        case FixedPointComponents::EXP_RANGED:
                            component_rows = macro_rows_amount(fix_exp_ranged, m1, m2);
                            break;
                        case FixedPointComponents::GATHER_ACC:
                            component_rows = macro_rows_amount(fix_gather_acc);
                            break;
                        case FixedPointComponents::LOG:
                            component_rows = macro_rows_amount(fix_log, m1, m2);
                            break;
                        case FixedPointComponents::MAX:
                            component_rows = macro_rows_amount(fix_max);
                            break;
                        case FixedPointComponents::MIN:
                            component_rows = macro_rows_amount(fix_min);
                            break;
                        case FixedPointComponents::MUL_RESCALE:
                            component_rows = macro_rows_amount(fix_mul_rescale);
                            break;
                        case FixedPointComponents::MUL_RESCALE_CONST:
                            component_rows = macro_rows_amount(fix_mul_rescale_const);
                            break;
                        case FixedPointComponents::NEG:
                            component_rows = macro_rows_amount(fix_neg);
                            break;
                        case FixedPointComponents::RANGE:
                            component_rows = macro_rows_amount(fix_range, m1, m2);
                            break;
                        case FixedPointComponents::REM:
                            component_rows = macro_rows_amount(fix_rem, m1, m2);
                            break;
                        case FixedPointComponents::RESCALE:
                            component_rows = macro_rows_amount(fix_rescale);
                            break;
                        case FixedPointComponents::SELECT:
                            component_rows = macro_rows_amount(fix_select);
                            break;
                        case FixedPointComponents::SIGN_ABS:
                            component_rows = macro_rows_amount(fix_sign_abs);
                            break;
                        case FixedPointComponents::SIN:
                            component_rows = macro_rows_amount(fix_sin, m1, m2);
                            break;
                        case FixedPointComponents::SQRT:
                            component_rows = macro_rows_amount(fix_sqrt, m1, m2);
                            break;
                        case FixedPointComponents::SQRT_FLOOR:
                            component_rows = macro_rows_amount(fix_sqrt_floor, m1, m2);
                            break;
                        case FixedPointComponents::SUB:
                            component_rows = macro_rows_amount(subtraction);
                            break;
                        case FixedPointComponents::TANH:
                            component_rows = macro_rows_amount(fix_tanh, m1, m2);
                            break;
                        case FixedPointComponents::TO_FIXEDPOINT:
                            component_rows = macro_rows_amount(int_to_fix);
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false);
                            component_rows = 0;
                            input_output_rows = 0;
                            break;
                    }
                    return component_rows + input_output_rows;
                }
#undef macro_rows_amount

                void add_testcase(FixedPointComponents component, std::vector<value_type> &inputs,
                                  std::vector<value_type> &outputs, std::vector<value_type> &constants, uint8_t m1,
                                  uint8_t m2, std::uint32_t size = 0) {
                    testcase test;
                    test.component = component;
                    test.inputs = inputs;
                    test.outputs = outputs;
                    test.constants = constants;
                    test.m1 = m1;
                    test.m2 = m2;
                    test.size = size;
                    auto prev_rows = rows_amount;
                    rows_amount += get_component_rows_amount(component, this->witness_amount(), 0, m1, m2, size);
                    // allows to test components by commenting others out
                    if (prev_rows != rows_amount)
                        testcases.push_back(test);
                }

                std::vector<std::uint32_t> get_witness_list() const {
                    std::vector<std::uint32_t> result;
                    result.reserve(this->witness_amount());
                    for (std::size_t i = 0; i < this->witness_amount(); ++i) {
                        result.push_back(this->W(i));
                    }
                    return result;
                }

                std::array<std::uint32_t, TESTER_MAX_CONSTANT_COLS> get_constant_list() const {
                    std::array<std::uint32_t, TESTER_MAX_CONSTANT_COLS> result;
                    for (std::size_t i = 0; i < this->constant_amount(); ++i) {
                        result[i] = this->C(i);
                    }
                    return result;
                }

                std::array<std::uint32_t, 0> get_public_input_list() const {
                    std::array<std::uint32_t, 0> result;
                    return result;
                }

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, TESTER_MAX_CONSTANT_COLS, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(1)), false);
                    return manifest;
                }

                std::size_t rows_amount = 0;

                struct input_type {

                    std::vector<var> all_vars() const {
                        return {};
                    }
                };

                struct result_type {

                    result_type(const fix_tester &component, std::uint32_t start_row_index) {
                    }

                    result_type(const fix_tester &component, std::size_t start_row_index) {
                    }

                    std::vector<var> all_vars() const {
                        return {};
                    }
                };

                bool requires_range_table(FixedPointComponents component) {
                    switch (component) {
                        case FixedPointComponents::ARGMAX:
                        case FixedPointComponents::ARGMIN:
                        case FixedPointComponents::CMP:
                        case FixedPointComponents::CMP_EXTENDED:
                        case FixedPointComponents::CMP_MIN_MAX:
                        case FixedPointComponents::COS:
                        case FixedPointComponents::DIV_BY_POS:
                        case FixedPointComponents::DIV:
                        case FixedPointComponents::DOT_RESCALE1:
                        case FixedPointComponents::DOT_RESCALE2:
                        case FixedPointComponents::EXP:
                        case FixedPointComponents::EXP_RANGED:
                        case FixedPointComponents::LOG:
                        case FixedPointComponents::MAX:
                        case FixedPointComponents::MIN:
                        case FixedPointComponents::MUL_RESCALE:
                        case FixedPointComponents::MUL_RESCALE_CONST:
                        case FixedPointComponents::RANGE:
                        case FixedPointComponents::REM:
                        case FixedPointComponents::RESCALE:
                        case FixedPointComponents::SIGN_ABS:
                        case FixedPointComponents::SIN:
                        case FixedPointComponents::SQRT:
                        case FixedPointComponents::SQRT_FLOOR:
                        case FixedPointComponents::SUB:
                        case FixedPointComponents::TANH:
                            return true;
                        default:
                            return false;
                    }
                }

                bool requires_exp_table(FixedPointComponents component) {
                    switch (component) {
                        case FixedPointComponents::EXP:
                        case FixedPointComponents::EXP_RANGED:
                        case FixedPointComponents::LOG:
                        case FixedPointComponents::TANH:
                            return true;
                        default:
                            return false;
                    }
                }

                bool requires_trig_table(FixedPointComponents component) {
                    switch (component) {
                        case FixedPointComponents::SIN:
                        case FixedPointComponents::COS:
                            return true;
                        default:
                            return false;
                    }
                }

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {};

                    // RANGE
                    for (auto &test : testcases) {
                        if (requires_range_table(test.component)) {
                            auto table = std::shared_ptr<lookup_table_definition>(new range_table());
                            result.push_back(table);
                            break;
                        }
                    }

                    // EXP 16
                    for (auto &test : testcases) {
                        if (requires_exp_table(test.component) && test.m2 == 1) {
                            auto table = std::shared_ptr<lookup_table_definition>(
                                new fixedpoint_exp_16_table<BlueprintFieldType>());
                            result.push_back(table);
                            break;
                        }
                    }

                    // EXP 32
                    for (auto &test : testcases) {
                        if (requires_exp_table(test.component) && test.m2 == 2) {
                            auto table = std::shared_ptr<lookup_table_definition>(
                                new fixedpoint_exp_32_table<BlueprintFieldType>());
                            result.push_back(table);
                            break;
                        }
                    }

                    // TRIGON 16
                    for (auto &test : testcases) {
                        if (requires_trig_table(test.component) && test.m2 == 1) {
                            auto table = std::shared_ptr<lookup_table_definition>(
                                new fixedpoint_trigon_16_table<BlueprintFieldType>());
                            result.push_back(table);
                            break;
                        }
                    }

                    // TRIGON 32
                    for (auto &test : testcases) {
                        if (requires_trig_table(test.component) && test.m2 == 2) {
                            auto table = std::shared_ptr<lookup_table_definition>(
                                new fixedpoint_trigon_32_table<BlueprintFieldType>());
                            result.push_back(table);
                            break;
                        }
                    }

                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    for (auto &test : testcases) {
                        // RANGE
                        if (requires_range_table(test.component)) {
                            lookup_tables[range_table::FULL_TABLE_NAME] = 0;    // REQUIRED_TABLE}
                        }

                        // EXP 16
                        if (requires_exp_table(test.component) && test.m2 == 1) {
                            lookup_tables[fixedpoint_exp_16_table<BlueprintFieldType>::A_TABLE_NAME] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_exp_16_table<BlueprintFieldType>::B_TABLE_NAME] =
                                0;    // REQUIRED_TABLE
                        }

                        // EXP 32
                        if (requires_exp_table(test.component) && test.m2 == 2) {

                            lookup_tables[fixedpoint_exp_32_table<BlueprintFieldType>::A_TABLE_NAME] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_exp_32_table<BlueprintFieldType>::B_TABLE_NAME] =
                                0;    // REQUIRED_TABLE
                        }

                        // TRIGON 16
                        if (requires_trig_table(test.component) && test.m2 == 1) {
                            lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_SIN_A] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_SIN_B] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_COS_A] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_16_table<BlueprintFieldType>::FULL_COS_B] =
                                0;    // REQUIRED_TABLE
                        }

                        // TRIGON 32
                        if (requires_trig_table(test.component) && test.m2 == 2) {
                            lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_A] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_B] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_SIN_C] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_COS_A] =
                                0;    // REQUIRED_TABLE
                            lookup_tables[fixedpoint_trigon_32_table<BlueprintFieldType>::FULL_COS_B] =
                                0;    // REQUIRED_TABLE
                        }
                    }

                    return lookup_tables;
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_tester(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fix_tester(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_tester =
                fix_tester<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

///////////////////////////////////////////////////////////////////////////////
//  macros for generating the circuit and the assignments
#define macro_component(name, ...)                                                                        \
    using new_component_type = name<ArithmetizationType, BlueprintFieldType, PolicyType>;                 \
    new_component_type component_instance(witness_list, constant_list, public_input_list, ##__VA_ARGS__); \
    component_name = #name;
///////////////////////////////////////////////////////////////////////////////
#define macro_func(num_constant, func)                                           \
    BLUEPRINT_RELEASE_ASSERT(instance_input.all_vars().size() == inputs.size()); \
    BLUEPRINT_RELEASE_ASSERT(constants.size() == num_constant);                  \
    vars = func;                                                                 \
    component_rows = component_instance.rows_amount;
///////////////////////////////////////////////////////////////////////////////
#define macro_assigner()                                                                                        \
    generate_assignments(component_instance, assignment, instance_input, current_row_index + input_output_rows) \
        .all_vars()
///////////////////////////////////////////////////////////////////////////////
#define macro_circuit()                                                                                         \
    generate_circuit(component_instance, bp, assignment, instance_input, current_row_index + input_output_rows) \
        .all_vars()
///////////////////////////////////////////////////////////////////////////////
#define macro_1_input() \
    typename new_component_type::input_type instance_input {var(component.W(0), current_row_index, false)};
///////////////////////////////////////////////////////////////////////////////
#define macro_2_inputs()                                                                                   \
    typename new_component_type::input_type instance_input {var(component.W(0), current_row_index, false), \
                                                            var(component.W(1), current_row_index, false)};
///////////////////////////////////////////////////////////////////////////////
#define macro_3_inputs()                                                                                    \
    typename new_component_type::input_type instance_input {var(component.W(0), current_row_index, false),  \
                                                            var(component.W(1), current_row_index, false),  \
                                                            var(component.W(2), current_row_index, false)}; \
///////////////////////////////////////////////////////////////////////////////
#define macro_dot_input()                                                                         \
    std::vector<var> instance_input_x;                                                            \
    std::vector<var> instance_input_y;                                                            \
    instance_input_x.reserve(size);                                                               \
    instance_input_y.reserve(size);                                                               \
    for (std::size_t i = 0; i < size; ++i) {                                                      \
        auto [column_x, row_x] = tester::split(witness_list.size(), current_row_index, i);        \
        auto [column_y, row_y] = tester::split(witness_list.size(), current_row_index, i + size); \
        instance_input_x.push_back(var(component.W(column_x), row_x, false));                     \
        instance_input_y.push_back(var(component.W(column_y), row_y, false));                     \
    }                                                                                             \
    auto [column, row] = tester::split(witness_list.size(), current_row_index, 2 * size);         \
    var zero = var(component.W(column), row, false);                                              \
    typename new_component_type::input_type instance_input {instance_input_x, instance_input_y, zero};
///////////////////////////////////////////////////////////////////////////////
#define macro_assigner_1_input(name, num_constant, ...) \
    macro_component(name, ##__VA_ARGS__);               \
    macro_1_input();                                    \
    macro_func(num_constant, macro_assigner());
///////////////////////////////////////////////////////////////////////////////
#define macro_assigner_2_inputs(name, num_constant, ...) \
    macro_component(name, ##__VA_ARGS__);                \
    macro_2_inputs();                                    \
    macro_func(num_constant, macro_assigner());
///////////////////////////////////////////////////////////////////////////////
#define macro_assigner_3_inputs(name, num_constant, ...) \
    macro_component(name, ##__VA_ARGS__);                \
    macro_3_inputs();                                    \
    macro_func(num_constant, macro_assigner());
///////////////////////////////////////////////////////////////////////////////
#define macro_circuit_1_input(name, num_constant, ...) \
    macro_component(name, ##__VA_ARGS__);              \
    macro_1_input();                                   \
    macro_func(num_constant, macro_circuit());
///////////////////////////////////////////////////////////////////////////////
#define macro_circuit_2_inputs(name, num_constant, ...) \
    macro_component(name, ##__VA_ARGS__);               \
    macro_2_inputs();                                   \
    macro_func(num_constant, macro_circuit());
///////////////////////////////////////////////////////////////////////////////
#define macro_circuit_3_inputs(name, num_constant, ...) \
    macro_component(name, ##__VA_ARGS__);               \
    macro_3_inputs();                                   \
    macro_func(num_constant, macro_circuit());
            ///////////////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using var = typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::var;
                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using PolicyType = nil::blueprint::basic_non_native_policy<BlueprintFieldType>;
                using tester = plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>;

                auto witness_list = component.get_witness_list();
                auto constant_list = component.get_constant_list();
                auto public_input_list = component.get_public_input_list();

                auto current_row_index = start_row_index;

                for (auto &test : component.get_testcases()) {
                    auto &inputs = test.inputs;
                    auto &outputs = test.outputs;
                    auto &constants = test.constants;
                    auto m1 = test.m1;
                    auto m2 = test.m2;
                    auto size = test.size;

                    std::vector<var> vars;
                    auto input_output_rows = 1;
                    auto component_rows = 0;
                    std::string component_name = "";

                    // Put inputs and outputs in the witness columns in the current row and put gadget into the
                    // next, we will have copy constraints to them later
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        auto [column, row] = tester::split(witness_list.size(), current_row_index, i);
                        assignment.witness(component.W(column), row) = inputs[i];
                    }
                    for (std::size_t i = 0; i < outputs.size(); ++i) {
                        auto [column, row] = tester::split(witness_list.size(), current_row_index, i + inputs.size());
                        assignment.witness(component.W(column), row) = outputs[i];
                    }

                    switch (test.component) {
                        case FixedPointComponents::ADD: {
                            macro_assigner_2_inputs(addition, 0);
                            break;
                        }
                        case FixedPointComponents::ARGMAX: {
                            bool select_last_index = constants[1] == 0 ? false : true;
                            macro_assigner_3_inputs(fix_argmax, 2, m1, m2, constants[0], select_last_index);
                            break;
                        }
                        case FixedPointComponents::ARGMIN: {
                            bool select_last_index = constants[1] == 0 ? false : true;
                            macro_assigner_3_inputs(fix_argmin, 2, m1, m2, constants[0], select_last_index);
                            break;
                        }
                        case FixedPointComponents::CMP: {
                            macro_assigner_2_inputs(fix_cmp, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::CMP_EXTENDED: {
                            macro_assigner_2_inputs(fix_cmp_extended, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::CMP_MIN_MAX: {
                            macro_assigner_2_inputs(fix_cmp_min_max, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::COS: {
                            macro_assigner_1_input(fix_cos, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::DIV_BY_POS: {
                            macro_assigner_2_inputs(fix_div_by_pos, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::DIV: {
                            macro_assigner_2_inputs(fix_div, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::DOT_RESCALE1: {
                            input_output_rows = tester::io_rows_for_dot(witness_list.size(), size);
                            macro_component(fix_dot_rescale_1_gate, size, m2);
                            macro_dot_input();
                            macro_func(0, macro_assigner());
                            break;
                        }
                        case FixedPointComponents::DOT_RESCALE2: {
                            input_output_rows = tester::io_rows_for_dot(witness_list.size(), size);
                            macro_component(fix_dot_rescale_2_gates, size, m2);
                            macro_dot_input();
                            macro_func(0, macro_assigner());
                            break;
                        }
                        case FixedPointComponents::EXP: {
                            macro_assigner_1_input(fix_exp, 0, m2);
                            break;
                        }
                        case FixedPointComponents::EXP_RANGED: {
                            macro_assigner_1_input(fix_exp_ranged, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::GATHER_ACC: {
                            macro_assigner_3_inputs(fix_gather_acc, 1, constants[0]);
                            break;
                        }
                        case FixedPointComponents::LOG: {
                            macro_assigner_1_input(fix_log, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::MAX: {
                            macro_assigner_2_inputs(fix_max, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::MIN: {
                            macro_assigner_2_inputs(fix_min, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::MUL_RESCALE: {
                            macro_assigner_2_inputs(fix_mul_rescale, 0, m2);
                            break;
                        }
                        case FixedPointComponents::MUL_RESCALE_CONST: {
                            macro_assigner_1_input(fix_mul_rescale_const, 1, constants[0], m2);
                            break;
                        }
                        case FixedPointComponents::NEG: {
                            macro_assigner_1_input(fix_neg, 0);
                            break;
                        }
                        case FixedPointComponents::RANGE: {
                            macro_assigner_1_input(fix_range, 2, m1, m2, constants[0], constants[1]);
                            break;
                        }
                        case FixedPointComponents::REM: {
                            macro_assigner_2_inputs(fix_rem, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::RESCALE: {
                            macro_assigner_1_input(fix_rescale, 0, m2);
                            break;
                        }
                        case FixedPointComponents::SELECT: {
                            macro_assigner_3_inputs(fix_select, 0);
                            break;
                        }
                        case FixedPointComponents::SIGN_ABS: {
                            macro_assigner_1_input(fix_sign_abs, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SIN: {
                            macro_assigner_1_input(fix_sin, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SQRT: {
                            macro_assigner_1_input(fix_sqrt, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SQRT_FLOOR: {
                            macro_assigner_1_input(fix_sqrt_floor, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SUB: {
                            macro_assigner_2_inputs(subtraction, 0);
                            break;
                        }
                        case FixedPointComponents::TANH: {
                            macro_assigner_1_input(fix_tanh, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::TO_FIXEDPOINT: {
                            macro_assigner_1_input(int_to_fix, 0, m2);
                            break;
                        }
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    // Output check
                    BLUEPRINT_RELEASE_ASSERT(vars.size() == outputs.size());
                    for (auto i = 0; i < vars.size(); i++) {
                        BLUEPRINT_RELEASE_ASSERT(var_value(assignment, vars[i]) == outputs[i]);
                    }

                    // std::cout << "Component " << component_name << " (" << (int)m1 << ", " << (int)m2 << ") at row "
                    // << current_row_index << " with " << component_rows + input_output_rows << " rows"   << std::endl;

                    current_row_index += component_rows + input_output_rows;
                }

                return typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::var;
                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using PolicyType = nil::blueprint::basic_non_native_policy<BlueprintFieldType>;
                using tester = plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>;

                auto witness_list = component.get_witness_list();
                auto constant_list = component.get_constant_list();
                auto public_input_list = component.get_public_input_list();

                auto current_row_index = start_row_index;

                for (auto &test : component.get_testcases()) {
                    auto &inputs = test.inputs;
                    auto &outputs = test.outputs;
                    auto &constants = test.constants;
                    auto m1 = test.m1;
                    auto m2 = test.m2;
                    auto size = test.size;

                    std::vector<var> vars;
                    auto input_output_rows = 1;
                    auto component_rows = 0;
                    std::string component_name = "";

                    switch (test.component) {
                        case FixedPointComponents::ADD: {
                            macro_circuit_2_inputs(addition, 0);
                            break;
                        }
                        case FixedPointComponents::ARGMAX: {
                            bool select_last_index = constants[1] == 0 ? false : true;
                            macro_circuit_3_inputs(fix_argmax, 2, m1, m2, constants[0], select_last_index);
                            break;
                        }
                        case FixedPointComponents::ARGMIN: {
                            bool select_last_index = constants[1] == 0 ? false : true;
                            macro_circuit_3_inputs(fix_argmin, 2, m1, m2, constants[0], select_last_index);
                            break;
                        }
                        case FixedPointComponents::CMP: {
                            macro_circuit_2_inputs(fix_cmp, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::CMP_EXTENDED: {
                            macro_circuit_2_inputs(fix_cmp_extended, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::CMP_MIN_MAX: {
                            macro_circuit_2_inputs(fix_cmp_min_max, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::COS: {
                            macro_circuit_1_input(fix_cos, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::DIV_BY_POS: {
                            macro_circuit_2_inputs(fix_div_by_pos, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::DIV: {
                            macro_circuit_2_inputs(fix_div, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::DOT_RESCALE1: {
                            input_output_rows = tester::io_rows_for_dot(witness_list.size(), size);
                            macro_component(fix_dot_rescale_1_gate, size, m2);
                            macro_dot_input();
                            macro_func(0, macro_circuit());
                            break;
                        }
                        case FixedPointComponents::DOT_RESCALE2: {
                            input_output_rows = tester::io_rows_for_dot(witness_list.size(), size);
                            macro_component(fix_dot_rescale_2_gates, size, m2);
                            macro_dot_input();
                            macro_func(0, macro_circuit());
                            break;
                        }
                        case FixedPointComponents::EXP: {
                            macro_circuit_1_input(fix_exp, 0, m2);
                            break;
                        }
                        case FixedPointComponents::EXP_RANGED: {
                            macro_circuit_1_input(fix_exp_ranged, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::GATHER_ACC: {
                            macro_circuit_3_inputs(fix_gather_acc, 1, constants[0]);
                            break;
                        }
                        case FixedPointComponents::LOG: {
                            macro_circuit_1_input(fix_log, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::MAX: {
                            macro_circuit_2_inputs(fix_max, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::MIN: {
                            macro_circuit_2_inputs(fix_min, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::MUL_RESCALE: {
                            macro_circuit_2_inputs(fix_mul_rescale, 0, m2);
                            break;
                        }
                        case FixedPointComponents::MUL_RESCALE_CONST: {
                            macro_circuit_1_input(fix_mul_rescale_const, 1, constants[0], m2);
                            break;
                        }
                        case FixedPointComponents::NEG: {
                            macro_circuit_1_input(fix_neg, 0);
                            break;
                        }
                        case FixedPointComponents::RANGE: {
                            macro_circuit_1_input(fix_range, 2, m1, m2, constants[0], constants[1]);
                            break;
                        }
                        case FixedPointComponents::REM: {
                            macro_circuit_2_inputs(fix_rem, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::RESCALE: {
                            macro_circuit_1_input(fix_rescale, 0, m2);
                            break;
                        }
                        case FixedPointComponents::SELECT: {
                            macro_circuit_3_inputs(fix_select, 0);
                            break;
                        }
                        case FixedPointComponents::SIGN_ABS: {
                            macro_circuit_1_input(fix_sign_abs, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SIN: {
                            macro_circuit_1_input(fix_sin, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SQRT: {
                            macro_circuit_1_input(fix_sqrt, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SQRT_FLOOR: {
                            macro_circuit_1_input(fix_sqrt_floor, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::SUB: {
                            macro_circuit_2_inputs(subtraction, 0);
                            break;
                        }
                        case FixedPointComponents::TANH: {
                            macro_circuit_1_input(fix_tanh, 0, m1, m2);
                            break;
                        }
                        case FixedPointComponents::TO_FIXEDPOINT: {
                            macro_circuit_1_input(int_to_fix, 0, m2);
                            break;
                        }
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    // Copy constraints for outputs
                    BLUEPRINT_RELEASE_ASSERT(vars.size() == outputs.size());
                    for (auto i = 0; i < vars.size(); i++) {
                        auto [column, row] = tester::split(witness_list.size(), current_row_index, i + inputs.size());
                        bp.add_copy_constraint({var(component.W(column), row, false), vars[i]});
                    }

                    current_row_index += component_rows + input_output_rows;
                }

                return typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
#undef macro_component
#undef macro_func
#undef macro_assigner
#undef macro_circuit
#undef macro_1_input
#undef macro_2_inputs
#undef macro_3_inputs
#undef macro_dot_input
#undef macro_assigner_1_input
#undef macro_assigner_2_inputs
#undef macro_assigner_3_inputs
#undef macro_circuit_1_input
#undef macro_circuit_2_inputs
#undef macro_circuit_3_inputs

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
            struct is_component_tester : std::false_type { };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            struct is_component_tester<BlueprintFieldType, ArithmetizationParams,
                                       plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>>
                : std::true_type { };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TESTER_HPP
