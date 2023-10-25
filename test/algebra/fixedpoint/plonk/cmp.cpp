#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_cmp_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/type.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/cmp.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/select.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/max.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/cmp_min_max.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/range.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON = 0.001;

bool doubleEquals(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    return fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

template<typename FixedType>
void test_fixedpoint_cmp(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 8 + FixedType::M_1 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_cmp<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    bool expected_res_less_f = input1_f < input2_f;
    bool expected_res_greater_f = input1_f > input2_f;
    bool expected_res_equal_f = fabs(input1_f - input2_f) < pow(2., -FixedType::SCALE);
    bool expected_res_less = input1 < input2;
    bool expected_res_greater = input1 > input2;
    bool expected_res_equal = input1 == input2;

    auto result_check = [&expected_res_less,
                         &expected_res_greater,
                         &expected_res_equal,
                         &expected_res_less_f,
                         &expected_res_greater_f,
                         &expected_res_equal_f,
                         input1,
                         input2](AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_less = var_value(assignment, real_res.lt) == 1;
        auto real_res_greater = var_value(assignment, real_res.gt) == 1;
        auto real_res_equal = var_value(assignment, real_res.eq) == 1;
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point cmp test: "
                  << "\n";
        std::cout << "input_f  :" << input1.to_double() << " " << input2.to_double() << "\n";
        std::cout << "input    : " << input1.get_value().data << " " << input2.get_value().data << "\n";
        std::cout << "expected<: " << expected_res_less_f << "\n";
        std::cout << "real<    : " << real_res_less << "\n";
        std::cout << "expected>: " << expected_res_greater_f << "\n";
        std::cout << "real>    : " << real_res_greater << "\n";
        std::cout << "expected=: " << expected_res_equal_f << "\n";
        std::cout << "real=    : " << real_res_equal << "\n\n";
#endif
        if ((expected_res_less_f != real_res_less) || (expected_res_less != real_res_less)) {
            std::cout << "expected<        : " << expected_res_less << "\n";
            std::cout << "real<            : " << real_res_less << "\n";
            std::cout << "expected< (float): " << expected_res_less_f << "\n\n";
            abort();
        }
        if ((expected_res_greater_f != real_res_greater) || (expected_res_greater != real_res_greater)) {
            std::cout << "expected>        : " << expected_res_greater << "\n";
            std::cout << "real>            : " << real_res_greater << "\n";
            std::cout << "expected> (float): " << expected_res_greater_f << "\n\n";
            abort();
        }
        if ((expected_res_equal_f != real_res_equal) || (expected_res_equal != real_res_equal)) {
            std::cout << "expected=        : " << expected_res_equal << "\n";
            std::cout << "real=            : " << real_res_equal << "\n";
            std::cout << "expected= (float): " << expected_res_equal_f << "\n\n";
            abort();
        }
        BLUEPRINT_RELEASE_ASSERT((uint8_t)real_res_equal + (uint8_t)real_res_greater + (uint8_t)real_res_less == 1);
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_select_internal(FixedType input1, FixedType input2, bool input1_select) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 4;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_select<ArithmetizationType,
                                          BlueprintFieldType,
                                          nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input),
                                                          var(0, 2, false, var::column_type::public_input)};

    double expected_res_f = input1_select ? input1.to_double() : input2.to_double();
    auto expected_res = input1_select ? input1 : input2;

    auto result_check = [&expected_res, &expected_res_f, input1_select, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point select test: "
                  << "\n";
        std::cout << "choose inp1: " << input1_select << "\n";
        std::cout << "input_f : " << input1.to_double() << " " << input2.to_double() << "\n";
        std::cout << "input   : " << input1.get_value().data << " " << input2.get_value().data << "\n";
        std::cout << "expected: " << expected_res_f << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n\n";
            std::cout << "expected (float): " << expected_res_f << "\n";
            std::cout << "real (float)    : " << real_res_f << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>());

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        typename BlueprintFieldType::value_type((uint64_t)input1_select), input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_select(FixedType input1, FixedType input2) {
    test_fixedpoint_select_internal(input1, input2, true);
    test_fixedpoint_select_internal(input1, input2, false);
}

template<typename FixedType>
void test_fixedpoint_max(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 5 + FixedType::M_1 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_max<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    double expected_res_f = input1_f > input2_f ? input1_f : input2_f;
    auto expected_res = input1 > input2 ? input1 : input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point max test: "
                  << "\n";
        std::cout << "input_f : " << input1.to_double() << " " << input2.to_double() << "\n";
        std::cout << "input   : " << input1.get_value().data << " " << input2.get_value().data << "\n";
        std::cout << "expected: " << expected_res_f << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n\n";
            std::cout << "expected (float): " << expected_res_f << "\n";
            std::cout << "real (float)    : " << real_res_f << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_cmp_min_max(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 10 + FixedType::M_1 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_cmp_min_max<ArithmetizationType,
                                               BlueprintFieldType,
                                               nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    bool expected_res_less_f = input1_f < input2_f;
    bool expected_res_greater_f = input1_f > input2_f;
    bool expected_res_equal_f = fabs(input1_f - input2_f) < pow(2., -FixedType::SCALE);
    double expected_res_min_f = input1_f < input2_f ? input1_f : input2_f;
    double expected_res_max_f = input1_f > input2_f ? input1_f : input2_f;
    bool expected_res_less = input1 < input2;
    bool expected_res_greater = input1 > input2;
    bool expected_res_equal = input1 == input2;
    auto expected_res_min = input1 < input2 ? input1 : input2;
    auto expected_res_max = input1 > input2 ? input1 : input2;

    auto result_check = [&expected_res_less,
                         &expected_res_greater,
                         &expected_res_equal,
                         &expected_res_min,
                         &expected_res_max,
                         &expected_res_less_f,
                         &expected_res_greater_f,
                         &expected_res_equal_f,
                         &expected_res_min_f,
                         &expected_res_max_f,
                         input1,
                         input2](AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_less = var_value(assignment, real_res.lt) == 1;
        auto real_res_greater = var_value(assignment, real_res.gt) == 1;
        auto real_res_equal = var_value(assignment, real_res.eq) == 1;
        auto real_res_min = FixedType(var_value(assignment, real_res.min), FixedType::SCALE);
        auto real_res_max = FixedType(var_value(assignment, real_res.max), FixedType::SCALE);
        auto real_res_min_f = real_res_min.to_double();
        auto real_res_max_f = real_res_max.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point cmp_min_max test: "
                  << "\n";
        std::cout << "input_f  :" << input1.to_double() << " " << input2.to_double() << "\n";
        std::cout << "input    : " << input1.get_value().data << " " << input2.get_value().data << "\n";
        std::cout << "expected<   : " << expected_res_less_f << "\n";
        std::cout << "real<       : " << real_res_less << "\n";
        std::cout << "expected>   : " << expected_res_greater_f << "\n";
        std::cout << "real>       : " << real_res_greater << "\n";
        std::cout << "expected=   : " << expected_res_equal_f << "\n";
        std::cout << "real=       : " << real_res_equal << "\n";
        std::cout << "expected min: " << expected_res_min_f << "\n";
        std::cout << "real min    : " << real_res_min_f << "\n";
        std::cout << "expected max: " << expected_res_max_f << "\n";
        std::cout << "real max    : " << real_res_max_f << "\n\n";
#endif
        if ((expected_res_less_f != real_res_less) || (expected_res_less != real_res_less)) {
            std::cout << "expected<        : " << expected_res_less << "\n";
            std::cout << "real<            : " << real_res_less << "\n";
            std::cout << "expected< (float): " << expected_res_less_f << "\n\n";
            abort();
        }
        if ((expected_res_greater_f != real_res_greater) || (expected_res_greater != real_res_greater)) {
            std::cout << "expected>        : " << expected_res_greater << "\n";
            std::cout << "real>            : " << real_res_greater << "\n";
            std::cout << "expected> (float): " << expected_res_greater_f << "\n\n";
            abort();
        }
        if ((expected_res_equal_f != real_res_equal) || (expected_res_equal != real_res_equal)) {
            std::cout << "expected=        : " << expected_res_equal << "\n";
            std::cout << "real=            : " << real_res_equal << "\n";
            std::cout << "expected= (float): " << expected_res_equal_f << "\n\n";
            abort();
        }
        if (!doubleEquals(expected_res_min_f, real_res_min_f, EPSILON) || expected_res_min != real_res_min) {
            std::cout << "expected min    : " << expected_res_min.get_value().data << "\n";
            std::cout << "real min        : " << real_res_min.get_value().data << "\n";
            std::cout << "expected (float): " << expected_res_min_f << "\n";
            std::cout << "real (float)    : " << real_res_min_f << "\n\n";
            abort();
        }
        if (!doubleEquals(expected_res_max_f, real_res_max_f, EPSILON) || expected_res_max != real_res_max) {
            std::cout << "expected max    : " << expected_res_max.get_value().data << "\n";
            std::cout << "real max        : " << real_res_max.get_value().data << "\n";
            std::cout << "expected (float): " << expected_res_max_f << "\n";
            std::cout << "real (float)    : " << real_res_max_f << "\n\n";
            abort();
        }
        BLUEPRINT_RELEASE_ASSERT((uint8_t)real_res_equal + (uint8_t)real_res_greater + (uint8_t)real_res_less == 1);
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_range(FixedType input, FixedType x_lo, FixedType x_hi) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 16;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_range<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input),
    };

    if (x_lo > x_hi) {
        std::swap(x_lo, x_hi);
    }

    double input_f = input.to_double();
    double x_lo_f = x_lo.to_double();
    double x_hi_f = x_hi.to_double();
    bool expected_res_less_f = input_f < x_lo_f;
    bool expected_res_greater_f = input_f > x_hi_f;
    bool expected_res_in_f = (input_f >= x_lo_f) && (input_f <= x_hi_f);
    bool expected_res_less = input < x_lo;
    bool expected_res_greater = input > x_hi;
    bool expected_res_in = (input >= x_lo) && (input <= x_hi);

    auto result_check = [&expected_res_less,
                         &expected_res_greater,
                         &expected_res_in,
                         &expected_res_less_f,
                         &expected_res_greater_f,
                         &expected_res_in_f,
                         input,
                         x_lo,
                         x_hi](AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_less = var_value(assignment, real_res.lt) == 1;
        auto real_res_greater = var_value(assignment, real_res.gt) == 1;
        auto real_res_in = var_value(assignment, real_res.in) == 1;
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point range test: "
                  << "\n";
        std::cout << "input_f  :" << input.to_double() << " " << x_lo.to_double() << " " << x_hi.to_double() << "\n";
        std::cout << "input    : " << input.get_value().data << " " << x_lo.get_value().data << " "
                  << x_hi.get_value().data << "\n";
        std::cout << "expected<: " << expected_res_less_f << "\n";
        std::cout << "real<    : " << real_res_less << "\n";
        std::cout << "expected>: " << expected_res_greater_f << "\n";
        std::cout << "real>    : " << real_res_greater << "\n";
        std::cout << "expected=: " << expected_res_in_f << "\n";
        std::cout << "real=    : " << real_res_in << "\n\n";
#endif
        if ((expected_res_less_f != real_res_less) || (expected_res_less != real_res_less)) {
            std::cout << "expected<        : " << expected_res_less << "\n";
            std::cout << "real<            : " << real_res_less << "\n";
            std::cout << "expected< (float): " << expected_res_less_f << "\n\n";
            abort();
        }
        if ((expected_res_greater_f != real_res_greater) || (expected_res_greater != real_res_greater)) {
            std::cout << "expected>        : " << expected_res_greater << "\n";
            std::cout << "real>            : " << real_res_greater << "\n";
            std::cout << "expected> (float): " << expected_res_greater_f << "\n\n";
            abort();
        }
        if ((expected_res_in_f != real_res_in) || (expected_res_in != real_res_in)) {
            std::cout << "expected=        : " << expected_res_in << "\n";
            std::cout << "real=            : " << real_res_in << "\n";
            std::cout << "expected= (float): " << expected_res_in_f << "\n\n";
            abort();
        }
        BLUEPRINT_RELEASE_ASSERT((uint8_t)real_res_in + (uint8_t)real_res_greater + (uint8_t)real_res_less == 1);
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(witness_list,
                                      std::array<std::uint32_t, 2>({0, 1}),
                                      std::array<std::uint32_t, 0>(),
                                      FixedType::M_1,
                                      FixedType::M_2,
                                      x_lo.get_value(),
                                      x_hi.get_value());

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FieldType, typename RngType>
FieldType generate_random_for_fixedpoint(uint8_t m1, uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m1 > 0 && m1 < 3);
    BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);
    auto m = m1 + m2;

    uint64_t max = 0;
    if (m == 4) {
        max = -1;
    } else {
        max = (1ull << (16 * m)) - 1;
    }

    distribution dist = distribution(0, max);
    uint64_t x = dist(rng);
    distribution dist_bool = distribution(0, 1);
    bool sign = dist_bool(rng) == 1;
    if (sign) {
        return -FieldType(x);
    } else {
        return FieldType(x);
    }
}

template<typename FixedType, typename RngType>
void test_components_on_random_data(RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType y(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType z(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);

    test_fixedpoint_select<FixedType>(x, y);
    test_fixedpoint_cmp<FixedType>(x, y);
    test_fixedpoint_max<FixedType>(x, y);
    test_fixedpoint_cmp_min_max<FixedType>(x, y);
    test_fixedpoint_range<FixedType>(x, y, z);
}

template<typename FixedType>
void test_components(int i, int j) {
    FixedType x((int64_t)i);
    FixedType y((int64_t)j);

    test_fixedpoint_select<FixedType>(x, y);
    test_fixedpoint_cmp<FixedType>(x, y);
    test_fixedpoint_max<FixedType>(x, y);
    test_fixedpoint_cmp_min_max<FixedType>(x, y);
    test_fixedpoint_range<FixedType>(x, x, y);
}

template<typename FixedType, std::size_t RandomTestsAmount>
void field_operations_test() {
    for (int i = -2; i < 3; i++) {
        for (int j = -2; j < 3; j++) {
            test_components<FixedType>(i, j);
        }
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_random_data<FixedType>(seed_seq);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_cmp_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_cmp_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_cmp_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
