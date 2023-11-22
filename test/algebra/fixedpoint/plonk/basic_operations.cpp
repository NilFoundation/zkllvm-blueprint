#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_basic_test

// Enable for faster tests
// #define TEST_WITHOUT_LOOKUP_TABLES

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/rescale.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/mul_rescale.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/mul_rescale_const.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/div.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/rem.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/neg.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/to_fixedpoint.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>

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
void test_add(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 3;
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
        addition<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double expected_res_f = input1.to_double() + input2.to_double();
    auto expected_res = input1 + input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point add test: "
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

    component_type component_instance({0, 1, 2}, {}, {});

    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_sub(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 3;
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
        blueprint::components::subtraction<ArithmetizationType,
                                           BlueprintFieldType,
                                           nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double expected_res_f = input1.to_double() - input2.to_double();
    auto expected_res = input1 - input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point sub test: "
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

    component_type component_instance({0, 1, 2}, {}, {});

    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_rescale(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 2 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_rescale<ArithmetizationType,
                                           BlueprintFieldType,
                                           nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = input.to_double();
    auto expected_res = input.rescale();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point rescale test: "
                  << "\n";
        std::cout << "input_f : " << input.to_double() << "\n";
        std::cout << "input   : " << input.get_value().data << "\n";
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
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_int_to_fixedpoint(typename FixedType::value_type input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 2;
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
        blueprint::components::int_to_fix<ArithmetizationType,
                                          BlueprintFieldType,
                                          nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = FixedType::helper::field_to_double(input);
    auto expected_res = FixedType(input);

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "int to fixed_point test: "
                  << "\n";
        std::cout << "input   : " << input.data << "\n";
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
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_mul_rescale(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 3 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_mul_rescale<ArithmetizationType,
                                               BlueprintFieldType,
                                               nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double expected_res_f = input1.to_double() * input2.to_double();
    auto expected_res = input1 * input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point mul test: "
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
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_div(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_div<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double expected_res_f = input1.to_double() / input2.to_double();
    auto expected_res = input1 / input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point div test: "
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
void test_fixedpoint_div_by_pos(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 10;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_div_by_pos<ArithmetizationType,
                                              BlueprintFieldType,
                                              nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double expected_res_f = input1.to_double() / input2.to_double();
    auto expected_res = input1 / input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point div by pos test: "
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
void test_fixedpoint_mod(FixedType input1, FixedType input2) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_rem<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    double input2_f = input2.to_double();
    double expected_res_f = remainder(input1.to_double(), input2_f);
    // Correct signs for onnx specififcation
    if ((expected_res_f < 0 && input2_f > 0) || (expected_res_f > 0 && input2_f < 0)) {
        expected_res_f += input2_f;
    }
    auto expected_res = input1 % input2;

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point mod test: "
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
    component_type component_instance(witness_list,
                                      std::array<std::uint32_t, 1>({0}),
                                      std::array<std::uint32_t, 0>(),
                                      FixedType::M_1,
                                      FixedType::M_2);
 
    std::vector<typename BlueprintFieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_neg(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 2;
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
        fix_neg<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = -input.to_double();
    auto expected_res = -input;

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point neg test: "
                  << "\n";
        std::cout << "input_f : " << input.to_double() << "\n";
        std::cout << "input   : " << input.get_value().data << "\n";
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

    component_type component_instance({0, 1}, {}, {});

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_mul_rescale_const(FixedType priv_input, FixedType const_input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 2 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_mul_rescale_const<ArithmetizationType,
                                                     BlueprintFieldType,
                                                     nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = priv_input.to_double() * const_input.to_double();
    auto expected_res = priv_input * const_input;

    auto result_check = [&expected_res, &expected_res_f, priv_input, const_input](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point mul const test: "
                  << "\n";
        std::cout << "input_f : " << priv_input.to_double() << " " << const_input.to_double() << "\n";
        std::cout << "input   : " << priv_input.get_value().data << " " << const_input.get_value().data << "\n";
        std::cout << "expected: " << expected_res_f << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n\n";
            std::cout << "expected (float): " << expected_res_f << "\n";
            std::cout << "real (float)   : " << real_res_f << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(witness_list,
                                      std::array<std::uint32_t, 1>({0}),
                                      std::array<std::uint32_t, 0>(),
                                      const_input.get_value(),
                                      FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {priv_input.get_value()};
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

template<typename FieldType, typename RngType>
FieldType generate_random_pre_comma(uint8_t m1, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m1 > 0 && m1 < 3);

    uint64_t max = (1ull << (16 * m1)) - 1;

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

    typename FixedType::value_type z = generate_random_pre_comma<typename FixedType::value_type>(FixedType::M_1, rng);

    test_add<FixedType>(x, y);
    test_sub<FixedType>(x, y);
    test_fixedpoint_rescale<FixedType>(FixedType(x.get_value() * FixedType::DELTA, FixedType::SCALE * 2));
    test_fixedpoint_mul_rescale<FixedType>(x, y);
    test_fixedpoint_mul_rescale_const<FixedType>(x, y);
    test_fixedpoint_neg<FixedType>(x);
    test_int_to_fixedpoint<FixedType>(z);
    if (y.get_value() != 0) {
        test_fixedpoint_div<FixedType>(x, y);
        test_fixedpoint_mod<FixedType>(x, y);
        if (y.geq_0()) {
            test_fixedpoint_div_by_pos<FixedType>(x, y);
        }
    }
}

template<typename FixedType>
void test_components(int i, int j) {
    FixedType x((int64_t)i);
    FixedType y((int64_t)j);

    test_add<FixedType>(x, y);
    test_sub<FixedType>(x, y);
    test_fixedpoint_rescale<FixedType>(FixedType(x.get_value() * FixedType::DELTA, FixedType::SCALE * 2));
    test_fixedpoint_mul_rescale<FixedType>(x, y);
    test_fixedpoint_mul_rescale_const<FixedType>(x, y);
    test_fixedpoint_neg<FixedType>(x);
    test_int_to_fixedpoint<FixedType>((int64_t)i);
    if (y.get_value() != 0) {
        test_fixedpoint_div<FixedType>(x, y);
        test_fixedpoint_mod<FixedType>(x, y);
        if (y.geq_0()) {
            test_fixedpoint_div_by_pos<FixedType>(x, y);
        }
    }
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

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_basic_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_basic_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_basic_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
