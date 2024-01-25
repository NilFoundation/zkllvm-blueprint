#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_hyperbolic_operations_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/sinh.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/cosh.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint16_32;
using nil::blueprint::components::FixedPoint32_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON = 0.01;

#define PRINT_FIXED_POINT_TEST(what)                                                                                \
    std::cout << "fixed_point " << what << " test:\n";                                                              \
    std::cout << "input           : " << input.get_value().data << "\n";                                            \
    std::cout << "input (float)   : " << input.to_double() << "\n";                                                 \
    std::cout << "expected        : " << expected_res.get_value().data << "\n";                                     \
    std::cout << "real            : " << real_res_.get_value().data << "\n";                                        \
    std::cout << "expected (float): " << expected_res_f << "\n";                                                    \
    std::cout << "real (float)    : " << real_res_f << "\n";                                                        \
    std::cout << "modulus    : " << BlueprintFieldType::modulus << "\n";                                            \
    std::cout << "having " << static_cast<int>(16 * FixedType::M_1) << "." << static_cast<int>(16 * FixedType::M_2) \
              << std::endl;

bool doubleEquals(double a, double b, double epsilon, uint8_t m1, uint8_t m2) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    // or just smaller epsilon
    double upper = 0.;
    if (2 == (m1 + m2)) {
        upper = static_cast<double>(4294967295ULL) / static_cast<double>(1ULL << (16 * m2));    // 2^32 - 1
    } else if (3 == (m1 + m2)) {
        upper = static_cast<double>(281474976710655ULL) / static_cast<double>(1ULL << (16 * m2));    // 2^48 - 1
    } else if (4 == (m1 + m2)) {
        upper = static_cast<double>(18446744073709551615ULL) / static_cast<double>(1ULL << (16 * m2));    // 2^64 - 1
    }
    if (fabs(a) >= upper) {
        return true;
    }
    return fabs(a - b) < epsilon || fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

template<typename FixedType>
void test_fixedpoint_sinh(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns =
        FixedType::M_2 == 1 ? 9 + 2 * (FixedType::M_1 + FixedType::M_2) : 7 + FixedType::M_1 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
#ifdef TEST_WITHOUT_LOOKUP_TABLES
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
#else
    constexpr std::size_t ConstantColumns = 8;
    constexpr std::size_t SelectorColumns = 8;
#endif
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_sinh<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = sinh(input.to_double());
    auto expected_res = input.sinh();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        PRINT_FIXED_POINT_TEST("sinh")
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON, FixedType::M_1, FixedType::M_2) ||
            expected_res != real_res_) {
            PRINT_FIXED_POINT_TEST("sinh")
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    std::vector<std::uint32_t> const_list;
    const_list.reserve(ConstantColumns);
    for (auto i = 0; i < ConstantColumns; i++) {
        const_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, const_list, std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance,
        public_input,
        result_check,
        instance_input,
        crypto3::detail::connectedness_check_type::STRONG,
        FixedType::M_1,
        FixedType::M_2);
}

template<typename FixedType>
void test_fixedpoint_cosh(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns =
        FixedType::M_2 == 1 ? 9 + 2 * (FixedType::M_1 + FixedType::M_2) : 7 + FixedType::M_1 + FixedType::M_2;
    constexpr std::size_t PublicInputColumns = 1;
#ifdef TEST_WITHOUT_LOOKUP_TABLES
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
#else
    constexpr std::size_t ConstantColumns = 8;
    constexpr std::size_t SelectorColumns = 8;
#endif
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_cosh<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = cosh(input.to_double());
    auto expected_res = input.cosh();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        PRINT_FIXED_POINT_TEST("cosh")
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON, FixedType::M_1, FixedType::M_2) ||
            expected_res != real_res_) {
            PRINT_FIXED_POINT_TEST("cosh")
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    std::vector<std::uint32_t> const_list;
    const_list.reserve(ConstantColumns);
    for (auto i = 0; i < ConstantColumns; i++) {
        const_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, const_list, std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance,
        public_input,
        result_check,
        instance_input,
        crypto3::detail::connectedness_check_type::STRONG,
        FixedType::M_1,
        FixedType::M_2);
}

template<typename FieldType, typename RngType>
FieldType generate_small_random_for_fixedpoint(uint8_t m1, uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m1 > 0 && m1 < 3);
    BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);

    distribution dist = distribution(0, 23ULL << (16 * m2));
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
FieldType generate_random_for_fixedpoint(uint8_t m1, uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m1 > 0 && m1 < 3);
    BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);

    uint64_t upper = 0;
    auto m = m1 + m2;
    if (2 == m) {
        upper = 4294967295ULL;    // 2^32 - 1
    } else if (3 == m) {
        upper = 281474976710655ULL;    // 2^48 - 1
    } else if (4 == m) {
        upper = 18446744073709551615ULL;    // 2^64 - 1
    }

    distribution dist = distribution(0, upper);
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
    test_fixedpoint_sinh<FixedType>(x);
    test_fixedpoint_cosh<FixedType>(x);
    FixedType y(
        generate_small_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
        FixedType::SCALE);
    test_fixedpoint_sinh<FixedType>(y);
    test_fixedpoint_cosh<FixedType>(y);
}

template<typename FixedType>
void test_components(double i) {
    FixedType x(i);
    test_fixedpoint_sinh<FixedType>(x);
    test_fixedpoint_cosh<FixedType>(x);
}

template<typename FixedType, std::size_t RandomTestsAmount>
void field_operations_test() {

    for (int i = -23; i < 24; i++) {
        test_components<FixedType>(i);
        test_components<FixedType>(i);
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_random_data<FixedType>(seed_seq);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_hyperbolic_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint16_32<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_hyperbolic_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint16_32<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_hyperbolic_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint16_32<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
