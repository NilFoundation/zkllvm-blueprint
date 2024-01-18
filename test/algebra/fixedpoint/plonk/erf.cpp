#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_erf_operations_test

// Enable for faster tests
// #define TEST_WITHOUT_LOOKUP_TABLES

// Enable to see progress on stdout
// #define STDOUT_TEST_PROGRESS

#include <iomanip>

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/erf.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint16_32;
using nil::blueprint::components::FixedPoint32_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON_16 = 8e-06;
static constexpr double EPSILON_32 = 3e-07;

#define PRINT_FIXED_POINT_TEST(what)                                                                            \
    std::cout << std::fixed << int(16 * FixedType::M_1) << "." << int(16 * FixedType::M_2) << " " << what       \
              << ": expected (C++)=" << std::setw(11) << std::setprecision(8) << expected_res_f                 \
              << ", expected (type.hpp)=" << std::setw(11) << std::setprecision(8) << expected_res.to_double()  \
              << ", real=" << std::setw(11) << std::setprecision(8) << real_res_f << ", diff=" << std::setw(11) \
              << std::setprecision(8) << abs(expected_res_f - real_res_f) << ", input=" << std::setw(11)        \
              << std::setprecision(8) << input.to_double() << " (" << input.get_value().data << ")" << std::endl;

bool doubleEquals(double a, double b, double epsilon) {
    return fabs(a - b) < epsilon;
}

template<typename FixedType>
void test_fixedpoint_erf(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
#ifdef TEST_WITHOUT_LOOKUP_TABLES
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 15;
#else
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 15;
#endif
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_erf<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = erf(input.to_double());
    auto expected_res = input.erf();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef STDOUT_TEST_PROGRESS
        PRINT_FIXED_POINT_TEST("erf")
#endif
        constexpr const auto epsilon = FixedType::M_2 == 1 ? EPSILON_16 : EPSILON_32;
        if (!doubleEquals(expected_res_f, real_res_f, epsilon) || expected_res != real_res_) {
            PRINT_FIXED_POINT_TEST("erf")
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
double generate_random_for_fixedpoint(uint8_t m1, uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m1 > 0 && m1 < 3);
    BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);

    static constexpr const auto num = 4ULL;
    static constexpr const auto resolution = 1ULL << 32ULL;

    distribution dist = distribution(0, num * resolution);
    return static_cast<double>(dist(rng)) / static_cast<double>(resolution);
}

template<typename FixedType, typename RngType>
void test_components_on_random_data(RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng));
    test_fixedpoint_erf<FixedType>(x);
    test_fixedpoint_erf<FixedType>(-x);
}

template<typename FixedType>
void test_components(double i) {
    FixedType x(i);
    test_fixedpoint_erf<FixedType>(x);
    test_fixedpoint_erf<FixedType>(-x);
}

template<typename FixedType, std::size_t RandomTestsAmount>
void field_operations_test() {

    for (int i = 0; i < 5; i++) {
        test_components<FixedType>(static_cast<double>(i));
    }

    for (size_t i = 0; i < FixedType::M_1; i++) {
        test_components<FixedType>(2 * (1ULL << (16 * i)));
        test_components<FixedType>(34012 * (1ULL << (16 * i)));
    }

    boost::random::mt19937 seed_seq(FixedType::M_1 * 4 + FixedType::M_2 + 1);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_random_data<FixedType>(seed_seq);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_erf_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint16_32<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_erf_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint16_32<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_erf_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint16_32<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
