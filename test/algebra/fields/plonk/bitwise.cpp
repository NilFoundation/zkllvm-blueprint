#define BOOST_TEST_MODULE blueprint_plonk_fields_bitwise_test

// Enable for faster tests
// #define TEST_WITHOUT_LOOKUP_TABLES

// Enable to see progress on stdout
// #define STDOUT_TEST_PROGRESS

#include <boost/test/unit_test.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

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

#include <nil/blueprint/components/algebra/fields/plonk/bitwise_and.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/bitwise_xor.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/bitwise_or.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#define macro_component_setup(name)                                                                                    \
    constexpr std::size_t WitnessColumns = 15;                                                                         \
    constexpr std::size_t PublicInputColumns = 5;                                                                      \
    constexpr std::size_t ConstantColumns = 15;                                                                        \
    constexpr std::size_t SelectorColumns = 30;                                                                        \
                                                                                                                       \
    using value_type = typename BlueprintFieldType::value_type;                                                        \
    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, \
                                                                                   ConstantColumns, SelectorColumns>;  \
    using ArithmetizationType =                                                                                        \
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;                        \
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;                                                          \
    constexpr std::size_t Lambda = 40;                                                                                 \
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;                                            \
                                                                                                                       \
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;                           \
                                                                                                                       \
    using component_type = blueprint::components::name<ArithmetizationType, BlueprintFieldType,                        \
                                                       nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

#define macro_component_run(readable_name)                                                                      \
                                                                                                                \
    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),     \
                                                          var(0, 1, false, var::column_type::public_input)};    \
                                                                                                                \
    auto result_check = [expected_res, a, b, m](AssignmentType &assignment,                                     \
                                                typename component_type::result_type &real_res) {               \
        auto real_res_ = var_value(assignment, real_res.output);                                                \
        auto expected = value_type(expected_res);                                                               \
        if (expected != real_res_) {                                                                            \
            std::cout << std::endl << "ERROR at " << readable_name << ":" << std::endl;                         \
            std::cout << "a                : " << a << std::endl;                                               \
            std::cout << "a (field)        : " << value_type(a) << std::endl;                                   \
            std::cout << "b                : " << b << std::endl;                                               \
            std::cout << "b (field)        : " << value_type(b) << std::endl;                                   \
            std::cout << "expected         : " << expected_res << std::endl;                                    \
            std::cout << "expected (field) : " << expected << std::endl;                                        \
            std::cout << "real (field)     : " << real_res_ << std::endl;                                       \
            std::cout << "m                : " << int(m) << std::endl;                                          \
            abort();                                                                                            \
        }                                                                                                       \
    };                                                                                                          \
                                                                                                                \
    std::vector<std::uint32_t> witness_list;                                                                    \
    witness_list.reserve(WitnessColumns);                                                                       \
    for (auto i = 0; i < WitnessColumns; i++) {                                                                 \
        witness_list.push_back(i);                                                                              \
    }                                                                                                           \
    std::vector<std::uint32_t> const_list;                                                                      \
    const_list.reserve(ConstantColumns);                                                                        \
    for (auto i = 0; i < ConstantColumns; i++) {                                                                \
        const_list.push_back(i);                                                                                \
    }                                                                                                           \
    component_type component_instance(witness_list, const_list, std::array<std::uint32_t, 0>(), m);             \
    std::vector<typename BlueprintFieldType::value_type> public_input = {value_type(a), value_type(b)};         \
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>( \
        component_instance, public_input, result_check, instance_input,                                         \
        crypto3::detail::connectedness_check_type::STRONG, m);

#define macro_stdout_test_progress(readable_name)                                \
    std::cout << std::endl << "STARTING " << readable_name << ":" << std::endl;  \
    std::cout << "a                : " << a << std::endl;                        \
    std::cout << "a (field)        : " << value_type(a) << std::endl;            \
    std::cout << "b                : " << b << std::endl;                        \
    std::cout << "b (field)        : " << value_type(b) << std::endl;            \
    std::cout << "expected         : " << expected_res << std::endl;             \
    std::cout << "expected (field) : " << value_type(expected_res) << std::endl; \
    std::cout << "m                : " << int(m) << std::endl;

template<typename BlueprintFieldType, typename IntegerType>
void test_bitwise_and(IntegerType a, IntegerType b, uint8_t m) {
    const static char *readable_name = "bitwise AND component";
    macro_component_setup(bitwise_and);
    IntegerType expected_res = a & b;
#ifdef STDOUT_TEST_PROGRESS
    macro_stdout_test_progress(readable_name);
#endif    // STDOUT_TEST_PROGRESS
    macro_component_run(readable_name);
}

template<typename BlueprintFieldType, typename IntegerType>
void test_bitwise_xor(IntegerType a, IntegerType b, uint8_t m) {
    const static char *readable_name = "bitwise XOR component";
    macro_component_setup(bitwise_xor);
    IntegerType expected_res = a ^ b;
#ifdef STDOUT_TEST_PROGRESS
    macro_stdout_test_progress(readable_name);
#endif    // STDOUT_TEST_PROGRESS
    macro_component_run(readable_name);
}

template<typename BlueprintFieldType, typename IntegerType>
void test_bitwise_or(IntegerType a, IntegerType b, uint8_t m) {
    const static char *readable_name = "bitwise OR component";
    macro_component_setup(bitwise_or);
    IntegerType expected_res = a | b;
#ifdef STDOUT_TEST_PROGRESS
    macro_stdout_test_progress(readable_name);
#endif    // STDOUT_TEST_PROGRESS
    macro_component_run(readable_name);
}

constexpr static const std::size_t random_tests_amount = 10;

template<typename BlueprintFieldType, typename IntegerType>
void test_bitwise(IntegerType a, IntegerType b, uint8_t m) {
    test_bitwise_and<BlueprintFieldType, IntegerType>(a, b, m);
    test_bitwise_xor<BlueprintFieldType, IntegerType>(a, b, m);
    test_bitwise_or<BlueprintFieldType, IntegerType>(a, b, m);
}

template<typename BlueprintFieldType, typename IntegerType, typename RngType>
void test_random(uint8_t m, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<IntegerType>;
    IntegerType max = std::numeric_limits<IntegerType>::max();
    IntegerType min = std::numeric_limits<IntegerType>::min();
    distribution dist = distribution(min, max);
    for (size_t i = 0; i < random_tests_amount; i++) {
        IntegerType a = dist(rng);
        IntegerType b = dist(rng);
        test_bitwise<BlueprintFieldType, IntegerType>(a, b, m);
    }
}

template<typename BlueprintFieldType>
void test_integer_variants() {
    boost::random::mt19937 rng(0);
    test_random<BlueprintFieldType, int8_t, boost::random::mt19937>(1, rng);
    test_random<BlueprintFieldType, int16_t, boost::random::mt19937>(2, rng);
    test_random<BlueprintFieldType, int32_t, boost::random::mt19937>(4, rng);
    test_random<BlueprintFieldType, int64_t, boost::random::mt19937>(8, rng);
    test_random<BlueprintFieldType, uint8_t, boost::random::mt19937>(1, rng);
    test_random<BlueprintFieldType, uint16_t, boost::random::mt19937>(2, rng);
    test_random<BlueprintFieldType, uint32_t, boost::random::mt19937>(4, rng);
    test_random<BlueprintFieldType, uint64_t, boost::random::mt19937>(8, rng);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_bitwise_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    test_integer_variants<field_type>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_bitwise_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_integer_variants<field_type>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_bitwise_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    test_integer_variants<field_type>();
}

BOOST_AUTO_TEST_SUITE_END()
