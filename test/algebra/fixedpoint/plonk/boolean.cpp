#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_boolean_operations_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/boolean.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON = 0.01;

#define PRINT_FIXED_POINT_TEST(what)                                            \
    std::cout << "fixed_point " << what << " test:\n";                          \
    std::cout << "a                : " << a.get_value().data << "\n";           \
    std::cout << "b                : " << b.get_value().data << "\n";           \
    std::cout << "expected a_inv   : " << a_inv_.get_value().data << "\n";      \
    std::cout << "real a_inv       : " << real_a_inv_.get_value().data << "\n"; \
    std::cout << "expected b_inv   : " << b_inv_.get_value().data << "\n";      \
    std::cout << "real b_inv       : " << real_b_inv_.get_value().data << "\n"; \
    std::cout << "expected and     : " << and_.get_value().data << "\n";        \
    std::cout << "real and         : " << real_and_.get_value().data << "\n";   \
    std::cout << "expected or      : " << or_.get_value().data << "\n";         \
    std::cout << "real or          : " << real_or_.get_value().data << "\n";    \
    std::cout << "expected xor     : " << xor_.get_value().data << "\n";        \
    std::cout << "real xor         : " << real_xor_.get_value().data << "\n";

bool doubleEquals(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    // or just smaller epsilon
    return fabs(a - b) < epsilon || fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

template<typename FixedType>
void test_fixedpoint_boolean(FixedType a, FixedType b) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 7;
    constexpr std::size_t PublicInputColumns = 1;
#ifdef TEST_WITHOUT_LOOKUP_TABLES
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
#else
    constexpr std::size_t ConstantColumns = 15;
    constexpr std::size_t SelectorColumns = 15;
#endif
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_boolean<ArithmetizationType,
                                           BlueprintFieldType,
                                           nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    using value_type = typename FixedType::value_type;
    auto zero = FixedType(value_type(0), FixedType::SCALE);
    auto one = FixedType(value_type(1), FixedType::SCALE);

    auto and_ = a == one && b == one ? one : zero;
    auto or_ = a == one ? a : b;
    auto xor_ = a == b ? zero : one;
    auto a_inv_ = a == one ? zero : one;
    auto b_inv_ = b == one ? zero : one;
    // the above is true for a, b in {0, 1}. Other values are caught by lookup tables

    auto result_check = [&and_, &or_, &xor_, &a_inv_, &b_inv_, &a, &b](AssignmentType &assignment,
                                                                       typename component_type::result_type &real_res) {
        auto real_and_ = FixedType(var_value(assignment, real_res.and_), FixedType::SCALE);
        auto real_or_ = FixedType(var_value(assignment, real_res.or_), FixedType::SCALE);
        auto real_xor_ = FixedType(var_value(assignment, real_res.xor_), FixedType::SCALE);
        auto real_a_inv_ = FixedType(var_value(assignment, real_res.a_inv_), FixedType::SCALE);
        auto real_b_inv_ = FixedType(var_value(assignment, real_res.b_inv_), FixedType::SCALE);
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        PRINT_FIXED_POINT_TEST("boolean")
#endif
        if (real_and_ != and_ || real_or_ != or_ || real_xor_ != xor_ || real_a_inv_ != a_inv_ ||
            real_b_inv_ != b_inv_) {
            PRINT_FIXED_POINT_TEST("boolean")
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

    std::vector<typename BlueprintFieldType::value_type> public_input = {a.get_value(), b.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void field_operations_test() {
    using value_type = typename FixedType::value_type;
    auto zero = FixedType(value_type(0), FixedType::SCALE);
    auto one = FixedType(value_type(1), FixedType::SCALE);
    test_fixedpoint_boolean(zero, zero);
    test_fixedpoint_boolean(zero, one);
    test_fixedpoint_boolean(one, zero);
    test_fixedpoint_boolean(one, one);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_trigonometric_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_trigonometric_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_trigonometric_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_SUITE_END()
