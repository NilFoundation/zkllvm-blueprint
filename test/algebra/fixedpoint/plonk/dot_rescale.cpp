#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_dot_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/dot_rescale_1_gate.hpp>

#include <nil/blueprint/components/algebra/fixedpoint/plonk/dot_rescale_2_gates.hpp>

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
void test_fixedpoint_dot_1_gate(std::vector<FixedType> &input1, std::vector<FixedType> &input2) {
    auto dots = input1.size();
    BLUEPRINT_RELEASE_ASSERT(dots == input2.size());
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 8;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_dot_rescale_1_gate<ArithmetizationType,
                                                      BlueprintFieldType,
                                                      nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::vector<var> instance_input_x;
    std::vector<var> instance_input_y;
    std::vector<typename BlueprintFieldType::value_type> public_input(2 * dots + 1,
                                                                      BlueprintFieldType::value_type::zero());
    instance_input_x.reserve(dots);
    instance_input_y.reserve(dots);

    auto zero = var(0, 0, false, var::column_type::public_input);
    for (auto i = 0; i < dots; i++) {
        instance_input_x.push_back(var(0, i + 1, false, var::column_type::public_input));
        instance_input_y.push_back(var(0, i + dots + 1, false, var::column_type::public_input));
        public_input[i + 1] = input1[i].get_value();
        public_input[i + dots + 1] = input2[i].get_value();
    }

    typename component_type::input_type instance_input = {instance_input_x, instance_input_y, zero};

    double expected_res_f = 0.;
    for (auto i = 0; i < input1.size(); i++) {
        expected_res_f += input1[i].to_double() * input2[i].to_double();
    }
    auto expected_res = FixedType::dot(input1, input2);

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point dot_rescale (1 gate) test: "
                  << "\n";
        std::cout << "dot_size : " << input1.size() << "\n";
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
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), dots, FixedType::M_2);

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_dot_2_gates(std::vector<FixedType> &input1, std::vector<FixedType> &input2) {
    auto dots = input1.size();
    BLUEPRINT_RELEASE_ASSERT(dots == input2.size());
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 7;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_dot_rescale_2_gates<ArithmetizationType,
                                                       BlueprintFieldType,
                                                       nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::vector<var> instance_input_x;
    std::vector<var> instance_input_y;
    std::vector<typename BlueprintFieldType::value_type> public_input(2 * dots + 1,
                                                                      BlueprintFieldType::value_type::zero());
    instance_input_x.reserve(dots);
    instance_input_y.reserve(dots);

    auto zero = var(0, 0, false, var::column_type::public_input);
    for (auto i = 0; i < dots; i++) {
        instance_input_x.push_back(var(0, i + 1, false, var::column_type::public_input));
        instance_input_y.push_back(var(0, i + dots + 1, false, var::column_type::public_input));
        public_input[i + 1] = input1[i].get_value();
        public_input[i + dots + 1] = input2[i].get_value();
    }

    typename component_type::input_type instance_input = {instance_input_x, instance_input_y, zero};

    double expected_res_f = 0.;
    for (auto i = 0; i < input1.size(); i++) {
        expected_res_f += input1[i].to_double() * input2[i].to_double();
    }
    auto expected_res = FixedType::dot(input1, input2);

    auto result_check = [&expected_res, &expected_res_f, input1, input2](
                            AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point dot_rescale (2 gates) test: "
                  << "\n";
        std::cout << "dot_size : " << input1.size() << "\n";
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
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), dots, FixedType::M_2);

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
void test_components_on_random_data(std::size_t dots, RngType &rng) {
    std::vector<FixedType> x;
    std::vector<FixedType> y;
    x.reserve(dots);
    y.reserve(dots);

    for (auto i = 0; i < dots; i++) {
        x.push_back(FixedType(
            generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
            FixedType::SCALE));
        y.push_back(FixedType(
            generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
            FixedType::SCALE));
    }

    test_fixedpoint_dot_1_gate<FixedType>(x, y);
    test_fixedpoint_dot_2_gates<FixedType>(x, y);
}

template<typename FixedType>
void test_components(std::size_t dots) {
    std::vector<FixedType> x;
    std::vector<FixedType> y;
    x.reserve(dots);
    y.reserve(dots);

    for (auto i = 1; i <= dots; i++) {
        x.push_back(FixedType((int64_t)i));
        y.push_back(FixedType((int64_t)i));
    }

    test_fixedpoint_dot_1_gate<FixedType>(x, y);
    test_fixedpoint_dot_2_gates<FixedType>(x, y);
}

template<typename FixedType>
void field_operations_test() {
    for (std::size_t i = 1; i <= 5; i++) {
        test_components<FixedType>(i);
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 1; i <= 5; i++) {
        test_components_on_random_data<FixedType>(i, seed_seq);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_dot_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_dot_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_dot_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_SUITE_END()
