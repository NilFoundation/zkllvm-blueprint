#define BOOST_TEST_MODULE blueprint_plonk_fields_dot_test

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

#include <nil/blueprint/components/algebra/fields/plonk/dot_2_gates.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

static constexpr double EPSILON = 0.001;

template<typename BlueprintFieldType>
void test_dot_2_gates(std::vector<typename BlueprintFieldType::value_type> &input1,
                      std::vector<typename BlueprintFieldType::value_type> &input2) {
    using value_type = typename BlueprintFieldType::value_type;
    auto dots = input1.size();
    BLUEPRINT_RELEASE_ASSERT(dots == input2.size());
    constexpr std::size_t WitnessColumns = 7;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 5;
    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::dot_2_gates<ArithmetizationType, BlueprintFieldType,
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
        public_input[i + 1] = input1[i];
        public_input[i + dots + 1] = input2[i];
    }

    typename component_type::input_type instance_input = {instance_input_x, instance_input_y, zero};

    value_type expected_res = value_type::zero();
    for (auto i = 0; i < input1.size(); i++) {
        expected_res += input1[i] * input2[i];
    }

    auto result_check = [&expected_res, input1, input2](AssignmentType &assignment,
                                                        typename component_type::result_type &real_res) {
        auto real_res_ = var_value(assignment, real_res.output);
        if (expected_res != real_res_) {
            std::cout << "expected        : " << expected_res << "\n";
            std::cout << "real            : " << real_res_ << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                      dots);

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input, crypto3::detail::connectedness_check_type::NONE,
        static_cast<uint32_t>(dots));
    // The zero is sometimes not connected
}

template<typename BlueprintFieldType, typename RngType>
typename BlueprintFieldType::value_type generate_random(RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;
    using value_type = typename BlueprintFieldType::value_type;

    uint64_t max = static_cast<uint64_t>(-1);
    ;

    distribution dist = distribution(0, max);
    uint64_t x = dist(rng);
    return value_type(x);
}

template<typename BlueprintFieldType, typename RngType>
void test_components_on_random_data(std::size_t dots, RngType &rng) {
    using value_type = typename BlueprintFieldType::value_type;
    std::vector<value_type> x;
    std::vector<value_type> y;
    x.reserve(dots);
    y.reserve(dots);

    for (auto i = 0; i < dots; i++) {
        x.push_back(value_type(generate_random<BlueprintFieldType>(rng)));
        y.push_back(value_type(generate_random<BlueprintFieldType>(rng)));
    }

    test_dot_2_gates<BlueprintFieldType>(x, y);
}

template<typename BlueprintFieldType>
void test_components(std::size_t dots) {
    using value_type = typename BlueprintFieldType::value_type;
    std::vector<value_type> x;
    std::vector<value_type> y;
    x.reserve(dots);
    y.reserve(dots);

    for (auto i = 1; i <= dots; i++) {
        x.push_back(value_type((int64_t)i));
        y.push_back(value_type((int64_t)i));
    }

    test_dot_2_gates<BlueprintFieldType>(x, y);
}

template<typename BlueprintFieldType>
void field_operations_test() {
    for (std::size_t i = 1; i <= 5; i++) {
        test_components<BlueprintFieldType>(i);
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 1; i <= 5; i++) {
        test_components_on_random_data<BlueprintFieldType>(i, seed_seq);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_dot_test_vesta) {
    using BlueprintFieldType = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<BlueprintFieldType>();
    field_operations_test<BlueprintFieldType>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_dot_test_pallas) {
    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<BlueprintFieldType>();
    field_operations_test<BlueprintFieldType>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_dot_test_bls12) {
    using BlueprintFieldType = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<BlueprintFieldType>();
    field_operations_test<BlueprintFieldType>();
}

BOOST_AUTO_TEST_SUITE_END()
