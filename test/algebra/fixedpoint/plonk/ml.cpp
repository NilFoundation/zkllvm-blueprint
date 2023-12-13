#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_ml_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/gather_acc.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/argmax.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/argmin.hpp>

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
void test_fixedpoint_gather_acc_inner(FixedType acc,
                                      FixedType data,
                                      typename FixedType::value_type index_a,
                                      typename FixedType::value_type index_b) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 6;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_gather_acc<ArithmetizationType, BlueprintFieldType,
                                              nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input),
                                                          var(0, 2, false, var::column_type::public_input)};

    double expected_res_f = (index_a == index_b) ? acc.to_double() + data.to_double() : acc.to_double();
    auto expected_res = (index_a == index_b) ? acc + data : acc;

    auto result_check = [&expected_res, &expected_res_f, acc, data, index_a,
                         index_b](AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point gather_acc test: "
                  << "\n";
        std::cout << "acc_f : " << acc.to_double() << "\n";
        std::cout << "acc   : " << acc.get_value().data << "\n";
        std::cout << "data_f: " << data.to_double() << "\n";
        std::cout << "data  : " << data.get_value().data << "\n";
        std::cout << "index_a: " << index_a << "\n";
        std::cout << "index_b: " << index_b << "\n";
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
    component_type component_instance(witness_list, std::array<std::uint32_t, 1>({0}), std::array<std::uint32_t, 0>(),
                                      index_b);

    std::vector<typename BlueprintFieldType::value_type> public_input = {acc.get_value(), data.get_value(), index_a};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_argmax_inner(FixedType x, FixedType y, typename FixedType::value_type index_x,
                                  typename FixedType::value_type index_y, bool select_last_index) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 10;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_argmax<ArithmetizationType, BlueprintFieldType,
                                          nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input),
                                                          var(0, 2, false, var::column_type::public_input)};

    BLUEPRINT_RELEASE_ASSERT(index_x < index_y);

    double x_f = x.to_double();
    double y_f = y.to_double();

    double expected_res_f;
    FixedType expected_res(0, FixedType::SCALE);
    typename FixedType::value_type expected_index;

    expected_res_f = y.to_double();

    if (select_last_index) {
        // We have to evaluate x > y
        expected_res_f = x_f > y_f ? x_f : y_f;
        expected_res = x > y ? x : y;
        expected_index = x_f > y_f ? index_x : index_y;
    } else {
        // We have to evaluate x >= y
        expected_res_f = x_f >= y_f ? x_f : y_f;
        expected_res = x >= y ? x : y;
        expected_index = x_f >= y_f ? index_x : index_y;
    }

    auto result_check = [&expected_res, &expected_res_f, &expected_index, select_last_index, x, y, index_x,
                         index_y](AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.max), FixedType::SCALE);
        auto real_index = var_value(assignment, real_res.index);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point argmax test: "
                  << "\n";
        std::cout << "x_f            : " << x.to_double() << "\n";
        std::cout << "y_f            : " << y.to_double() << "\n";
        std::cout << "x              : " << x.get_value().data << "\n";
        std::cout << "y              : " << y.get_value().data << "\n";
        std::cout << "index_x        : " << index_x << "\n";
        std::cout << "index_y        : " << index_y << "\n";
        std::cout << "select_last    : " << select_last_index << "\n";
        std::cout << "expected       : " << expected_res_f << "\n";
        std::cout << "real           : " << real_res_f << "\n";
        std::cout << "expected index : " << expected_index.data << "\n";
        std::cout << "real index     : " << real_index.data << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_ ||
            expected_index != real_index) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n";
            std::cout << "expected_index  : " << expected_index.data << "\n";
            std::cout << "real_index      : " << real_index.data << "\n";
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
    component_type component_instance(witness_list, std::array<std::uint32_t, 1>({0}), std::array<std::uint32_t, 0>(),

                                      FixedType::M_1, FixedType::M_2, index_y, select_last_index);

    std::vector<typename BlueprintFieldType::value_type> public_input = {x.get_value(), y.get_value(), index_x};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input,
        crypto3::detail::connectedness_check_type::STRONG, FixedType::M_1, FixedType::M_2);
}

template<typename FixedType>
void test_fixedpoint_argmin_inner(FixedType x, FixedType y, typename FixedType::value_type index_x,
                                  typename FixedType::value_type index_y, bool select_last_index) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 10;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_argmin<ArithmetizationType, BlueprintFieldType,
                                          nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input),
                                                          var(0, 2, false, var::column_type::public_input)};

    BLUEPRINT_RELEASE_ASSERT(index_x < index_y);

    double x_f = x.to_double();
    double y_f = y.to_double();

    double expected_res_f;
    FixedType expected_res(0, FixedType::SCALE);
    typename FixedType::value_type expected_index;

    expected_res_f = y.to_double();

    if (select_last_index) {
        // We have to evaluate x < y
        expected_res_f = x_f < y_f ? x_f : y_f;
        expected_res = x < y ? x : y;
        expected_index = x_f < y_f ? index_x : index_y;
    } else {
        // We have to evaluate x <= y
        expected_res_f = x_f <= y_f ? x_f : y_f;
        expected_res = x <= y ? x : y;
        expected_index = x_f <= y_f ? index_x : index_y;
    }

    auto result_check = [&expected_res, &expected_res_f, &expected_index, select_last_index, x, y, index_x,
                         index_y](AssignmentType &assignment, typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.min), FixedType::SCALE);
        auto real_index = var_value(assignment, real_res.index);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point argmin test: "
                  << "\n";
        std::cout << "x_f            : " << x.to_double() << "\n";
        std::cout << "y_f            : " << y.to_double() << "\n";
        std::cout << "x              : " << x.get_value().data << "\n";
        std::cout << "y              : " << y.get_value().data << "\n";
        std::cout << "index_x        : " << index_x << "\n";
        std::cout << "index_y        : " << index_y << "\n";
        std::cout << "select_last    : " << select_last_index << "\n";
        std::cout << "expected       : " << expected_res_f << "\n";
        std::cout << "real           : " << real_res_f << "\n";
        std::cout << "expected index : " << expected_index.data << "\n";
        std::cout << "real index     : " << real_index.data << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_ ||
            expected_index != real_index) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n";
            std::cout << "expected_index  : " << expected_index.data << "\n";
            std::cout << "real_index      : " << real_index.data << "\n";
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
    component_type component_instance(witness_list, std::array<std::uint32_t, 1>({0}), std::array<std::uint32_t, 0>(),

                                      FixedType::M_1, FixedType::M_2, index_y, select_last_index);

    std::vector<typename BlueprintFieldType::value_type> public_input = {x.get_value(), y.get_value(), index_x};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input,
        crypto3::detail::connectedness_check_type::STRONG, FixedType::M_1, FixedType::M_2);
}

template<typename FixedType>
void test_fixedpoint_gather_acc(FixedType x,
                                FixedType y,
                                typename FixedType::value_type index_a,
                                typename FixedType::value_type index_b) {
    auto acc = FixedType::value_type::zero();
    test_fixedpoint_gather_acc_inner<FixedType>(acc, x, index_a, index_a);    // new_acc should be x
    test_fixedpoint_gather_acc_inner<FixedType>(x, y, index_a, index_b);      // new_acc should stay x
}

template<typename FixedType>
void test_fixedpoint_argmax(FixedType x,
                            FixedType y,
                            typename FixedType::value_type index_x,
                            typename FixedType::value_type index_y) {
    if (index_y < index_x) {
        std::swap(index_x, index_y);
    }
    test_fixedpoint_argmax_inner<FixedType>(x, y, index_x, index_y, true);
    test_fixedpoint_argmax_inner<FixedType>(x, y, index_x, index_y, false);
}

template<typename FixedType>
void test_fixedpoint_argmin(FixedType x,
                            FixedType y,
                            typename FixedType::value_type index_x,
                            typename FixedType::value_type index_y) {
    if (index_y < index_x) {
        std::swap(index_x, index_y);
    }
    test_fixedpoint_argmin_inner<FixedType>(x, y, index_x, index_y, true);
    test_fixedpoint_argmin_inner<FixedType>(x, y, index_x, index_y, false);
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

static constexpr std::size_t INDEX_MAX = 1000;

template<typename FieldType, typename RngType>
FieldType generate_random_index(RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    distribution dist = distribution(0, INDEX_MAX);
    uint64_t x = dist(rng);
    return FieldType(x);
}

template<typename FixedType, typename RngType>
void test_components_on_random_data(RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType y(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);

    auto index_a = generate_random_index<typename FixedType::value_type>(rng);
    auto index_b = generate_random_index<typename FixedType::value_type>(rng);
    while (index_a == index_b) {
        index_b = generate_random_index<typename FixedType::value_type>(rng);
    }

    test_fixedpoint_gather_acc<FixedType>(x, y, index_a, index_b);
    test_fixedpoint_argmax<FixedType>(x, y, index_a, index_b);
    test_fixedpoint_argmin<FixedType>(x, y, index_a, index_b);
}

template<typename FixedType>
void test_components(int i, int j) {
    FixedType x((int64_t)i);
    FixedType y((int64_t)j);

    auto index_a = FixedType::value_type::one();
    auto index_b = typename FixedType::value_type(2);

    test_fixedpoint_gather_acc<FixedType>(x, y, index_a, index_b);
    test_fixedpoint_argmax<FixedType>(x, y, index_a, index_b);
    test_fixedpoint_argmin<FixedType>(x, y, index_a, index_b);
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

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_ml_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_ml_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_ml_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
