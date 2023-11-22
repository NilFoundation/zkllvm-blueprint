#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_tester_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/tester.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using blueprint::components::FixedPoint;

static constexpr double EPSILON = 0.001;

bool doubleEquals(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    return fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

bool doubleEqualsExp(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    // or just smaller epsilon
    return fabs(a - b) < epsilon || fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

template<typename FixedType, typename ComponentType>
void add_add(ComponentType &component, FixedType input1, FixedType input2) {

    double expected_res_f = input1.to_double() + input2.to_double();
    auto expected_res = input1 + input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::ADD, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_sub(ComponentType &component, FixedType input1, FixedType input2) {

    double expected_res_f = input1.to_double() - input2.to_double();
    auto expected_res = input1 - input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::SUB, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_mul_rescale(ComponentType &component, FixedType input1, FixedType input2) {

    double expected_res_f = input1.to_double() * input2.to_double();
    auto expected_res = input1 * input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::MUL_RESCALE, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_mul_rescale_const(ComponentType &component, FixedType input1, FixedType input2) {

    double expected_res_f = input1.to_double() * input2.to_double();
    auto expected_res = input1 * input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {input2.get_value()};

    component.add_testcase(blueprint::components::FixedPointComponents::MUL_RESCALE_CONST, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_div_by_pos(ComponentType &component, FixedType input1, FixedType input2) {
    double expected_res_f = input1.to_double() / input2.to_double();
    auto expected_res = input1 / input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::DIV_BY_POS, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_div(ComponentType &component, FixedType input1, FixedType input2) {

    double expected_res_f = input1.to_double() / input2.to_double();
    auto expected_res = input1 / input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::DIV, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_mod(ComponentType &component, FixedType input1, FixedType input2) {

    double input2_f = input2.to_double();
    double expected_res_f = remainder(input1.to_double(), input2_f);
    // Correct signs for onnx specififcation
    if ((expected_res_f < 0 && input2_f > 0) || (expected_res_f > 0 && input2_f < 0)) {
        expected_res_f += input2_f;
    }
    auto expected_res = input1 % input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::REM, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_rescale(ComponentType &component, FixedType input) {

    double expected_res_f = input.to_double();
    auto expected_res = input.rescale();

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::RESCALE, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_neg(ComponentType &component, FixedType input) {

    double expected_res_f = -input.to_double();
    auto expected_res = -input;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::NEG, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_int_to_fixedpoint(ComponentType &component, typename FixedType::value_type input) {

    double expected_res_f = FixedType::helper::field_to_double(input);
    auto expected_res = FixedType(input);

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::TO_FIXEDPOINT, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_exp(ComponentType &component, FixedType input) {

    double expected_res_f = exp(input.to_double());
    auto expected_res = input.exp();

    BLUEPRINT_RELEASE_ASSERT(doubleEqualsExp(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::EXP, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_exp_ranged(ComponentType &component, FixedType input) {

    auto max_exp = FixedType::max();
    auto max_exp_f = max_exp.to_double();

    double expected_res_f = exp(input.to_double());
    if (expected_res_f > max_exp_f) {
        expected_res_f = max_exp_f;
    }
    auto expected_res = input.exp(true);

    BLUEPRINT_RELEASE_ASSERT(expected_res <= max_exp);
    BLUEPRINT_RELEASE_ASSERT(doubleEqualsExp(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::EXP_RANGED, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_tanh(ComponentType &component, FixedType input) {

    double expected_res_f = tanh(input.to_double());
    auto expected_res = input.tanh();

    BLUEPRINT_RELEASE_ASSERT(doubleEqualsExp(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::TANH, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_sqrt(ComponentType &component, FixedType input) {

    double expected_res_f = sqrt(input.to_double());
    auto expected_res = input.sqrt();

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::SQRT, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_sqrt_floor(ComponentType &component, FixedType input) {

    double expected_res_f = sqrt(input.to_double());
    auto expected_res = input.sqrt(true);

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::SQRT_FLOOR, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_log(ComponentType &component, FixedType input) {

    double expected_res_f = log(input.to_double());
    auto expected_res = input.log();

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::LOG, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_cmp(ComponentType &component, FixedType input1, FixedType input2) {
    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    bool expected_res_less_f = input1_f < input2_f;
    bool expected_res_greater_f = input1_f > input2_f;
    bool expected_res_equal_f = fabs(input1_f - input2_f) < pow(2., -FixedType::SCALE);
    bool expected_res_less = input1 < input2;
    bool expected_res_greater = input1 > input2;
    bool expected_res_equal = input1 == input2;

    BLUEPRINT_RELEASE_ASSERT(expected_res_less_f == expected_res_less);
    BLUEPRINT_RELEASE_ASSERT(expected_res_greater_f == expected_res_greater);
    BLUEPRINT_RELEASE_ASSERT(expected_res_equal_f == expected_res_equal);
    BLUEPRINT_RELEASE_ASSERT((uint8_t)expected_res_equal + (uint8_t)expected_res_greater + (uint8_t)expected_res_less ==
                             1);

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res_equal ? 1 : 0, expected_res_less ? 1 : 0,
                                                           expected_res_greater ? 1 : 0};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::CMP, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_cmp_extended(ComponentType &component, FixedType input1, FixedType input2) {
    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    bool expected_res_less_f = input1_f < input2_f;
    bool expected_res_greater_f = input1_f > input2_f;
    bool expected_res_equal_f = fabs(input1_f - input2_f) < pow(2., -FixedType::SCALE);
    bool expected_res_leq_f = input1_f <= input2_f;
    bool expected_res_geq_f = input1_f >= input2_f;
    bool expected_res_neq_f = fabs(input1_f - input2_f) >= pow(2., -FixedType::SCALE);
    bool expected_res_less = input1 < input2;
    bool expected_res_greater = input1 > input2;
    bool expected_res_equal = input1 == input2;
    bool expected_res_geq = input1 >= input2;
    bool expected_res_leq = input1 <= input2;
    bool expected_res_neq = input1 != input2;

    BLUEPRINT_RELEASE_ASSERT(expected_res_less_f == expected_res_less);
    BLUEPRINT_RELEASE_ASSERT(expected_res_greater_f == expected_res_greater);
    BLUEPRINT_RELEASE_ASSERT(expected_res_equal_f == expected_res_equal);
    BLUEPRINT_RELEASE_ASSERT(expected_res_leq_f == expected_res_leq);
    BLUEPRINT_RELEASE_ASSERT(expected_res_geq_f == expected_res_geq);
    BLUEPRINT_RELEASE_ASSERT(expected_res_neq_f == expected_res_neq);
    BLUEPRINT_RELEASE_ASSERT((uint8_t)expected_res_equal + (uint8_t)expected_res_greater + (uint8_t)expected_res_less ==
                             1);
    BLUEPRINT_ASSERT(expected_res_eq != expected_res_neq);
    BLUEPRINT_ASSERT(expected_res_geq != expected_res_less);
    BLUEPRINT_ASSERT(expected_res_leq != expected_res_greater);

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res_equal ? 1 : 0,   expected_res_less ? 1 : 0,
                                                           expected_res_greater ? 1 : 0, expected_res_neq ? 1 : 0,
                                                           expected_res_leq ? 1 : 0,     expected_res_geq ? 1 : 0};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::CMP_EXTENDED, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_select_internal(ComponentType &component, FixedType input1, FixedType input2, bool input1_select) {

    double expected_res_f = input1_select ? input1.to_double() : input2.to_double();
    auto expected_res = input1_select ? input1 : input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1_select ? 1 : 0, input1.get_value(),
                                                          input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::SELECT, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_select(ComponentType &component, FixedType input1, FixedType input2) {
    add_select_internal(component, input1, input2, true);
    add_select_internal(component, input1, input2, false);
}

template<typename FixedType, typename ComponentType>
void add_max(ComponentType &component, FixedType input1, FixedType input2) {
    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    double expected_res_f = input1_f > input2_f ? input1_f : input2_f;
    auto expected_res = input1 > input2 ? input1 : input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::MAX, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_min(ComponentType &component, FixedType input1, FixedType input2) {
    double input1_f = input1.to_double();
    double input2_f = input2.to_double();
    double expected_res_f = input1_f < input2_f ? input1_f : input2_f;
    auto expected_res = input1 < input2 ? input1 : input2;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::MIN, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_cmp_min_max(ComponentType &component, FixedType input1, FixedType input2) {
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

    BLUEPRINT_RELEASE_ASSERT(expected_res_less_f == expected_res_less);
    BLUEPRINT_RELEASE_ASSERT(expected_res_greater_f == expected_res_greater);
    BLUEPRINT_RELEASE_ASSERT(expected_res_equal_f == expected_res_equal);
    BLUEPRINT_RELEASE_ASSERT((uint8_t)expected_res_equal + (uint8_t)expected_res_greater + (uint8_t)expected_res_less ==
                             1);

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_min_f, expected_res_min.to_double(), EPSILON));
    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_max_f, expected_res_max.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input1.get_value(), input2.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res_equal ? 1 : 0, expected_res_less ? 1 : 0,
                                                           expected_res_greater ? 1 : 0, expected_res_min.get_value(),
                                                           expected_res_max.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::CMP_MIN_MAX, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_range(ComponentType &component, FixedType input, FixedType x_lo, FixedType x_hi) {
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

    BLUEPRINT_RELEASE_ASSERT(expected_res_less_f == expected_res_less);
    BLUEPRINT_RELEASE_ASSERT(expected_res_greater_f == expected_res_greater);
    BLUEPRINT_RELEASE_ASSERT(expected_res_in_f == expected_res_in);
    BLUEPRINT_RELEASE_ASSERT((uint8_t)expected_res_in + (uint8_t)expected_res_greater + (uint8_t)expected_res_less ==
                             1);

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res_in ? 1 : 0, expected_res_less ? 1 : 0,
                                                           expected_res_greater ? 1 : 0};
    std::vector<typename FixedType::value_type> constants = {x_lo.get_value(), x_hi.get_value()};

    component.add_testcase(blueprint::components::FixedPointComponents::RANGE, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_gather_acc_inner(ComponentType &component, FixedType acc, FixedType data,
                          typename FixedType::value_type index_a, typename FixedType::value_type index_b) {

    double expected_res_f = (index_a == index_b) ? acc.to_double() + data.to_double() : acc.to_double();
    auto expected_res = (index_a == index_b) ? acc + data : acc;

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {acc.get_value(), data.get_value(), index_a};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {index_b};

    component.add_testcase(blueprint::components::FixedPointComponents::GATHER_ACC, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_gather_acc(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_a,
                    typename FixedType::value_type index_b) {
    auto acc = FixedType::value_type::zero();
    add_gather_acc_inner<FixedType, ComponentType>(component, acc, x, index_a, index_a);    // new_acc should be x
    add_gather_acc_inner<FixedType, ComponentType>(component, x, y, index_a, index_b);      // new_acc should stay x
}

template<typename FixedType, typename ComponentType>
void add_argmax_inner(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_x,
                      typename FixedType::value_type index_y, bool select_last_index) {
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

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {x.get_value(), y.get_value(), index_x};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value(), expected_index};
    std::vector<typename FixedType::value_type> constants = {index_y, select_last_index ? 1 : 0};

    component.add_testcase(blueprint::components::FixedPointComponents::ARGMAX, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_argmax(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_x,
                typename FixedType::value_type index_y) {
    if (index_y < index_x) {
        std::swap(index_x, index_y);
    }
    add_argmax_inner<FixedType, ComponentType>(component, x, y, index_x, index_y, true);
    add_argmax_inner<FixedType, ComponentType>(component, x, y, index_x, index_y, false);
}

template<typename FixedType, typename ComponentType>
void add_argmin_inner(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_x,
                      typename FixedType::value_type index_y, bool select_last_index) {
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

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {x.get_value(), y.get_value(), index_x};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value(), expected_index};
    std::vector<typename FixedType::value_type> constants = {index_y, select_last_index ? 1 : 0};

    component.add_testcase(blueprint::components::FixedPointComponents::ARGMIN, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_argmin(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_x,
                typename FixedType::value_type index_y) {
    if (index_y < index_x) {
        std::swap(index_x, index_y);
    }
    add_argmin_inner<FixedType, ComponentType>(component, x, y, index_x, index_y, true);
    add_argmin_inner<FixedType, ComponentType>(component, x, y, index_x, index_y, false);
}

template<typename FixedType, typename ComponentType>
void add_dot_1_gate(ComponentType &component, std::vector<FixedType> &input1, std::vector<FixedType> &input2) {

    auto dots = input1.size();
    BLUEPRINT_RELEASE_ASSERT(dots == input2.size());

    double expected_res_f = 0.;
    for (auto i = 0; i < input1.size(); i++) {
        expected_res_f += input1[i].to_double() * input2[i].to_double();
    }
    auto expected_res = FixedType::dot(input1, input2);

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs;
    inputs.reserve(2 * dots + 1);
    for (auto i = 0; i < dots; i++) {
        inputs.push_back(input1[i].get_value());
    }
    for (auto i = 0; i < dots; i++) {
        inputs.push_back(input2[i].get_value());
    }
    inputs.push_back(0);

    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::DOT_RESCALE1, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2, dots);
}

template<typename FixedType, typename ComponentType>
void add_dot_2_gates(ComponentType &component, std::vector<FixedType> &input1, std::vector<FixedType> &input2) {

    auto dots = input1.size();
    BLUEPRINT_RELEASE_ASSERT(dots == input2.size());

    double expected_res_f = 0.;
    for (auto i = 0; i < input1.size(); i++) {
        expected_res_f += input1[i].to_double() * input2[i].to_double();
    }
    auto expected_res = FixedType::dot(input1, input2);

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs;
    inputs.reserve(2 * dots + 1);
    for (auto i = 0; i < dots; i++) {
        inputs.push_back(input1[i].get_value());
    }
    for (auto i = 0; i < dots; i++) {
        inputs.push_back(input2[i].get_value());
    }
    inputs.push_back(0);

    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::DOT_RESCALE2, inputs, outputs, constants,
                           FixedType::M_1, FixedType::M_2, dots);
}

template<typename FixedType, typename ComponentType>
void add_sin(ComponentType &component, FixedType input) {

    double expected_res_f = sin(input.to_double());
    auto expected_res = input.sin();

    BLUEPRINT_RELEASE_ASSERT(doubleEqualsExp(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::SIN, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

template<typename FixedType, typename ComponentType>
void add_cos(ComponentType &component, FixedType input) {

    double expected_res_f = cos(input.to_double());
    auto expected_res = input.cos();

    BLUEPRINT_RELEASE_ASSERT(doubleEqualsExp(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {input.get_value()};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value()};
    std::vector<typename FixedType::value_type> constants = {};

    component.add_testcase(blueprint::components::FixedPointComponents::COS, inputs, outputs, constants, FixedType::M_1,
                           FixedType::M_2);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static constexpr std::size_t INDEX_MAX = 1000;

template<typename FieldType, typename RngType>
FieldType generate_random_index(RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    distribution dist = distribution(0, INDEX_MAX);
    uint64_t x = dist(rng);
    return FieldType(x);
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

constexpr static const std::size_t UPPER_BOUND = 6;

template<typename FieldType, typename RngType>
typename FieldType::value_type generate_bounded_random_for_fixedpoint(uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;
    using value_type = typename FieldType::value_type;

    distribution dist = distribution(0, UPPER_BOUND);
    uint64_t pre = dist(rng);
    distribution dist_ = distribution(0, (1ULL << (16 * m2)) - 1);
    uint64_t post = dist_(rng);
    distribution dist_bool = distribution(0, 1);
    bool sign = dist_bool(rng) == 1;

    if (sign) {
        return -value_type(pre << (16 * m2)) + post;
    } else {
        return value_type(pre << (16 * m2)) + post;
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

template<typename FieldType, typename RngType>
FieldType generate_random_post_comma_for_fixedpoint(uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);

    uint64_t max = (1ull << (16 * m2)) - 1;

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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

template<typename FixedType, typename ComponentType>
void test_components_unary_basic(ComponentType &component, int i) {
    FixedType x((int64_t)i);

    constexpr double pi_half = 1.5707963267948966;
    constexpr double pi = 3.141592653589793;
    constexpr double pi_two = 6.283185307179586;

    // BASIC
    add_rescale<FixedType, ComponentType>(component, FixedType(x.get_value() * FixedType::DELTA, FixedType::SCALE * 2));
    add_neg<FixedType, ComponentType>(component, x);
    add_int_to_fixedpoint<FixedType, ComponentType>(component, (int64_t)i);

    // EXP
    add_exp<FixedType, ComponentType>(component, x);
    add_exp_ranged<FixedType, ComponentType>(component, x);
    add_tanh<FixedType, ComponentType>(component, x);

    // TRIGON
    for (int i = -2; i < 3; i++) {
        auto i_dbl = static_cast<double>(i);
        for (int quadrant = 0; quadrant < 4; quadrant++) {
            auto q_dbl = static_cast<double>(quadrant);
            FixedType a(i_dbl * pi_two + pi_half * q_dbl);
            FixedType b(i_dbl * pi_two + pi_half * q_dbl + pi_half / 2.);
            add_sin<FixedType, ComponentType>(component, a);
            add_cos<FixedType, ComponentType>(component, b);
        }
    }
}

template<typename FixedType, typename ComponentType>
void test_components_unary_positive(ComponentType &component, int i) {
    BLUEPRINT_RELEASE_ASSERT(i >= 0);
    FixedType x((int64_t)i);

    // ADVANCED
    add_sqrt<FixedType, ComponentType>(component, x);
    add_sqrt_floor<FixedType, ComponentType>(component, x);
    if (x.get_value() > 0) {
        add_log<FixedType, ComponentType>(component, x);
    }
}

template<typename FixedType, typename ComponentType>
void test_components_binary_one_positive(ComponentType &component, int i, int j) {
    BLUEPRINT_RELEASE_ASSERT(j >= 0);
    FixedType x((int64_t)i);
    FixedType y((int64_t)j);

    // BASIC
    if (y.get_value() != 0) {
        add_div_by_pos<FixedType, ComponentType>(component, x, y);
    }
}

template<typename FixedType, typename ComponentType>
void test_components_binary_basic(ComponentType &component, int i, int j) {
    FixedType x((int64_t)i);
    FixedType y((int64_t)j);

    auto index_a = FixedType::value_type::one();
    auto index_b = typename FixedType::value_type(2);

    // BASIC
    add_add<FixedType, ComponentType>(component, x, y);
    add_sub<FixedType, ComponentType>(component, x, y);
    add_mul_rescale<FixedType, ComponentType>(component, x, y);
    add_mul_rescale_const<FixedType, ComponentType>(component, x, y);
    if (y.get_value() != 0) {
        add_div<FixedType, ComponentType>(component, x, y);
        add_mod<FixedType, ComponentType>(component, x, y);
    }

    // CMP
    add_select<FixedType, ComponentType>(component, x, y);
    add_cmp<FixedType, ComponentType>(component, x, y);
    add_cmp_extended<FixedType, ComponentType>(component, x, y);
    add_max<FixedType, ComponentType>(component, x, y);
    add_min<FixedType, ComponentType>(component, x, y);
    add_cmp_min_max<FixedType, ComponentType>(component, x, y);
    add_range<FixedType, ComponentType>(component, x, x, y);

    // ML
    add_gather_acc<FixedType, ComponentType>(component, x, y, index_a, index_b);
    add_argmax<FixedType, ComponentType>(component, x, y, index_a, index_b);
    add_argmin<FixedType, ComponentType>(component, x, y, index_a, index_b);
}

template<typename FixedType, typename ComponentType, typename RngType>
void test_components_on_bounded_random_data(ComponentType &component, RngType &rng) {
    FixedType x(generate_bounded_random_for_fixedpoint<typename FixedType::field_type>(FixedType::M_2, rng),
                FixedType::SCALE);

    // EXP
    add_exp<FixedType, ComponentType>(component, x);
    add_exp_ranged<FixedType, ComponentType>(component, x);
    add_tanh<FixedType, ComponentType>(component, x);
}

template<typename FixedType, typename ComponentType, typename RngType>
void test_components_on_random_data(ComponentType &component, RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType y(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType z(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);

    typename FixedType::value_type integer =
        generate_random_pre_comma<typename FixedType::value_type>(FixedType::M_1, rng);

    auto index_a = generate_random_index<typename FixedType::value_type>(rng);
    auto index_b = generate_random_index<typename FixedType::value_type>(rng);
    while (index_a == index_b) {
        index_b = generate_random_index<typename FixedType::value_type>(rng);
    }

    // BASIC
    add_add<FixedType, ComponentType>(component, x, y);
    add_sub<FixedType, ComponentType>(component, x, y);
    add_rescale<FixedType, ComponentType>(component, FixedType(x.get_value() * FixedType::DELTA, FixedType::SCALE * 2));
    add_mul_rescale<FixedType, ComponentType>(component, x, y);
    add_mul_rescale_const<FixedType, ComponentType>(component, x, y);
    add_neg<FixedType, ComponentType>(component, x);
    add_int_to_fixedpoint<FixedType, ComponentType>(component, integer);
    if (y.get_value() != 0) {
        add_div<FixedType, ComponentType>(component, x, y);
        add_mod<FixedType, ComponentType>(component, x, y);
        if (y.geq_0()) {
            add_div_by_pos<FixedType, ComponentType>(component, x, y);
        } else {
            add_div_by_pos<FixedType, ComponentType>(component, x, -y);
        }
    }

    // ADVANCED
    if (x.geq_0()) {
        add_sqrt<FixedType, ComponentType>(component, x);
        add_sqrt_floor<FixedType, ComponentType>(component, x);
        if (x.get_value() != 0) {
            add_log<FixedType, ComponentType>(component, x);
        }
    } else {
        add_sqrt<FixedType, ComponentType>(component, -x);
        add_sqrt_floor<FixedType, ComponentType>(component, -x);
        if (x.get_value() != 0) {
            add_log<FixedType, ComponentType>(component, -x);
        }
    }

    // EXP
    add_exp_ranged<FixedType, ComponentType>(component, x);
    add_tanh<FixedType, ComponentType>(component, x);

    // CMP
    add_select<FixedType, ComponentType>(component, x, y);
    add_cmp<FixedType, ComponentType>(component, x, y);
    add_cmp_extended<FixedType, ComponentType>(component, x, y);
    add_max<FixedType, ComponentType>(component, x, y);
    add_min<FixedType, ComponentType>(component, x, y);
    add_cmp_min_max<FixedType, ComponentType>(component, x, y);
    add_range<FixedType, ComponentType>(component, x, y, z);

    // ML
    add_gather_acc<FixedType, ComponentType>(component, x, y, index_a, index_b);
    add_argmax<FixedType, ComponentType>(component, x, y, index_a, index_b);
    add_argmin<FixedType, ComponentType>(component, x, y, index_a, index_b);

    // TRIGON
    add_sin<FixedType, ComponentType>(component, x);
    add_cos<FixedType, ComponentType>(component, x);
}

template<typename FixedType, typename ComponentType, typename RngType>
void test_components_on_post_comma_random_data(ComponentType &component, RngType &rng) {
    FixedType x(generate_random_post_comma_for_fixedpoint<typename FixedType::value_type>(FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType y(generate_random_post_comma_for_fixedpoint<typename FixedType::value_type>(FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType z(generate_random_post_comma_for_fixedpoint<typename FixedType::value_type>(FixedType::M_2, rng),
                FixedType::SCALE);

    auto index_a = generate_random_index<typename FixedType::value_type>(rng);
    auto index_b = generate_random_index<typename FixedType::value_type>(rng);
    while (index_a == index_b) {
        index_b = generate_random_index<typename FixedType::value_type>(rng);
    }

    // BASIC
    add_add<FixedType, ComponentType>(component, x, y);
    add_sub<FixedType, ComponentType>(component, x, y);
    add_rescale<FixedType, ComponentType>(component, FixedType(x.get_value() * FixedType::DELTA, FixedType::SCALE * 2));
    add_mul_rescale<FixedType, ComponentType>(component, x, y);
    add_mul_rescale_const<FixedType, ComponentType>(component, x, y);
    add_neg<FixedType, ComponentType>(component, x);
    if (y.get_value() != 0) {
        add_div<FixedType, ComponentType>(component, x, y);
        add_mod<FixedType, ComponentType>(component, x, y);
        if (y.geq_0()) {
            add_div_by_pos<FixedType, ComponentType>(component, x, y);
        } else {
            add_div_by_pos<FixedType, ComponentType>(component, x, -y);
        }
    }

    // ADVANCED
    if (x.geq_0()) {
        add_sqrt<FixedType, ComponentType>(component, x);
        add_sqrt_floor<FixedType, ComponentType>(component, x);
        if (x.get_value() != 0) {
            add_log<FixedType, ComponentType>(component, x);
        }
    } else {
        add_sqrt<FixedType, ComponentType>(component, -x);
        add_sqrt_floor<FixedType, ComponentType>(component, -x);
        if (x.get_value() != 0) {
            add_log<FixedType, ComponentType>(component, -x);
        }
    }

    // EXP
    add_exp<FixedType, ComponentType>(component, x);
    add_exp_ranged<FixedType, ComponentType>(component, x);
    add_tanh<FixedType, ComponentType>(component, x);

    // CMP
    add_select<FixedType, ComponentType>(component, x, y);
    add_cmp<FixedType, ComponentType>(component, x, y);
    add_cmp_extended<FixedType, ComponentType>(component, x, y);
    add_max<FixedType, ComponentType>(component, x, y);
    add_min<FixedType, ComponentType>(component, x, y);
    add_cmp_min_max<FixedType, ComponentType>(component, x, y);
    add_range<FixedType, ComponentType>(component, x, y, z);

    // ML
    add_gather_acc<FixedType, ComponentType>(component, x, y, index_a, index_b);
    add_argmax<FixedType, ComponentType>(component, x, y, index_a, index_b);
    add_argmin<FixedType, ComponentType>(component, x, y, index_a, index_b);
}

template<typename FixedType, typename ComponentType>
void test_sized_components(ComponentType &component, std::size_t size) {
    std::vector<FixedType> x;
    std::vector<FixedType> y;
    x.reserve(size);
    y.reserve(size);

    for (int i = 0; i < size; i++) {
        x.push_back(FixedType((int64_t)i - 2));
    }
    for (int i = 0; i < size; i++) {
        y.push_back(FixedType((int64_t)i - 4));
    }

    // DOT PRODUCTS
    add_dot_1_gate<FixedType, ComponentType>(component, x, y);
    add_dot_2_gates<FixedType, ComponentType>(component, x, y);
}

template<typename FixedType, typename ComponentType, typename RngType>
void test_sized_components_on_random_data(ComponentType &component, RngType &rng, std::size_t size) {
    std::vector<FixedType> x;
    std::vector<FixedType> y;
    x.reserve(size);
    y.reserve(size);

    for (auto i = 0; i < size; i++) {
        x.push_back(FixedType(
            generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
            FixedType::SCALE));
        y.push_back(FixedType(
            generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
            FixedType::SCALE));
    }

    // DOT PRODUCTS
    add_dot_1_gate<FixedType, ComponentType>(component, x, y);
    add_dot_2_gates<FixedType, ComponentType>(component, x, y);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

template<typename FixedType, typename ComponentType, std::size_t RandomTestsAmount>
void field_operations_test_inner(ComponentType &component) {
    for (int i = -2; i < 3; i++) {
        test_components_unary_basic<FixedType, ComponentType>(component, i);
        for (int j = -2; j < 3; j++) {
            test_components_binary_basic<FixedType, ComponentType>(component, i, j);
        }
    }

    for (int i = 0; i < 5; i++) {
        test_components_unary_positive<FixedType, ComponentType>(component, i);
        for (int j = -2; j < 3; j++) {
            test_components_binary_one_positive<FixedType, ComponentType>(component, j, i);
        }
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_bounded_random_data<FixedType, ComponentType>(component, seed_seq);
        test_components_on_random_data<FixedType, ComponentType>(component, seed_seq);
        test_components_on_post_comma_random_data<FixedType, ComponentType>(component, seed_seq);
    }

    std::vector<std::size_t> sizes = {1, 5, 15, 50, 123};
    for (auto size : sizes) {
        test_sized_components<FixedType, ComponentType>(component, size);
        test_sized_components_on_random_data<FixedType, ComponentType>(component, seed_seq, size);
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#define macro_component_setup()                                                                                        \
    constexpr std::size_t WitnessColumns = 15;                                                                         \
    constexpr std::size_t PublicInputColumns = 1;                                                                      \
    constexpr std::size_t ConstantColumns = 30;                                                                        \
    constexpr std::size_t SelectorColumns = 70;                                                                        \
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
    using component_type =                                                                                             \
        blueprint::components::fix_tester<ArithmetizationType, BlueprintFieldType,                                     \
                                          nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;                \
                                                                                                                       \
    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};             \
                                                                                                                       \
    std::vector<std::uint32_t> witness_list;                                                                           \
    witness_list.reserve(WitnessColumns);                                                                              \
    for (auto i = 0; i < WitnessColumns; i++) {                                                                        \
        witness_list.push_back(i);                                                                                     \
    }                                                                                                                  \
    std::array<std::uint32_t, 0> public_list;                                                                          \
    std::array<std::uint32_t, blueprint::components::TESTER_MAX_CONSTANT_COLS> constant_list;                          \
    for (auto i = 0; i < blueprint::components::TESTER_MAX_CONSTANT_COLS; i++) {                                       \
        constant_list[i] = i;                                                                                          \
    }                                                                                                                  \
                                                                                                                       \
    component_type component_instance(witness_list, constant_list, public_list);

#define macro_component_run()                                                                                   \
    typename component_type::input_type instance_input = {};                                                    \
    std::vector<typename BlueprintFieldType::value_type> public_input = {};                                     \
                                                                                                                \
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>( \
        component_instance, public_input, result_check, instance_input,                                         \
        crypto3::detail::connectedness_check_type::WEAK);                                                       \
    // We do not have inputs/outputs so the weak check is sufficient

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

template<typename BlueprintFieldType, std::size_t RandomTestsAmount, uint8_t M1, uint8_t M2>
void field_operations_test() {
    macro_component_setup();

    ////////////////////////////////////////////////////////////////////////////
    // Add tests for FixedTypes
    field_operations_test_inner<FixedPoint<BlueprintFieldType, M1, M2>, component_type, RandomTestsAmount>(
        component_instance);
    ////////////////////////////////////////////////////////////////////////////

    macro_component_run();
}
#undef macro_component_setup
#undef macro_component_run

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_tester_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<field_type, random_tests_amount, 1, 1>();
    field_operations_test<field_type, random_tests_amount, 1, 2>();
    field_operations_test<field_type, random_tests_amount, 2, 1>();
    field_operations_test<field_type, random_tests_amount, 2, 2>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_tester_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<field_type, random_tests_amount, 1, 1>();
    field_operations_test<field_type, random_tests_amount, 1, 2>();
    field_operations_test<field_type, random_tests_amount, 2, 1>();
    field_operations_test<field_type, random_tests_amount, 2, 2>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_tester_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<field_type, random_tests_amount, 1, 1>();
    field_operations_test<field_type, random_tests_amount, 1, 2>();
    field_operations_test<field_type, random_tests_amount, 2, 1>();
    field_operations_test<field_type, random_tests_amount, 2, 2>();
}

BOOST_AUTO_TEST_SUITE_END()
