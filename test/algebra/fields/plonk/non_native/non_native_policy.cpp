#define BOOST_TEST_MODULE blueprint_algebra_fields_plonk_non_native_non_native_policy_test

#include <iostream>

#include <boost/test/unit_test.hpp>

#include <nil/blueprint/basic_non_native_policy.hpp>
#include <../test/algebra/fields/plonk/non_native/glue_non_native.hpp>

using namespace nil;

template<typename NativeFieldType, typename NonNativeFieldType>
void test_chopping(const typename NonNativeFieldType::value_type &non_native_field_el) {
    using non_native_policy_type =
        blueprint::detail::basic_non_native_policy_field_type<NativeFieldType, NonNativeFieldType>;
    using chunked_non_native_type = typename non_native_policy_type::chopped_value_type;

    auto chopping_result = non_native_policy_type::chop_non_native(non_native_field_el);
    std::cout << std::hex;

    for (std::size_t i = 0; i < 4; i++) {
        std::cout << chopping_result[i].data << " ";
    }

    assert((glue_non_native<NativeFieldType, NonNativeFieldType>(chopping_result)) == non_native_field_el);
}

BOOST_AUTO_TEST_SUITE(blueprint_non_native_policy_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_policy_25519) {
    using non_native_field_type = typename crypto3::algebra::curves::ed25519::base_field_type;
    using native_field_type = crypto3::algebra::curves::pallas::base_field_type;
    test_chopping<native_field_type, non_native_field_type>(0x0);
    test_chopping<native_field_type, non_native_field_type>(
        0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c_cppui252);
    test_chopping<native_field_type, non_native_field_type>(
        0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853_cppui252);
    test_chopping<native_field_type, non_native_field_type>(
        0x2ad46cbfb78773b6254adc1d80c6efa02f3bf948c37e5a2222136421d7bec942_cppui252);
    test_chopping<native_field_type, non_native_field_type>(
        0x14e9693f16d75f7065ce51e1f46ae6c60841ca1e0cf264eda26398e36ca2ed69_cppui252);
    test_chopping<native_field_type, non_native_field_type>(non_native_field_type::modulus - 1);
}

BOOST_AUTO_TEST_SUITE_END()
