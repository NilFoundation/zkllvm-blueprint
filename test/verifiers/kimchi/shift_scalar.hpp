#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

template <typename CurveType>
struct shift_params;

template<>
struct shift_params<nil::crypto3::algebra::curves::pallas> {
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type shift_base = 2;
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type shift_for_1_0_neg1 = shift_base.pow(255) + 1;
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type denominator_for_1_0_neg1 = 2;
};

template<>
struct shift_params<nil::crypto3::algebra::curves::vesta> {
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type shift_base = 2;
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type shift_for_1_0_neg1 = shift_base.pow(255);
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type denominator_for_1_0_neg1 = 1;
};

template<typename CurveType>
typename CurveType::base_field_type::value_type shift_scalar_base(typename CurveType::scalar_field_type::value_type unshifted) {
	typename CurveType::scalar_field_type::value_type shift_base = 2;
	typename CurveType::scalar_field_type::value_type shift = shift_base.pow(255) + 1;
	typename CurveType::scalar_field_type::value_type denominator = 2;

	typename CurveType::scalar_field_type::value_type shift_for_1_0_neg1 =  shift_params<CurveType>::shift_for_1_0_neg1;
	typename CurveType::scalar_field_type::value_type denominator_for_1_0_neg1 =  shift_params<CurveType>::denominator_for_1_0_neg1;

	typename CurveType::scalar_field_type::value_type shifted;

	if ((unshifted == 1) || (unshifted == 0) || (unshifted == -1)){
		shifted = (unshifted - shift_for_1_0_neg1) / denominator_for_1_0_neg1;
	}
	else {
		shifted = (unshifted - shift) / denominator;
	}

	typename CurveType::scalar_field_type::integral_type shifted_integral_type = typename CurveType::scalar_field_type::integral_type(shifted.data);
	typename CurveType::base_field_type::value_type shifted_base_value_type = shifted_integral_type;
	return shifted_base_value_type;
}

template<typename CurveType>
typename CurveType::scalar_field_type::value_type shift_scalar_scalar(typename CurveType::scalar_field_type::value_type unshifted) {
	typename CurveType::scalar_field_type::value_type shift_base = 2;
	typename CurveType::scalar_field_type::value_type shift = shift_base.pow(255) + 1;
	typename CurveType::scalar_field_type::value_type denominator = 2;

	typename CurveType::scalar_field_type::value_type shift_for_1_0_neg1 =  shift_params<CurveType>::shift_for_1_0_neg1;
	typename CurveType::scalar_field_type::value_type denominator_for_1_0_neg1 =  shift_params<CurveType>::denominator_for_1_0_neg1;

	typename CurveType::scalar_field_type::value_type shifted;

	if ((unshifted == 1) || (unshifted == 0) || (unshifted == -1)){
		shifted = (unshifted - shift_for_1_0_neg1) / denominator_for_1_0_neg1;
	}
	else {
		shifted = (unshifted - shift) / denominator;
	}

    return shifted;
}





// template <typename CurveType>
// typename CurveType::base_field_type::value_type shift_scalar_base(typename CurveType::scalar_field_type::value_type input) { 
//     typename CurveType::scalar_field_type::value_type base = 2;
//     if ((input != 1) & (input != 0) & (input != -1)){
//         input = (input - base.pow(255) - 1) / 2;
//     } else {
//         input = input - base.pow(255);
//     }
//     typename CurveType::scalar_field_type::integral_type integral_scalar = typename CurveType::scalar_field_type::integral_type(input.data);
//     typename CurveType::base_field_type::value_type base_scalar = integral_scalar;
//     return base_scalar;
// }


// template <typename CurveType>
// typename CurveType::scalar_field_type::value_type shift_scalar_scalar(typename CurveType::scalar_field_type::value_type input) { 
//     typename CurveType::scalar_field_type::value_type base = 2;
//     if ((input != 1) & (input != 0) & (input != -1)){
//         input = (input - base.pow(255) - 1) / 2;
//     } else {
//         input = input - base.pow(255);
//     }
//     return input;
// }