
template <typename CurveType>
typename CurveType::base_field_type::value_type shift_scalar_base(typename CurveType::scalar_field_type::value_type input) { 
    typename CurveType::scalar_field_type::value_type base = 2;
    if ((input != 1) & (input != 0) & (input != -1)){
        input = (input - base.pow(255) - 1) / 2;
    } else {
        input = input - base.pow(255);
    }
    typename CurveType::scalar_field_type::integral_type integral_scalar = typename CurveType::scalar_field_type::integral_type(input.data);
    typename CurveType::base_field_type::value_type base_scalar = integral_scalar;
    return base_scalar;
}


template <typename CurveType>
typename CurveType::scalar_field_type::value_type shift_scalar_scalar(typename CurveType::scalar_field_type::value_type input) { 
    typename CurveType::scalar_field_type::value_type base = 2;
    if ((input != 1) & (input != 0) & (input != -1)){
        input = (input - base.pow(255) - 1) / 2;
    } else {
        input = input - base.pow(255);
    }
    return input;
}