//---------------------------------------------------------------------------//
// Copyright (c) 2020-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_DETAIL_HPP
#define CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_DETAIL_HPP

#include <array>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/multiprecision/types/bitfield.hpp>


namespace nil {
    namespace blueprint {
        namespace detail {

            template<std::size_t... Ns>
            struct chopped_lengths_storage {
                static constexpr std::size_t values[] = {Ns...};
            };

            template<typename BlueprintFieldType, typename OperatingFieldType, typename chopped_lengths_storage>
            struct basic_non_native_policy_field_type_base {
                using non_native_field_t = OperatingFieldType;
                using native_field_t = BlueprintFieldType;
                using var_t = crypto3::zk::snark::plonk_variable<typename native_field_t::value_type>;

                static constexpr std::size_t chopped_elements_amount = sizeof(chopped_lengths_storage::values)/sizeof(std::size_t);
                static_assert(chopped_elements_amount != 0, "native_bit_lengths must be specialized for the field types");

                using chopped_value_type = std::array<typename native_field_t::value_type, chopped_elements_amount>;
                using non_native_var_t = std::array<var_t, chopped_elements_amount>;

                static chopped_value_type chop_non_native(typename non_native_field_t::value_type input) {
                    using unit_type = unsigned char;
                    nil::marshalling::status_type status;

                    std::vector<unit_type> cv = marshalling::pack<marshalling::option::big_endian>(input, status);

                    // TODO: Check status here?

                    chopping_field chopping_field_instance = marshalling::pack(input, status);

                    // TODO: Check status here?

                    auto &members = chopping_field_instance.value();
                    return convert_to_chopped_value_type(members, std::make_index_sequence<chopped_elements_amount>{});
                }

                private:
                    using be_field_base_t = marshalling::field_type<marshalling::option::big_endian>;

                    template <std::size_t bit_length>
                    using intermediate_t = crypto3::marshalling::types::pure_field_element<
                        be_field_base_t,
                        typename native_field_t::value_type,
                        marshalling::option::fixed_bit_length<bit_length>
                    >;

                    // We need to reverse the lengths, because that's how the serialization works. Fields are written from right to left
                    template <std::size_t Index>
                    using intermediate_for_index_t = intermediate_t<chopped_lengths_storage::values[chopped_elements_amount-Index-1]>;

                    template <std::size_t... Indices>
                    static constexpr std::tuple<intermediate_for_index_t<Indices>...> generate_bitfield_tuple(std::index_sequence<Indices...>) {
                        return {};
                    }

                    using chopping_field = nil::crypto3::marshalling::types::bitfield<
                        be_field_base_t,
                        decltype(generate_bitfield_tuple(std::make_index_sequence<chopped_elements_amount>{}))
                    >;

                    template <std::size_t... Indices>
                    static chopped_value_type convert_to_chopped_value_type(const typename chopping_field::value_type& members, std::index_sequence<Indices...>) {
                        return {std::get<Indices>(members).value()...};
                    }
            };

        }    // namespace detail
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_DETAIL_HPP
