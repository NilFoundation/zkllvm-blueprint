//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_private_input_extractor_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>

#include <nil/blueprint/private_input_extractor.hpp>

#include "test_plonk_component.hpp"

using namespace nil;


BOOST_AUTO_TEST_CASE(blueprint_plonk_private_input_test) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<field_type>;
    zk::snark::plonk_table_description<field_type> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;

    using component_type = blueprint::components::addition<ArithmetizationType, field_type,
                                                           nil::blueprint::basic_non_native_policy<field_type>>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input),
        var(0, 1, false, var::column_type::public_input)
    };

    component_type component_instance({0, 1, 2}, {}, {});

    auto unopt = nil::blueprint::input_assignment_variables<field_type, component_type>(
        component_instance, desc, instance_input, 3);
    BOOST_ASSERT(unopt.size() == 2);
    BOOST_ASSERT(unopt.count(instance_input.x) == 1);
    BOOST_ASSERT(unopt.count(instance_input.y) == 1);
    BOOST_ASSERT(unopt[instance_input.x] == var(0, 3, false, var::column_type::witness));
    BOOST_ASSERT(unopt[instance_input.y] == var(1, 3, false, var::column_type::witness));
}
