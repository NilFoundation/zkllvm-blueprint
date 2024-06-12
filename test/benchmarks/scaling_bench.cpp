//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>=
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

#define BOOST_TEST_MODULE blueprint_scaling_benchmarks

#include <iostream>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/benchmarks/circuit_generator.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/padding.hpp>

#include "../benchmark_utils.hpp"

using namespace nil;

BOOST_AUTO_TEST_SUITE(blueprint_scaling_benchmarks_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_scaling_benchmarks_table_description_parser_test) {
    using curve_type = crypto3::algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    const std::string benchmark_description = "\
        witness_columns: 2\n\
        public_input_columns: 3\n\
        constant_columns: 4\n\
        selector_columns: 5\n\
        usable_rows_amount: 6\n";
    crypto3::zk::snark::plonk_table_description<field_type> table_description =
        parse_table_description<field_type>(benchmark_description);

    BOOST_ASSERT(table_description.witness_columns == 2);
    BOOST_ASSERT(table_description.public_input_columns == 3);
    BOOST_ASSERT(table_description.constant_columns == 4);
    BOOST_ASSERT(table_description.selector_columns == 5);
    BOOST_ASSERT(table_description.usable_rows_amount == 6);
    BOOST_ASSERT(table_description.rows_amount == table_description.usable_rows_amount);
}

BOOST_AUTO_TEST_CASE(blueprint_scaling_benchmarks_constraints_generation_params_parser_test) {
    const std::string benchmark_constraints_generation_params = "\
        copy_constraints_amount: 100500\n\
        constraints_amount: 20\n\
        max_constraint_degree: 7\n\
        max_linear_comb_size: 4\n";

    constraints_generation_params cg_params =
        parse_constraints_generation_params(benchmark_constraints_generation_params);

    BOOST_ASSERT(cg_params.copy_constraints_amount == 100500);
    BOOST_ASSERT(cg_params.constraints_amount == 20);
    BOOST_ASSERT(cg_params.max_constraint_degree == 7);
    BOOST_ASSERT(cg_params.max_linear_comb_size == 4);
}

/*BOOST_AUTO_TEST_CASE(blueprint_scaling_benchmarks_params_parser_test) {
    using curve_type = crypto3::algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    const std::string benchmark_description = "\
        witness_columns: 2\n\
        public_input_columns: 3\n\
        constant_columns: 4\n\
        selector_columns: 5\n\
        usable_rows_amount: 6\n\
        copy_constraints_amount: 100500\n\
        constraints_amount: 20\n\
        max_constraint_degree: 7\n\
        max_linear_comb_size: 4\n";

    benchmarks_params_parser<decltype(benchmark_description.cbegin()), field_type> parser;
    boost::tuple<plonk_table_description_type_wrapper<field_type>, constraints_generation_params> params;
    bool parsing_result =
        boost::spirit::qi::phrase_parse(
            benchmark_description.cbegin(), benchmark_description.cend(), parser, boost::spirit::qi::ascii::space, params);
    BOOST_ASSERT(parsing_result);
    boost::tuple<crypto3::zk::snark::plonk_table_description<field_type>, constraints_generation_params> unwrapped_params =
        {params.get<0>().unwrap(), params.get<1>()};

    BOOST_ASSERT(boost::get<0>(unwrapped_params).witness_columns == 2);
    BOOST_ASSERT(boost::get<0>(unwrapped_params).public_input_columns == 3);
    BOOST_ASSERT(boost::get<0>(unwrapped_params).constant_columns == 4);
    BOOST_ASSERT(boost::get<0>(unwrapped_params).selector_columns == 5);
    BOOST_ASSERT(boost::get<0>(unwrapped_params).usable_rows_amount == 6);
    BOOST_ASSERT(boost::get<0>(unwrapped_params).rows_amount == boost::get<0>(unwrapped_params).usable_rows_amount);

    BOOST_ASSERT(boost::get<1>(unwrapped_params).copy_constraints_amount == 100500);
    BOOST_ASSERT(boost::get<1>(unwrapped_params).constraints_amount == 20);
    BOOST_ASSERT(boost::get<1>(unwrapped_params).max_constraint_degree == 7);
    BOOST_ASSERT(boost::get<1>(unwrapped_params).max_linear_comb_size == 4);
}*/

BOOST_AUTO_TEST_CASE(blueprint_scaling_benchmarks) {
    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 2;
    constexpr std::size_t M = 2;

    const std::string benchmark_table_description = "\
        witness_columns: 150\n\
        public_input_columns: 1\n\
        constant_columns: 1\n\
        selector_columns: 4\n\
        usable_rows_amount: 6000\n";

    const std::string benchmark_constraints_generation_params = "\
        copy_constraints_amount: 10\n\
        constraints_amount: 500\n\
        max_constraint_degree: 7\n\
        max_linear_comb_size: 40\n";

    constraints_generation_params cg_params =
        parse_constraints_generation_params(benchmark_constraints_generation_params);
    const std::size_t copy_constraints_amount = cg_params.copy_constraints_amount;
    const std::size_t constraints_amount = cg_params.constraints_amount;
    const std::size_t max_constraint_degree = cg_params.max_constraint_degree;
    const std::size_t max_linear_comb_size = cg_params.max_linear_comb_size;

    boost::random::mt19937 random_engine(1444);

    crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc =
        parse_table_description<BlueprintFieldType>(benchmark_table_description);
    blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> bp;
    blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> assignments(
        desc.witness_columns, desc.public_input_columns,
        desc.constant_columns, desc.selector_columns);

    blueprint::fill_assignment_table(assignments, desc.usable_rows_amount, random_engine);
    blueprint::generate_random_copy_constraints(assignments, bp, copy_constraints_amount, random_engine);
    blueprint::generate_random_gates(
        assignments, bp, assignments.selectors_amount(), max_constraint_degree,
        max_linear_comb_size, constraints_amount, random_engine);
    blueprint::fill_selectors(assignments, bp, random_engine);
    auto timing_info = run_prover<BlueprintFieldType, hash_type, M, Lambda>(desc, bp, assignments);

    std::cout << timing_info;
}

BOOST_AUTO_TEST_SUITE_END()
