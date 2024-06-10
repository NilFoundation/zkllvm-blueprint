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

#include <boost/test/unit_test.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/phoenix/phoenix.hpp>
#include <boost/random.hpp>

#include <fstream>
#include <string>
#include <chrono>
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

using namespace nil;

using boost::spirit::qi::uint_;
using boost::spirit::qi::lit;
using boost::phoenix::val;
using boost::spirit::qi::_val;
using boost::phoenix::construct;
using boost::phoenix::function;

struct prover_timing_information {
    // microseconds
    using duration_type = std::chrono::duration<double, std::ratio<1, 1000000>>;

    duration_type total_time;
    duration_type preprocessor_time;
    duration_type prover_time;
    duration_type verifier_time;
};

std::ostream& operator<<(std::ostream &os, const prover_timing_information &info) {
    os << "Total time: " << info.total_time.count() / 1000000  << "s\n";
    os << "Preprocessor time: " << info.preprocessor_time.count() / 1000000 << "s\n";
    os << "Prover time: " << info.prover_time.count() / 1000000 << "s\n";
    os << "Verifier time: " << info.verifier_time.count() / 1000000 << "s\n";
    return os;
}

struct constraints_generation_params {
    std::size_t copy_constraints_amount;
    std::size_t constraints_amount;
    std::size_t max_constraint_degree;
    std::size_t max_linear_comb_size;
};

BOOST_FUSION_ADAPT_STRUCT(
    constraints_generation_params,
    (std::size_t, copy_constraints_amount)
    (std::size_t, constraints_amount)
    (std::size_t, max_constraint_degree)
    (std::size_t, max_linear_comb_size)
)

// We use this to avoid a few problems caused by plonk_table_description_type lacking a default constructor
// parsers do not want to play nicely otherwise
template<typename BlueprintFieldType>
struct plonk_table_description_type_wrapper {
    using plonk_table_description_type = nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType>;
    plonk_table_description_type description;

    plonk_table_description_type_wrapper(const plonk_table_description_type_wrapper& other) = default;

    plonk_table_description_type_wrapper()
        : description(0, 0, 0, 0) {}

    plonk_table_description_type_wrapper(std::size_t witness_columns, std::size_t public_input_columns,
                                         std::size_t constant_columns, std::size_t selector_columns)
        : description(witness_columns, public_input_columns, constant_columns, selector_columns) {}

    plonk_table_description_type_wrapper(std::size_t witness_columns, std::size_t public_input_columns,
                                         std::size_t constant_columns, std::size_t selector_columns,
                                         std::size_t usable_rows_amount, std::size_t rows_amount)
        : description(witness_columns, public_input_columns, constant_columns, selector_columns,
                        usable_rows_amount, rows_amount) {}

    plonk_table_description_type unwrap() {
        return description;
    }
};

template<typename Iterator>
struct constraints_generation_params_parser :
        boost::spirit::qi::grammar<Iterator, constraints_generation_params(), boost::spirit::qi::ascii::space_type> {
    constraints_generation_params_parser() : constraints_generation_params_parser::base_type(start) {
        start = (lit("copy_constraints_amount:") > uint_ >
                 lit("constraints_amount:") > uint_ >
                 lit("max_constraint_degree:") > uint_ >
                 lit("max_linear_comb_size:") > uint_);
        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n"));
    }

    boost::spirit::qi::rule<Iterator, constraints_generation_params(), boost::spirit::qi::ascii::space_type> start;
};

constraints_generation_params parse_constraints_generation_params(const std::string &description) {
    boost::spirit::qi::ascii::space_type space;
    auto parser = constraints_generation_params_parser<decltype(description.cbegin())>();
    constraints_generation_params constraints_params;
    bool parsing_result =
        boost::spirit::qi::phrase_parse(
            description.cbegin(), description.cend(), parser, space, constraints_params);
    BOOST_ASSERT(parsing_result);
    return constraints_params;
}

template<typename BlueprintFieldType>
struct table_description_constructor {
    using plonk_table_description_type = plonk_table_description_type_wrapper<BlueprintFieldType>;

    typedef plonk_table_description_type result_type;

    template<typename Arg1, typename Arg2, typename Arg3, typename Arg4>
    plonk_table_description_type operator()(Arg1 witness_columns, Arg2 public_input_columns, Arg3 constant_columns,
                                            Arg4 selector_columns) const {
        return plonk_table_description_type(witness_columns, public_input_columns, constant_columns, selector_columns);
    }

    template<typename Arg1, typename Arg2, typename Arg3, typename Arg4, typename Arg5>
    plonk_table_description_type operator()(Arg1 witness_columns, Arg2 public_input_columns, Arg3 constant_columns,
                                            Arg4 selector_columns, Arg5 usable_rows_amount) const {
        return plonk_table_description_type(witness_columns, public_input_columns, constant_columns, selector_columns,
                                            usable_rows_amount, usable_rows_amount);
    }
    // just in case we might want to pass padded rows amount somehow?
    template<typename Arg1, typename Arg2, typename Arg3, typename Arg4, typename Arg5, typename Arg6>
    plonk_table_description_type operator()(Arg1 witness_columns, Arg2 public_input_columns, Arg3 constant_columns,
                                            Arg4 selector_columns, Arg5 usable_rows_amount, Arg6 rows_amount) const {
        return plonk_table_description_type(witness_columns, public_input_columns, constant_columns, selector_columns,
                                            usable_rows_amount, rows_amount);
    }
};

template<typename Iterator, typename BlueprintFieldType>
struct table_description_parser : boost::spirit::qi::grammar<Iterator,
        plonk_table_description_type_wrapper<BlueprintFieldType>(), boost::spirit::qi::ascii::space_type> {
    table_description_parser() : table_description_parser::base_type(start) {

        function<table_description_constructor<BlueprintFieldType>> table_description_constructor;
        start = (lit("witness_columns:") > uint_ >
                 lit("public_input_columns:") > uint_ >
                 lit("constant_columns:") > uint_ >
                 lit("selector_columns:") > uint_ >
                 lit("usable_rows_amount:") > uint_)
                [_val = table_description_constructor(boost::spirit::_1, boost::spirit::_2, boost::spirit::_3,
                                                      boost::spirit::_4, boost::spirit::_5)];

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, plonk_table_description_type_wrapper<BlueprintFieldType>(),
                            boost::spirit::qi::ascii::space_type> start;
};

template<typename BlueprintFieldType>
crypto3::zk::snark::plonk_table_description<BlueprintFieldType> parse_table_description(
        const std::string &description) {
    boost::spirit::qi::ascii::space_type space;
    auto parser = table_description_parser<decltype(description.cbegin()), BlueprintFieldType>();
    plonk_table_description_type_wrapper<BlueprintFieldType> table_description;
    bool parsing_result =
        boost::spirit::qi::phrase_parse(
            description.cbegin(), description.cend(), parser, space, table_description);
    BOOST_ASSERT(parsing_result);
    return table_description.unwrap();
}

template<typename BlueprintFieldType>
struct benchmarks_params_constructor {
    using plonk_table_description_type = plonk_table_description_type_wrapper<BlueprintFieldType>;
    using constraints_generation_params_type = constraints_generation_params;

    typedef boost::tuple<plonk_table_description_type, constraints_generation_params_type> result_type;

    template<typename Arg1, typename Arg2>
    boost::tuple<plonk_table_description_type, constraints_generation_params_type> operator()(
        Arg1 table_description, Arg2 constraints_params) const {
        return boost::make_tuple(table_description, constraints_params);
    }
};

template<typename Iterator, typename BlueprintFieldType>
struct benchmarks_params_parser : boost::spirit::qi::grammar<Iterator, boost::tuple<
        plonk_table_description_type_wrapper<BlueprintFieldType>, constraints_generation_params>(),
        boost::spirit::qi::ascii::space_type> {

    benchmarks_params_parser() : benchmarks_params_parser::base_type(start) {
        auto table_desc = table_description_parser<Iterator, BlueprintFieldType>();
        auto constraints_params = constraints_generation_params_parser<Iterator>();
        start = table_desc > constraints_params;

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, boost::tuple<plonk_table_description_type_wrapper<BlueprintFieldType>,
                                                   constraints_generation_params>(),
                            boost::spirit::qi::ascii::space_type> start;
};

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

template<typename BlueprintFieldType, typename HashType, std::size_t M, std::size_t Lambda>
prover_timing_information run_prover(
        crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc,
        blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
        blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments) {
    using circuit_params = typename crypto3::zk::snark::placeholder_circuit_params<BlueprintFieldType>;
    using lpc_params_type = typename nil::crypto3::zk::commitments::list_polynomial_commitment_params<
        HashType, HashType, M>;
    using commitment_type =
        typename nil::crypto3::zk::commitments::list_polynomial_commitment<BlueprintFieldType, lpc_params_type>;
    using commitment_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<commitment_type>;
    using placeholder_params_type =
        typename nil::crypto3::zk::snark::placeholder_params<circuit_params, commitment_scheme_type>;
    using fri_type = typename commitment_type::fri_type;

    prover_timing_information timing_info;

    desc.rows_amount = zk::snark::basic_padding(assignments);
    const std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params(1, table_rows_log, Lambda, 2);
    commitment_scheme_type lpc_scheme(fri_params);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    auto start = std::chrono::high_resolution_clock::now();
    typename nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
            bp, assignments.public_table(), desc, lpc_scheme, permutation_size
        );
    typename nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
            bp, assignments.private_table(), desc
        );
    timing_info.preprocessor_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start);

    auto prover_start = std::chrono::high_resolution_clock::now();
    auto proof = nil::crypto3::zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, bp, lpc_scheme
    );
    timing_info.prover_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - prover_start);
    // we actually do not care about the verification results
    // our random circuit is very unlikely to be satisfied by our random assignment
    auto verifier_start = std::chrono::high_resolution_clock::now();
    nil::crypto3::zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, bp, lpc_scheme
    );
    timing_info.verifier_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - verifier_start);

    timing_info.total_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start);

    return timing_info;
}

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
