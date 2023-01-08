//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_batch_verify_base_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
//#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/assignment/plonk.hpp>
#include <nil/blueprint_mc/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/detail/table_commitment.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/blueprint_mc/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/lookup_test.hpp"

#include "test_plonk_component_mc.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_table_commitment_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_table_commitment_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using ScalarFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint_mc::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t eval_rounds = 1;
    constexpr static const std::size_t comm_size = 1;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;

    constexpr static std::size_t witness_columns = 5;
    constexpr static std::size_t perm_size = 5;

    constexpr static std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = nil::blueprint_mc::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = nil::blueprint_mc::components::index_terms_scalars_list_lookup_test<ArithmetizationType>;
    using circuit_description = nil::blueprint_mc::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using KimchiParamsType = nil::blueprint_mc::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using commitment_type = typename 
                        nil::blueprint_mc::components::kimchi_commitment_type<BlueprintFieldType, 
                            KimchiParamsType::commitment_params_type::shifted_commitment_split>;
    using kimchi_constants = nil::blueprint_mc::components::kimchi_inner_constants<KimchiParamsType>;

    using component_type = nil::blueprint_mc::components::table_commitment<ArithmetizationType,
                                                                   KimchiParamsType,
                                                                   curve_type,
                                                                   0,
                                                                   1,
                                                                   2,
                                                                   3,
                                                                   4,
                                                                   5,
                                                                   6,
                                                                   7,
                                                                   8,
                                                                   9,
                                                                   10,
                                                                   11,
                                                                   12,
                                                                   13,
                                                                   14>;
    using var_ec_point = typename nil::blueprint_mc::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static const std::size_t lookup_columns = KimchiParamsType::circuit_params::lookup_columns;

    constexpr std::size_t use_lookup_runtime = KimchiParamsType::circuit_params::lookup_runtime ? 1 : 0; 

    // zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    std::vector<typename BlueprintFieldType::value_type> public_input;
    std::vector<commitment_type> lookup_columns_var;
    std::array<var, lookup_columns> lookup_scalars_var;
    commitment_type runtime_var;
    std::size_t j = 0;
    std::size_t split_size = KimchiParamsType::commitment_params_type::shifted_commitment_split;

    std::array<typename BlueprintFieldType::value_type, lookup_columns> table_x; // commitments from PolyComm::multi_scalar_mul(&commitments, &scalars) https://github.com/NilFoundation/o1-labs-proof-systems/blob/master/kimchi/src/circuits/lookup/tables/mod.rs#L136
    std::array<typename BlueprintFieldType::value_type, lookup_columns> table_y;

    table_x[0] = 0x277BDD3B233EA5EB80EAAE059B87B9FC730CC6FBAC8BB3C3A8B37F81BC1432F9_cppui256;
    table_y[0] = 0x28E3C2C6FE5F4986D4BA82F33E3A8042BADAEEDB0F029A597F97242DEC238AD0_cppui256;
    table_x[1] = 0x098AF79386D7BB3F4E30A6A4892011EF516DA03D5A4A52F48590433A56AFA945_cppui256;
    table_y[1] = 0x00971880CEDCE9CA26D693B377CF1388F003246050D2C37647A38E255929F630_cppui256;
    table_x[2] = 0x227D843831934787019F8D1D37CBBFBE4374A068CED7466DCF9DC92F1B1DD344_cppui256;
    table_y[2] = 0x307EAB146623927E242AF38331A7A9287BEE6502B940F0681B7F38AF1D5599F9_cppui256;

    for (std::size_t i = j; i < lookup_columns; i++){
        commitment_type column_var;
        for (std::size_t k = 0; k < split_size; k++) {
            // public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().X);
            // public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().Y);
            public_input.push_back(table_x[i]);
            public_input.push_back(table_y[i]);
            
            column_var.parts[k] = {
                var(0, j, false, var::column_type::public_input),
                var(0, j + 1, false, var::column_type::public_input)
            };
            j+=2;
        }
        lookup_columns_var.push_back(column_var);
    }

    if (KimchiParamsType::circuit_params::lookup_runtime){
        for (std::size_t k = 0; k < split_size; k++) {
            public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().X);
            public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().Y);
            runtime_var.parts[k] = {
                var(0, j, false, var::column_type::public_input),
                var(0, j + 1, false, var::column_type::public_input)
            };
            j+=2;
        }
    }

    std::array<typename curve_type::scalar_field_type::value_type, 3> unprepared_lookup_scalars_data; // scalars from PolyComm::multi_scalar_mul(&commitments, &scalars) https://github.com/NilFoundation/o1-labs-proof-systems/blob/master/kimchi/src/circuits/lookup/tables/mod.rs#L136
    unprepared_lookup_scalars_data[0] = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;
    unprepared_lookup_scalars_data[1] = 0x20E959472C74FBEA783D62870B979033E1BD490EDF01DD51D69F4C89B52DAA3B_cppui256;
    unprepared_lookup_scalars_data[2] = 0x244DCFC9E49D7EF7EE803233A777F72016706EDB1534F75F4F9561FF4EB23255_cppui256;

    std::array<typename BlueprintFieldType::value_type, lookup_columns> lookup_scalars_data;
    lookup_scalars_data[0] = 0x448d31f81299f237325a61da00000003_cppui256;  // (unprepared[0] - 2^255)
    lookup_scalars_data[1] = 0x1074aca3963a7df53c1eb14385cbc81a13253d8378cde7c4847cd731da96d51e_cppui256;  // (unprepared[1] - 2^255 - 1) / 2
    lookup_scalars_data[2] = 0x1226e7e4f24ebf7bf7401919d3bbfb902d7ed06993e774cb40f7e1eca759192b_cppui256;  // (unprepared[2] - 2^255 - 1) / 2

    std::size_t s = lookup_columns + j;
    std::size_t lookup_scalars_iter = 0;
    for (std::size_t i = j; i < s; i++){
        // public_input.push_back(algebra::random_element<curve_type::base_field_type>());
        public_input.push_back(lookup_scalars_data[lookup_scalars_iter]);
        lookup_scalars_var[lookup_scalars_iter] = (var(0, i, false, var::column_type::public_input));
        j++;
        lookup_scalars_iter++;
    }

    typename component_type::params_type params = {lookup_columns_var, lookup_scalars_var, runtime_var};

    std::array<typename BlueprintFieldType::value_type, 4> expected_result;
    expected_result[0] = 0x1F74B3087CCB2064D2F9ED4552E7D2A794CA42687528D777F6B18A5D8B63EDC1_cppui256; // rust X for input 1, j, j^2
    expected_result[1] = 0x03FD6EC26748E1B5C7AFBF50C4C250217D2AA2A343F94C174FE0BEF28608277C_cppui256; // rust y for input 1, j, j^2

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T0;
    T0.X = table_x[0];
    T0.Y = table_y[0];
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T1;
    T1.X = table_x[1];
    T1.Y = table_y[1];
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T2;
    T2.X = table_x[2];
    T2.Y = table_y[2];
    
    expected_result[2] = (unprepared_lookup_scalars_data[0]*T0 + unprepared_lookup_scalars_data[1]*T1 + unprepared_lookup_scalars_data[2]*T2).X;
    expected_result[3] = (unprepared_lookup_scalars_data[0]*T0 + unprepared_lookup_scalars_data[1]*T1 + unprepared_lookup_scalars_data[2]*T2).Y;

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result[0] == expected_result[2]);                      // rust x == expected x
        assert(expected_result[1] == expected_result[3]);                      // rust y == expected y
        assert(expected_result[2] == assignment.var_value(real_res.output.X)); // expected x = real x
        assert(expected_result[3] == assignment.var_value(real_res.output.Y)); // expected x = real x
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
};
BOOST_AUTO_TEST_SUITE_END()