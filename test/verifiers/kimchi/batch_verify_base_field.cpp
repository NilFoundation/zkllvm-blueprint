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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"
#include "batch_scalars_data.hpp"
#include "shift_scalar.hpp"

#include <verifiers/kimchi/mina_state_proof_constants.hpp>

using namespace nil::crypto3;

template <typename BlueprintFieldType>
std::vector<typename zk::components::var_ec_point<BlueprintFieldType>> read_vector_points(
    std::vector<typename BlueprintFieldType::value_type>& public_input,
    std::string test_name,
    std::string input_filename) {

    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    std::vector<var_ec_point> output;
    var_ec_point current_point;

    std::string points_filename = "../../../../libs/blueprint/test/verifiers/kimchi/data/";
    points_filename.append(test_name).append("/").append(input_filename);

    std::ifstream point_fstream(points_filename);
    int i = 0;
    
    if (!point_fstream) {
        std::cerr <<  "cannot open " << points_filename << " file" << std::endl;
        assert(1==0 && "cannot open points file");
    }
        else{
            while (true) {
                std::string input_x;
                std::string input_y;
        
                point_fstream >> input_x >> input_y;
                if (input_x.empty() || input_y.empty()) {
                    std::cerr << "empty line in " << points_filename << "!" << std::endl;
                    break;
                }

                typename BlueprintFieldType::extended_integral_type number_x(input_x);
                assert(number_x < BlueprintFieldType::modulus && "input does not fit into BlueprintFieldType");
                
                typename BlueprintFieldType::extended_integral_type number_y(input_y);
                assert(number_y < BlueprintFieldType::modulus && "input does not fit into BlueprintFieldType");

                public_input.push_back(number_x);
                public_input.push_back(number_y);

                current_point = {
                    var(0, public_input.size() - 2, false, var::column_type::public_input),
                    var(0, public_input.size() - 1, false, var::column_type::public_input)
                };

                output.push_back(current_point);

                i++;

                if (point_fstream.eof()) {
                    break;
                }

            }
        }
    
    point_fstream.close();
    std::cout << "points amount is " << i << " in " << input_filename << std::endl;

    return output;
}


template <typename CurveType, typename BlueprintFieldType>
std::vector<zk::snark::plonk_variable<BlueprintFieldType>> read_vector_scalars(
    std::vector<typename BlueprintFieldType::value_type>& public_input,
    std::string test_name,
    std::string input_filename) {

    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    
    std::vector<var> output;

    std::string scalars_filename = "../../../../libs/blueprint/test/verifiers/kimchi/data/";
    scalars_filename.append(test_name).append("/").append(input_filename);

    std::ifstream scalars_fstream(scalars_filename);
        if (!scalars_fstream) {
            std::cerr <<  "cannot open " << scalars_filename << " file" << std::endl;
            assert(1==0 && "cannot open scalars file");
        }
        else {
            while (true) {
                std::string input_string;
        
                scalars_fstream >> input_string;
                if (input_string.empty()) {
                    std::cerr << "empty line in " << scalars_filename << "!" << std::endl;
                    break;
                }

                typename CurveType::base_field_type::extended_integral_type number(input_string);
                assert(number < CurveType::scalar_field_type::modulus && "input does not fit into BlueprintFieldType");
                public_input.push_back(shift_scalar_base<CurveType>(number));
                output.push_back(var(0, public_input.size() - 1,  false, var::column_type::public_input));

                if (scalars_fstream.eof()) {
                    break;
                }

            }
        }
    scalars_fstream.close();
    std::cout << "scalars amount: " << output.size() << " in " << input_filename << std::endl;

    return output;
}


BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_batch_verify_base_field_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_batch_verify_base_field_test_generic_rs) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t comm_size = 1;

    constexpr static std::size_t public_input_size = generic_constants.public_input_size;
    constexpr static std::size_t max_poly_size = generic_constants.max_poly_size;
    constexpr static std::size_t eval_rounds = generic_constants.eval_rounds;

    constexpr static std::size_t witness_columns = generic_constants.witness_columns;
    constexpr static std::size_t perm_size = generic_constants.perm_size;

    constexpr static std::size_t srs_len = generic_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = generic_constants.prev_chal_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_generic_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);

    using component_type = zk::components::batch_verify_base_field<ArithmetizationType,
                                                                   curve_type,
                                                                   kimchi_params,
                                                                   commitment_params,
                                                                   batch_size,
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

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    // using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType,
    //                                 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
    //                                 W11, W12, W13, W14>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using batch_proof_type = typename zk::components::
        batch_evaluation_proof_base<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>;

    std::size_t row = 0;

    std::cout << "batch_verify_base_field test on data from generic.rs" << std::endl;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    var_ec_point H_var = read_vector_points<BlueprintFieldType>(public_input, "generic", "h_points.txt")[0];
    var_ec_point op_proof_g_var = read_vector_points<BlueprintFieldType>(public_input, "generic", "opening_sg.txt")[0];
    var_ec_point delta_var = read_vector_points<BlueprintFieldType>(public_input, "generic", "delta.txt")[0];

    std::vector <var_ec_point> G_var = read_vector_points<BlueprintFieldType>(public_input, "generic", "g_points.txt");
    std::vector <var_ec_point> L_vector = read_vector_points<BlueprintFieldType>(public_input, "generic", "l_points.txt");
    std::vector <var_ec_point> R_vector = read_vector_points<BlueprintFieldType>(public_input, "generic", "r_points.txt");
    std::vector <var_ec_point> commitments = read_vector_points<BlueprintFieldType>(public_input, "generic", "commitments.txt");
    
    std::vector<var> scalars_var  = read_vector_scalars<curve_type, BlueprintFieldType>(public_input, "generic", "scalars.txt");

    curve_type::base_field_type::value_type cip_shifted = 0x0877E225F785892E118B95754A625F1D008505745AF6E4B174D07168343CB13A_cppui256;
    public_input.push_back(cip_shifted);
    var cip_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state0 = 0x08C6DB20754B2277C8D16895B976293798DD898B19D348D4CDA80AE41B836A67_cppui256;
    public_input.push_back(state0);
    var state0_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state1 = 0x11EF8F246F63C43E46E22BC179C7171A3F2A9776AC62E5C488C482403FB00E07_cppui256;
    public_input.push_back(state1);
    var state1_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state2 = 0x3A44A14684FEA941DA87BFF86D42E61EC587BB5F7A33DC36B2C5324416FA8715_cppui256;
    public_input.push_back(state2);
    var state2_var = var(0, public_input.size() - 1, false, var::column_type::public_input);


    typename component_type::params_type params;
 
    for (std::size_t i = 0; i < commitments.size(); i++){
        params.proofs[0].comm[i].parts[0] = commitments[i];
    }
    for (std::size_t i = 0; i < eval_rounds; i++){
        params.proofs[0].opening_proof.L[i] = L_vector[i];
        params.proofs[0].opening_proof.R[i] = R_vector[i];
    }
    params.proofs[0].opening_proof.G = op_proof_g_var;
    params.verifier_index.H = H_var;
    params.verifier_index.G = G_var;
    params.fr_output.scalars = scalars_var;
    params.proofs[0].opening_proof.delta = delta_var;
    params.fr_output.cip_shifted[0] = cip_var;
    params.proofs[0].transcript.sponge.state[0] = state0_var;
    params.proofs[0].transcript.sponge.state[1] =  state1_var;
    params.proofs[0].transcript.sponge.state[2] =  state2_var;



    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {
        std::cout << "batch_verify_base_field_res: " << assignment.var_value(real_res.output.X).data << " " << assignment.var_value(real_res.output.Y).data << std::endl;
        assert (assignment.var_value(real_res.output.X) == 0);
        assert (assignment.var_value(real_res.output.Y) == 0);
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
};

BOOST_AUTO_TEST_CASE(blueprint_plonk_batch_verify_base_field_test_ec_rs) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t comm_size = 1;

    constexpr static std::size_t public_input_size =    ec_constants.public_input_size;
    constexpr static std::size_t max_poly_size =        ec_constants.max_poly_size;
    constexpr static std::size_t eval_rounds =          ec_constants.eval_rounds;

    constexpr static std::size_t witness_columns =      ec_constants.witness_columns;
    constexpr static std::size_t perm_size =            ec_constants.perm_size;

    constexpr static std::size_t srs_len =              ec_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = ec_constants.prev_chal_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);

    using component_type = zk::components::batch_verify_base_field<ArithmetizationType,
                                                                   curve_type,
                                                                   kimchi_params,
                                                                   commitment_params,
                                                                   batch_size,
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

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    // using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType,
    //                                 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
    //                                 W11, W12, W13, W14>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using batch_proof_type = typename zk::components::
        batch_evaluation_proof_base<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>;

    std::cout << "batch_verify_base_field test on data from ec.rs" << std::endl;
    std::vector<typename BlueprintFieldType::value_type> public_input;

    var_ec_point H_var = read_vector_points<BlueprintFieldType>(public_input, "ec", "h_points.txt")[0];
    var_ec_point op_proof_g_var = read_vector_points<BlueprintFieldType>(public_input, "ec", "opening_sg.txt")[0];
    var_ec_point delta_var = read_vector_points<BlueprintFieldType>(public_input, "ec", "delta.txt")[0];

    std::vector <var_ec_point> G_var = read_vector_points<BlueprintFieldType>(public_input, "ec", "g_points.txt");
    std::vector <var_ec_point> L_vector = read_vector_points<BlueprintFieldType>(public_input, "ec", "l_points.txt");
    std::vector <var_ec_point> R_vector = read_vector_points<BlueprintFieldType>(public_input, "ec", "r_points.txt");
    std::vector <var_ec_point> commitments = read_vector_points<BlueprintFieldType>(public_input, "ec", "commitments.txt");
    
    std::vector<var> scalars_var  = read_vector_scalars<curve_type, BlueprintFieldType>(public_input, "ec", "scalars.txt");

    curve_type::base_field_type::value_type cip_shifted = 0x3AA52C0B2BC507CEC6CEEDBFD2C02B9C74CFA1043847011BA789D6F871201A52_cppui256; // ec
    public_input.push_back(cip_shifted);
    var cip_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state0 = 0x176FDD22E886DEF7D57620F5982A9902CE60C696BB2745745A9BCC5ECEEE3AE5_cppui256; // ec
    public_input.push_back(state0);
    var state0_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state1 = 0x0ACB65E0765F80498D643313EAAEBFBC7899766A4A337EAF61261344E8C2C551_cppui256; // ec
    public_input.push_back(state1);
    var state1_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state2 = 0x1AA5199A2E6814DAC6759D5B55B3DF040BBE77EB9A0A00DD42925803CE370BC1_cppui256; // ec
    public_input.push_back(state2);
    var state2_var = var(0, public_input.size() - 1, false, var::column_type::public_input);



    typename component_type::params_type params;
 
    for (std::size_t i = 0; i < commitments.size(); i++){
        params.proofs[0].comm[i].parts[0] = commitments[i];
    }
    for (std::size_t i = 0; i < eval_rounds; i++){
        params.proofs[0].opening_proof.L[i] = L_vector[i];
        params.proofs[0].opening_proof.R[i] = R_vector[i];
    }
    params.proofs[0].opening_proof.G = op_proof_g_var;
    params.verifier_index.H = H_var;
    params.verifier_index.G = G_var;
    params.fr_output.scalars = scalars_var;
    params.proofs[0].opening_proof.delta = delta_var;
    params.fr_output.cip_shifted[0] = cip_var;
    params.proofs[0].transcript.sponge.state[0] = state0_var;
    params.proofs[0].transcript.sponge.state[1] =  state1_var;
    params.proofs[0].transcript.sponge.state[2] =  state2_var;



    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {
        std::cout << "batch_verify_base_field_res: " << assignment.var_value(real_res.output.X).data << " " << assignment.var_value(real_res.output.Y).data << std::endl;
        assert (assignment.var_value(real_res.output.X) == 0);
        assert (assignment.var_value(real_res.output.Y) == 0);
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
};

BOOST_AUTO_TEST_CASE(blueprint_plonk_batch_verify_base_field_test_chacha_rs) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static std::size_t public_input_size =    chacha_constants.public_input_size;
    constexpr static std::size_t max_poly_size =        chacha_constants.max_poly_size;
    constexpr static std::size_t eval_rounds =          chacha_constants.eval_rounds;

    constexpr static std::size_t witness_columns =      chacha_constants.witness_columns;
    constexpr static std::size_t perm_size =            chacha_constants.perm_size;

    constexpr static std::size_t srs_len =              chacha_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = chacha_constants.prev_chal_size;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t comm_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_chacha_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);

    using component_type = zk::components::batch_verify_base_field<ArithmetizationType,
                                                                   curve_type,
                                                                   kimchi_params,
                                                                   commitment_params,
                                                                   batch_size,
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

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    // using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType,
    //                                 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
    //                                 W11, W12, W13, W14>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using batch_proof_type = typename zk::components::
        batch_evaluation_proof_base<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>;


    std::cout << "batch_verify_base_field test on data from chacha.rs" << std::endl;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    var_ec_point H_var = read_vector_points<BlueprintFieldType>(public_input, "chacha", "h_points.txt")[0];
    var_ec_point op_proof_g_var = read_vector_points<BlueprintFieldType>(public_input, "chacha", "opening_sg.txt")[0];
    var_ec_point delta_var = read_vector_points<BlueprintFieldType>(public_input, "chacha", "delta.txt")[0];

    std::vector <var_ec_point> G_var = read_vector_points<BlueprintFieldType>(public_input, "chacha", "g_points.txt");
    std::vector <var_ec_point> L_vector = read_vector_points<BlueprintFieldType>(public_input, "chacha", "l_points.txt");
    std::vector <var_ec_point> R_vector = read_vector_points<BlueprintFieldType>(public_input, "chacha", "r_points.txt");
    std::vector <var_ec_point> commitments = read_vector_points<BlueprintFieldType>(public_input, "chacha", "commitments.txt");
    
    std::vector<var> scalars_var  = read_vector_scalars<curve_type, BlueprintFieldType>(public_input, "chacha", "scalars.txt");

    curve_type::base_field_type::value_type cip_shifted = 0x1C46F778300ED8499E12AC99920C8F426C59D3E94CCDD17941523412F6574A93_cppui256;
    public_input.push_back(cip_shifted);
    var cip_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
    
    curve_type::base_field_type::value_type state0 = 0x1CA18F11BE5840BDC7700504D8D7F7A075682BC2C8E8E561028A9B44CB52E0AB_cppui256;
    public_input.push_back(state0);
    var state0_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state1 = 0x2C85FCC264A1C8E1082E97E5686196CB1A7EF642F7B162EB21723CCCB6344341_cppui256;
    public_input.push_back(state1);
    var state1_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state2 = 0x221A064E37C3EE4CD60EAF94EAA8001F84D625A2E608B7CCC49CC05C6C5B4A24_cppui256;
    public_input.push_back(state2);
    var state2_var = var(0, public_input.size() - 1, false, var::column_type::public_input);



    typename component_type::params_type params;
 
    for (std::size_t i = 0; i < commitments.size(); i++){
        params.proofs[0].comm[i].parts[0] = commitments[i];
    }
    for (std::size_t i = 0; i < eval_rounds; i++){
        params.proofs[0].opening_proof.L[i] = L_vector[i];
        params.proofs[0].opening_proof.R[i] = R_vector[i];
    }
    params.proofs[0].opening_proof.G = op_proof_g_var;
    params.verifier_index.H = H_var;
    params.verifier_index.G = G_var;
    params.fr_output.scalars = scalars_var;
    params.proofs[0].opening_proof.delta = delta_var;
    params.fr_output.cip_shifted[0] = cip_var;
    params.proofs[0].transcript.sponge.state[0] = state0_var;
    params.proofs[0].transcript.sponge.state[1] =  state1_var;
    params.proofs[0].transcript.sponge.state[2] =  state2_var;

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {
        std::cout << "batch_verify_base_field_res: " << assignment.var_value(real_res.output.X).data << " " << assignment.var_value(real_res.output.Y).data << std::endl;
        assert (assignment.var_value(real_res.output.X) == 0);
        assert (assignment.var_value(real_res.output.Y) == 0);
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
};

BOOST_AUTO_TEST_SUITE_END()