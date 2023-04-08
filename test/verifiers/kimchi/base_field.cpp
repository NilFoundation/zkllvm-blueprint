//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_base_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
//#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>

#include "test_plonk_component.hpp"
#include "verifiers/kimchi/index_terms_instances/generic_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/recursion_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_index_terms.hpp"

#include "shift_scalar.hpp"
#include <verifiers/kimchi/mina_state_proof_constants.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_base_field_test_suite)

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

                if (point_fstream.eof()) {
                    break;
                }
                i++;

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

template<typename BlueprintFieldType, typename params_type, typename var, typename var_ec_point,
typename commitment_type, typename commitment_t_type, typename CurveType, typename commitment_params,
typename circuit_description, typename kimchi_constants, typename KimchiParamsType>
void fill_params_verify_base(
    std::vector<typename BlueprintFieldType::value_type>& public_input,
    params_type& params,
    std::string current_testname) {

    std::vector<var> scalars_var  = read_vector_scalars<CurveType, BlueprintFieldType>(public_input, current_testname, "scalars.txt");

    var cip_var;
    std::vector<var> cip_vector = read_vector_scalars<CurveType, BlueprintFieldType>(public_input, current_testname, "cip.txt");
    cip_var = cip_vector[0];

    std::vector<var> neg_pub = read_vector_scalars<CurveType, BlueprintFieldType>(public_input, current_testname, "neg_pub.txt");

    std::vector<var> zeta_to_srs_len_vector = read_vector_scalars<CurveType, BlueprintFieldType>(public_input, current_testname, "zeta_to_srs_len.txt");
    var zeta_to_srs_len_var  = zeta_to_srs_len_vector[0];

    std::vector<var> zeta_to_domain_size_minus_one_vector = read_vector_scalars<CurveType, BlueprintFieldType>(
        public_input, current_testname, "zeta_to_domain_size_minus_1.txt");
    var zeta_to_domain_size_minus_1_var = zeta_to_domain_size_minus_one_vector[0];

    std::vector<typename zk::components::var_ec_point<BlueprintFieldType>> witness_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "witness_comm.txt");
    std::vector<commitment_type> witness_comm = std::vector<commitment_type> (circuit_description::witness_columns);
    for (std::size_t i = 0; i < witness_comm.size(); i++) {witness_comm[i].parts[0] = witness_comm_vector[i];}

    commitment_type z_comm;
    std::vector <var_ec_point> z_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "z_comm.txt");
    z_comm.parts[0] = z_comm_vector[0];

    std::array<commitment_type, KimchiParamsType::prev_challenges_size> prev_chal;
    std::vector <var_ec_point> prev_chal_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "prev_chal.txt");
    for (std::size_t i = 0; i < KimchiParamsType::prev_challenges_size; i++) {
        prev_chal[i].parts[0] = prev_chal_vector[i];
    }

    commitment_t_type t_comm;
    std::vector <var_ec_point> t_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "t_comm.txt");
    for (std::size_t i = 0; i < commitment_params::t_comm_size; i++) {t_comm.parts[i] = t_comm_vector[i];}

    std::array<var_ec_point, commitment_params::eval_rounds> L_var;
    std::vector<typename zk::components::var_ec_point<BlueprintFieldType>> L_var_points = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "l_points.txt");
    for (std::size_t i = 0; i < commitment_params::eval_rounds; i++) {L_var[i] = L_var_points[i];}

    std::array<var_ec_point, commitment_params::eval_rounds> R_var;
    std::vector<typename zk::components::var_ec_point<BlueprintFieldType>> R_var_points = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "r_points.txt");
    for (std::size_t i = 0; i < commitment_params::eval_rounds; i++) {R_var[i] = R_var_points[i];}

    std::vector <var_ec_point> delta_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "delta.txt");
    var_ec_point delta_var = delta_vector[0];

    std::vector <var_ec_point> op_proof_g_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "opening_sg.txt");
    var_ec_point op_proof_g_var = op_proof_g_vector[0];

    std::vector<var> f_comm_scalars_vector  = read_vector_scalars<CurveType, BlueprintFieldType>(public_input, current_testname, "f_comm_scalars_part_1.txt");
    std::vector<var> f_comm_scalars_part_2_vector  = read_vector_scalars<CurveType, BlueprintFieldType>(public_input, current_testname, "f_comm_scalars_part_2.txt");
    f_comm_scalars_vector.insert(f_comm_scalars_vector.end(), f_comm_scalars_part_2_vector.begin(), f_comm_scalars_part_2_vector.end());
    assert(f_comm_scalars_vector.size() == kimchi_constants::f_comm_msm_size);


    std::vector <var_ec_point> H_var_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "h_points.txt");
    var_ec_point H_var = H_var_vector[0];

    std::vector <var_ec_point> G_var = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "g_points.txt");

    std::vector<var_ec_point> lagrange_bases_var = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "lagrange_bases.txt"); // len = public_input_size

    std::array<commitment_type, circuit_description::permut_size> sigma_comm_var;
    std::vector<typename zk::components::var_ec_point<BlueprintFieldType>> sigma_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "sigma_comm.txt");
    for (std::size_t i = 0; i < circuit_description::permut_size; i++) {sigma_comm_var[i].parts[0] = sigma_comm_vector[i];}

    std::array<commitment_type, circuit_description::witness_columns> coefficient_comm_var;
    std::vector<typename zk::components::var_ec_point<BlueprintFieldType>> coefficient_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "coefficient_comm.txt");
    for (std::size_t i = 0; i < coefficient_comm_var.size(); i++) {coefficient_comm_var[i].parts[0] = coefficient_comm_vector[i];}

    commitment_type generic_comm;
    std::vector<var_ec_point> generic_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "generic_comm.txt");
    generic_comm.parts[0] = generic_comm_vector[0];

    commitment_type psm_comm;
    std::vector<var_ec_point> psm_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "psm_comm.txt");
    psm_comm.parts[0] = psm_comm_vector[0];

    commitment_type complete_add_comm;
    std::vector<var_ec_point> complete_add_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "complete_add_comm.txt");
    complete_add_comm.parts[0] = complete_add_comm_vector[0];

    commitment_type mul_comm;
    std::vector<var_ec_point> mul_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "mul_comm.txt");
    mul_comm.parts[0] = mul_comm_vector[0];

    commitment_type emul_comm;
    std::vector<var_ec_point> emul_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "emul_comm.txt");
    emul_comm.parts[0] = emul_comm_vector[0];

    commitment_type endomul_scalar_comm;
    std::vector<var_ec_point> endomul_scalar_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "endomul_scalar_comm.txt");
    endomul_scalar_comm.parts[0] = endomul_scalar_comm_vector[0];

    std::array<commitment_type, 4> chacha_comm;
    std::vector<var_ec_point> chacha_comm_vector = read_vector_points<BlueprintFieldType>(
        public_input, current_testname, "chacha_comm.txt");
    for (std::size_t i = 0; i < 4; i++) {chacha_comm[i].parts[0] = chacha_comm_vector[i];}
    
        // params.fr_data //
    params.fr_data.scalars = scalars_var;
    // params.fr_data.f_comm_scalars = f_comm_scalars_vector;
    params.fr_data.cip_shifted[0] = cip_var;
    params.fr_data.neg_pub = neg_pub;
    params.fr_data.zeta_to_srs_len[0] = zeta_to_srs_len_var;
    params.fr_data.zeta_to_domain_size_minus_1 = zeta_to_domain_size_minus_1_var;
    // fr_data.std::array<var, lookup_columns> joint_combiner_powers_prepared;
    // fr_data.std::array<std::vector<VarType>, BatchSize> step_bulletproof_challenges;

        // params.proofs //
    params.proofs[0].comm.witness = witness_comm;
    // comm.commitment_type lookup_runtime;
    // comm.commitment_type table;
    // comm.std::vector<commitment_type> lookup_sorted;
    // comm.commitment_type lookup_agg;
    params.proofs[0].comm.z = z_comm;
    for (std::size_t i = 0; i < commitment_params::t_comm_size; i++) {params.proofs[0].comm.t.parts[i] = t_comm.parts[i];}
    params.proofs[0].comm.prev_challenges = prev_chal;
    params.proofs[0].o.L = L_var;
    params.proofs[0].o.R = R_var;
    params.proofs[0].o.delta = delta_var;
    params.proofs[0].o.G = op_proof_g_var;
    params.proofs[0].scalars = f_comm_scalars_vector;

        // params.verifier_index //
    params.verifier_index.H = H_var;
    params.verifier_index.G = G_var;
    params.verifier_index.lagrange_bases = lagrange_bases_var;
    params.verifier_index.comm.sigma = sigma_comm_var;
    params.verifier_index.comm.coefficient = coefficient_comm_var;
    params.verifier_index.comm.generic = generic_comm;
    params.verifier_index.comm.psm = psm_comm;
    // lookup_selectors
    // runtime_tables_selector
    // lookup_table
    params.verifier_index.comm.complete_add = complete_add_comm;
    params.verifier_index.comm.var_base_mul = mul_comm;
    params.verifier_index.comm.endo_mul = emul_comm;
    params.verifier_index.comm.endo_mul_scalar = endomul_scalar_comm;
    params.verifier_index.comm.chacha = chacha_comm;
    // params.verifier_index.comm.rang_check;

    }
// /*
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_base_field_test_generic) {

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
    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
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

    using component_type = zk::components::base_field<ArithmetizationType,
                                                      curve_type,
                                                      kimchi_params,
                                                      commitment_params,
                                                      batch_size,
                            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14>;

    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;
    using commitment_t_type = typename zk::components::kimchi_commitment_type<BlueprintFieldType, commitment_params::t_comm_size>;
    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;
    using verifier_index_type = zk::components::kimchi_verifier_index_base<curve_type, kimchi_params>;
    using proof_type = zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;
    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);
    using ec_point = curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;
    std::vector<typename BlueprintFieldType::value_type> public_input;

    typename component_type::params_type params;
    fill_params_verify_base<BlueprintFieldType, typename component_type::params_type, 
        var, var_ec_point, commitment_type, commitment_t_type, curve_type, commitment_params, 
        circuit_description, kimchi_constants, kimchi_params>(public_input, params, "generic");

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}
// */
// /*
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_base_field_test_recursion) {

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
    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    constexpr std::size_t Lambda = 40;
    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t comm_size = 1;

    constexpr static std::size_t public_input_size = recursion_constants.public_input_size;
    constexpr static std::size_t max_poly_size =     recursion_constants.max_poly_size;
    constexpr static std::size_t eval_rounds =       recursion_constants.eval_rounds;

    constexpr static std::size_t witness_columns =   recursion_constants.witness_columns;
    constexpr static std::size_t perm_size =         recursion_constants.perm_size;

    constexpr static std::size_t srs_len =           recursion_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = recursion_constants.prev_chal_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_recursion_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type = zk::components::base_field<ArithmetizationType,
                                                      curve_type,
                                                      kimchi_params,
                                                      commitment_params,
                                                      batch_size,
                            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14>;

    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;
    using commitment_t_type = typename zk::components::kimchi_commitment_type<BlueprintFieldType, commitment_params::t_comm_size>;
    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;
    using verifier_index_type = zk::components::kimchi_verifier_index_base<curve_type, kimchi_params>;
    using proof_type = zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;
    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);
    using ec_point = curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;
    std::vector<typename BlueprintFieldType::value_type> public_input;

    typename component_type::params_type params;
    fill_params_verify_base<BlueprintFieldType, typename component_type::params_type, 
        var, var_ec_point, commitment_type, commitment_t_type, curve_type, commitment_params, 
        circuit_description, kimchi_constants, kimchi_params>(public_input, params, "recursion");

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}
// */
// /*
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_base_field_test_ec) {

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
    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    constexpr std::size_t Lambda = 40;
    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t comm_size = 1;

    constexpr static std::size_t public_input_size = ec_constants.public_input_size;
    constexpr static std::size_t max_poly_size =     ec_constants.max_poly_size;
    constexpr static std::size_t eval_rounds =       ec_constants.eval_rounds;

    constexpr static std::size_t witness_columns =   ec_constants.witness_columns;
    constexpr static std::size_t perm_size =         ec_constants.perm_size;

    constexpr static std::size_t srs_len =           ec_constants.srs_len;
    constexpr static const std::size_t prev_chal_size = ec_constants.prev_chal_size;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type = zk::components::base_field<ArithmetizationType,
                                                      curve_type,
                                                      kimchi_params,
                                                      commitment_params,
                                                      batch_size,
                            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14>;

    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;
    using commitment_t_type = typename zk::components::kimchi_commitment_type<BlueprintFieldType, commitment_params::t_comm_size>;
    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;
    using verifier_index_type = zk::components::kimchi_verifier_index_base<curve_type, kimchi_params>;
    using proof_type = zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;
    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);
    using ec_point = curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type;
    std::vector<typename BlueprintFieldType::value_type> public_input;

    typename component_type::params_type params;
    fill_params_verify_base<BlueprintFieldType, typename component_type::params_type, 
        var, var_ec_point, commitment_type, commitment_t_type, curve_type, commitment_params, 
        circuit_description, kimchi_constants, kimchi_params>(public_input, params, "ec");

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}
// */
BOOST_AUTO_TEST_SUITE_END()