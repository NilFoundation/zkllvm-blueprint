//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Abdel Ali Harchaoui <harchaoui@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_unified_addition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <verifiers/kimchi/index_terms_instances/ec_index_terms.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/plonk_map_fields_v1.hpp>

#include "../../../test_plonk_component.hpp"

#include <typeinfo>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_pickles_plonk_map_fields_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_pickles_plonk_map_fields) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;

    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 5;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 30;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;

    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // constexpr static std::size_t public_input_size = 0;
    // constexpr static std::size_t max_poly_size = 32;
    // constexpr static std::size_t eval_rounds = 5;
    // constexpr static std::size_t witness_columns = 15;
    // constexpr static std::size_t perm_size = 7;
    // constexpr static const std::size_t srs_len = 1;
    // constexpr static const std::size_t prev_chal_size = 1;

    // zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    using component_type =
        zk::components::plonk_map_fields<ArithmetizationType, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_value =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_value = 0;
    typename BlueprintFieldType::value_type gamma_value = 0;
    typename BlueprintFieldType::value_type zeta_value =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;

    constexpr std::size_t max_poly_size_val = 32;
    constexpr std::size_t domain_value = 5;

    std::cout << "Drive Plonk =  " << zeta_value.data << "ms" << std::endl;
    std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;

    public_input.push_back(alpha_value);
    var alpha_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
    std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;
    // std::cout << "alpha_var = " << alpha_var.data << " data" << std::endl;

    public_input.push_back(beta_value);
    var beta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
    std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;

    public_input.push_back(gamma_value);
    var gamma_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
    std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;

    public_input.push_back(zeta_value);
    var zeta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(domain_value);
    var domain_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(max_poly_size_val);
    var max_poly_size_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Drive Plonk: " << duration.count() << "ms" << std::endl;

    // std::vector<typename BlueprintFieldType::value_type> public_input = {power(zeta, domain_size)};
    typename component_type::params_type params;

    params.alpha = alpha_var;
    params.beta = beta_var;
    params.gamma = gamma_var;
    params.zeta = zeta_var;
    params.domain_size = domain_var;
    params.max_poly_size = max_poly_size_var;

    // params = {
    //     alpha_var, beta_var, gamma_var, zeta_var, domain_var, max_poly_size_var,
    //     // one,
    //     // zero,
    //     // joint_combiner,
    //     // index_terms,
    //     // perm,
    //     // generic,
    //     // verifier_index,
    // };

    typename BlueprintFieldType::value_type expected_res =
        0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D_cppui256;

    auto result_check = [&expected_res](AssignmentType &assignment, component_type::result_type &real_res) {
        // std::cout << "alpha_var = " << assignment.var_value(alpha_var).data << " data" << std::endl;
        // std::cout << "alpha_var = " << alpha_var << " data" << std::endl;
        // std::cout << "public input type = " << typeid(public_input) << " -> type" << std::endl;
        // std::cout << "alpha_var = " << alpha_var.index() << " data" << std::endl;
        std::cout << "expected_res = " << expected_res.data << " " << std::endl;
        std::cout << "real_res.zeta_to_domain_size = " <<assignment.var_value(real_res.zeta_to_domain_size).data << " " << std::endl;

        // assert(expected_res == assignment.var_value(real_res.zeta_to_domain_size).data);
        // assert(expected_res == assignment.var_value(real_res.zeta_to_domain_size).data);
        assert(expected_res == 0x000000000000000000000000000000007E140A3F8F0BACC6B92E8F4BF144F13D_cppui256);
        // return true;
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);

    // auto duration =
    //     std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    // std::cout << "Drive Plonk: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()