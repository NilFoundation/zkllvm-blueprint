//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE BLUEPRINT_VERIFIERS_PICKLES_SCALAR_DETAILS_PLONK_MAP_FIELDS

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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/plonk_map_fields.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/perm_scalars.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_verifiers_plonk_pickles_plonk_map_fields_test_suite)
BOOST_AUTO_TEST_CASE(blueprint_plonk_map_fields_pallas) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;

    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr typename BlueprintFieldType::integral_type vesta_base_field_modulus =
         0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui255;
     constexpr typename BlueprintFieldType::integral_type pallas_base_field_modulus =
         0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 0;
    std::size_t domain_size = 512;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description =
        zk::components::kimchi_circuit_description<index_terms_list, witness_columns, perm_size>;
    using kimchi_params = zk::components::
        kimchi_params_type<curve_type, commitment_params, circuit_description, public_input_size, prev_chal_size>;

    using component_type = zk::components::plonk_map_fields<ArithmetizationType,
                                                            kimchi_params,
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

    std::array<typename BlueprintFieldType::value_type, 4> index_scalars = {
        0x017EEEF7695889AFB5311D7B36B31455AFF02B103BDA9BABF5BC29107B8F3AB7_cppui256,    // varBaseMul
        0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256,    // endoMul
        0x0F297E2FA4E61DD377911C6B14C03F5CABC1114813C5D5C4CDCBDFBE84C526DB_cppui256,    // endoMulScalar
        0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256,    // completeAdd
    };

    std::vector<typename BlueprintFieldType::value_type> public_input;
    typename BlueprintFieldType::value_type alpha_val =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    typename BlueprintFieldType::value_type perm_scalar_val =
        0x0E7F540B2F6CE243D4F603210A7EF55620EEC89679E894777E34D1AA3A33C689_cppui256;

    typename BlueprintFieldType::value_type zeta_to_domain_size;
    typename BlueprintFieldType::value_type zeta_to_srs_length;
    zeta_to_domain_size = zeta_val.pow(domain_size);
    zeta_to_srs_length = zeta_val.pow(max_poly_size);

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(1);
    var one = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(alpha_val);
    var alpha_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_to_domain_size);
    var zeta_to_domain_size_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_to_srs_length);
    var zeta_to_srs_length_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(perm_scalar_val);
    var perm_scalar_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> index_scalars_unprepared;

    index_scalars_unprepared.push_back(
        typename BlueprintFieldType::value_type(typename BlueprintFieldType::integral_type(zeta_to_domain_size.data)));

    index_scalars_unprepared.push_back(
        typename BlueprintFieldType::value_type(typename BlueprintFieldType::integral_type(zeta_to_srs_length.data)));

    for (size_t i = 0; i < index_scalars.size(); i++) {
        index_scalars_unprepared.push_back(index_scalars[i]);
    }

    index_scalars_unprepared.push_back(
        typename BlueprintFieldType::value_type(typename BlueprintFieldType::integral_type(perm_scalar_val.data)));

    typename BlueprintFieldType::value_type base = 2;
    typename BlueprintFieldType::value_type shift;
    typename BlueprintFieldType::value_type denominator;

     if (typename BlueprintFieldType::integral_type(curve_type::base_field_type::modulus) - vesta_base_field_modulus == 0) {
         shift = base.pow(255);
         denominator = 1;
     }
     if (typename BlueprintFieldType::integral_type(curve_type::base_field_type::modulus) - pallas_base_field_modulus == 0) {
         shift = base.pow(255) + 1;
         denominator = base;
     }

    std::vector<typename BlueprintFieldType::value_type> expected_res;
    expected_res.push_back(alpha_val);
    expected_res.push_back(beta_val);
    expected_res.push_back(gamma_val);
    expected_res.push_back(zeta_val);

    for (int i = 0; i < index_scalars_unprepared.size(); ++i) {
        typename BlueprintFieldType::value_type expected;
        if ((index_scalars_unprepared[i] != 1) & (index_scalars_unprepared[i] != 0) &
            (index_scalars_unprepared[i] != -1)) {
            expected = (index_scalars_unprepared[i] - base.pow(255) - 1) / 2;
        } else {
            expected = (index_scalars_unprepared[i] - shift) / denominator;
        }
        expected_res.push_back(expected);
    }
    expected_res.push_back(perm_scalar_val);

    typename component_type::params_type params = {};
    params.alpha = alpha_var;
    params.beta = beta_var;
    params.gamma = gamma_var;
    params.zeta = zeta_var;

    params.zeta_to_domain_size = zeta_to_domain_size_var;
    params.zeta_to_srs_len = zeta_to_srs_length_var;

    std::array<var, 4> index_scalars_var;
    for (std::size_t i = 0; i < index_scalars.size(); i++) {
        public_input.push_back(index_scalars[i]);
        index_scalars_var[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    params.index_terms_scalars = index_scalars_var;

    params.permutation_scalars = perm_scalar_var;

    auto result_check = [&expected_res](AssignmentType &assignment, component_type::result_type &real_res) {
        for (int i = 0; i < real_res.output.size(); ++i) {
            assert(expected_res[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Plonk map fields: " << duration.count() << "ms" << std::endl;
}
BOOST_AUTO_TEST_SUITE_END()