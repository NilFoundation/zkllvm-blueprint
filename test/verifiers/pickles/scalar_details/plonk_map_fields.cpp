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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>

// #include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/plonk_map_fields_v1.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/plonk_map_fields.hpp>

#include "../../../test_plonk_component.hpp"

#include <typeinfo>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_pickles_plonk_map_fields_suite)

// BOOST_AUTO_TEST_CASE(blueprint_plonk_pickles_plonk_map_fields) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;

//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 5;
//     constexpr std::size_t ConstantColumns = 2;
//     constexpr std::size_t SelectorColumns = 30;

//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns,
//         SelectorColumns>;

//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     // constexpr static std::size_t public_input_size = 0;
//     // constexpr static std::size_t max_poly_size = 32;
//     // constexpr static std::size_t eval_rounds = 5;
//     // constexpr static std::size_t witness_columns = 15;
//     // constexpr static std::size_t perm_size = 7;
//     // constexpr static const std::size_t srs_len = 1;
//     // constexpr static const std::size_t prev_chal_size = 1;

//     // zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;

//     std::vector<typename BlueprintFieldType::value_type> public_input;

//     using component_type = zk::components::plonk_map_fields<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7,
//     8,
//                                                             9, 10, 11, 12, 13, 14>;

//     typename BlueprintFieldType::value_type alpha_value =
//         0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
//     typename BlueprintFieldType::value_type beta_value = 0;
//     typename BlueprintFieldType::value_type gamma_value = 0;
//     typename BlueprintFieldType::value_type zeta_value =
//         0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;

//     constexpr std::size_t max_poly_size_val = 32;
//     constexpr std::size_t domain_value = 5;

//     std::cout << "Drive Plonk =  " << zeta_value.data << "ms" << std::endl;
//     std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;

//     public_input.push_back(alpha_value);
//     var alpha_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;
//     // std::cout << "alpha_var = " << alpha_var.data << " data" << std::endl;

//     public_input.push_back(beta_value);
//     var beta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;

//     public_input.push_back(gamma_value);
//     var gamma_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     std::cout << "public_input.size() = " << public_input.size() << " size" << std::endl;

//     public_input.push_back(zeta_value);
//     var zeta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     public_input.push_back(domain_value);
//     var domain_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     public_input.push_back(max_poly_size_val);
//     var max_poly_size_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     auto duration =
//         std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "Drive Plonk: " << duration.count() << "ms" << std::endl;

//     // std::vector<typename BlueprintFieldType::value_type> public_input = {power(zeta, domain_size)};
//     typename component_type::params_type params;

//     params.alpha = alpha_var;
//     params.beta = beta_var;
//     params.gamma = gamma_var;
//     params.zeta = zeta_var;
//     params.domain_size = domain_var;
//     params.max_poly_size = max_poly_size_var;

//     // params = {
//     //     alpha_var, beta_var, gamma_var, zeta_var, domain_var, max_poly_size_var,
//     //     // one,
//     //     // zero,
//     //     // joint_combiner,
//     //     // index_terms,
//     //     // perm,
//     //     // generic,
//     //     // verifier_index,
//     // };

//     // zeta_to_n  = zeta**n
//     typename BlueprintFieldType::value_type zeta_to_n;
//     typename BlueprintFieldType::value_type zeta_to_n_minus_1;
//     typename BlueprintFieldType::value_type zeta_to_domain_size;
//     typename BlueprintFieldType::value_type zeta_to_srs_length;
//     zeta_to_n = zeta_value.pow(domain_value);
//     // zeta_to_n_minus_1
//     zeta_to_n_minus_1 = zeta_to_n - 1;
//     // zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
//     zeta_to_domain_size = zeta_to_n_minus_1 + 1;

//     // zeta_to_srs_length = zeta^max_poly_size
//     zeta_to_srs_length = zeta_value.pow(max_poly_size_val);

//     std::vector<typename BlueprintFieldType::value_type> expected_res = {zeta_to_domain_size, zeta_to_srs_length};
//     // typename BlueprintFieldType::value_type expected_res =

//     auto result_check = [&expected_res](AssignmentType &assignment, component_type::result_type &real_res) {
//         std::cout << "expected_res [zeta_to_domain_size]  = " << expected_res[0].data << " " << std::endl;
//         std::cout << "real_res [zeta_to_domain_size ]" << assignment.var_value(real_res.zeta_to_domain_size).data <<
//         " "
//                   << std::endl;

//         std::cout << "expected_res.zeta_to_srs_length  = " << expected_res[1].data << " " << std::endl;
//         std::cout << "real_res.zeta_to_srs_length = " << assignment.var_value(real_res.zeta_to_srs_len).data << " "
//                   << std::endl;

//         assert(expected_res[0].data == assignment.var_value(real_res.zeta_to_domain_size).data);
//         assert(expected_res[1].data == assignment.var_value(real_res.zeta_to_srs_len).data);

//         // return true;
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params,
//     public_input,
//                                                                                                  result_check);

//     // auto duration =
//     //     std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     // std::cout << "Drive Plonk: " << duration.count() << "ms" << std::endl;
// }
// BOOST_AUTO_TEST_CASE(blueprint_plonk_map_fields_prepare_scalars_vesta) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 4;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns,
//         SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;
//     constexpr typename BlueprintFieldType::value_type vesta_base_field_modulus =
//         0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui256;
//     constexpr typename BlueprintFieldType::value_type pallas_base_field_modulus =
//         0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     constexpr std::size_t InputSize = 5;

//     using component_type = zk::components::prepare_scalars<ArithmetizationType, curve_type, InputSize, 0, 1, 2, 3, 4,
//     5,
//                                                            6, 7, 8, 9, 10, 11, 12, 13, 14>;

//     std::vector<typename BlueprintFieldType::value_type> scalars;
//     std::vector<var> scalars_var(InputSize);

//     scalars.push_back(-1);
//     scalars.push_back(0);
//     scalars.push_back(1);

//     // zeta_to_domain_size
//     scalars.push_back(nil::crypto3::multiprecision::cpp_int(
//         "25683473110178991334501255871320279430685201616810948269936967417769229419574"));
//     // zeta_to_srs_len
//     scalars.push_back(nil::crypto3::multiprecision::cpp_int(
//         "18813912306561527183948812749325437170224484852483637491740618125844332209574"));

//     // for (int i = 0; i < InputSize; ++i) {
//     //     if (i == 0) {
//     //         scalars.push_back(1);
//     //     } else if (i == 1) {
//     //         scalars.push_back(0);
//     //     } else if (i == 2) {
//     //         scalars.push_back(-1);
//     //     } else {
//     //         scalars.push_back(algebra::random_element<BlueprintFieldType>());
//     //     }
//     // }

//     // scalars[0] = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;
//     // scalars[1] = 0x20E959472C74FBEA783D62870B979033E1BD490EDF01DD51D69F4C89B52DAA3B_cppui256;
//     // scalars[2] = 0x244DCFC9E49D7EF7EE803233A777F72016706EDB1534F75F4F9561FF4EB23255_cppui256;
//     // scalars[3] = -1;
//     // scalars[4] = 0;

//     typename BlueprintFieldType::value_type base = 2;
//     typename BlueprintFieldType::value_type shift;
//     typename BlueprintFieldType::value_type denominator;

//     if (curve_type::base_field_type::modulus - vesta_base_field_modulus == 0) {
//         shift = base.pow(255);
//         denominator = 1;
//     }
//     if (curve_type::base_field_type::modulus - pallas_base_field_modulus == 0) {
//         shift = base.pow(255) + 1;
//         denominator = base;
//     }

//     std::vector<typename BlueprintFieldType::value_type> expected_res;
//     for (int i = 0; i < InputSize; ++i) {
//         typename BlueprintFieldType::value_type expected;
//         if ((scalars[i] != 1) & (scalars[i] != 0) & (scalars[i] != -1)) {
//             expected = (scalars[i] - base.pow(255) - 1) / 2;
//         } else {
//             expected = (scalars[i] - shift) / denominator;
//         }
//         expected_res.push_back(expected);
//         std::cout << "scalars unprepared[" << i << "] = " << scalars[i].data << std::endl;
//         std::cout << "scalars prepared  [" << i << "] = " << expected.data << std::endl;
//     }

//     std::vector<typename BlueprintFieldType::value_type> public_input;
//     for (int i = 0; i < InputSize; ++i) {
//         public_input.push_back(scalars[i]);
//         scalars_var[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     }

//     typename component_type::params_type params = {scalars_var};

//     auto result_check = [&expected_res](AssignmentType &assignment, component_type::result_type &real_res) {
//         for (int i = 0; i < InputSize; ++i) {
//             // std::cout << "assertion[" << i << "]:" << std::endl;
//             // std::cout << expected_res[i].data  << " == " << assignment.var_value(real_res.output[i]).data <<
//             // std::endl;
//             assert(expected_res[i] == assignment.var_value(real_res.output[i]));
//         }
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params,
//     public_input,
//                                                                                                  result_check);

//     auto duration =
//         std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "prepare scalars: " << duration.count() << "ms" << std::endl;
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_map_fields_index_terms_scalar_ec_test_suite) {

//     using curve_type = algebra::curves::pallas;
//     using BlueprintFieldType = typename curve_type::base_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 30;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns,
//         SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     constexpr static std::size_t public_input_size = 3;
//     constexpr static std::size_t max_poly_size = 32;
//     constexpr static std::size_t eval_rounds = 5;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 10;
//     constexpr static const std::size_t prev_chal_size = 0;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
//     using circuit_description =
//         zk::components::kimchi_circuit_description<index_terms_list, witness_columns, perm_size>;
//     using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//                                                              public_input_size, prev_chal_size>;

//     using component_type = zk::components::index_terms_scalars<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4, 5,
//     6,
//                                                                7, 8, 9, 10, 11, 12, 13, 14>;

//     std::array<typename BlueprintFieldType::value_type, witness_columns> eval0_w = {
//         0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
//         0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
//         0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
//         0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
//         0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
//         0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
//         0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
//         0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
//         0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
//         0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
//         0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
//         0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
//         0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
//         0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
//         0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256};

//     typename BlueprintFieldType::value_type eval0_z =
//         0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

//     std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
//         0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
//         0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
//         0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
//         0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
//         0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
//         0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256};

//     std::array<typename BlueprintFieldType::value_type, witness_columns> eval1_w = {
//         0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
//         0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
//         0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
//         0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
//         0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
//         0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
//         0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
//         0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
//         0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
//         0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
//         0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
//         0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
//         0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
//         0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
//         0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256};

//     typename BlueprintFieldType::value_type eval1_z =
//         0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

//     std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
//         0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
//         0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
//         0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
//         0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
//         0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
//         0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
//     };

//     std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};

//     std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};

//     std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

//     typename BlueprintFieldType::value_type alpha_val =
//         0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
//     typename BlueprintFieldType::value_type beta_val =
//         0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
//     typename BlueprintFieldType::value_type gamma_val =
//         0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
//     typename BlueprintFieldType::value_type zeta_val =
//         0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

//     typename BlueprintFieldType::value_type omega_val =
//         0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
//     std::size_t domain_size = 512;

//     std::array<typename BlueprintFieldType::value_type, 19> expected_result = {
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x017EEEF7695889AFB5311D7B36B31455AFF02B103BDA9BABF5BC29107B8F3AB7_cppui256,    // varBaseMul
//         0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256,    // endoMul
//         0x0F297E2FA4E61DD377911C6B14C03F5CABC1114813C5D5C4CDCBDFBE84C526DB_cppui256,    // endoMulScalar
//         0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256,    // completeAdd
//     };

//     std::vector<typename BlueprintFieldType::value_type> public_input;

//     public_input.push_back(0);
//     var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
//     std::array<evaluations_type, 2> evals;

//     for (std::size_t i = 0; i < 2; i++) {
//         for (std::size_t j = 0; j < witness_columns; j++) {
//             public_input.push_back(eval_w[i][j]);
//             var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
//             evals[i].w[j] = w;
//         }

//         public_input.push_back(eval_z[i]);
//         var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         evals[i].z = z;

//         for (std::size_t j = 0; j < perm_size; j++) {
//             public_input.push_back(eval_s[i][j]);
//             var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
//             evals[i].s[j] = s;
//         }

//         evals[i].poseidon_selector = zero;
//         evals[i].generic_selector = zero;
//     }

//     public_input.push_back(alpha_val);
//     var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     public_input.push_back(beta_val);
//     var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     public_input.push_back(gamma_val);
//     var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     public_input.push_back(zeta_val);
//     var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     var joint_combiner = zero;

//     public_input.push_back(omega_val);
//     var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     typename component_type::params_type params = {zeta, alpha, beta, gamma, joint_combiner, evals, omega,
//     domain_size};

//     auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
//         for (std::size_t i = 0; i < expected_result.size(); ++i) {
//         std::cout << "scalars unprepared[" << i << "] = " << expected_result[i].data << std::endl;
//         // std::cout << "scalars prepared  [" << i << "] = " << expected.data << std::endl;
//             assert(expected_result[i] == assignment.var_value(real_res.output[i]));
//         }
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params,
//     public_input,
//                                                                                                  result_check);
// }
// BOOST_AUTO_TEST_CASE(blueprint_plonk_map_fields_index_terms_scalar_ec_test_suite) {

//     using curve_type = algebra::curves::pallas;
//     using BlueprintFieldType = typename curve_type::base_field_type;
//     constexpr std::size_t WitnessColumns = 15;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 30;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns,
//         SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     constexpr static std::size_t public_input_size = 3;
//     constexpr static std::size_t max_poly_size = 32;
//     constexpr static std::size_t eval_rounds = 5;

//     constexpr static std::size_t witness_columns = 15;
//     constexpr static std::size_t perm_size = 7;

//     constexpr static std::size_t srs_len = 10;
//     constexpr static const std::size_t prev_chal_size = 0;

//     using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//     using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
//     using circuit_description =
//         zk::components::kimchi_circuit_description<index_terms_list, witness_columns, perm_size>;
//     using kimchi_params = zk::components::
//         kimchi_params_type<curve_type, commitment_params, circuit_description, public_input_size, prev_chal_size>;

//     using component_type = zk::components::plonk_map_fields<ArithmetizationType,
//                                                             curve_type,
//                                                             kimchi_params,
//                                                             0,
//                                                             1,
//                                                             2,
//                                                             3,
//                                                             4,
//                                                             5,
//                                                             6,
//                                                             7,
//                                                             8,
//                                                             9,
//                                                             10,
//                                                             11,
//                                                             12,
//                                                             13,
//                                                             14>;

//     std::array<typename BlueprintFieldType::value_type, witness_columns> eval0_w = {
//         0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
//         0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
//         0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
//         0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
//         0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
//         0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
//         0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
//         0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
//         0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
//         0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
//         0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
//         0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
//         0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
//         0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
//         0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256};

//     typename BlueprintFieldType::value_type eval0_z =
//         0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

//     std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
//         0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
//         0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
//         0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
//         0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
//         0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
//         0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256};

//     std::array<typename BlueprintFieldType::value_type, witness_columns> eval1_w = {
//         0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
//         0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
//         0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
//         0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
//         0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
//         0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
//         0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
//         0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
//         0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
//         0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
//         0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
//         0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
//         0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
//         0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
//         0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256};

//     typename BlueprintFieldType::value_type eval1_z =
//         0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

//     std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
//         0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
//         0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
//         0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
//         0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
//         0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
//         0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
//     };

//     std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
//     std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
//     std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

//     typename BlueprintFieldType::value_type alpha_val =
//         0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
//     typename BlueprintFieldType::value_type beta_val =
//         0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
//     typename BlueprintFieldType::value_type gamma_val =
//         0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
//     typename BlueprintFieldType::value_type zeta_val =
//         0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

//     typename BlueprintFieldType::value_type omega_val =
//         0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
//     std::size_t domain_size = 512;

//     std::array<typename BlueprintFieldType::value_type, 19> expected_result = {
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
//         0x017EEEF7695889AFB5311D7B36B31455AFF02B103BDA9BABF5BC29107B8F3AB7_cppui256,    // varBaseMul
//         0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256,    // endoMul
//         0x0F297E2FA4E61DD377911C6B14C03F5CABC1114813C5D5C4CDCBDFBE84C526DB_cppui256,    // endoMulScalar
//         0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256,    // completeAdd
//     };

//     std::vector<typename BlueprintFieldType::value_type> public_input;

//     public_input.push_back(0);
//     var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     public_input.push_back(1);
//     var one = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
//     std::array<evaluations_type, 2> evals;

//     for (std::size_t i = 0; i < 2; i++) {
//         for (std::size_t j = 0; j < witness_columns; j++) {
//             public_input.push_back(eval_w[i][j]);
//             var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
//             evals[i].w[j] = w;
//         }

//         public_input.push_back(eval_z[i]);
//         var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
//         evals[i].z = z;

//         for (std::size_t j = 0; j < perm_size; j++) {
//             public_input.push_back(eval_s[i][j]);
//             var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
//             evals[i].s[j] = s;
//         }

//         evals[i].poseidon_selector = zero;
//         evals[i].generic_selector = zero;
//     }

//     public_input.push_back(alpha_val);
//     var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     public_input.push_back(beta_val);
//     var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
//     public_input.push_back(gamma_val);
//     var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     public_input.push_back(zeta_val);
//     var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     var joint_combiner = zero;

//     public_input.push_back(omega_val);
//     var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

//     typename component_type::params_type params = {};
//     params.alpha = alpha;
//     params.beta = beta;
//     params.gamma = gamma;
//     params.zeta = zeta;
//     params.omega = omega;
//     params.domain_size = domain_size;
//     params.joint_combiner = joint_combiner;
//     params.zero = zero;
//     params.one = one;
//     params.evaluations = evals;
//     // params.max_poly_size = max_poly_size_var;

//     // {alpha, beta, gamma, zeta, omega, params.domain_size, one, zero, joint_combiner, max_poly_size, evals};

//     auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
//         for (std::size_t i = 0; i < expected_result.size(); ++i) {
//             std::cout << "scalars unprepared [" << i << "] = " << expected_result[i].data << std::endl;
//             std::cout << "scalars unprepared [" << i << "] = " << assignment.var_value(real_res.output[i]).data
//                       << std::endl;
//             // std::cout << "scalars prepared  [" << i << "] = " << expected.data << std::endl;
//             // assert(expected_result[i] == assignment.var_value(real_res.output[i]));
//         }
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
//         params, public_input, result_check);
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_map_fields_prepare_scalars_2_vesta) {
    auto start = std::chrono::high_resolution_clock::now();

    // START common params
    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    // END common params

    // START prepared_scalars Params
    constexpr typename BlueprintFieldType::value_type vesta_base_field_modulus =
        0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui256;
    constexpr typename BlueprintFieldType::value_type pallas_base_field_modulus =
        0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // [TODO] get input size from result_type struct size
    constexpr std::size_t InputSize = 6;
    // END prepared_scalars Params

    // START plonk_map_fields Params
    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description =
        zk::components::kimchi_circuit_description<index_terms_list, witness_columns, perm_size>;
    using kimchi_params = zk::components::
        kimchi_params_type<curve_type, commitment_params, circuit_description, public_input_size, prev_chal_size>;

    using component_type = zk::components::plonk_map_fields<ArithmetizationType,
                                                            curve_type,
                                                            kimchi_params,
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
    // END plonk_map_fields Params
    std::vector<var> scalars_var(InputSize);
    std::array<typename BlueprintFieldType::value_type, witness_columns> eval0_w = {
        0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
        0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
        0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
        0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
        0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
        0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
        0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
        0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
        0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
        0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
        0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
        0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
        0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
        0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
        0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256};

    typename BlueprintFieldType::value_type eval0_z =
        0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256};

    std::array<typename BlueprintFieldType::value_type, witness_columns> eval1_w = {
        0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
        0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
        0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
        0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
        0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
        0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
        0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
        0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
        0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
        0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
        0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
        0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
        0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
        0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
        0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256};

    typename BlueprintFieldType::value_type eval1_z =
        0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    
    std::array<typename BlueprintFieldType::value_type, 21> index_scalars = {
        0x3A9E12B994C36F4C3CFF4260F9DFC68C9EF211675689603A86714550CBA27AE8_cppui256,    // zeta_to_domain_size
        0x3DD41971C9BD2F7B86F3692CB754C30DB30F47867B3837179D10A638A5F1387F_cppui256,    // zeta_to_srs_len
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
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;

    // zero_var
    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(1);
    var one = var(0, public_input.size() - 1, false, var::column_type::public_input);

    // to be used in expo and index_terms_scalars
    std::size_t domain_size = 512;

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(domain_size);
    var domain_expo_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    // public_input.push_back(domain_size_integral);
    // var domain_size_integral_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(domain_size);
    var domain_size_scalars_sizet = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(max_poly_size);
    var max_poly_size_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    // START: compute zeta_to_domain_size & zeta_to_srs_length
    typename BlueprintFieldType::value_type zeta_to_n;
    typename BlueprintFieldType::value_type zeta_to_n_minus_1;
    typename BlueprintFieldType::value_type zeta_to_domain_size;
    typename BlueprintFieldType::value_type zeta_to_srs_length;

    // START test zeta_to_domain_size and  zeta_to_srs_length
    //  zeta_to_n  = zeta**n
    zeta_to_n = zeta_val.pow(domain_size);
    // zeta_to_n_minus_1
    zeta_to_n_minus_1 = zeta_to_n - 1;
    // zeta_to_domain_size = env.zeta_to_n_minus_1 + F.one
    zeta_to_domain_size = zeta_to_n_minus_1 + 1;

    // zeta_to_srs_length = zeta^max_poly_size
    zeta_to_srs_length = zeta_val.pow(max_poly_size);

    // END test zeta_to_domain_size and  zeta_to_srs_length

    std::vector<typename BlueprintFieldType::value_type> index_scalars_unprepared;
    // std::vector<typename BlueprintFieldType::value_type> scalars;

    public_input.push_back(zeta_to_domain_size);
    var zeta_to_domain_size_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_to_srs_length);
    var zeta_to_srs_length_var = var(0, public_input.size() - 1, false, var::column_type::public_input);
    var joint_combiner = zero;

    // std::cout << "debugin " << InputSize << std::endl;
    // zeta_to_domain_size
    // index_scalars_unprepared.push_back(nil::crypto3::multiprecision::cpp_int(zeta_to_domain_size.data));
    // std::cout << "zeta_to_domain_size cpp " << nil::crypto3::multiprecision::cpp_int(zeta_to_domain_size.data)
    // << std::endl;

    // std::cout << "index_scalars_unprepared " << index_scalars_unprepared.size() << std::endl;
    // zeta_to_srs_len
    // index_scalars_unprepared.push_back(nil::crypto3::multiprecision::cpp_int(zeta_to_srs_length.data));
    // std::cout << "index_scalars_unprepared " << index_scalars_unprepared.size() << std::endl;

    for (size_t i = 0; i < index_scalars.size(); i++) {
        index_scalars_unprepared.push_back(index_scalars[i]);
    }
    // std::cout << "index_scalars_unprepared " << index_scalars_unprepared.size() << std::endl;

    // START test prepare scalars
    typename BlueprintFieldType::value_type base = 2;
    typename BlueprintFieldType::value_type shift;
    typename BlueprintFieldType::value_type denominator;

    if (curve_type::base_field_type::modulus - vesta_base_field_modulus == 0) {
        shift = base.pow(255);
        denominator = 1;
    }
    if (curve_type::base_field_type::modulus - pallas_base_field_modulus == 0) {
        shift = base.pow(255) + 1;
        denominator = base;
    }

    // std::cout << "size of InputSize = " << InputSize << std::endl;
    // std::cout << "index_scalars_unprepared size = " << index_scalars_unprepared.size() << std::endl;

    std::vector<typename BlueprintFieldType::value_type> expected_res;
    for (int i = 0; i < InputSize; ++i) {
        typename BlueprintFieldType::value_type expected;
        if ((index_scalars_unprepared[i] != 1) & (index_scalars_unprepared[i] != 0) &
            (index_scalars_unprepared[i] != -1)) {
            expected = (index_scalars_unprepared[i] - base.pow(255) - 1) / 2;
        } else {
            expected = (index_scalars_unprepared[i] - shift) / denominator;
        }
        expected_res.push_back(expected);
    }
    // END test prepare scalars
    for (int i = 0; i < InputSize; ++i) {
        public_input.push_back(index_scalars_unprepared[i]);
        scalars_var[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // typename component_type::params_type params = {scalars_var};
    typename component_type::params_type params = {};
    params.alpha = alpha_var;
    params.beta = beta_var;
    params.gamma = gamma_var;
    params.zeta = zeta_var;
    // not used
    params.domain_size_scalars_sizet = domain_size;    // creates problem in exponentation (using var)
    params.domain_expo_var =
        domain_expo_var;    // creates problem in index_terms_scalars (using domain_size as std::size_t)
    params.max_poly_size = max_poly_size_var;
    params.joint_combiner = joint_combiner;
    params.max_poly_size = max_poly_size_var;
    params.zero = max_poly_size_var;
    params.one = max_poly_size_var;
    params.evaluations = evals;

    // std::cout << " IN CPP FILE " << std::endl;
    // std::cout << "========================================== " << std::endl;

    auto result_check = [&expected_res](AssignmentType &assignment, component_type::result_type &real_res) {
        for (int i = 0; i < InputSize; ++i) {
            // std::cout << "expe[" << i << "]\t=" << expected_res[i].data << "" << std::endl;
            // std::cout << "real[" << i << "]\t=" << assignment.var_value(real_res.output[i]).data << "" << std::endl;

            assert(expected_res[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "prepare scalars: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()