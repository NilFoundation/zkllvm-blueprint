//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/prepare_scalars_inversion.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_prepare_scalars_inversion_vesta) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    constexpr typename BlueprintFieldType::value_type  vesta_base_field_modulus = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui256;
    constexpr typename BlueprintFieldType::value_type pallas_base_field_modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr typename BlueprintFieldType::value_type  shifted_neg1 = 0x448d31f81299f237325a61da00000001_cppui255;
    constexpr typename BlueprintFieldType::value_type shifted_0 = 0x448d31f81299f237325a61da00000002_cppui255;
    constexpr typename BlueprintFieldType::value_type  shifted_1 = 0x448d31f81299f237325a61da00000003_cppui255;

    constexpr std::size_t InputSize = 4;

    using component_type = zk::components::prepare_scalars_inversion<ArithmetizationType, curve_type, 
        InputSize, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                                            11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> shifted_scalars;
    for (int i = 0; i < InputSize; ++i) {
        if (i == 0) {
            shifted_scalars.push_back(shifted_neg1);
        } else if (i == 1) {
            shifted_scalars.push_back(shifted_0);
        } else if (i == 2) {
            shifted_scalars.push_back(shifted_1);
        } else {
            shifted_scalars.push_back(algebra::random_element<BlueprintFieldType>());
        }
    }


    // scalars[0] = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;
    // scalars[1] = 0x20E959472C74FBEA783D62870B979033E1BD490EDF01DD51D69F4C89B52DAA3B_cppui256;
    // scalars[2] = 0x244DCFC9E49D7EF7EE803233A777F72016706EDB1534F75F4F9561FF4EB23255_cppui256;
    // scalars[3] = -1;
    // scalars[4] = 0;    
    

    typename BlueprintFieldType::value_type base = 2;


    std::vector<typename BlueprintFieldType::value_type> expected_res;
    for (int i = 0; i < InputSize; ++i) {
        typename BlueprintFieldType::value_type expected;
        if ((shifted_scalars[i] != shifted_neg1) & (shifted_scalars[i] != shifted_0) & (shifted_scalars[i] != shifted_1)){
            expected = 2 * shifted_scalars[i] + base.pow(255) + 1;
        } else {
            expected = shifted_scalars[i] + base.pow(255);
        }
        expected_res.push_back(expected);
        // std::cout << "scalars unprepared[" << i << "] = " << shifted_scalars[i].data << std::endl;
        // std::cout << "scalars prepared  [" << i << "] = " << expected.data << std::endl;
    }

    std::vector<typename BlueprintFieldType::value_type> public_input;
    for (int i = 0; i < InputSize; ++i) {
        public_input.push_back(shifted_scalars[i]);
    }
    for (int i = 0; i < InputSize; ++i) {
        public_input.push_back(expected_res[i]);
    }

    typename component_type::params_type params;

    for (std::size_t i = 0; i < InputSize; i++) {
        params.scalars[i] = var(0, i, false, var::column_type::public_input);
    }


    auto result_check = [&expected_res](AssignmentType &assignment,
        component_type::result_type &real_res) {
        for (int i = 0; i < InputSize; ++i) {
            // std::cout << "assertion[" << i << "]:" << std::endl;
            // std::cout << expected_res[i].data  << " == " << assignment.var_value(real_res.output[i]).data << std::endl;
            assert(expected_res[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "prepare scalars inversion vesta test: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_prepare_scalars_inversion_pallas) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    constexpr typename BlueprintFieldType::value_type  vesta_base_field_modulus = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui256;
    constexpr typename BlueprintFieldType::value_type pallas_base_field_modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr typename BlueprintFieldType::value_type  shifted_neg1 = 0x224698fc0994a8dd8c46eb2100000000_cppui255;
    constexpr typename BlueprintFieldType::value_type shifted_0 = 0x200000000000000000000000000000003369e57a0e5efd4c526a60b180000001_cppui255;
    constexpr typename BlueprintFieldType::value_type  shifted_1 = 0x224698fc0994a8dd8c46eb2100000001_cppui255;

    constexpr std::size_t InputSize = 4;

    using component_type = zk::components::prepare_scalars_inversion<ArithmetizationType, curve_type, 
        InputSize, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                                            11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> shifted_scalars;
    for (int i = 0; i < InputSize; ++i) {
        if (i == 0) {
            shifted_scalars.push_back(shifted_neg1);
        } else if (i == 1) {
            shifted_scalars.push_back(shifted_0);
        } else if (i == 2) {
            shifted_scalars.push_back(shifted_1);
        } else {
            shifted_scalars.push_back(algebra::random_element<BlueprintFieldType>());
        }
    }


    // scalars[0] = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;
    // scalars[1] = 0x20E959472C74FBEA783D62870B979033E1BD490EDF01DD51D69F4C89B52DAA3B_cppui256;
    // scalars[2] = 0x244DCFC9E49D7EF7EE803233A777F72016706EDB1534F75F4F9561FF4EB23255_cppui256;
    // scalars[3] = -1;
    // scalars[4] = 0;    
    

    typename BlueprintFieldType::value_type base = 2;

    std::vector<typename BlueprintFieldType::value_type> expected_res;
    for (int i = 0; i < InputSize; ++i) {
        typename BlueprintFieldType::value_type expected;
        expected = 2 * shifted_scalars[i] + base.pow(255) + 1;
        
        expected_res.push_back(expected);
        // std::cout << "scalars unprepared[" << i << "] = " << shifted_scalars[i].data << std::endl;
        // std::cout << "scalars prepared  [" << i << "] = " << expected.data << std::endl;
    }

    std::vector<typename BlueprintFieldType::value_type> public_input;
    for (int i = 0; i < InputSize; ++i) {
        public_input.push_back(shifted_scalars[i]);
    }
    for (int i = 0; i < InputSize; ++i) {
        public_input.push_back(expected_res[i]);
    }

    typename component_type::params_type params;

    for (std::size_t i = 0; i < InputSize; i++) {
        params.scalars[i] = var(0, i, false, var::column_type::public_input);
    }


    auto result_check = [&expected_res](AssignmentType &assignment,
        component_type::result_type &real_res) {
        for (int i = 0; i < InputSize; ++i) {
            // std::cout << "assertion[" << i << "]: expected == real" << std::endl;
            // std::cout << expected_res[i].data  << " == " << assignment.var_value(real_res.output[i]).data << std::endl;
            assert(expected_res[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "prepare scalars inversion pallas test: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
