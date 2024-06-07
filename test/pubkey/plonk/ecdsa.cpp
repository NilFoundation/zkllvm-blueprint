//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_pubkey_ecdsa_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/algebra/curves/secp_k1.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/pubkey/ecdsa/plonk/ecdsa_recovery.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;
template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns>
void test_ecdsa_recovery(
    typename CurveType::scalar_field_type::value_type z,
    typename CurveType::scalar_field_type::value_type r,
    typename CurveType::scalar_field_type::value_type s,
    typename CurveType::scalar_field_type::value_type v,
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type QA) {

    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 6; // how small can this get?
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::ecdsa_recovery<ArithmetizationType, BlueprintFieldType, CurveType, num_chunks, bit_size_chunk>;
    using foreign_integral_type = typename CurveType::scalar_field_type::extended_integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    // transform EC point coords into chunks and put them into public input column
    std::vector<typename BlueprintFieldType::value_type> public_input;

    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          zf = foreign_integral_type(z.data),
                          rf = foreign_integral_type(r.data),
                          sf = foreign_integral_type(s.data),
                          vf = foreign_integral_type(v.data);

    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(value_type(t % B));
            t /= B;
        }
    };

    chunks_to_public_input(zf);
    chunks_to_public_input(rf);
    chunks_to_public_input(sf);
    public_input.push_back(value_type(vf));

    // put references to public input column into instance input
    typename component_type::input_type instance_input;

    for(std::size_t i = 0; i < num_chunks; i++) {
        instance_input.z[i] = var(0, i, false, var::column_type::public_input);
        instance_input.r[i] = var(0, num_chunks + i, false, var::column_type::public_input);
        instance_input.s[i] = var(0, 2*num_chunks + i, false, var::column_type::public_input);
    }
    instance_input.v = var(0, 4*num_chunks, false, var::column_type::public_input);

/*
    using scalar_value_type = typename CurveType::scalar_field_type::value_type;
    using scalar_integral_type = typename CurveType::scalar_field_type::integral_type;

    using base_value_type = typename CurveType::base_field_type::value_type;
    using base_integral_type = typename CurveType::base_field_type::integral_type;

    using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;

    ec_point_value_type G = ec_point_value_type::one();

    scalar_value_type u1 = -z/r,
                      u2 = s/r;
    base_integral_type a = CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::params_type::b;
    base_value_type x1 = scalar_integral_type(r.data);
    base_value_type y1 = (x1*x1*x1 + a).sqrt();

    if (base_integral_type(y1.data) % 2 != scalar_integral_type(v.data) % 2) {
        y1 = -y1;
    }

    ec_point_value_type R = ec_point_value_type(scalar_integral_type(x1.data), scalar_integral_type(y1.data)),
                        QA_rec = G*u1 + R*u2;

    std::cout << "Recovered QA" << std::endl;
    std::cout << "x = " << QA_rec.X.data << std::endl;
    std::cout << "y = " << QA_rec.Y.data << std::endl;
    std::cout << "Inintial QA" << std::endl;
    std::cout << "x = " << QA.X.data << std::endl;
    std::cout << "y = " << QA.Y.data << std::endl;
    assert(QA_rec.X.data == QA.X.data);
    assert(QA_rec.Y.data == QA.Y.data);
*/
    auto result_check = [&QA, &B](AssignmentType &assignment, typename component_type::result_type &real_res) {
        foreign_integral_type xQA = 0,
                              yQA = 0;
        for(std::size_t i = num_chunks; i > 0; i--) {
            xQA *= B;
            yQA *= B;
            xQA += foreign_integral_type(var_value(assignment, real_res.xQA[i-1]).data);
            yQA += foreign_integral_type(var_value(assignment, real_res.yQA[i-1]).data);
        }
//        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "ecdsa_recovery test: " << "\n";
        std::cout << "expected: " << QA.X.data << " " << QA.Y.data << "\n";
        std::cout << "real    : " << xQA << " " << yQA << "\n\n";
//        #endif
//        assert(foreign_integral_type(QA.X.data) == xQA);
//        assert(foreign_integral_type(QA.Y.data) == yQA);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 1>{0}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);

}

template<typename CurveType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t WitnessColumns, std::size_t RandomTestAmount> void multi_test_recovery() {
    nil::crypto3::random::algebraic_engine<typename CurveType::scalar_field_type> generate_random_scalar;

    boost::random::mt19937 seed_seq;
    generate_random_scalar.seed(seed_seq);

    using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename CurveType::scalar_field_type::value_type;
    using scalar_integral_type = typename CurveType::scalar_field_type::integral_type;
    using base_integral_type = typename CurveType::base_field_type::integral_type;

    scalar_value_type d, z, k, r, s, v;
    ec_point_value_type G = ec_point_value_type::one(),
                        QA, R;

    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        d = generate_random_scalar(); // private key
        QA = G*d; // public key

        z = generate_random_scalar(); // instead of taking part of the hash we just generate a random number

        do {
           k = generate_random_scalar(); // this random generation is part of the signature procedure
           R = G*k;
           v = scalar_value_type(scalar_integral_type(R.Y.data) % 2);
           r = base_integral_type(R.X.data);
           s = k.inversed() * (z + r*d);
        } while(r.is_zero() || s.is_zero());

        std::cout << "Random test # " << (i+1) << std::endl;
        test_ecdsa_recovery<CurveType,BlueprintFieldType,num_chunks,bit_size_chunk,WitnessColumns>(z,r,s,v,QA);
    }
}

constexpr static const std::size_t random_tests_amount = 1;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_pubkey_non_native_ecdsa_secp256k1) {
    using curve_type = typename crypto3::algebra::curves::secp256k1;
    using base_field_type = typename curve_type::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using curve_point = typename curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;

    // <curve_type, base_field_type, num_chunks, bit_size_chunk, witness_amount, random_tests_amount>
    multi_test_recovery<curve_type, vesta_field_type, 5, 64, 16, random_tests_amount>();
}
BOOST_AUTO_TEST_SUITE_END()
