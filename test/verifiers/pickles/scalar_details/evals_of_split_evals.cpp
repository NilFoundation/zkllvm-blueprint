//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_pickles_scalar_details_evals_of_split_evals_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/evals_of_split_evals.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "verifiers/kimchi/proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_pickles_scalar_details_evals_of_split_evals_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proofs(std::array<zk::snark::proof_type<CurveType>, KimchiParamsType::split_size> &original_proofs,
                   std::array<zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvalRounds>, KimchiParamsType::split_size> &circuit_proofs,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    for (std::size_t split_idx = 0; split_idx < KimchiParamsType::split_size; split_idx++) {
        // eval_proofs
        for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
            // w
            for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                public_input.push_back(original_proofs[split_idx].evals[point_idx].w[i][0]);
                circuit_proofs[point_idx].proof_evals[split_idx].w[i] =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
            // z
            public_input.push_back(original_proofs[split_idx].evals[point_idx].z[0]);
            circuit_proofs[point_idx].proof_evals[split_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
            // s
            for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                public_input.push_back(original_proofs[split_idx].evals[point_idx].s[i][0]);
                circuit_proofs[point_idx].proof_evals[split_idx].s[i] =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
            // lookup
            if (KimchiParamsType::use_lookup) {
                for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                    public_input.push_back(original_proofs[split_idx].evals[point_idx].lookup.sorted[i][0]);
                    circuit_proofs[point_idx].proof_evals[split_idx].lookup.sorted[i] =
                        var(0, public_input.size() - 1, false, var::column_type::public_input);
                }

                public_input.push_back(original_proofs[split_idx].evals[point_idx].lookup.aggreg[0]);
                circuit_proofs[point_idx].proof_evals[split_idx].lookup.aggreg =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);

                public_input.push_back(original_proofs[split_idx].evals[point_idx].lookup.table[0]);
                circuit_proofs[point_idx].proof_evals[split_idx].lookup.table =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);

                if (KimchiParamsType::circuit_params::lookup_runtime) {
                    public_input.push_back(original_proofs[split_idx].evals[point_idx].lookup.runtime[0]);
                    circuit_proofs[point_idx].proof_evals[split_idx].lookup.runtime =
                        var(0, public_input.size() - 1, false, var::column_type::public_input);
                }
            }
            // generic_selector
            if (KimchiParamsType::circuit_params::generic_gate) {
                public_input.push_back(original_proofs[split_idx].evals[point_idx].generic_selector[0]);
                circuit_proofs[point_idx].proof_evals[split_idx].generic_selector =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
            // poseidon_selector
            if (KimchiParamsType::circuit_params::poseidon_gate) {
                public_input.push_back(original_proofs[split_idx].evals[point_idx].poseidon_selector[0]);
                circuit_proofs[point_idx].proof_evals[split_idx].poseidon_selector =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_pickles_scalar_details_evals_of_split_evals_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 16;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::evals_of_split_evals<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                             5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::size_t split_size = kimchi_params::split_size;

    std::array<zk::snark::proof_type<curve_type>, kimchi_params::eval_points_amount> kimchi_proofs = {
        test_proof(), test_proof_generic()
    };

    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type zetaw_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;

    std::array<zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds>,
               kimchi_params::eval_points_amount> proofs;

    std::vector<typename BlueprintFieldType::value_type> public_input = {zeta_val, zetaw_val};

    var zeta(0, 0, false, var::column_type::public_input);
    var zetaw(0, 1, false, var::column_type::public_input);

    prepare_proofs<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proofs, proofs, public_input);

    typename component_type::params_type params;
    //params.split_evals = {proofs[0].proof_evals, proofs[1].proof_evals};
    params.split_evals[0] = proofs[0].proof_evals;
    params.split_evals[1] = proofs[1].proof_evals;
    params.points = {zeta, zetaw};

    auto result_check = [&kimchi_proofs, &zeta_val, &zetaw_val, split_size]
            (AssignmentType &assignment, component_type::result_type &real_res) {
        std::array<typename BlueprintFieldType::value_type, kimchi_params::eval_points_amount> pows = {
            algebra::fields::detail::power(zeta_val, 1 << eval_rounds),
            algebra::fields::detail::power(zetaw_val, 1 << eval_rounds)
        };
        for (std::size_t i = 0; i < kimchi_params::eval_points_amount; i++) {
            // w
            typename BlueprintFieldType::value_type acc = 0;
            for (std::size_t k = 0; k < kimchi_proofs[0].evals[i].w.size(); k++) {
                acc = 0;
                for (std::size_t j = 0; j < split_size; j++) {
                    acc = kimchi_proofs[j].evals[i].w[k][0] + acc * pows[i];
                }
                assert(acc == assignment.var_value(real_res.output[i].w[k]));
            }
            // z
            acc = 0;
            for (std::size_t j = 0; j < split_size; j++) {
                acc = kimchi_proofs[j].evals[i].z[0] + acc * pows[i];
            }
            assert(acc == assignment.var_value(real_res.output[i].z));
            // s
            for (std::size_t k = 0; k < kimchi_proofs[0].evals[i].s.size(); k++) {
                acc = 0;
                for (std::size_t j = 0; j < split_size; j++) {
                    acc = kimchi_proofs[j].evals[i].s[k][0] + acc * pows[i];
                }
                assert(acc == assignment.var_value(real_res.output[i].s[k]));
            }
            // lookup
            if (kimchi_params::use_lookup) {
                for (std::size_t k = 0; k < kimchi_proofs[0].evals[i].lookup.sorted.size(); k++) {
                    acc = 0;
                    for (std::size_t j = 0; j < split_size; j++) {
                        acc = kimchi_proofs[j].evals[i].lookup.sorted[k][0] + acc * pows[i];
                    }
                    assert(acc == assignment.var_value(real_res.output[i].lookup.sorted[k]));
                }

                acc = 0;
                for (std::size_t j = 0; j < split_size; j++) {
                    acc = kimchi_proofs[j].evals[i].lookup.aggreg[0] + acc * pows[i];
                }
                assert(acc == assignment.var_value(real_res.output[i].lookup.aggreg));

                acc = 0;
                for (std::size_t j = 0; j < split_size; j++) {
                    acc = kimchi_proofs[j].evals[i].lookup.table[0] + acc * pows[i];
                }
                assert(acc == assignment.var_value(real_res.output[i].lookup.table));

                if (kimchi_params::circuit_params::lookup_runtime) {
                    acc = 0;
                    for (std::size_t j = 0; j < split_size; j++) {
                        acc = kimchi_proofs[j].evals[i].lookup.runtime[0] + acc * pows[i];
                    }
                    assert(acc == assignment.var_value(real_res.output[i].lookup.runtime));
                }
            }
            // generic_selector
            if (kimchi_params::generic_gate) {
                acc = 0;
                for (std::size_t j = 0; j < split_size; j++) {
                    acc = kimchi_proofs[j].evals[i].generic_selector[0] + acc * pows[i];
                }
                assert(acc == assignment.var_value(real_res.output[i].generic_selector));
            }
            // poseidon_selector
            if (kimchi_params::poseidon_gate) {
                acc = 0;
                for (std::size_t j = 0; j < split_size; j++) {
                    acc = kimchi_proofs[j].evals[i].poseidon_selector[0] + acc * pows[i];
                }
                assert(acc == assignment.var_value(real_res.output[i].poseidon_selector));
            }
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check
    );
}

BOOST_AUTO_TEST_SUITE_END()