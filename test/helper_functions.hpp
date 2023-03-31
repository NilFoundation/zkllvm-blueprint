//---------------------------------------------------------------------------//
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

#ifndef BLUEPRINT_TEST_VERIFIERS_PICKLES_SCALAR_DETAILS_HELPER_FUNCTIONS
#define BLUEPRINT_TEST_VERIFIERS_PICKLES_SCALAR_DETAILS_HELPER_FUNCTIONS

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <limits>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                    template<typename BlueprintFieldType, std::size_t N>
                    typename BlueprintFieldType::value_type b_poly_compute(
                            std::array<typename BlueprintFieldType::value_type, N> challenges_values,
                            typename BlueprintFieldType::value_type zeta_value){
                        std::vector<typename BlueprintFieldType::value_type> powers_twos;
                        powers_twos.resize(N);
                        powers_twos[0] = zeta_value;
                        for (std::size_t i = 1; i < N; i++) {
                            powers_twos[i] = powers_twos[i - 1] * powers_twos[i - 1];
                        }

                        typename BlueprintFieldType::value_type expected_result = 1;
                        for (std::size_t i = 0; i < N; i++) {
                            typename BlueprintFieldType::value_type term =
                                1 + challenges_values[i] * powers_twos[N - 1 - i];
                            expected_result = expected_result * term;
                        }

                        return expected_result;
                    }

                    template<typename BlueprintFieldType, typename KimchiParamsType,
                             std::size_t ItemsSize, std::size_t ChalAmount>
                    typename BlueprintFieldType::value_type combine_evals_compute(
                                std::array<std::array<typename BlueprintFieldType::value_type, 16>, ChalAmount> old_bulletproof_challenges,
                                typename BlueprintFieldType::value_type prev_evals_public_input_0,
                                std::array<typename BlueprintFieldType::value_type, 2> z,
                                std::array<typename BlueprintFieldType::value_type, 2> generic_selector,
                                std::array<typename BlueprintFieldType::value_type, 2> poseidon_selector,
                                std::array<std::array<typename BlueprintFieldType::value_type, KimchiParamsType::witness_columns>, 2> w,
                                std::array<std::array<typename BlueprintFieldType::value_type,
                                        KimchiParamsType::permut_size - 1>, 2> s,
                                typename BlueprintFieldType::value_type xi,
                                typename BlueprintFieldType::value_type ft,
                                typename BlueprintFieldType::value_type pt
                            ){

                        std::array<typename BlueprintFieldType::value_type, ChalAmount> chal_polys;
                        for (std::size_t i = 0; i < ChalAmount; i++) {
                            chal_polys[i] = zk::components::b_poly_compute<BlueprintFieldType, 16>(
                                old_bulletproof_challenges[i], pt);
                        }

                        std::array<typename BlueprintFieldType::value_type, ItemsSize> items;
                        std::copy(chal_polys.begin(), chal_polys.end(), items.begin());
                        std::size_t idx = ChalAmount;
                        items[idx] = prev_evals_public_input_0;
                        idx++;
                        items[idx] = ft;
                        idx++;
                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = z[j];
                            idx++;
                        }
                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = generic_selector[j];
                            idx++;
                        }
                        for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                            items[idx] = poseidon_selector[j];
                            idx++;
                        }
                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = w[j][i];
                                idx++;
                            }
                        }
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            for (std::size_t j = 0; j < KimchiParamsType::split_size; j++) {
                                items[idx] = s[j][i];
                                idx++;
                            }
                        }

                        typename BlueprintFieldType::value_type expected_result = items.back();
                        for (std::size_t i = items.size() - 2; i != std::numeric_limits<size_t>::max(); i--) {
                            expected_result *= xi;
                            expected_result += items[i];
                        }

                        assert(idx == ItemsSize);
                        // TODO: lookup_test
                        return expected_result;
                    }
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil


#endif   // BLUEPRINT_TEST_VERIFIERS_PICKLES_SCALAR_DETAILS_HELPER_FUNCTIONS