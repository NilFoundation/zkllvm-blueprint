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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PROOF_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PROOF_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/deferred_values.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename BlueprintFieldType, typename KimchiParamsType>
                struct proof_type {
                    private:
                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
                    using kimchi_proof_evaluations = kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;
                    using deferred_values_type = deferred_values_type<BlueprintFieldType>;

                    public:
                    struct statement_type {
                        struct proof_state_type {
                            // challenges inside deferred_values need conversion from bits when passed into prover
                            deferred_values_type deferred_values;
                            // in mina this is 4x64 bits, need to convert to var when passing to prover
                            // mina does the conversion before passing to sponge
                            var sponge_digest_before_evaluations;

                            struct messages_wrap_type {
                                // this one is on tock curve
                                var_ec_point challenge_polynomial_commitment;
                                // need to convert from bits when passed into prover
                                std::vector<std::array<var, 15>> old_bulletproof_challenges;
                            } messages_for_next_wrap_proof;
                        } proof_state;

                        struct messages_step_type {
                            // app_state starts out as Null (unit in OCaml) and gets initialised inside verify
                            // to the app_state from instance
                            // thus we ignore it and just use the app_state from instance

                            // these are on Tock curve
                            // might need to figure out the size
                            std::vector<var_ec_point> challenge_polynomial_commitments;
                            // challenges need conversion from bits when passed into prover
                            std::array<std::vector<var>, 16> old_bulletproof_challenges;
                        } messages_for_next_step_proof;
                    } statement;

                    struct prev_evals_type {
                        // in mina the template parameter is an array
                        // so e.g. kimchi_proof_evaluations would be parametrised by array
                        struct evals_type {
                            std::array<std::array<kimchi_proof_evaluations, KimchiParamsType::split_size>,
                                       2> evals;

                            std::array<var, 2> public_input;
                        } evals;

                        var ft_eval1;
                    } prev_evals;

                    struct proof_subtype {
                        struct messages_type {
                            std::array<std::vector<var_ec_point>, KimchiParamsType::witness_columns> w_comm;
                            std::vector<var_ec_point> z_comm;
                            std::vector<var_ec_point> t_comm;
                            // option
                            struct lookup_type {
                                std::vector<std::vector<var_ec_point>> sorted;
                                std::vector<var_ec_point> aggreg;
                                // option
                                std::vector<var_ec_point> runtime;
                            } lookup;
                        } messages;

                        struct openings_type {
                            struct bulletproof_type {
                                std::vector<var_ec_point> lr;
                                var z_1;
                                var z_2;
                                var_ec_point delta;
                                var_ec_point challenge_polynomial_commitment;
                            } proof;
                            // in mina the template parameter for kimchi_proof_evaluations is an array
                            std::array<std::vector<kimchi_proof_evaluations>, 2> evals;
                            var ft_eval;
                        } openings;
                    } proof;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif   // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PROOF_HPP
