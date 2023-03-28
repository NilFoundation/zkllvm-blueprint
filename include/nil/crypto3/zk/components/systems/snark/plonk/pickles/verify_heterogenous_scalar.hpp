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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_SCALAR_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_SCALAR_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/oracles_cip.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verify_scalar.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/environment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/batch_dlog_accumulator_check_base.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/evals_of_split_evals.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/derive_plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/scalars_env.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/instance.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/verification_key.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/prepare_scalars_inversion.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/deferred_values.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // scalar field part of verify_generogenous
                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/verify.ml#L30
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                         typename KimchiCommitmentParamsType, std::size_t BatchSize, std::size_t list_size,
                         std::size_t evals_size, std::size_t... WireIndexes>
                class verify_heterogenous_scalar;

                template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,
                         typename KimchiCommitmentParamsType, std::size_t BatchSize, std::size_t list_size,
                         std::size_t evals_size, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class verify_heterogenous_scalar<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize, list_size, evals_size, W0, W1,
                    W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    using ArithmetizationType =
                        snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using pickles_plonk_min = nil::crypto3::zk::components::pickles_plonk_min<BlueprintFieldType>;
                    using pickles_plonk_circuit = nil::crypto3::zk::components::pickles_plonk_circuit<BlueprintFieldType>;

                    using endo_scalar_component =
                        zk::components::endo_scalar<ArithmetizationType, CurveType, KimchiParamsType::scalar_challenge_size,
                                                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    // mul_by_constant_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;

                    using add_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    using b_poly_component =
                        zk::components::b_poly<ArithmetizationType, 16, W0, W1, W2,
                                               W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using transcript_type =
                        kimchi_transcript_fr<ArithmetizationType, CurveType, KimchiParamsType, W0, W1, W2, W3, W4, W5,
                                             W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using combined_evals_component =
                        zk::components::evals_of_split_evals<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using derive_plonk_component =
                        zk::components::derive_plonk<ArithmetizationType, KimchiParamsType, CurveType,
                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using prepare_scalars_inversion_component =
                        zk::components::prepare_scalars_inversion<ArithmetizationType, KimchiParamsType, evals_size, W0,
                                                                  W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                                                  W13, W14>;

                    using cip_component =
                        zk::components::oracles_cip<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6,
                                                    W7, W8, W9, W10, W11, W12, W13, W14>;

                    using batch_verify_component =
                        zk::components::batch_dlog_accumulator_check_base<ArithmetizationType, CurveType,
                                                                          KimchiParamsType, W0, W1, W2, W3, W4, W5, W6,
                                                                          W7, W8, W9, W10, W11, W12, W13, W14>;

                    using scalars_env_component =
                        zk::components::scalars_env<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6,
                                                    W7, W8, W9, W10, W11, W12, W13, W14>;

                    /*using kimchi_verify_component =
                        zk::components::verify_scalar<ArithmetizationType, CurveType, KimchiParamsType,
                            KimchiParamsType::commitment_params_type, BatchSize,
                                                                W0, W1, W2, W3,
                                                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;*/

                    using proof_binding =
                        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;
                    using pickles_instance_type = instance_type_t<BlueprintFieldType, KimchiParamsType>;
                    using proof_type = proof_type<BlueprintFieldType, KimchiParamsType>;
                    using deferred_values_type = deferred_values_type<BlueprintFieldType>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;
                        for (std::size_t i = 0; i < list_size; i++) {

                            row += endo_scalar_component::rows_amount;
                            row += endo_scalar_component::rows_amount;
                            row += endo_scalar_component::rows_amount;
                            row += mul_component::rows_amount;
                            if (KimchiParamsType::circuit_params::use_lookup) {
                                row += endo_scalar_component::rows_amount;
                            }
                            row += combined_evals_component::rows_amount;
                            row += scalars_env_component::rows_amount;
                            row += derive_plonk_component::rows_amount;
                            for (std::size_t j = 0; j < list_size; j++) {
                                row += endo_scalar_component::rows_amount;
                            }
                            row += transcript_type::init_rows;
                            for (std::size_t j = 0; j < list_size; j++) {
                                row += transcript_type::absorb_rows;
                            }
                            row += transcript_type::challenge_rows;

                            row += transcript_type::init_rows;
                            row += transcript_type::absorb_rows;
                            row += transcript_type::absorb_rows;

                            row += transcript_type::absorb_split_evaluations_rows;

                            row += transcript_type::challenge_rows;
                            row += transcript_type::challenge_rows;

                            row += cip_component::rows_amount;

                            for (std::size_t j = 0; j < list_size; j++) {
                                row += endo_scalar_component::rows_amount;
                            }

                            row += b_poly_component::rows_amount;

                            row += b_poly_component::rows_amount;
                            row += mul_component::rows_amount;
                            row += add_component::rows_amount;

                            row += prepare_scalars_inversion_component::rows_amount;

                            row += prepare_scalars_inversion_component::rows_amount;
                        }
                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<pickles_instance_type, BatchSize> ts;

                        // typename proof_binding::template fr_data<var, BatchSize> fr_data;
                        // typename proof_binding::template fq_data<var> fq_data;

                        // std::array<typename proof_binding::fq_sponge_output, BatchSize> &fq_output;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);
                        for (std::size_t i = 0; i < list_size; i++) {
                            pickles_instance_type instance = params.ts[i];
                            typename proof_type::statement_type statement =
                                instance.proof.statement;
                            typename proof_type::statement_type::proof_state_type proof_state =
                                statement.proof_state;
                            typename proof_type::prev_evals_type evals =
                                instance.proof.prev_evals;
                            deferred_values_type deferred_values = proof_state.deferred_values;

                            auto def_values_xi = endo_scalar_component::generate_circuit(
                                bp, assignment,
                                {
                                    deferred_values.xi,
                                },
                                row)
                                .output;
                            row += endo_scalar_component::rows_amount;
                            auto zeta = endo_scalar_component::generate_circuit(
                                bp, assignment,
                                {
                                    deferred_values.plonk.zeta,
                                },
                                row)
                                .output;
                            row += endo_scalar_component::rows_amount;
                            auto alpha = endo_scalar_component::generate_circuit(
                                bp, assignment,
                                {
                                    deferred_values.plonk.alpha,
                                },
                                row)
                                .output;
                            row += endo_scalar_component::rows_amount;
                            auto w = get_domain_root(
                                start_row_index,
                                deferred_values.branch_data.domain_log2
                            );
                            auto zetaw =
                                zk::components::generate_circuit<mul_component>(
                                    bp, assignment,
                                    {
                                        zeta,
                                        w
                                    },
                                    row)
                                    .output;
                            row += mul_component::rows_amount;
                            var min_poly_joint_combiner;
                            if (KimchiParamsType::circuit_params::use_lookup) {
                                min_poly_joint_combiner =
                                    endo_scalar_component::generate_circuit(
                                        bp, assignment,
                                        {
                                            deferred_values.plonk.joint_combiner,
                                        },
                                        row)
                                        .output;
                                row += endo_scalar_component::rows_amount;
                            }
                            pickles_plonk_min min_poly = {
                                alpha,
                                deferred_values.plonk.beta,
                                deferred_values.plonk.gamma,
                                zeta,
                                min_poly_joint_combiner,
                            };

                            auto tick_combined_evals =
                                combined_evals_component::generate_circuit(
                                    bp, assignment, {evals.evals.evals, {zeta, zetaw}}, row)
                                    .output;
                            row += combined_evals_component::rows_amount;

                            auto env = scalars_env_component::generate_circuit(
                                bp, assignment,
                                {
                                    min_poly,
                                    w,
                                    deferred_values.branch_data.domain_log2
                                },
                                row).output;
                            row += scalars_env_component::rows_amount;

                            auto plonk = derive_plonk_component::generate_circuit(
                                bp, assignment,
                                {
                                    min_poly,
                                    env,
                                    tick_combined_evals,
                                },
                                row).output;
                            row += derive_plonk_component::rows_amount;

                            plonk.alpha = min_poly.alpha;
                            plonk.beta = min_poly.beta;
                            plonk.gamma = min_poly.gamma;
                            plonk.zeta = min_poly.zeta;
                            if (KimchiParamsType::circuit_params::use_lookup) {
                                plonk.lookup.joint_combiner = min_poly.joint_combiner;
                            }

                            std::array<std::vector<var>, 16> old_bulletproof_challenges;
                            for (std::size_t j = 0; j < old_bulletproof_challenges.size(); j++) {
                                for (std::size_t k = 0; k < old_bulletproof_challenges[j].size(); k++) {
                                    old_bulletproof_challenges[j].push_back(
                                        endo_scalar_component::generate_circuit(
                                            bp, assignment,
                                            {statement.messages_for_next_step_proof.old_bulletproof_challenges[j][k]},
                                            row)
                                            .output);
                                    row += endo_scalar_component::rows_amount;
                                }
                            }

                            transcript_type bulletproofs_transcript;
                            bulletproofs_transcript.init_circuit(bp, assignment, zero, row);
                            row += transcript_type::init_rows;
                            for (std::size_t j = 0; j < old_bulletproof_challenges.size(); j++) {
                                for (std::size_t k = 0; k < old_bulletproof_challenges[j].size(); k++) {
                                    bulletproofs_transcript.absorb_circuit(
                                        bp, assignment, old_bulletproof_challenges[j][k], row);
                                    row += transcript_type::absorb_rows;
                                }
                            }
                            var challenges_digest = bulletproofs_transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;

                            transcript_type transcript;
                            transcript.init_circuit(bp, assignment, zero, row);
                            row += transcript_type::init_rows;
                            transcript.absorb_circuit(
                                bp, assignment, proof_state.sponge_digest_before_evaluations, row);
                            row += transcript_type::absorb_rows;
                            transcript.absorb_circuit(bp, assignment, challenges_digest, row);
                            row += transcript_type::absorb_rows;

                            transcript.absorb_split_evaluations_circuit(bp, assignment, evals, row);
                            row += transcript_type::absorb_split_evaluations_rows;

                            var xi_actual_challenge = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;
                            var r_actual_challenge = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;

                            var combined_inner_product_actual =
                                cip_component::generate_circuit(bp, assignment,
                                                                {r_actual_challenge, min_poly,
                                                                 evals.ft_eval1,
                                                                 evals.evals},
                                                                row)
                                    .output;
                            row += cip_component::rows_amount;

                            std::array<var, 16> bulletproof_challenges;
                            for (std::size_t j = 0; j < old_bulletproof_challenges.size(); j++) {
                                bulletproof_challenges[j] =
                                    endo_scalar_component::generate_circuit(
                                        bp, assignment,
                                        {deferred_values.bulletproof_challenges[j]},
                                        row)
                                        .output;
                                row += endo_scalar_component::rows_amount;
                            }

                            auto chal_zeta = b_poly_component::generate_circuit(
                                                 bp, assignment, {bulletproof_challenges, zeta, one}, row)
                                                 .output;
                            row += b_poly_component::rows_amount;

                            auto chal_zetaw = b_poly_component::generate_circuit(
                                                  bp, assignment, {bulletproof_challenges, zetaw, one}, row)
                                                  .output;
                            row += b_poly_component::rows_amount;
                            auto t = zk::components::generate_circuit<mul_component>(
                                         bp, assignment, {chal_zetaw, r_actual_challenge}, row)
                                         .output;
                            row += mul_component::rows_amount;
                            auto b_actual =
                                zk::components::generate_circuit<add_component>(bp, assignment, {chal_zeta, t}, row)
                                    .output;
                            row += add_component::rows_amount;

                            auto shifted_combined_inner_product =
                                prepare_scalars_inversion_component::generate_circuit(
                                    bp, assignment,
                                    {deferred_values.combined_inner_product}, row)
                                    .output;
                            row += prepare_scalars_inversion_component::rows_amount;

                            auto shifted_b =
                                prepare_scalars_inversion_component::generate_circuit(
                                    bp, assignment, {deferred_values.b}, row)
                                    .output;
                            row += prepare_scalars_inversion_component::rows_amount;
                        }

                        /*kimchi_verify_component::generate_circuit(bp, assignment,
                            {params.fr_data, params.fq_data, params.ts[0].verifier_index, params.proof,
                        params.fq_output}, row); row += kimchi_verify_component::rows_amount;*/

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        assert(row == start_row_index + rows_amount);
                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);
                        for (std::size_t i = 0; i < list_size; i++) {
                            pickles_instance_type instance = params.ts[i];
                            typename proof_type::statement_type statement =
                                instance.proof.statement;
                            typename proof_type::statement_type::proof_state_type proof_state =
                                statement.proof_state;
                            typename proof_type::prev_evals_type evals =
                                instance.proof.prev_evals;
                            deferred_values_type deferred_values = proof_state.deferred_values;

                            auto def_values_xi =
                                endo_scalar_component::generate_assignments(
                                    assignment, {deferred_values.xi}, row)
                                    .output;
                            row += endo_scalar_component::rows_amount;
                            auto zeta = endo_scalar_component::generate_assignments(
                                assignment,
                                {
                                    deferred_values.plonk.zeta,
                                },
                                row)
                                .output;
                            row += endo_scalar_component::rows_amount;
                            auto alpha = endo_scalar_component::generate_assignments(
                                assignment,
                                {
                                    deferred_values.plonk.alpha,
                                },
                                row)
                                .output;
                            row += endo_scalar_component::rows_amount;

                            auto w = get_domain_root(
                                start_row_index,
                                deferred_values.branch_data.domain_log2
                            );
                            auto zetaw =
                                mul_component::generate_assignments(
                                    assignment,
                                    {
                                        zeta,
                                        w
                                    },
                                    row)
                                    .output;
                            row += mul_component::rows_amount;
                            var min_poly_joint_combiner;
                            if (KimchiParamsType::circuit_params::use_lookup) {
                                min_poly_joint_combiner =
                                    endo_scalar_component::generate_assignments(
                                        assignment,
                                        {deferred_values.plonk.joint_combiner}, row)
                                        .output;
                                row += endo_scalar_component::rows_amount;
                            }
                            pickles_plonk_min min_poly = {
                                alpha,
                                deferred_values.plonk.beta,
                                deferred_values.plonk.gamma,
                                zeta,
                                min_poly_joint_combiner
                            };

                            auto tick_combined_evals =
                                combined_evals_component::generate_assignments(
                                    assignment, {evals.evals.evals, {zeta, zetaw}}, row)
                                    .output;
                            row += combined_evals_component::rows_amount;

                            auto env = scalars_env_component::generate_assignments(
                                assignment,
                                {
                                    min_poly,
                                    w,
                                    deferred_values.branch_data.domain_log2
                                },
                                row).output;
                            row += scalars_env_component::rows_amount;

                            auto plonk = derive_plonk_component::generate_assignments(
                                assignment,
                                {
                                    min_poly,
                                    env,
                                    tick_combined_evals,
                                },
                                row).output;
                            row += derive_plonk_component::rows_amount;

                            plonk.alpha = min_poly.alpha;
                            plonk.beta = min_poly.beta;
                            plonk.gamma = min_poly.gamma;
                            plonk.zeta = min_poly.zeta;
                            if (KimchiParamsType::circuit_params::use_lookup) {
                                plonk.lookup.joint_combiner = min_poly.joint_combiner;
                            }

                            std::array<std::vector<var>, 16> old_bulletproof_challenges;
                            for (std::size_t j = 0; j < old_bulletproof_challenges.size(); j++) {
                                for (std::size_t k = 0; k < old_bulletproof_challenges[j].size(); k++) {
                                    old_bulletproof_challenges[j].push_back(
                                        endo_scalar_component::generate_assignments(
                                            assignment,
                                            {statement.messages_for_next_step_proof.old_bulletproof_challenges[j]},
                                            row)
                                            .output);
                                    row += endo_scalar_component::rows_amount;
                                }
                            }

                            transcript_type bulletproofs_transcript;
                            bulletproofs_transcript.init_assignment(assignment, zero, row);
                            row += transcript_type::init_rows;
                            for (std::size_t j = 0; j < old_bulletproof_challenges.size(); j++) {
                                for (std::size_t k = 0; k < old_bulletproof_challenges[j].size(); k++) {
                                    bulletproofs_transcript.absorb_assignment(
                                        assignment, old_bulletproof_challenges[j][k], row);
                                    row += transcript_type::absorb_rows;
                                }
                            }
                            var challenges_digest = bulletproofs_transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            transcript_type transcript;
                            transcript.init_assignment(assignment, zero, row);
                            row += transcript_type::init_rows;
                            transcript.absorb_assignment(
                                assignment, proof_state.sponge_digest_before_evaluations, row);
                            row += transcript_type::absorb_rows;
                            transcript.absorb_assignment(assignment, challenges_digest, row);
                            row += transcript_type::absorb_rows;

                            transcript.absorb_split_evaluations_assignment(assignment, evals, row);
                            row += transcript_type::absorb_split_evaluations_rows;

                            var xi_actual_challenge = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;
                            var r_actual_challenge = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            var combined_inner_product_actual =
                                cip_component::generate_assignments(assignment,
                                                                    {r_actual_challenge, min_poly,
                                                                     evals.ft_eval1,
                                                                     evals.evals},
                                                                    row)
                                    .output;
                            row += cip_component::rows_amount;

                            std::array<var, 16> bulletproof_challenges;
                            for (std::size_t j = 0; j < old_bulletproof_challenges.size(); j++) {
                                bulletproof_challenges[j] =
                                    endo_scalar_component::generate_assignments(
                                        assignment,
                                        {deferred_values.bulletproof_challenges[j]},
                                        row)
                                        .output;
                                row += endo_scalar_component::rows_amount;
                            }

                            auto chal_zeta = b_poly_component::generate_assignments(
                                                 assignment, {bulletproof_challenges, zeta, one}, row)
                                                 .output;
                            row += b_poly_component::rows_amount;

                            auto chal_zetaw = b_poly_component::generate_assignments(
                                                  assignment, {bulletproof_challenges, zetaw, one}, row)
                                                  .output;
                            row += b_poly_component::rows_amount;

                            auto t =
                                mul_component::generate_assignments(assignment, {chal_zetaw, r_actual_challenge}, row)
                                    .output;
                            row += mul_component::rows_amount;

                            auto b_actual = add_component::generate_assignments(assignment, {chal_zeta, t}, row).output;
                            row += add_component::rows_amount;

                            auto shifted_combined_inner_product =
                                prepare_scalars_inversion_component::generate_assignments(
                                    assignment,
                                    {deferred_values.combined_inner_product}, row)
                                    .output;
                            row += prepare_scalars_inversion_component::rows_amount;

                            auto shifted_b =
                                prepare_scalars_inversion_component::generate_assignments(
                                    assignment, {deferred_values.b}, row)
                                    .output;
                            row += prepare_scalars_inversion_component::rows_amount;
                        }

                        /*batch_verify_component::generate_assignments(assignment,
                            {instance.proof.statement.proof_state.deferred_values.bulletproof_challenges}, row);
                        row += batch_verify_component::rows_amount;

                        kimchi_verify_component::generate_assignments(assignment,
                            {params.fr_data, params.fq_data, verifier_index, params.proof, params.fq_output},
                            row);
                        row += kimchi_verify_component::rows_amount;*/
                        assert(row == start_row_index + rows_amount);
                        return result_type();
                    }

                private:
                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        // endo scalar components should take up enough space so that this does not conflict with any subcomponents
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                        // 2^k-th roots of unity
                        for (size_t i = 2; i < (1 << 17); i <<= 1) {
                            assignment.constant(0)[row] = nil::crypto3::math::unity_root<BlueprintFieldType>(i);
                            row++;
                        }
                    }

                    static var get_domain_root(
                            const std::size_t start_row_index,
                            const std::size_t domain_size_log2) {
                        assert (domain_size_log2 < 17);
                        return var(0, start_row_index + domain_size_log2, false, var::column_type::constant);
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_SCALAR_HPP