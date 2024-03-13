//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Placeholder verifier circuit component
//---------------------------------------------------------------------------//

#ifndef BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_VERIFIER_HPP
#define BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_VERIFIER_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/profiling.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/systems/snark/plonk/verifier/proof_wrapper.hpp>
#include <nil/blueprint/components/systems/snark/plonk/verifier/proof_input_type.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/poseidon.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/swap.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType>
            class plonk_flexible_verifier: public plonk_component<BlueprintFieldType>{
            public:
                using component_type =  plonk_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;
                using poseidon_component_type = plonk_flexible_poseidon<BlueprintFieldType>;
                using swap_component_type = plonk_flexible_swap<BlueprintFieldType>;
                using placeholder_info_type = nil::crypto3::zk::snark::placeholder_info;

                std::size_t rows_amount;
                std::size_t fri_params_r;
                std::size_t fri_params_lambda;
                value_type fri_omega;
                std::size_t fri_domain_size;
                std::size_t fri_initial_merkle_proof_size;
                placeholder_info_type placeholder_info;

                struct challenges{
                    var eta;
                    var perm_beta;
                    var perm_gamma;
                    var lookup_theta;
                    var lookup_gamma;
                    var lookup_beta;
                    std::vector<var> lookup_alphas;
                    var gate_theta;
                    std::array<var, 8> alphas;
                    std::vector<var> fri_alphas;
                    std::vector<var> fri_xs;
                    var lpc_theta;
                    var xi;
                };

                struct input_type {
                    std::vector<var> proof;
                    std::vector<var> commitments;
                    std::vector<var> fri_roots;
                    std::vector<std::vector<var>> merkle_tree_positions;
                    std::vector<std::vector<var>> initial_proof_values;
                    std::vector<std::vector<var>> initial_proof_hashes;
                    std::vector<std::vector<var>> round_proof_values;
                    std::vector<std::vector<var>> round_proof_hashes;
                    var challenge;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(proof.size());
                        result.insert(result.end(), proof.begin(), proof.end());

                        return result;
                    }

                    template<typename SrcParams>
                    input_type(detail::placeholder_proof_input_type<SrcParams> proof_input){
                        proof = proof_input.vector();
                        commitments = proof_input.commitments();
                        fri_roots = proof_input.fri_roots();
                        challenge = proof_input.challenge();
                        merkle_tree_positions = proof_input.merkle_tree_positions();
                        initial_proof_values = proof_input.initial_proof_values();
                        initial_proof_hashes = proof_input.initial_proof_hashes();
                        round_proof_values = proof_input.round_proof_values();
                        round_proof_hashes = proof_input.round_proof_hashes();
                    }
                };
                struct result_type {
                    static constexpr std::size_t output_size = 1;
                    std::array<var, output_size> output = {var(0, 0, false)};

                    result_type(std::uint32_t start_row_index) {
                        output[0] = var(0, start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), output.begin(), output.end());
                        return result;
                    }
                };

                using manifest_type = plonk_component_manifest;

                static const std::size_t gates_amount = 0;

                class gate_manifest_type : public component_gate_manifest {
                    std::size_t num_gates;
                public:
                    gate_manifest_type(std::size_t witness_amount){
                        std::cout << "Verifier gate_manifet_type constructor with witness = " << witness_amount << std::endl;
                        num_gates = poseidon_component_type::get_gate_manifest(witness_amount, 0).get_gates_amount();
                        std::cout << "Swap component gates " << 1 << std::endl;
                        num_gates += 1; // Swap component
                    }
                    std::uint32_t gates_amount() const override {
                        std::cout << "Verifier gates_amount " << num_gates << std::endl;
                        return num_gates;
                    }
                };

                template <typename SrcParams>
                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    std::size_t lookup_column_amount,
                    SrcParams src_params,
                    const typename SrcParams::constraint_system_type &constraint_system,
                    const typename SrcParams::common_data_type &common_data,
                    const typename SrcParams::fri_params_type &fri_params
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(5)),
                        false
                    );
                    return manifest;
                }

                template <typename SrcParams>
                constexpr static std::size_t get_rows_amount(
                    std::size_t witness_amount,
                    std::size_t lookup_column_amount,
                    SrcParams src_params,
                    const typename SrcParams::constraint_system_type &constraint_system,
                    const typename SrcParams::common_data_type &common_data,
                    const typename SrcParams::fri_params_type &fri_params
                ) {
                    return 100;
                }

                template <
                    typename WitnessContainerType,
                    typename ConstantContainerType,
                    typename PublicInputContainerType,
                    typename SrcParams
                >
                plonk_flexible_verifier(
                    WitnessContainerType witnesses,
                    ConstantContainerType constants,
                    PublicInputContainerType public_inputs,
                    SrcParams src_params,
                    const typename SrcParams::constraint_system_type &constraint_system,
                    const typename SrcParams::common_data_type &common_data,
                    const typename SrcParams::fri_params_type &fri_params
                ):  component_type(witnesses, constants, public_inputs, get_manifest())
                {
                    placeholder_info = nil::crypto3::zk::snark::prepare_placeholder_info<typename SrcParams::placeholder_params>(
                        constraint_system,
                        common_data, fri_params,
                        SrcParams::WitnessColumns + SrcParams::PublicInputColumns + SrcParams::ComponentConstantColumns
                    );
                    rows_amount = 500000; // TODO: count rows carefully
                    vk0 = common_data.vk.constraint_system_with_params_hash;
                    vk1 = common_data.vk.fixed_values_commitment;
                    fri_params_r = fri_params.r;
                    fri_params_lambda = SrcParams::Lambda;
                    fri_omega = fri_params.D[0]->get_domain_element(1);
                    fri_domain_size = fri_params.D[0]->size();
                    fri_initial_merkle_proof_size = log2(fri_params.D[0]->m) - 1;
                    // Change after implementing minimized permutation_argument
                }

                std::vector<std::uint32_t> all_witnesses() const{
                    return this->_W;
                }

                typename BlueprintFieldType::value_type vk0;
                typename BlueprintFieldType::value_type vk1;
            };

            template<typename BlueprintFieldType>
            typename plonk_flexible_verifier<BlueprintFieldType>::result_type
            generate_assignments(
                const plonk_flexible_verifier<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_flexible_verifier<BlueprintFieldType>::input_type instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_flexible_verifier<BlueprintFieldType>;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using swap_component_type = typename component_type::swap_component_type;
                using var = typename component_type::var;

                typename component_type::challenges challenges;

                std::size_t row = start_row_index;
                std::cout << "Generate assignments" << std::endl;

                const typename component_type::result_type result(start_row_index);
                // Set constants
                assignment.constant(component.C(0),start_row_index) = typename BlueprintFieldType::value_type(0);
                assignment.constant(component.C(0),start_row_index+1) = typename BlueprintFieldType::value_type(1);
                assignment.constant(component.C(0),start_row_index+2) = component.vk0;
                assignment.constant(component.C(0),start_row_index+3) = component.vk1;

                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                var vk0_var = var(component.C(0), start_row_index+2, false, var::column_type::constant);
                var vk1_var = var(component.C(0), start_row_index+3, false, var::column_type::constant);

                typename poseidon_component_type::input_type poseidon_input = {zero_var, vk0_var, vk1_var};
                poseidon_component_type poseidon_instance(component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>());
                std::cout << "Poseidon prepared" << std::endl;
                auto poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);

                typename swap_component_type::input_type swap_input;
                std::vector<std::pair<var, var>> swapped_vars;

                challenges.eta = poseidon_output.output_state[2];
                auto variable_value_var = instance_input.commitments[0];
                row += poseidon_instance.rows_amount;

                poseidon_input = {challenges.eta, variable_value_var, zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.perm_beta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                poseidon_input = {challenges.perm_beta, zero_var, zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.perm_gamma = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                // TODO: if use_lookups
                poseidon_input = {challenges.perm_gamma, instance_input.commitments[1], zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.gate_theta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                for(std::size_t i = 0; i < 8; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    challenges.alphas[i] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                }

                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[2], zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.xi = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;
                BOOST_ASSERT(var_value(assignment, challenges.xi) == var_value(assignment, instance_input.challenge));

                poseidon_input = {poseidon_output.output_state[2], vk1_var, instance_input.commitments[0]};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                row += poseidon_instance.rows_amount;

                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[1], instance_input.commitments[2]};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.lpc_theta = poseidon_output.output_state[2];
                std::cout << "lpc_theta = " << var_value(assignment, challenges.lpc_theta) << std::endl;
                row += poseidon_instance.rows_amount;

                // TODO: if use_lookups state[1] should be equal to sorted polynomial commitment
                // poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                // poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                // row += poseidon_instance.rows_amount;

                for( std::size_t i = 0; i < component.fri_params_r; i+=1){
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    challenges.fri_alphas.push_back(poseidon_output.output_state[2]);
                    std::cout << "alpha_challenge = " << var_value(assignment, challenges.fri_alphas[i]) << std::endl;
                    row += poseidon_instance.rows_amount;
                }

                for( std::size_t i = 0; i < component.fri_params_lambda; i+=1){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    challenges.fri_xs.push_back(poseidon_output.output_state[2]);
                    std::cout << "x_challenge = " << var_value(assignment, challenges.fri_xs[i]) << std::endl;
                    row += poseidon_instance.rows_amount;
                }
/*
                std::cout << "Check table values" << std::endl;
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    // Just check x_index and merkle proof correspondense
                    std::size_t x_index = 0;
                    std::size_t factor = 1;
                    for( std::size_t j = 0; j < instance_input.merkle_tree_positions[i].size(); j++){
                        std::cout << var_value(assignment, instance_input.merkle_tree_positions[i][j]) << " ";
                        if( var_value(assignment, instance_input.merkle_tree_positions[i][j]) == 0 ) x_index += factor;
                        factor *= 2;
                    }
                    std::cout << " => " << x_index << std::endl;
                    auto fri_omega = component.fri_omega;
                    auto fri_domain_size = component.fri_domain_size;
                    std::cout << fri_omega << std::endl;
                    std::cout << x_index << " => " << fri_omega.pow(x_index) << std::endl;
                    std::cout << x_index + fri_domain_size/2  << " => " << -fri_omega.pow(x_index) << std::endl;
                    std::cout << var_value(assignment, challenges.fri_xs[i]).pow((BlueprintFieldType::modulus-1)/fri_domain_size) << std::endl;
                }
*/
                // Query proof check
                // Construct Merkle leaves and accumulate everything to swap_input
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    // Initial proof merkle leaf
                    std::size_t cur = 0;
                    std::size_t cur_hash = 0;
                    std::cout << "Query " << i << std::endl;
                    for( std::size_t j = 0; j < component.placeholder_info.batches_num; j++){
                        poseidon_input.input_state[0] = zero_var;
                        for( std::size_t k = 0; k < component.placeholder_info.batches_sizes[j]; k++, cur+=2){
                            poseidon_input.input_state[1] = instance_input.initial_proof_values[i][cur];
                            poseidon_input.input_state[2] = instance_input.initial_proof_values[i][cur+1];
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            poseidon_input.input_state[0] = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                        }
//                        std::cout << "Merkle leaf " << var_value(assignment, poseidon_output.output_state[2]) << std::endl;
                        var hash_var = poseidon_output.output_state[2];
//                        std::cout << "First hash i = " << i << "; cur_hash = " << cur_hash << " = " << instance_input.initial_proof_hashes[i][cur_hash] << " = " << var_value(assignment, instance_input.initial_proof_hashes[i][cur_hash]) << std::endl;
                        for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size; k++){
                            assignment.witness(component.W(1), row) = var_value(assignment, instance_input.merkle_tree_positions[i][k]) == 0? var_value(assignment, instance_input.initial_proof_hashes[i][cur_hash]): var_value(assignment, hash_var);
                            assignment.witness(component.W(2), row) = var_value(assignment, instance_input.merkle_tree_positions[i][k]) == 0? var_value(assignment, hash_var) : var_value(assignment, instance_input.initial_proof_hashes[i][cur_hash]);
                            poseidon_input = {zero_var, var(component.W(1),row, false), var(component.W(2),row, false)};
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
//                            std::cout << "\t("
//                                << var_value(assignment, poseidon_input.input_state[1]) << ", "
//                                << var_value(assignment, poseidon_input.input_state[2]) << ", "
//                                << ") => " << var_value(assignment, poseidon_output.output_state[2]) << std::endl;
                            swap_input.arr.push_back({instance_input.merkle_tree_positions[i][k], hash_var, instance_input.initial_proof_hashes[i][cur_hash]});
                            swapped_vars.push_back({var(component.W(1),row, false), var(component.W(2),row, false)});
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                            row += poseidon_instance.rows_amount;
                        }
                    }
                    // Round proofs
                    cur = 0;
                    cur_hash = 0;
                    var hash_var;
                    var y0;
                    var y1;
                    for( std::size_t j = 0; j < component.fri_params_r; j++){
                        if(j != 0){
                            poseidon_input = {zero_var, y0, y1};
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            hash_var = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                            for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size - j; k++){
                                assignment.witness(component.W(1), row) = var_value(assignment, instance_input.merkle_tree_positions[i][k]) == 0? var_value(assignment, instance_input.round_proof_hashes[i][cur_hash]): var_value(assignment, hash_var);
                                assignment.witness(component.W(2), row) = var_value(assignment, instance_input.merkle_tree_positions[i][k]) == 0? var_value(assignment, hash_var) : var_value(assignment, instance_input.round_proof_hashes[i][cur_hash]);
                                poseidon_input = {zero_var, var(component.W(1),row, false), var(component.W(2),row, false)};
                                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                                swap_input.arr.push_back({instance_input.merkle_tree_positions[i][k], hash_var, instance_input.round_proof_hashes[i][cur_hash]});
                                swapped_vars.push_back({var(component.W(1),row, false), var(component.W(2),row, false)});
                                row += poseidon_instance.rows_amount;
                                hash_var = poseidon_output.output_state[2];
                                cur_hash++;
                            }
                        }
                        else {
                            // TODO remove it when 1st round will be ready
                            cur_hash += component.fri_initial_merkle_proof_size;
                        }
                        y0 = instance_input.round_proof_values[i][cur*2];
                        y1 = instance_input.round_proof_values[i][cur*2 + 1];
                        cur++;
                    }
                }

                swap_component_type swap_instance(
                    component.all_witnesses(),
                    std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>(),
                    swap_input.arr.size()
                );
                std::cout << "Swap prepared size = " << swap_input.arr.size() << "check copy constraints" << std::endl;
                typename swap_component_type::result_type swap_output = generate_assignments(swap_instance, assignment, swap_input, row);
                for( std::size_t i = 0; i < swap_input.arr.size(); i++){
//                    std::cout << "\t"
//                        << var_value(assignment, std::get<0>(swap_input.arr[i])) << ", "
//                        << var_value(assignment, std::get<1>(swap_input.arr[i])) << ", "
//                        << var_value(assignment, std::get<2>(swap_input.arr[i])) << std::endl;
//                    std::cout << "\t" << var_value(assignment, swap_output.output[i].first) << ", " <<  var_value(assignment, swapped_vars[i].second) << "\n";
//                    std::cout << "\t" << var_value(assignment, swap_output.output[i].second) << ", " << var_value(assignment, swapped_vars[i].first) << std::endl;
                }
                row += swap_instance.rows_amount;

                std::cout << "Generated assignments real rows for " << component.all_witnesses().size() << " witness  = " << row - start_row_index << std::endl << std::endl << std::endl;
                return result;
            }


            template<typename BlueprintFieldType>
            const typename plonk_flexible_verifier<BlueprintFieldType>::result_type
            generate_circuit(
                const plonk_flexible_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_flexible_verifier<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index
            ) {
                std::cout << "Generate circuit" << std::endl;
                using component_type = plonk_flexible_verifier<BlueprintFieldType>;
                using var = typename component_type::var;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using swap_component_type = typename component_type::swap_component_type;
                typename component_type::challenges challenges;

                std::size_t row = start_row_index;

                const typename plonk_flexible_verifier<BlueprintFieldType>::result_type result(start_row_index);
                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                var vk0_var = var(component.C(0), start_row_index+2, false, var::column_type::constant);
                var vk1_var = var(component.C(0), start_row_index+3, false, var::column_type::constant);

                typename poseidon_component_type::input_type poseidon_input = {zero_var, vk0_var, vk1_var};
                poseidon_component_type poseidon_instance(component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>());
                auto poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);

                typename swap_component_type::input_type swap_input;
                std::vector<std::pair<var, var>> swapped_vars;

                challenges.eta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                poseidon_input = {challenges.eta, instance_input.commitments[0], zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.perm_beta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                poseidon_input = {challenges.perm_beta, zero_var, zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.perm_gamma = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                //TODO if use_lookups

                poseidon_input = {challenges.perm_gamma, instance_input.commitments[1], zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.gate_theta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                for(std::size_t i = 0; i < 8; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    challenges.alphas[i] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                }
                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[2], zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.xi = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                bp.add_copy_constraint({challenges.xi, instance_input.challenge});

                poseidon_input = {poseidon_output.output_state[2], vk1_var, instance_input.commitments[0]};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                row += poseidon_instance.rows_amount;

                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[1], instance_input.commitments[2]};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.lpc_theta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                // TODO: if use_lookups state[1] should be equal to sorted polynomial commitment
                // poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                // poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                // row += poseidon_instance.rows_amount;

                for( std::size_t i = 0; i < component.fri_params_r; i++){
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    challenges.fri_alphas.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    challenges.fri_xs.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                // Query proof check
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    std::cout << "Query proof " << i << std::endl;
                    // Initial proof merkle leaf
                    std::size_t cur = 0;
                    std::size_t cur_hash = 0;
                    for( std::size_t j = 0; j < component.placeholder_info.batches_num; j++){
                        poseidon_input.input_state[0] = zero_var;
                        for( std::size_t k = 0; k < component.placeholder_info.batches_sizes[j]; k++, cur+=2){
                            poseidon_input.input_state[1] = instance_input.initial_proof_values[i][cur];
                            poseidon_input.input_state[2] = instance_input.initial_proof_values[i][cur+1];
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            poseidon_input.input_state[0] = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                        }
                        var hash_var = poseidon_output.output_state[2];
                        for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size; k++){
                            poseidon_input = {zero_var, var(component.W(1),row, false), var(component.W(2),row, false)};
                            swapped_vars.push_back({poseidon_input.input_state[1], poseidon_input.input_state[2]});
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            swap_input.arr.push_back({instance_input.merkle_tree_positions[i][k], hash_var, instance_input.initial_proof_hashes[i][cur_hash]});
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                            row += poseidon_instance.rows_amount;
                        }
                        if( j == 0 )
                            bp.add_copy_constraint({poseidon_output.output_state[2], vk1_var});
                        else
                            bp.add_copy_constraint({poseidon_output.output_state[2], instance_input.commitments[j-1]});
                    }
                    // Compute y-s for first round
                    std::size_t round_merkle_proof_size = component.fri_initial_merkle_proof_size;
                    // Round proofs
                    cur = 0;
                    cur_hash = 0;
                    var hash_var;
                    var y0;
                    var y1;

                    for( std::size_t j = 0; j < component.fri_params_r; j++){
                        if(j != 0){
                            poseidon_input = {zero_var, y0, y1};
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            hash_var = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                            for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size - j; k++){
                                poseidon_input = {zero_var, var(component.W(1),row, false), var(component.W(2),row, false)};
                                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                                swap_input.arr.push_back({instance_input.merkle_tree_positions[i][k], hash_var, instance_input.round_proof_hashes[i][cur_hash]});
                                swapped_vars.push_back({var(component.W(1),row, false), var(component.W(2),row, false)});
                                row += poseidon_instance.rows_amount;
                                hash_var = poseidon_output.output_state[2];
                                cur_hash++;
                            }
                            bp.add_copy_constraint({poseidon_output.output_state[2], instance_input.fri_roots[j]});
                        } else {
                            cur_hash += component.fri_initial_merkle_proof_size;
                        }
                        y0 = instance_input.round_proof_values[i][cur*2];
                        y1 = instance_input.round_proof_values[i][cur*2 + 1];
                        cur++;
                    }
                }

                swap_component_type swap_instance(
                    component.all_witnesses(),
                    std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>(),
                    swap_input.arr.size()
                );
                std::cout << "Swap prepared size = " << swap_input.arr.size() << std::endl;
                typename swap_component_type::result_type swap_output = generate_circuit(swap_instance, bp, assignment, swap_input, row);
                for( std::size_t i = 0; i < swap_input.arr.size(); i++){
                    bp.add_copy_constraint({swap_output.output[i].first, swapped_vars[i].second});
                    bp.add_copy_constraint({swap_output.output[i].second, swapped_vars[i].first});
                    row += swap_instance.rows_amount;
                }

                std::cout << "Circuit generated real rows = " << row - start_row_index << std::endl;
                return result;
            }
        }
    }
}

#endif