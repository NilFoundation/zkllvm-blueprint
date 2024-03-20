//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for top-level SHA256 components.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_COMPONENT_HPP

#include <nil/crypto3/container/merkle/proof.hpp>
#include <nil/blueprint/components/hashes/hash_io.hpp>

#include <nil/blueprint/components/hashes/sha2/r1cs/sha256_construction.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            /**
             * Component for the SHA256 compression function.
             */
            template<typename FieldType>
            class sha256_compression_function_component : public component<FieldType> {
            public:
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_a;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_b;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_c;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_d;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_e;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_f;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_g;
                std::vector<detail::blueprint_linear_combination_vector<FieldType>> round_h;

                detail::blueprint_variable_vector<FieldType> packed_W;
                std::shared_ptr<sha256_message_schedule_component<FieldType>> message_schedule;
                std::vector<sha256_round_function_component<FieldType>> round_functions;

                detail::blueprint_variable_vector<FieldType> unreduced_output;
                detail::blueprint_variable_vector<FieldType> reduced_output;
                std::vector<lastbits_component<FieldType>> reduce_output;

            public:
                detail::blueprint_linear_combination_vector<FieldType> prev_output;
                detail::blueprint_variable_vector<FieldType> new_block;
                digest_variable<FieldType> output;

                sha256_compression_function_component(
                    blueprint<FieldType> &bp,
                    const detail::blueprint_linear_combination_vector<FieldType> &prev_output,
                    const detail::blueprint_variable_vector<FieldType> &new_block,
                    const digest_variable<FieldType> &output) :
                    component<FieldType>(bp), prev_output(prev_output), new_block(new_block), output(output) {

                    /* message schedule and inputs for it */
                    packed_W.allocate(bp, crypto3::block::detail::shacal2_policy<256>::rounds);
                    message_schedule.reset(new sha256_message_schedule_component<FieldType>(bp, new_block, packed_W));

                    /* initalize */
                    round_a.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 7 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 8 * crypto3::hashes::sha2<256>::word_bits));
                    round_b.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 6 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 7 * crypto3::hashes::sha2<256>::word_bits));
                    round_c.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 5 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 6 * crypto3::hashes::sha2<256>::word_bits));
                    round_d.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 4 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 5 * crypto3::hashes::sha2<256>::word_bits));
                    round_e.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 3 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 4 * crypto3::hashes::sha2<256>::word_bits));
                    round_f.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 2 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 3 * crypto3::hashes::sha2<256>::word_bits));
                    round_g.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 1 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 2 * crypto3::hashes::sha2<256>::word_bits));
                    round_h.push_back(detail::blueprint_linear_combination_vector<FieldType>(
                        prev_output.rbegin() + 0 * crypto3::hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 1 * crypto3::hashes::sha2<256>::word_bits));

                    /* do the rounds */
                    for (std::size_t i = 0; i < crypto3::block::detail::shacal2_policy<256>::rounds; ++i) {
                        round_h.push_back(round_g[i]);
                        round_g.push_back(round_f[i]);
                        round_f.push_back(round_e[i]);
                        round_d.push_back(round_c[i]);
                        round_c.push_back(round_b[i]);
                        round_b.push_back(round_a[i]);

                        detail::blueprint_variable_vector<FieldType> new_round_a_variables;
                        new_round_a_variables.allocate(bp, crypto3::hashes::sha2<256>::word_bits);
                        round_a.emplace_back(new_round_a_variables);

                        detail::blueprint_variable_vector<FieldType> new_round_e_variables;
                        new_round_e_variables.allocate(bp, crypto3::hashes::sha2<256>::word_bits);
                        round_e.emplace_back(new_round_e_variables);

                        round_functions.push_back(sha256_round_function_component<FieldType>(
                            bp, round_a[i], round_b[i], round_c[i], round_d[i], round_e[i], round_f[i], round_g[i],
                            round_h[i], packed_W[i], crypto3::block::detail::shacal2_policy<256>::constants[i],
                            round_a[i + 1], round_e[i + 1]));
                    }

                    /* finalize */
                    unreduced_output.allocate(bp, 8);
                    reduced_output.allocate(bp, 8);
                    for (std::size_t i = 0; i < 8; ++i) {
                        reduce_output.push_back(lastbits_component<FieldType>(
                            bp,
                            unreduced_output[i],
                            crypto3::hashes::sha2<256>::word_bits + 1,
                            reduced_output[i],
                            detail::blueprint_variable_vector<FieldType>(
                                output.bits.rbegin() + (7 - i) * crypto3::hashes::sha2<256>::word_bits,
                                output.bits.rbegin() + (8 - i) * crypto3::hashes::sha2<256>::word_bits)));
                    }
                }
                void generate_gates() {
                    message_schedule->generate_gates();
                    for (std::size_t i = 0; i < crypto3::block::detail::shacal2_policy<256>::rounds; ++i) {
                        round_functions[i].generate_gates();
                    }

                    for (std::size_t i = 0; i < 4; ++i) {
                        this->bp.add_r1cs_constraint(crypto3::zk::snark::r1cs_constraint<FieldType>(
                            1,
                            round_functions[3 - i].packed_d + round_functions[63 - i].packed_new_a,
                            unreduced_output[i]));

                        this->bp.add_r1cs_constraint(crypto3::zk::snark::r1cs_constraint<FieldType>(
                            1,
                            round_functions[3 - i].packed_h + round_functions[63 - i].packed_new_e,
                            unreduced_output[4 + i]));
                    }

                    for (std::size_t i = 0; i < 8; ++i) {
                        reduce_output[i].generate_gates();
                    }
                }
                void generate_assignments() {
                    message_schedule->generate_assignments();

                    for (std::size_t i = 0; i < crypto3::block::detail::shacal2_policy<256>::rounds; ++i) {
                        round_functions[i].generate_assignments();
                    }

                    for (std::size_t i = 0; i < 4; ++i) {
                        this->bp.val(unreduced_output[i]) = this->bp.val(round_functions[3 - i].packed_d) +
                                                            this->bp.val(round_functions[63 - i].packed_new_a);
                        this->bp.val(unreduced_output[4 + i]) = this->bp.val(round_functions[3 - i].packed_h) +
                                                                this->bp.val(round_functions[63 - i].packed_new_e);
                    }

                    for (std::size_t i = 0; i < 8; ++i) {
                        reduce_output[i].generate_assignments();
                    }
                }
            };

            /**
             * Component for the SHA256 compression function, viewed as a 2-to-1 hash
             * function, and using the same initialization vector as in SHA256
             * specification. Thus, any collision for
             * sha256_two_to_one_hash_component trivially extends to a collision for
             * full SHA256 (by appending the same padding).
             */
            template<typename FieldType>
            class sha256_two_to_one_hash_component : public component<FieldType> {
            public:
                typedef std::vector<bool> hash_value_type;
                typedef digest_variable<FieldType> hash_variable_type;
                typedef crypto3::containers::merkle_proof<crypto3::hashes::sha2<256>, 2> merkle_authentication_path_type;

                std::shared_ptr<sha256_compression_function_component<FieldType>> f;

                sha256_two_to_one_hash_component(blueprint<FieldType> &bp,
                                                 const digest_variable<FieldType> &left,
                                                 const digest_variable<FieldType> &right,
                                                 const digest_variable<FieldType> &output) : component<FieldType>(bp) {

                    /* concatenate block = left || right */
                    detail::blueprint_variable_vector<FieldType> block;
                    block.insert(block.end(), left.bits.begin(), left.bits.end());
                    block.insert(block.end(), right.bits.begin(), right.bits.end());

                    /* compute the hash itself */
                    f.reset(new sha256_compression_function_component<FieldType>(bp, SHA256_default_IV<FieldType>(bp),
                                                                                 block, output));
                }
                sha256_two_to_one_hash_component(blueprint<FieldType> &bp,
                                                 std::size_t block_length,
                                                 const block_variable<FieldType> &input_block,
                                                 const digest_variable<FieldType> &output) : component<FieldType>(bp) {

                    assert(block_length == hashes::sha2<256>::block_bits);
                    assert(input_block.bits.size() == block_length);
                    f.reset(new sha256_compression_function_component<FieldType>(bp, SHA256_default_IV<FieldType>(bp),
                                                                                 input_block.bits, output));
                }

                void generate_gates(bool ensure_output_bitness = true) {    // TODO: ignored for now
                    f->generate_gates();
                }

                void generate_assignments() {
                    f->generate_assignments();
                }

                static std::size_t get_block_len() {
                    return crypto3::hashes::sha2<256>::block_bits;
                }

                static std::size_t get_digest_len() {
                    return crypto3::hashes::sha2<256>::digest_bits;
                }

                static std::vector<bool> get_hash(const std::vector<bool> &input) {
                    blueprint<FieldType> bp;

                    block_variable<FieldType> input_variable(bp, crypto3::hashes::sha2<256>::block_bits);
                    digest_variable<FieldType> output_variable(bp, crypto3::hashes::sha2<256>::digest_bits);
                    sha256_two_to_one_hash_component<FieldType> f(bp, crypto3::hashes::sha2<256>::block_bits,
                                                                  input_variable, output_variable);

                    input_variable.generate_assignments(input);
                    f.generate_assignments();

                    return output_variable.get_digest();
                }

                static std::size_t expected_constraints(bool ensure_output_bitness = true) {    // TODO: ignored for now
                    return 27280;                                                               /* hardcoded for now */
                }
            };

            /**
             * Component for arbitary length sha256 hash based on
             * Merkle-Damagard padding. (i.e. standard sha256).
             */
            template<typename FieldType>
            class sha256_hash_component : public component<FieldType> {
            public:
                typedef std::vector<bool> hash_value_type;
                typedef digest_variable<FieldType> hash_variable_type;
                typedef crypto3::containers::merkle_proof<crypto3::hashes::sha2<256>, 2> merkle_authentication_path_type;

                std::vector<std::shared_ptr<sha256_compression_function_component<FieldType>>> blocks_components;
                std::vector<detail::blueprint_variable_vector<FieldType>> blocks_bits;
                std::vector<std::shared_ptr<digest_variable<FieldType>>> intermediate_outputs;
                std::shared_ptr<merkle_damagard_padding<FieldType>> padding;

                sha256_hash_component(blueprint<FieldType> &bp,
                                      std::size_t input_len,
                                      const block_variable<FieldType> &block_input,
                                      const digest_variable<FieldType> &output) : component<FieldType>(bp) {

                    assert(input_len == block_input.block_size);
                    const int length_bits_size = 64;

                    padding.reset(new merkle_damagard_padding<FieldType>(bp, input_len, length_bits_size,
                                                                         crypto3::hashes::sha2<256>::block_bits));
                    detail::blueprint_variable_vector<FieldType> bits = block_input.bits;
                    bits.insert(bits.end(), padding->bits.begin(), padding->bits.end());
                    assert(bits.size() % crypto3::hashes::sha2<256>::block_bits == 0);
                    std::size_t num_blocks = bits.size() / crypto3::hashes::sha2<256>::block_bits;

                    intermediate_outputs.resize(num_blocks - 1);
                    blocks_components.resize(num_blocks);
                    blocks_bits.resize(num_blocks);

                    const std::size_t chunk = crypto3::hashes::sha2<256>::block_bits;

                    for (std::size_t i = 0; i < num_blocks; ++i) {
                        blocks_bits[i] = detail::blueprint_variable_vector<FieldType>(bits.begin() + i * chunk,
                                                                                      bits.begin() + (i + 1) * chunk);
                    }

                    for (std::size_t i = 0; i < num_blocks - 1; ++i) {
                        intermediate_outputs[i].reset(
                            new digest_variable<FieldType>(bp, crypto3::hashes::sha2<256>::digest_bits));
                    }

                    if (num_blocks == 1) {
                        blocks_components[0].reset(new sha256_compression_function_component<FieldType>(
                            bp, SHA256_default_IV(bp), blocks_bits[0], output));
                    } else {
                        blocks_components[0].reset(new sha256_compression_function_component<FieldType>(
                            bp, SHA256_default_IV(bp), blocks_bits[0], *intermediate_outputs[0]));
                        for (std::size_t i = 1; i < num_blocks - 1; ++i) {
                            detail::blueprint_linear_combination_vector<FieldType> lcv(
                                intermediate_outputs[i - 1]->bits);
                            blocks_components[i].reset(new sha256_compression_function_component<FieldType>(
                                bp, lcv, blocks_bits[i], *intermediate_outputs[i]));
                        }
                        detail::blueprint_linear_combination_vector<FieldType> lcv(
                            intermediate_outputs[num_blocks - 2]->bits);
                        blocks_components[num_blocks - 1].reset(new sha256_compression_function_component<FieldType>(
                            bp, lcv, blocks_bits[num_blocks - 1], output));
                    }
                }

                void generate_gates(bool ensure_output_bitness = true) {    // TODO: ignored for now
                    padding->generate_gates();
                    for (auto f : blocks_components) {
                        f->generate_gates();
                    }
                }

                void generate_assignments() {
                    padding->generate_assignments();
                    for (auto f : blocks_components) {
                        f->generate_assignments();
                    }
                }

                static std::size_t get_block_len() {
                    return crypto3::hashes::sha2<256>::block_bits;
                }

                static std::size_t get_digest_len() {
                    return crypto3::hashes::sha2<256>::digest_bits;
                }

                static std::vector<bool> get_hash(const std::vector<bool> &input) {
                    blueprint<FieldType> bp;

                    block_variable<FieldType> input_variable(bp, input.size());
                    digest_variable<FieldType> output_variable(bp, crypto3::hashes::sha2<256>::digest_bits);
                    sha256_hash_component<FieldType> f(bp, input_variable.block_size, input_variable, output_variable);

                    input_variable.generate_assignments(input);
                    f.generate_assignments();

                    return output_variable.get_digest();
                }
            };
        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_COMPONENT_HPP
