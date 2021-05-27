//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_HASH_IO_HPP
#define CRYPTO3_ZK_HASH_IO_HPP

#include <cstddef>
#include <vector>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    template<typename FieldType>
                    class digest_variable : public component<FieldType> {
                    public:
                        std::size_t digest_size;
                        blueprint_variable_vector<FieldType> bits;

                        digest_variable(blueprint<FieldType> &bp, std::size_t digest_size) :
                            component<FieldType>(bp), digest_size(digest_size) {

                            bits.allocate(bp, digest_size);
                        }

                        digest_variable(blueprint<FieldType> &bp,
                                        std::size_t digest_size,
                                        const blueprint_variable_vector<FieldType> &partial_bits,
                                        const blueprint_variable<FieldType> &padding) :
                            component<FieldType>(bp),
                            digest_size(digest_size) {

                            assert(bits.size() <= digest_size);
                            bits = partial_bits;
                            while (bits.size() != digest_size) {
                                bits.emplace_back(padding);
                            }
                        }

                        void generate_r1cs_constraints() {
                            for (std::size_t i = 0; i < digest_size; ++i) {
                                generate_boolean_r1cs_constraint<FieldType>(this->bp, bits[i]);
                            }
                        }

                        void generate_r1cs_witness(const std::vector<bool> &contents) {
                            bits.fill_with_bits(this->bp, contents);
                        }

                        std::vector<bool> get_digest() const {
                            return bits.get_bits(this->bp);
                        }
                    };

                    template<typename FieldType>
                    class block_variable : public component<FieldType> {
                    public:
                        std::size_t block_size;
                        blueprint_variable_vector<FieldType> bits;

                        block_variable(blueprint<FieldType> &bp, std::size_t block_size) :
                            component<FieldType>(bp), block_size(block_size) {
                            bits.allocate(bp, block_size);
                        }

                        block_variable(blueprint<FieldType> &bp,
                                       const std::vector<blueprint_variable_vector<FieldType>> &parts) :
                            component<FieldType>(bp) {

                            for (auto &part : parts) {
                                bits.insert(bits.end(), part.begin(), part.end());
                            }
                        }

                        block_variable(blueprint<FieldType> &bp,
                                       const digest_variable<FieldType> &left,
                                       const digest_variable<FieldType> &right) :
                            component<FieldType>(bp) {

                            assert(left.bits.size() == right.bits.size());
                            block_size = 2 * left.bits.size();
                            bits.insert(bits.end(), left.bits.begin(), left.bits.end());
                            bits.insert(bits.end(), right.bits.begin(), right.bits.end());
                        }

                        void generate_r1cs_constraints();
                        void generate_r1cs_witness(const std::vector<bool> &contents) {
                            bits.fill_with_bits(this->bp, contents);
                        }

                        std::vector<bool> get_block() const {
                            return bits.get_bits(this->bp);
                        }
                    };

                    template<typename FieldType>
                    class merkle_damagard_padding : public component<FieldType> {
                    public:
                        blueprint_variable_vector<FieldType> bits;
                        blueprint_variable<FieldType> one;
                        blueprint_variable<FieldType> zero;

                        merkle_damagard_padding(blueprint<FieldType> bp,
                            size_t partial_block_bits,
                            size_t message_length,
                            size_t message_length_bits_length,
                            size_t total_block_bits
                        ): component<FieldType>(bp) {
                            assert(partial_block_bits + message_length_bits_length <= total_block_bits);
                            one.allocate(bp);
                            zero.allocate(bp);
                            size_t padding_length = total_block_bits - partial_block_bits - message_length_bits_length;
                            bits.resize(padding_length + message_length_bits_length);
                            if(padding_length > 0) {
                                bits[0] = one;
                                for(size_t i = 1; i < padding_length; ++i) {
                                    bits[i] = zero;
                                }
                            }
                            for(size_t i = 0; i < message_length_bits_length; ++i) {
                                bits[padding_length + i] = (message_length & 1 ? one : zero);
                                message_length >> 1;
                            }
                            assert(message_length == 0);
                        }                        

                        void generate_r1cs_constraints() {
                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>(1, one, 1));
                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>(1, zero, 0));
                        }

                        void generate_r1cs_witness() {
                            this->bp.val(one) = 1;
                            this->bp.val(zero) = 0;
                        }
                    };
                }    // namespace components        
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_HASH_IO_HPP
