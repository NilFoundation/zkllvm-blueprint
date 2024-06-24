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

#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {

        enum bitwise_type { B_AND, B_OR, B_XOR };

        template<typename BlueprintFieldType>
        class zkevm_bitwise_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_bitwise_operation(bitwise_type _bit_operation) : bit_operation(_bit_operation) {}

            bitwise_type bit_operation;

            std::map<gate_class, std::vector<constraint_type>> generate_gates(zkevm_circuit_type &zkevm_circuit) override {
                std::vector<constraint_type> constraints;
                constexpr const std::size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };
                // Table layout
                // +-----+------+
                // |  a  |   b  | 4
                // +-----+------+
                // | bytes of a | 3
                // +------------+
                // | bytes of b | 2
                // +------------+
                // | bytes of r | 1
                // +------------+
                // |  r  |      | 0
                // +-----+------+

                constraint_type position_1 = zkevm_circuit.get_opcode_row_constraint(3, this->rows_amount());
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    var a_chunk = var_gen(i, -1),
                        b_chunk = var_gen(chunk_amount + i, -1),
                        a_lo = var_gen(2*i, 0),
                        a_hi = var_gen(2*i+1, 0),
                        b_lo = var_gen(2*i, +1),
                        b_hi = var_gen(2*i+1, +1);
                    constraints.push_back(position_1 * (a_chunk - a_lo - a_hi*256));
                    constraints.push_back(position_1 * (b_chunk - b_lo - b_hi*256));
                }

                constraint_type position_2 = zkevm_circuit.get_opcode_row_constraint(2, this->rows_amount());
                //TODO: this is where we should have lookup constraints assuring a,b and r bytes are related by the correct bitwise op
                // NB: once this is done, we don't need any other lookup constraints for this opcode. r_chunks are enough constrained.

                constraint_type position_3 = zkevm_circuit.get_opcode_row_constraint(1, this->rows_amount());
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    var r_chunk = var_gen(i, +1),
                        r_lo = var_gen(2*i, 0),
                        r_hi = var_gen(2*i+1, 0);
                    constraints.push_back(position_3 * (r_chunk - r_lo -r_hi*256));
                }

                return {{gate_class::MIDDLE_OP, constraints}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                word_type a = stack.pop();
                word_type b = stack.pop();

                word_type result;
                switch(bit_operation) {
                    case B_AND: result = a & b; break;
                    case B_OR:  result = a | b; break;
                    case B_XOR: result = a ^ b; break;
                }

                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(result);
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();

                size_t chunk_amount = a_chunks.size();

                // TODO: replace with memory access, which would also do range checks!
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row) = a_chunks[i];
                    assignment.witness(witness_cols[chunk_amount + i], curr_row) = b_chunks[i];
                    assignment.witness(witness_cols[2*i], curr_row + 1) = integral_type(a_chunks[i].data) % 256;
                    assignment.witness(witness_cols[2*i+1], curr_row + 1) = integral_type(a_chunks[i].data) / 256;
                    assignment.witness(witness_cols[2*i], curr_row + 2) = integral_type(b_chunks[i].data) % 256;
                    assignment.witness(witness_cols[2*i+1], curr_row + 2) = integral_type(b_chunks[i].data) / 256;
                    assignment.witness(witness_cols[2*i], curr_row + 3) = integral_type(r_chunks[i].data) % 256;
                    assignment.witness(witness_cols[2*i+1], curr_row + 3) = integral_type(r_chunks[i].data) / 256;
                    assignment.witness(witness_cols[i], curr_row + 4) = r_chunks[i];
                }

                // reset the machine state; hope that we won't have to do this manually
                stack.push(b);
                stack.push(a);
            }

            std::size_t rows_amount() override {
                return 5;
            }
        };
    }   // namespace blueprint
}   // namespace nil
