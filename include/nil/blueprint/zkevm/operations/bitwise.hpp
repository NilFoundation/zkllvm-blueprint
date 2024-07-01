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
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_bitwise_operation(bitwise_type _bit_operation) : bit_operation(_bit_operation) {}

            bitwise_type bit_operation;

            std::map<gate_class, std::pair<std::vector<constraint_type>,std::vector<lookup_constraint_type>>>
                generate_gates(zkevm_circuit_type &zkevm_circuit) override {

                std::vector<constraint_type> constraints;
                std::vector<lookup_constraint_type> lookup_constraints;
                constexpr const std::size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };
                const std::size_t byte_and_table_index = zkevm_circuit.get_circuit().get_reserved_indices().at("byte_and_xor_table/and");
                const std::size_t byte_xor_table_index = zkevm_circuit.get_circuit().get_reserved_indices().at("byte_and_xor_table/xor");

                // Table layout
                // +-----+------+
                // | bytes of a | 2
                // +------------+
                // | bytes of b | 1
                // +------------+
                // | bytes of r | 0
                // +------------+

                constraint_type position = zkevm_circuit.get_opcode_row_constraint(1, this->rows_amount());
                //TODO: this is where we should have lookup constraints assuring a,b and r bytes are related by the correct bitwise op
                // NB: once this is done, we don't need any other lookup constraints for this opcode. r_chunks are enough constrained.
                for(std::size_t i = 0; i < 2*chunk_amount; i++) {
                    var a_byte = var_gen(i, -1),
                        b_byte = var_gen(i, 0),
                        r_byte = var_gen(i, +1);
                        switch(bit_operation) {
                           case B_AND:
                             lookup_constraints.push_back({byte_and_table_index, {position * a_byte, position * b_byte,
                                                                                  position * r_byte }});
                           break;
                           case B_XOR:
                             lookup_constraints.push_back({byte_xor_table_index, {position * a_byte, position * b_byte,
                                                                                  position * r_byte }});
                           break;
                           case B_OR:
                             lookup_constraints.push_back({byte_and_table_index, {position * (255 - a_byte), position * (255 - b_byte),
                                                                                  position * (255 - r_byte) }});
                           break;
                        }
                }
                return { {gate_class::MIDDLE_OP, {constraints, lookup_constraints}} };
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

                // TODO: replace with memory access
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[2*i], curr_row) = integral_type(a_chunks[i].data) % 256;
                    assignment.witness(witness_cols[2*i+1], curr_row) = integral_type(a_chunks[i].data) / 256;
                    assignment.witness(witness_cols[2*i], curr_row + 1) = integral_type(b_chunks[i].data) % 256;
                    assignment.witness(witness_cols[2*i+1], curr_row + 1) = integral_type(b_chunks[i].data) / 256;
                    assignment.witness(witness_cols[2*i], curr_row + 2) = integral_type(r_chunks[i].data) % 256;
                    assignment.witness(witness_cols[2*i+1], curr_row + 2) = integral_type(r_chunks[i].data) / 256;
                }

                // reset the machine state; hope that we won't have to do this manually
                stack.push(b);
                stack.push(a);
            }

            std::size_t rows_amount() override {
                return 3;
            }
        };
    }   // namespace blueprint
}   // namespace nil
