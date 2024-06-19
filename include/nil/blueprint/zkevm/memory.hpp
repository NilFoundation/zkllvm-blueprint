//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, ffree of charge, to any person obtaining a copy
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <ostream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace nil {
    namespace blueprint {
        constexpr std::uint8_t START_OP = 0;
        constexpr std::uint8_t STACK_OP = 1;
        constexpr std::uint8_t MEMORY_OP = 2;
        constexpr std::uint8_t STORAGE_OP = 3;
        constexpr std::uint8_t TRANSIENT_STORAGE_OP = 4;
        constexpr std::uint8_t CALL_CONTEXT_OP = 5;
        constexpr std::uint8_t ACCOUNT_OP = 6;
        constexpr std::uint8_t TX_REFUND_OP = 7;
        constexpr std::uint8_t TX_ACCESS_LIST_ACCOUNT_OP = 8;
        constexpr std::uint8_t TX_ACCESS_LIST_ACCOUNT_STORAGE_OP = 9;
        constexpr std::uint8_t TX_LOG_OP = 10;
        constexpr std::uint8_t TX_RECEIPT_OP = 11;
        constexpr std::uint8_t PADDING_OP = 12;
        constexpr std::uint8_t rw_options_amount = 13;

        struct rw_operation{
            std::uint8_t op;             // described above
            std::size_t id;            // call_id for stack, memory, tx_id for
            zkevm_word_type address;     // 10 bit for stack, 160 bit for
            std::uint8_t field;          // Not used for stack, memory, storage
            zkevm_word_type storage_key; // 256-bit, not used for stack, memory
            std::size_t rw_id;           // 32-bit
            bool is_write;               // 1 if it's write operation
            zkevm_word_type value;       // It's full 256 words for storage and stack, but it's only byte for memory.
            zkevm_word_type value_prev;

            bool operator< (const rw_operation &other) const {
                if( op != other.op ) return op < other.op;
                if( address != other.address ) return address < other.address;
                if( field != other.field ) return field < other.field;
                if( storage_key != other.storage_key ) return storage_key < other.storage_key;
                if( rw_id != other.rw_id) return rw_id < other.rw_id;
                return false;
            }
        };

        // For testing purposes
        std::ostream& operator<<(std::ostream& os, const rw_operation& obj){
            if(obj.op == START_OP )                           os << "START                              : ";
            if(obj.op == STACK_OP )                           os << "STACK                              : ";
            if(obj.op == MEMORY_OP )                          os << "MEMORY                             : ";
            if(obj.op == STORAGE_OP )                         os << "STORAGE                            : ";
            if(obj.op == TRANSIENT_STORAGE_OP )               os << "TRANSIENT_STORAGE                  : ";
            if(obj.op == CALL_CONTEXT_OP )                    os << "CALL_CONTEXT_OP                    : ";
            if(obj.op == ACCOUNT_OP )                         os << "ACCOUNT_OP                         : ";
            if(obj.op == TX_REFUND_OP )                       os << "TX_REFUND_OP                       : ";
            if(obj.op == TX_ACCESS_LIST_ACCOUNT_OP )          os << "TX_ACCESS_LIST_ACCOUNT_OP          : ";
            if(obj.op == TX_ACCESS_LIST_ACCOUNT_STORAGE_OP )  os << "TX_ACCESS_LIST_ACCOUNT_STORAGE_OP  : ";
            if(obj.op == TX_LOG_OP )                          os << "TX_LOG_OP                          : ";
            if(obj.op == TX_RECEIPT_OP )                      os << "TX_RECEIPT_OP                      : ";
            os << obj.rw_id << ", addr =" << obj.address;
            if(obj.is_write) os << " W "; else os << " R ";
            os << "[" << std::hex << obj.value_prev << std::dec <<"] => ";
            os << "[" << std::hex << obj.value << std::dec <<"]";
            return os;
        }

        rw_operation start_operation(){
            return rw_operation({START_OP, 0, 0, 0, 0, 0, 0, 0});
        }

        rw_operation stack_operation(std::size_t id, uint16_t address, std::size_t rw_id, bool is_write, zkevm_word_type value){
            BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
            BOOST_ASSERT(address < 1024);
            return rw_operation({STACK_OP, id, address, 0, 0, rw_id, is_write, value, 0});
        }

        rw_operation memory_operation(std::size_t id, zkevm_word_type address, std::size_t rw_id, bool is_write, zkevm_word_type value){
            BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
            return rw_operation({MEMORY_OP, id, address, 0, 0, rw_id, is_write, value, 0});
        }

        rw_operation storage_operation(
            std::size_t id,
            zkevm_word_type address,
            zkevm_word_type storage_key,
            std::size_t rw_id,
            bool is_write,
            zkevm_word_type value,
            zkevm_word_type value_prev
        ){
            return rw_operation({STORAGE_OP, id, address, 0, storage_key, rw_id, is_write, value, value_prev});
        }

        rw_operation padding_operation(){
            return rw_operation({PADDING_OP, 0, 0, 0, 0, 0, 0, 0});
        }

        template<typename BlueprintFieldType>
        class rw_trace{
        public:
            using val = typename BlueprintFieldType::value_type;
        protected:
            std::vector<rw_operation> rw_ops;
            std::size_t call_id;

            std::uint8_t char_to_hex(char c) {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            }

            zkevm_word_type zkevm_word_from_string(std::string val){
                zkevm_word_type result;
                for(std::size_t i = 0; i < val.size(); i++ ){
                    result *= 16;
                    result += char_to_hex(val[i]);
                }
                return result;
            }

            std::vector<zkevm_word_type> zkevm_word_vector_from_ptree(const boost::property_tree::ptree &ptree){
                std::vector<zkevm_word_type> result;
                for(auto it = ptree.begin(); it != ptree.end(); it++){
                    result.push_back(zkevm_word_from_string(it->second.data()));
                }
                return result;
            }

            std::map<zkevm_word_type, zkevm_word_type> key_value_storage_from_ptree(const boost::property_tree::ptree &ptree){
                std::map<zkevm_word_type, zkevm_word_type> result;
//              std::cout << "Storage:" << std::endl;
                for(auto it = ptree.begin(); it != ptree.end(); it++){
                    result[zkevm_word_from_string(it->first.data())] = zkevm_word_from_string(it->second.data());
//                    std::cout << "\t" << it->first.data() << "=>" <<  it->second.data() << std::endl;
                }
                return result;
            }

            std::vector<std::uint8_t> byte_vector_from_ptree(const boost::property_tree::ptree &ptree){
                std::vector<std::uint8_t> result;
//                std::cout << "MEMORY words " << ptree.size() << ":";
                for(auto it = ptree.begin(); it != ptree.end(); it++){
                    for(std::size_t i = 0; i < it->second.data().size(); i+=2){
                        std::uint8_t byte = char_to_hex(it->second.data()[i]) * 16 + char_to_hex(it->second.data()[i+1]);
//                        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::size_t(byte) << " ";
                        result.push_back(byte);
                    }
                }
//                std::cout << std::endl;
                return result;
            }

            void append_opcode(
                std::string opcode,
                const std::vector<zkevm_word_type> &stack,       // Stack state before operation
                const std::vector<zkevm_word_type> &stack_next,  // stack state after operation. We need it for correct PUSH and correct SLOAD
                const std::vector<uint8_t> &memory ,     // Memory state before operation in bytes format
                const std::map<zkevm_word_type, zkevm_word_type> &storage,// Storage state before operation
                const std::map<zkevm_word_type, zkevm_word_type> &storage_next// Storage state before operation
            ){
                // Opcode is not presented in RW lookup table. We just take it from json
                std::cout << opcode << std::endl;
                if(opcode == "PUSH1") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH2") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH4") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MSTORE") {
                    // READ from stack
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    auto bytes = w_to_8(stack[stack.size() - 2]);
                    for( std::size_t i = 0; i < 32; i++){
                        rw_ops.push_back(memory_operation(call_id, addr + i, rw_ops.size(), true, bytes[i]));
                        std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    }
                    // TODO add memory rows for write in memory operation
                } else if(opcode == "CALLVALUE") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    std::cout << stack.size() << "=>" << stack_next.size() << std::endl;
                } else if(opcode == "ISZERO") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "JUMPI") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "JUMPDEST") {
                } else if(opcode == "POP") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLDATASIZE") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LT") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLDATALOAD") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SHR") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "EQ") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "JUMP") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP1") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP2") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP3") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP4") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP5") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP6") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP7") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-7, rw_ops.size(), false, stack[stack.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP8") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-8, rw_ops.size(), false, stack[stack.size()-8]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP9") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-9, rw_ops.size(), false, stack[stack.size()-9]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP10") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-10, rw_ops.size(), false, stack[stack.size()-10]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP11") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-11, rw_ops.size(), false, stack[stack.size()-11]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP12") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-12, rw_ops.size(), false, stack[stack.size()-12]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP13") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-13, rw_ops.size(), false, stack[stack.size()-13]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP14") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-14, rw_ops.size(), false, stack[stack.size()-14]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP15") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-15, rw_ops.size(), false, stack[stack.size()-15]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP16") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-16, rw_ops.size(), false, stack[stack.size()-16]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "ADD") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SUB") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SLT") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP1") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-2, rw_ops.size(), true, stack_next[stack_next.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP2") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-3, rw_ops.size(), true, stack_next[stack_next.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP3") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-4, rw_ops.size(), true, stack_next[stack_next.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP4") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-5, rw_ops.size(), true, stack_next[stack_next.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP5") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-6, rw_ops.size(), true, stack_next[stack_next.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP6") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-7, rw_ops.size(), false, stack[stack.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-7, rw_ops.size(), true, stack_next[stack_next.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP7") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-8, rw_ops.size(), false, stack[stack.size()-8]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-8, rw_ops.size(), true, stack_next[stack_next.size()-8]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP8") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-9, rw_ops.size(), false, stack[stack.size()-9]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-9, rw_ops.size(), true, stack_next[stack_next.size()-9]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP9") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-10, rw_ops.size(), false, stack[stack.size()-10]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-10, rw_ops.size(), true, stack_next[stack_next.size()-10]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP10") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-11, rw_ops.size(), false, stack[stack.size()-11]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-11, rw_ops.size(), true, stack_next[stack_next.size()-11]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP11") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-12, rw_ops.size(), false, stack[stack.size()-12]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-12, rw_ops.size(), true, stack_next[stack_next.size()-12]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP12") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-13, rw_ops.size(), false, stack[stack.size()-13]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-13, rw_ops.size(), true, stack_next[stack_next.size()-13]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP13") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-14, rw_ops.size(), false, stack[stack.size()-14]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-14, rw_ops.size(), true, stack_next[stack_next.size()-14]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP14") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-15, rw_ops.size(), false, stack[stack.size()-15]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-15, rw_ops.size(), true, stack_next[stack_next.size()-15]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP15") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-16, rw_ops.size(), false, stack[stack.size()-16]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-16, rw_ops.size(), true, stack_next[stack_next.size()-16]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP16") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-17, rw_ops.size(), false, stack[stack.size()-17]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-17, rw_ops.size(), true, stack_next[stack_next.size()-17]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MLOAD") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    for( std::size_t i = 0; i < 32; i++){
                        rw_ops.push_back(memory_operation(call_id, addr+i, rw_ops.size(), false, addr+i < memory.size() ? memory[std::size_t(addr+i)]: 0));
                        std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    }
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "RETURN") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "GT") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SLOAD") {
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    rw_ops.push_back(storage_operation(
                        call_id,
                        0,
                        stack[stack.size()-1],
                        rw_ops.size(),
                        false,
                        storage_next.at(stack[stack.size()-1]),
                        storage_next.at(stack[stack.size()-1])
                    )); // Second parameter should be transaction_id)
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SSTORE") {
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));

                    rw_ops.push_back(storage_operation(
                        call_id,
                        0,
                        stack[stack.size()-1],
                        rw_ops.size(),
                        true,
                        stack[stack.size()-2],
                        // TODO: Remove this zero value in value_before by real previous storage value.
                        // Overwise lookup in MPT table won't be correct
                        (storage.find(stack[stack.size()-1]) == storage.end())? 0: storage.at(stack[stack.size()-1]))
                    ); // Second parameter should be transaction_id
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add storage write operations
                } else {
                    std::cout << "Unknown opcode " << std::hex << opcode << std::dec << std::endl;
                    BOOST_ASSERT(false);
                }
            }
        public:
            rw_trace(boost::property_tree::ptree const &pt, std::size_t rows_amount, std::size_t _call_id = 0){
                call_id = _call_id;

                boost::property_tree::ptree ptrace = pt.get_child("result.structLogs");
                boost::property_tree::ptree pstack;
                boost::property_tree::ptree pmemory;

                std::cout << "PT = " << ptrace.size() << std::endl;

                std::vector<zkevm_word_type> stack = zkevm_word_vector_from_ptree(ptrace.begin()->second.get_child("stack"));
                std::vector<std::uint8_t> memory = byte_vector_from_ptree(ptrace.begin()->second.get_child("memory"));
                std::vector<zkevm_word_type> stack_next;
                std::map<zkevm_word_type, zkevm_word_type> storage = key_value_storage_from_ptree(ptrace.begin()->second.get_child("storage"));
                std::map<zkevm_word_type, zkevm_word_type> storage_next;

                rw_ops.push_back(start_operation());
                for( auto it = ptrace.begin(); it!=ptrace.end(); it++ ){
                    if(std::distance(it, ptrace.end()) == 1)
                        append_opcode(it->second.get_child("op").data(), stack, {}, memory, storage, storage);
                    else{
                        stack_next = zkevm_word_vector_from_ptree(std::next(it)->second.get_child("stack"));
                        storage_next = key_value_storage_from_ptree(it->second.get_child("storage"));
                        append_opcode(it->second.get_child("op").data(), stack, stack_next, memory, storage, storage_next);
                        memory = byte_vector_from_ptree(std::next(it)->second.get_child("memory"));
                    }
                    storage = storage_next;
                    stack = stack_next;
                }
                std::sort(rw_ops.begin(), rw_ops.end(), [](rw_operation a, rw_operation b){
                    return a < b;
                });

                while( rw_ops.size() < rows_amount ) rw_ops.push_back(padding_operation());
            }
            const std::vector<rw_operation> &get_rw_ops() const{
                return rw_ops;
            }
        };
    } // namespace blueprint
} // namespace nil
