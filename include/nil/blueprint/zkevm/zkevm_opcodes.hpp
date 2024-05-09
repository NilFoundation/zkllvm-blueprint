//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <iostream>

namespace nil {
    namespace blueprint {
        #define ZKEVM_OPCODE_ENUM(X) \
            X(STOP) \
            X(ADD) \
            X(MUL) \
            X(SUB) \
            X(DIV) \
            X(SDIV) \
            X(MOD) \
            X(SMOD) \
            X(ADDMOD) \
            X(MULMOD) \
            X(EXP) \
            X(SIGNEXTEND) \
            X(LT) \
            X(GT) \
            X(SLT) \
            X(SGT) \
            X(EQ) \
            X(ISZERO) \
            X(AND) \
            X(OR) \
            X(XOR) \
            X(NOT) \
            X(BYTE) \
            X(SHL) \
            X(SHR) \
            X(SAR) \
            X(KECCAK256) \
            X(ADDRESS) \
            X(BALANCE) \
            X(ORIGIN) \
            X(CALLER) \
            X(CALLVALUE) \
            X(CALLDATALOAD) \
            X(CALLDATASIZE) \
            X(CALLDATACOPY) \
            X(GASPRICE) \
            X(EXTCODESIZE) \
            X(EXTCODECOPY) \
            X(RETURNDATASIZE) \
            X(RETURNDATACOPY) \
            X(EXTCODEHASH) \
            X(BLOCKHASH) \
            X(COINBASE) \
            X(TIMESTAMP) \
            X(NUMBER) \
            X(PREVRANDAO) \
            X(GASLIMIT) \
            X(CHAINID) \
            X(SELFBALANCE) \
            X(BASEFEE) \
            X(BLOBHASH) \
            X(BLOBBASEFEE) \
            X(POP) \
            X(MLOAD) \
            X(MSTORE) \
            X(MSTORE8) \
            X(SLOAD) \
            X(SSTORE) \
            X(JUMP) \
            X(JUMPI) \
            X(PC) \
            X(MSIZE) \
            X(GAS) \
            X(JUMPDEST) \
            X(TLOAD) \
            X(TSTORE) \
            X(MCOPY) \
            X(PUSH0) \
            X(PUSH1) \
            X(PUSH2) \
            X(PUSH3) \
            X(PUSH4) \
            X(PUSH5) \
            X(PUSH6) \
            X(PUSH7) \
            X(PUSH8) \
            X(PUSH9) \
            X(PUSH10) \
            X(PUSH11) \
            X(PUSH12) \
            X(PUSH13) \
            X(PUSH14) \
            X(PUSH15) \
            X(PUSH16) \
            X(PUSH17) \
            X(PUSH18) \
            X(PUSH19) \
            X(PUSH20) \
            X(PUSH21) \
            X(PUSH22) \
            X(PUSH23) \
            X(PUSH24) \
            X(PUSH25) \
            X(PUSH26) \
            X(PUSH27) \
            X(PUSH28) \
            X(PUSH29) \
            X(PUSH30) \
            X(PUSH31) \
            X(PUSH32) \
            X(DUP1) \
            X(DUP2) \
            X(DUP3) \
            X(DUP4) \
            X(DUP5) \
            X(DUP6) \
            X(DUP7) \
            X(DUP8) \
            X(DUP9) \
            X(DUP10) \
            X(DUP11) \
            X(DUP12) \
            X(DUP13) \
            X(DUP14) \
            X(DUP15) \
            X(DUP16) \
            X(SWAP1) \
            X(SWAP2) \
            X(SWAP3) \
            X(SWAP4) \
            X(SWAP5) \
            X(SWAP6) \
            X(SWAP7) \
            X(SWAP8) \
            X(SWAP9) \
            X(SWAP10) \
            X(SWAP11) \
            X(SWAP12) \
            X(SWAP13) \
            X(SWAP14) \
            X(SWAP15) \
            X(SWAP16) \
            X(LOG0) \
            X(LOG1) \
            X(LOG2) \
            X(LOG3) \
            X(LOG4) \
            X(CREATE) \
            X(CALL) \
            X(CALLCODE) \
            X(RETURN) \
            X(DELEGATECALL) \
            X(CREATE2) \
            X(STATICCALL) \
            X(REVERT) \
            X(INVALID) \
            X(SELFDESTRUCT) // ! please update LAST_ZKEVM_OPCODE below if changing this !

        enum zkevm_opcode {
            #define ENUM_DEF(name) name,
            ZKEVM_OPCODE_ENUM(ENUM_DEF)
            #undef ENUM_DEF
        };

        zkevm_opcode LAST_ZKEVM_OPCODE = zkevm_opcode::SELFDESTRUCT;

        std::string opcode_to_string(const zkevm_opcode& opcode) {
            switch (opcode) {
                #define ENUM_DEF(name) case zkevm_opcode::name: return #name;
                ZKEVM_OPCODE_ENUM(ENUM_DEF)
                #undef ENUM_DEF
            }
            return "unknown";
        }

        std::ostream& operator<<(std::ostream& os, const zkevm_opcode& opcode) {
            #define ENUM_DEF(name) case zkevm_opcode::name: os << #name; break;
            switch (opcode) {
                ZKEVM_OPCODE_ENUM(ENUM_DEF)
            }
            #undef ENUM_DEF
            return os;
        }
    }   // namespace blueprint
}   // namespace nil
