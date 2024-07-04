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

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"
#define BOOST_TEST_MODULE zkevm_workload_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include "nil/blueprint/zkevm/zkevm_word.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include "../opcode_tester.hpp"

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(zkevm_workload_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_workload_test) {
    using field_type = fields::pallas_base_field;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    const std::vector<zkevm_opcode> implemented_opcodes = {
        zkevm_opcode::ADD, zkevm_opcode::SUB, zkevm_opcode::AND, zkevm_opcode::OR, zkevm_opcode::XOR,
        zkevm_opcode::BYTE, zkevm_opcode::SHL, zkevm_opcode::SHR, zkevm_opcode::SAR, zkevm_opcode::SIGNEXTEND,
        zkevm_opcode::EQ, zkevm_opcode::GT, zkevm_opcode::LT, zkevm_opcode::SGT, zkevm_opcode::SLT,
        zkevm_opcode::DIV, zkevm_opcode::MOD, zkevm_opcode::SDIV, zkevm_opcode::SMOD, zkevm_opcode::ISZERO,
        zkevm_opcode::ADDMOD, zkevm_opcode::MULMOD, zkevm_opcode::MUL, zkevm_opcode::NOT};
    const std::size_t num_of_opcodes = implemented_opcodes.size(),
                      workload = 10000;

    assignment_type assignment(0, 0, 0, 0);
    circuit_type circuit;
    zkevm_circuit<field_type> zkevm_circuit(assignment, circuit);
    zkevm_machine_type machine = get_empty_machine();
    // incorrect test logic, but we have no memory operations so
    machine.stack.push(zwordc(0x1234567890_cppui_modular257));
    machine.stack.push(zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    machine.stack.push(zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    for(std::size_t i = 0; i < workload; i++) {
        zkevm_circuit.assign_opcode(implemented_opcodes[i % num_of_opcodes], machine);
    }
    zkevm_circuit.finalize_test();

    std::ofstream myfile;
    myfile.open("test_assignment.txt");
    assignment.export_table(myfile);
    myfile.close();
    myfile.open("test_circuit.txt");
    circuit.export_circuit(myfile);
    myfile.close();

    nil::crypto3::zk::snark::basic_padding(assignment);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}

BOOST_AUTO_TEST_SUITE_END()
