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

#define BOOST_TEST_MODULE zkevm_iszero_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include <nil/blueprint/zkevm/bytecode.hpp>

#include "../zkevm/opcode_tester.hpp"
#include "../benchmark_utils.hpp"

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(zkevm_increment_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_increment_test) {
    using field_type = fields::pallas_base_field;
    using value_type = field_type::value_type;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    using bytecode_type = nil::blueprint::components::zkevm_bytecode<arithmentization_type, field_type>;
    using var = nil::crypto3::zk::snark::plonk_variable<value_type>;
    static constexpr std::size_t test_size = 4096;
    assignment_type assignment(0, 0, 6, 10);
    circuit_type circuit;
    zkevm_circuit<field_type> zkevm_circuit(assignment, circuit);
    // bytecode circuit setup
    auto &selector_manager = zkevm_circuit.get_selector_manager();
    auto bytecode_manifest = bytecode_type::get_manifest();
    const compiler_manifest table_manifest(150, false);
    const auto intersection = table_manifest.intersect(bytecode_manifest);
    BOOST_ASSERT(intersection.is_satisfiable());
    const std::size_t bytecode_witness_amount = intersection.witness_amount->max_value_if_sat();
    std::vector<std::size_t> bytecode_columns(bytecode_witness_amount);
    for (std::size_t i = 0; i < bytecode_witness_amount; i++) {
        bytecode_columns[i] = selector_manager.allocate_witess_column();
    }
    bytecode_type bytecode_circuit(bytecode_columns, test_size);
    // setup some bytecode
    std::vector<std::vector<var>> bytecode_vars;
    std::vector<var> bytecode;
    bytecode.push_back(assignment.add_private_variable(test_size)); // length
    for (std::size_t j = 0; j < test_size; j++) {
        bytecode.push_back(
            assignment.add_private_variable(0x01)); // ADD
    }
    bytecode_vars.push_back(bytecode);
    std::vector<std::pair<var, var>> bytecode_hash_vars;
    bytecode_hash_vars.push_back(
        {assignment.add_private_variable(0x02), assignment.add_private_variable(0x03)});
    var rlc_challenge_var = assignment.add_private_variable(0x04);
    typename bytecode_type::input_type instance_input(bytecode_vars, bytecode_hash_vars, rlc_challenge_var);
    // lookup tables reservation for bytecode circuit
    auto lookup_tables = bytecode_circuit.component_lookup_tables();
    for(auto &[k,v]:lookup_tables){
        circuit.reserve_table(k);
    }
    // running bytecode circuit
    generate_assignments(bytecode_circuit, assignment, instance_input, 0);
    generate_circuit(bytecode_circuit, circuit, assignment, instance_input, 0);
    // running zkevm circuit
    zkevm_machine_type machine = get_empty_machine();
    machine.stack.push(0);
    for (std::size_t i = 0; i < test_size; i++) {
        machine.stack.push(i + 1);
        zkevm_circuit.assign_opcode(zkevm_opcode::DIV, machine);
    }
    zkevm_circuit.finalize_test();
    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
    //nil::crypto3::zk::snark::basic_padding(assignment);
    //BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
    crypto3::zk::snark::plonk_table_description<field_type> desc(
        assignment.witnesses_amount(), assignment.public_inputs_amount(),
        assignment.constants_amount(), assignment.selectors_amount());
    using hash_type = crypto3::hashes::keccak_1600<256>;
    auto timing_info = run_prover<field_type, hash_type, 2, 20>(desc, circuit, assignment);
    std::cout << timing_info;
}

BOOST_AUTO_TEST_SUITE_END()
