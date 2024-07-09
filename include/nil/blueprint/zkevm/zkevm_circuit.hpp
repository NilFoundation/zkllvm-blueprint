//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <iterator>
#include <map>
#include <memory>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/gate_id.hpp>

#include <nil/blueprint/zkevm/state.hpp>
#include <nil/blueprint/zkevm/state_selector.hpp>
#include <nil/blueprint/zkevm/zkevm_opcodes.hpp>

#include <nil/blueprint/zkevm/operations/iszero.hpp>
#include <nil/blueprint/zkevm/operations/add_sub.hpp>
#include <nil/blueprint/zkevm/operations/mul.hpp>
#include <nil/blueprint/zkevm/operations/div_mod.hpp>
#include <nil/blueprint/zkevm/operations/sdiv_smod.hpp>
#include <nil/blueprint/zkevm/operations/cmp.hpp>
#include <nil/blueprint/zkevm/operations/not.hpp>
#include <nil/blueprint/zkevm/operations/byte.hpp>
#include <nil/blueprint/zkevm/operations/signextend.hpp>
#include <nil/blueprint/zkevm/operations/bitwise.hpp>
#include <nil/blueprint/zkevm/operations/shl.hpp>
#include <nil/blueprint/zkevm/operations/shr.hpp>
#include <nil/blueprint/zkevm/operations/sar.hpp>
#include <nil/blueprint/zkevm/operations/addmod.hpp>
#include <nil/blueprint/zkevm/operations/mulmod.hpp>

namespace nil {
    namespace blueprint {
        // abstracts control over column indices
        // selectors are already tracked by circuit object by default
        // we implement only automatic extension of the amount of colunmns taken for convinience
        template<typename BlueprintFieldType>
        class selector_manager {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

            selector_manager(assignment_type &assignment_, circuit_type &circuit_)
                : assignment(assignment_), circuit(circuit_),
                  witness_index(0), constant_index(0) {}

            std::size_t allocate_witess_column() {
                if (witness_index >= assignment.witnesses_amount()) {
                    assignment.resize_witnesses(witness_index + 1);
                }
                return witness_index++;
            }

            std::size_t allocate_constant_column() {
                if (constant_index >= assignment.constants_amount()) {
                    assignment.resize_constants(constant_index + 1);
                }
                return constant_index++;
            }

            template<typename T>
            std::size_t add_gate(const T &args) {
                std::size_t selector = circuit.add_gate(args);
                if (selector >= assignment.selectors_amount()) {
                    assignment.resize_selectors(selector + 1);
                }
                return selector;
            }

            template<typename T>
            std::size_t add_lookup_gate(std::size_t selector_id, const T &args) {
                circuit.add_lookup_gate(selector_id, args);
                return selector_id;
            }
        private:
            assignment_type &assignment;
            circuit_type &circuit;
            std::size_t witness_index;
            std::size_t constant_index;
        };

        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_circuit {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
            using state_var_type = state_var<BlueprintFieldType>;
            using zkevm_state_type = zkevm_state<BlueprintFieldType>;
            using selector_manager_type = selector_manager<BlueprintFieldType>;
            using zkevm_operation_type = zkevm_operation<BlueprintFieldType>;
            using zkevm_opcode_gate_class = typename zkevm_operation<BlueprintFieldType>::gate_class;
            using state_selector_type = components::state_selector<arithmetization_type, BlueprintFieldType>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename crypto3::zk::snark::plonk_variable<value_type>;

            std::map<std::string, std::size_t> zkevm_circuit_lookup_tables() const {
                std::map<std::string, std::size_t> lookup_tables;
                lookup_tables["chunk_16_bits/full"] = 0;
                lookup_tables["byte_and_xor_table/and"] = 1;
                lookup_tables["byte_and_xor_table/xor"] = 2;
                return lookup_tables;
            }

            zkevm_circuit(assignment_type &assignment_, circuit_type &circuit_, std::size_t start_row_index_ = 1)
                :assignment(assignment_), circuit(circuit_), opcodes_info_instance(opcodes_info::instance()),
                 sel_manager(assignment_, circuit_),
                 curr_row(start_row_index_), start_row_index(start_row_index_) {

                // 5(?) constant columns. I'm not sure we really need them: satisfiability check passes even without them
                for(std::size_t i = 0; i < 5; i++) {
                    sel_manager.allocate_constant_column();
                }

                BOOST_ASSERT_MSG(start_row_index > 0,
                    "Start row index must be greater than zero, otherwise some gates would access non-existent rows.");
                for (auto &lookup_table : zkevm_circuit_lookup_tables()) {
                    circuit.reserve_table(lookup_table.first);
                }
                init_state();
                init_opcodes();
//std::cout << "WA = " << assignment.witnesses_amount() << std::endl;
                assignment.resize_selectors(assignment.selectors_amount() + 2); // for lookup table packing
//std::cout << "SA = " << assignment.selectors_amount() << std::endl;
            }

            void assign_state() {
                state.assign_state(assignment, curr_row);
            }

            void finalize_test() {
                finalize();
                // this is done in order for the vizualiser export to work correctly before padding the circuit.
                // otherwise constraints try to access non-existent rows
                assignment.witness(state_selector->W(0), curr_row) = value_type(0xC0FFEE);
            }

            void finalize() {
                BOOST_ASSERT_MSG(curr_row != 0, "Row underflow in finalization");
                // assignment.enable_selector(end_selector, curr_row - 1);
                assignment.witness(state.last_row_indicator.selector, curr_row - 1) = 1;
            }

            void assign_opcode(const zkevm_opcode opcode, zkevm_machine_interface &machine) {
                auto opcode_it = opcodes.find(opcode);
                if (opcode_it == opcodes.end()) {
                    BOOST_ASSERT_MSG(false, (std::string("Unimplemented opcode: ") + opcode_to_string(opcode)) != "");
                }
                // state management
                state.step_selection.value = 1;
                // state.rows_until_next_op.value = opcode_it->second->rows_amount() - 1;
                state.rows_until_next_op.value = max_opcode_height - 1;
                state.rows_until_next_op_inv.value =
                    state.rows_until_next_op.value == 0 ? 0 : state.rows_until_next_op.value.inversed();
                advance_rows(opcode, max_opcode_height - opcode_it->second->rows_amount());
                opcode_it->second->generate_assignments(*this, machine);
                advance_rows(opcode, opcode_it->second->rows_amount(), (max_opcode_height - opcode_it->second->rows_amount()) % 2);
            }

            void advance_rows(const zkevm_opcode opcode, std::size_t rows, std::size_t shift = 0) {
                assignment.enable_selector(middle_selector, curr_row, curr_row + rows - 1);
                // TODO: figure out what is going to happen on state change
                value_type opcode_val = opcodes_info_instance.get_opcode_value(opcode);
                for (std::size_t i = 0 + shift; i < rows + shift; i++) {
                    if (i % state_selector->rows_amount == 0) {
                        // TODO: switch to real bytecode
                        assignment.witness(state_selector->W(0), curr_row) = opcode_val;
                        components::generate_assignments(
                            *state_selector, assignment,
                            {var(state_selector->W(0), curr_row, false, var::column_type::witness)}, curr_row);
                    }
                    assignment.witness(opcode_row_selector->W(0), curr_row) = state.rows_until_next_op.value;
                    components::generate_assignments(
                        *opcode_row_selector, assignment,
                        {var(opcode_row_selector->W(0), curr_row, false, var::column_type::witness)}, curr_row);
                    assign_state();
                    if (i == 0) {
                        state.step_selection.value = 0;
                    }
                    assignment.witness(state_selector->W(0), curr_row) = opcode_val;
                    state.rows_until_next_op.value = state.rows_until_next_op.value - 1;
                    state.rows_until_next_op_inv.value = state.rows_until_next_op.value == 0 ?
                        0 : state.rows_until_next_op.value.inversed();
                    curr_row++;
                }
            }

            zkevm_state_type &get_state() {
                return state;
            }

            selector_manager_type &get_selector_manager() {
                return sel_manager;
            }

            const std::vector<std::size_t> &get_state_selector_cols() {
                return state_selector_cols;
            }

            const std::vector<std::size_t> &get_opcode_cols() {
                return opcode_cols;
            }

            std::size_t get_current_row() const {
                return curr_row;
            }

            assignment_type &get_assignment() {
                return assignment;
            }

            circuit_type &get_circuit() {
                return circuit;
            }

            // for opcode constraints at certain row of opcode execution
            // note that rows are counted "backwards", starting from opcode rows amount minus one
            // and ending in zero
            constraint_type get_opcode_row_constraint(std::size_t row) const {
                BOOST_ASSERT(row < max_opcode_height);
                var height_var = state.rows_until_next_op.variable();
                var height_var_inv = state.rows_until_next_op_inv.variable();
                // ordering here is important: minimising the degree when possible
                if (row == max_opcode_height - 1) {
                    return state.step_selection.variable();
                }
                if (row == max_opcode_height - 2) {
                    return state.step_selection.variable(-1);
                }
                if (row == 0) {
                    return 1 - height_var * height_var_inv;
                }
                // TODO: this is probably possible to optimise
                return opcode_row_selector->option_constraint(row);
            }

        private:
            void init_state() {
                state.pc = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 1);
                state.stack_size = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.memory_size = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.curr_gas = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.rows_until_next_op = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.rows_until_next_op_inv = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.step_selection = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 1);
                state.last_row_indicator = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
            }

            std::vector<constraint_type> generate_generic_transition_constraints(
                std::size_t start_selector,
                std::size_t end_selector
            ) {
                std::vector<constraint_type> constraints;

                auto rows_until_next_op_var = state.rows_until_next_op.variable();
                auto rows_until_next_op_prev_var = state.rows_until_next_op.variable(-1);
                auto rows_until_next_op_next_var = state.rows_until_next_op.variable(+1);
                auto rows_until_next_op_inv_var = state.rows_until_next_op_inv.variable();
                auto rows_until_next_op_inv_prev_var = state.rows_until_next_op_inv.variable(-1);
                auto step_selection_var = state.step_selection.variable();
                auto step_selection_next_var = state.step_selection.variable(+1);
                auto option_variable = state_selector->option_variable(0);
                auto option_variable_prev = state_selector->option_variable(-1);
                auto last_row_indicator_var = state.last_row_indicator.variable();
                // inverse or zero for rows_until_next_op/rows_until_next_op_inv
                constraints.push_back(
                    rows_until_next_op_var * rows_until_next_op_var * rows_until_next_op_inv_var
                    - rows_until_next_op_var);
                constraints.push_back(
                    (rows_until_next_op_var * rows_until_next_op_inv_var - 1) * rows_until_next_op_inv_var);
                // rows_until_next_op decrementing (unless we are at the last row of opcode)
                constraints.push_back(
                    rows_until_next_op_var * (rows_until_next_op_next_var - rows_until_next_op_var + 1));
                // step is copied unless new opcode is next
                constraints.push_back(
                    (1 - step_selection_var) * (option_variable - option_variable_prev));
                // new opcode selection is forced if new opcode is next
                constraints.push_back(
                    (1 - rows_until_next_op_inv_prev_var * rows_until_next_op_prev_var) * (1 - step_selection_var));
                // freeze some of the the state variables unless new opcode is next
                // or we are at the end of the circuit
                auto partial_state_transition_constraints = generate_transition_constraints(
                    state, generate_frozen_state_transition());
                // TODO: the problematic constraints are here \/ \/ \/
                for (auto constraint : partial_state_transition_constraints) {
                    constraints.push_back(
                        (1 - last_row_indicator_var) *
                        // ^^^ this fixes the problem from the commented line below
//                        (1 - var(end_selector, 0, true, var::column_type::selector)) *
                        (1 - step_selection_next_var) * constraint);
                }
                return constraints;
            }

            void init_opcodes() {
                // add all the implemented opcodes here
                // STOP
                opcodes[zkevm_opcode::ADD] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::MUL] = std::make_shared<zkevm_mul_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SUB] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::DIV] = std::make_shared<zkevm_div_mod_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::SDIV] = std::make_shared<zkevm_sdiv_smod_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::MOD] = std::make_shared<zkevm_div_mod_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::SMOD] = std::make_shared<zkevm_sdiv_smod_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::ADDMOD] = std::make_shared<zkevm_addmod_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::MULMOD] = std::make_shared<zkevm_mulmod_operation<BlueprintFieldType>>();
                // EXP
                opcodes[zkevm_opcode::SIGNEXTEND] = std::make_shared<zkevm_signextend_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::LT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_LT);
                opcodes[zkevm_opcode::GT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_GT);
                opcodes[zkevm_opcode::SLT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_SLT);
                opcodes[zkevm_opcode::SGT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_SGT);
                opcodes[zkevm_opcode::EQ] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_EQ);
                opcodes[zkevm_opcode::ISZERO] = std::make_shared<zkevm_iszero_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::AND] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_AND);
                opcodes[zkevm_opcode::OR] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_OR);
                opcodes[zkevm_opcode::XOR] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_XOR);
                opcodes[zkevm_opcode::NOT] = std::make_shared<zkevm_not_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::BYTE] = std::make_shared<zkevm_byte_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SHL] = std::make_shared<zkevm_shl_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SHR] = std::make_shared<zkevm_shr_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SAR] = std::make_shared<zkevm_sar_operation<BlueprintFieldType>>();

                const std::size_t range_check_table_index = this->get_circuit().get_reserved_indices().at("chunk_16_bits/full");

                std::vector<constraint_type> middle_constraints;
                std::vector<constraint_type> first_constraints;
                std::vector<constraint_type> last_constraints;

                std::vector<lookup_constraint_type> middle_lookup_constraints;

                // first step is step selection
                first_constraints.push_back(state.step_selection.variable() - 1);
                start_selector = sel_manager.add_gate(first_constraints);
                // TODO: proper end constraints
                middle_constraints.push_back(state.last_row_indicator.variable(-1));
                last_constraints.push_back(state.last_row_indicator.variable(-1) - 1);
                end_selector = circuit.add_gate(last_constraints);

                std::vector<std::size_t> opcode_range_checked_cols;

                const std::size_t opcodes_amount = opcodes_info_instance.get_opcodes_amount();
                const std::size_t state_selector_cols_amount =
                    state_selector_type::get_manifest(opcodes_amount,true).witness_amount->max_value_if_sat();

                for (std::size_t i = 0; i < state_selector_cols_amount; i++) {
                    state_selector_cols.push_back(sel_manager.allocate_witess_column());
                }
                for(std::size_t i = 0; i < opcode_range_checked_cols_amount; i++) {
                    opcode_range_checked_cols.push_back(sel_manager.allocate_witess_column());
                }

                opcode_cols = opcode_range_checked_cols; // range-checked columns are the first part of opcode columns

                for (std::size_t i = 0; i < opcode_other_cols_amount; i++) { // followed by some non-range-checked columns
                    opcode_cols.push_back(sel_manager.allocate_witess_column());
                }
                state_selector = std::make_shared<state_selector_type>(
                    state_selector_cols, std::array<std::uint32_t, 0>({}), std::array<std::uint32_t, 0>({}),
                    opcodes_amount,true);

                auto state_selector_constraints = state_selector->generate_constraints();

                const std::size_t opcode_row_selection_cols_amount =
                    state_selector_type::get_manifest(max_opcode_height,false).witness_amount->max_value_if_sat();
                for (std::size_t i = 0; i < opcode_row_selection_cols_amount; i++) {
                    opcode_row_selection_cols.push_back(sel_manager.allocate_witess_column());
                }
                opcode_row_selector = std::make_shared<state_selector_type>(
                    opcode_row_selection_cols, std::array<std::uint32_t, 0>({}), std::array<std::uint32_t, 0>({}),
                    max_opcode_height,false);
                auto opcode_row_selector_constraints = opcode_row_selector->generate_constraints();

                if (state_selector->is_compressed) {
                    // for a compressed state selector we rely upon opcode_row_selector parity data to apply constraints once in 2 rows
                    var parity_var = opcode_row_selector->parity_variable();
                    for(auto constraint : state_selector_constraints) {
                        middle_constraints.push_back(constraint * parity_var);
                    }
                } else {
                    middle_constraints.insert(middle_constraints.end(), state_selector_constraints.begin(),
                                              state_selector_constraints.end());
                }

                middle_constraints.insert(middle_constraints.end(), opcode_row_selector_constraints.begin(),
                                          opcode_row_selector_constraints.end());

                auto generic_state_transition_constraints = generate_generic_transition_constraints(
                    start_selector, end_selector);
                // TODO : the problematic constraints that prevent proof verification \/ \/ \/
                middle_constraints.insert(middle_constraints.end(), generic_state_transition_constraints.begin(),
                                          generic_state_transition_constraints.end());

                // "unconditional" range checks for some opcode columns
                for(std::size_t i = 0; i < opcode_range_checked_cols_amount; i++) {
                    middle_lookup_constraints.push_back({range_check_table_index,
                        {var(opcode_range_checked_cols[i], 0 ,true, var::column_type::witness) } });
                }

                using gate_id_type = gate_id<BlueprintFieldType>;
                std::map<gate_id_type, constraint_type> constraint_list;
                std::map<gate_id_type, constraint_type> virtual_selector;

                for (auto opcode_it : opcodes) {
                    std::size_t opcode_height = opcode_it.second->rows_amount();
                    if (opcode_height > max_opcode_height) {
                        BOOST_ASSERT("Opcode height exceeds maximum, please update max_opcode_height constant.");
                    }

                    std::size_t opcode_num = opcodes_info_instance.get_opcode_value(opcode_it.first);
                    auto // curr_opt_constraint = state_selector->option_constraint(opcode_num),
                         curr_opt_constraint_even = state_selector->option_constraint_even(opcode_num),
                         curr_opt_constraint_odd = state_selector->option_constraint_odd(opcode_num);
                    // force max height to be proper value at the start of the opcode
                    middle_constraints.push_back(
                        curr_opt_constraint_odd * (state.rows_until_next_op.variable() - (max_opcode_height - 1)) *
                        state.step_selection.variable());
                    // curr_opt_constraint is in _odd_ version here because max_opcode_height-1 is odd

                    auto opcode_gates = opcode_it.second->generate_gates(*this);
                    for (auto gate_it : opcode_gates) {
                        switch (gate_it.first) {
                            case zkevm_opcode_gate_class::FIRST_OP:
                                for (auto constraint_pair : gate_it.second.first) {
                                    std::size_t local_row = constraint_pair.first;
                                    constraint_type curr_opt_constraint =
                                        (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    constraint_type constraint = get_opcode_row_constraint(local_row) * constraint_pair.second;

                                    constraint_list[gate_id_type(constraint_pair.second)] = constraint_pair.second;
                                    virtual_selector[gate_id_type(constraint_pair.second)] +=
                                        get_opcode_row_constraint(local_row) * curr_opt_constraint * start_selector;
                                }
                                for (auto lookup_constraint_pair : gate_it.second.second) {
                                    std::size_t local_row = lookup_constraint_pair.first;
                                    constraint_type curr_opt_constraint =
                                        (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    lookup_constraint_type lookup_constraint = lookup_constraint_pair.second;
                                    auto lookup_table = lookup_constraint.table_id;
                                    auto lookup_expressions = lookup_constraint.lookup_input;
                                    constraint_type row_selector = get_opcode_row_constraint(local_row);
                                    std::vector<constraint_type> new_lookup_expressions;

                                    for(auto lookup_expr : lookup_expressions) {
                                        new_lookup_expressions.push_back(curr_opt_constraint * lookup_expr * row_selector * start_selector);
                                    }
                                    middle_lookup_constraints.push_back({lookup_table, new_lookup_expressions});
                                }
                                break;
                            case zkevm_opcode_gate_class::MIDDLE_OP:
                                for (auto constraint_pair : gate_it.second.first) {
                                    std::size_t local_row = constraint_pair.first;
                                    constraint_type curr_opt_constraint =
                                        (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    constraint_type constraint = get_opcode_row_constraint(local_row) * constraint_pair.second;

                                    constraint_list[gate_id_type(constraint_pair.second)] = constraint_pair.second;
                                    virtual_selector[gate_id_type(constraint_pair.second)] +=
                                        get_opcode_row_constraint(local_row) * curr_opt_constraint;
                                }
                                for (auto lookup_constraint_pair : gate_it.second.second) {
                                    std::size_t local_row = lookup_constraint_pair.first;
                                    constraint_type curr_opt_constraint =
                                        (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    lookup_constraint_type lookup_constraint = lookup_constraint_pair.second;
                                    auto lookup_table = lookup_constraint.table_id;
                                    auto lookup_expressions = lookup_constraint.lookup_input;
                                    constraint_type row_selector = get_opcode_row_constraint(local_row);
                                    std::vector<constraint_type> new_lookup_expressions;

                                    for(auto lookup_expr : lookup_expressions) {
                                        new_lookup_expressions.push_back(curr_opt_constraint * lookup_expr * row_selector);
                                    }
                                    middle_lookup_constraints.push_back({lookup_table, new_lookup_expressions});
                                }
                                break;
                            case zkevm_opcode_gate_class::LAST_OP:
                                BOOST_ASSERT("Unimplemented");
                                break;
                            case zkevm_opcode_gate_class::NOT_LAST_OP:
                                BOOST_ASSERT("Unimplemented");
                                break;
                            default:
                                BOOST_ASSERT("Unknown gate class");
                        }
                    }
                }

                for(const auto c : virtual_selector) {
                    constraint_type constraint = constraint_list[c.first];
                    middle_constraints.push_back(constraint * c.second);
                }

                middle_selector = sel_manager.add_gate(middle_constraints);
                sel_manager.add_lookup_gate(middle_selector, middle_lookup_constraints);

                assignment.enable_selector(start_selector, curr_row);
                assignment.enable_selector(middle_selector, curr_row);
            }

            zkevm_state_type state;
            // static selectors used to mark the places where the circuit starts/ends
            std::size_t start_selector;
            std::size_t end_selector;
            // dynamic selector: indicates when the circuit is acitve
            // currently represented as a selector column; hopefully this is possible to do in practice
            std::size_t middle_selector;
            // added for lookups
            std::size_t lookup_selector;
            // witness columns for opcodes
            std::vector<std::size_t> opcode_cols;
            // dynamic selectors for the state selector circuit
            std::vector<std::size_t> state_selector_cols;
            // columns for selecting specific rows from the opcode
            std::vector<std::size_t> opcode_row_selection_cols;
            // ---------------------------------------------------------------------------------------------
            // |Variables below this point are internal to the object and do not go into the actual circuit|
            // ---------------------------------------------------------------------------------------------
            // reference to the assignment/circuit objects
            assignment_type &assignment;
            circuit_type &circuit;
            // information about opcode metadata (mapping, etc.)
            const opcodes_info &opcodes_info_instance;
            selector_manager_type sel_manager;
            std::shared_ptr<state_selector_type> state_selector;
            std::shared_ptr<state_selector_type> opcode_row_selector;
            // opcode objects
            std::map<zkevm_opcode, std::shared_ptr<zkevm_operation<BlueprintFieldType>>> opcodes;
            // current row maintained between different calls to the circuit object
            std::size_t curr_row;
            // start and end rows for the circuit; both have to be fixed
            std::size_t start_row_index;
            std::size_t end_row_index;

            static const std::size_t opcode_range_checked_cols_amount = 32;
            static const std::size_t opcode_other_cols_amount = 16;
            static const std::size_t max_opcode_cols = opcode_range_checked_cols_amount + opcode_other_cols_amount;
            static const std::size_t max_opcode_height = 8;
        };
        template<typename BlueprintFieldType>
        const std::size_t zkevm_circuit<BlueprintFieldType>::max_opcode_height;

    }   // namespace blueprint
}   // namespace nil
