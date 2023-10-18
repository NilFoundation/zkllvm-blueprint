//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for FRI verification coset generating component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_COSETS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_COSETS_HPP

#include <cmath>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // compute the number of lines if we need to place o object with pl object per line
            template<typename T1, typename T2>
            T1 lfit(T1 o, T2 pl) {
                 return o/pl + (o % pl > 0);
            }

	    // Uses parameters  n, total_bits, omega
            // Input: x (challenge, originally uint64_t, takes total_bits bits)
            // Output: vector of triplets < (s,-s,b) >, where s_0 = omega^{x % 2^n}, s_{i+1} = s_i^2,
	    // b = 0 or 1, showing whether the pair (s,-s) needs reordering
            template<typename ArithmetizationType, typename FieldType>
            class fri_cosets;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class fri_cosets<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                static std::size_t gates_amount_internal(std::size_t witness_amount, std::size_t n, std::size_t total_bits) {
		    const std::size_t l = witness_amount / 6; // number of 6-blocks per row
                    const std::size_t last_l = n % l; // 6-blocks in transition row. If 0, no transition row exists
                    const std::size_t sixb_rows = lfit(n,l); // number of rows with 6-blocks
                    const std::size_t bl2 = lfit(total_bits-n,3);
                    const std::size_t remaining_bl2 = bl2 - ((last_l > 0)? 3*(l - last_l) : 0);

                    return (sixb_rows > 1) + (sixb_rows > 2) + 1 + (2*remaining_bl2 > witness_amount) + (remaining_bl2 > 0);
                }


                static std::size_t rows_amount_internal(std::size_t witness_amount,
                                                        std::size_t n,
                                                        std::size_t total_bits) {
                    return lfit(6*n + 2*lfit(total_bits-n,3), witness_amount ); // bits in chunks of 3, stored in 2-blocks
                }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    std::size_t n;
                    std::size_t total_bits;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t n_, std::size_t total_bits_)
                        : witness_amount(witness_amount_), n(n_), total_bits(total_bits_) {}

                    std::uint32_t gates_amount() const override {
                        return fri_cosets::gates_amount_internal(witness_amount,n,total_bits);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        std::size_t o_witness_amount = dynamic_cast<const gate_manifest_type*>(other)->witness_amount;
                        std::size_t o_n = dynamic_cast<const gate_manifest_type*>(other)->n;
                        std::size_t o_total_bits = dynamic_cast<const gate_manifest_type*>(other)->total_bits;

                        std::size_t l = witness_amount / 6;       std::size_t o_l = o_witness_amount / 6;
                        std::size_t last_l = n % l;               std::size_t o_last_l = o_n % o_l;
                        std::size_t sixb_rows = lfit(n,l);        std::size_t o_sixb_rows = lfit(o_n,o_l);
                        std::size_t bl2 = lfit(total_bits-n,3);   std::size_t o_bl2 = lfit(o_total_bits-o_n,3);

                        std::size_t remaining_bl2 = bl2 - ((last_l > 0)? 3*(l - last_l) : 0);
                        std::size_t o_remaining_bl2 = o_bl2 - ((o_last_l > 0)? 3*(o_l - o_last_l) : 0);

                        std::array<std::size_t,7> gates = { witness_amount,
                                                          last_l,
                                                          remaining_bl2 % (3*l),
                                                          (sixb_rows > 1),
                                                          (sixb_rows > 2),
                                                          (remaining_bl2 > 0),
                                                          (2*remaining_bl2 > witness_amount) };
                        std::array<std::size_t,7> o_gates = { o_witness_amount,
                                                            o_last_l,
                                                            o_remaining_bl2 % (3*o_l),
                                                            (o_sixb_rows > 1),
                                                            (o_sixb_rows > 2),
                                                            (o_remaining_bl2 > 0),
                                                            (2*o_remaining_bl2 > o_witness_amount) };
                        return (gates < o_gates);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t n,
                                                       std::size_t total_bits) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount,n,total_bits));
                    return manifest;
                }


                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(6,384,6) // 384 = 6*64, because we plan n <= 64
                        ),
                        true // constant column required
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t n,
                                                             std::size_t total_bits) {
                    return rows_amount_internal(witness_amount,n,total_bits);
                }
                // Initialized by constructor
                std::size_t n;
                std::size_t total_bits;
                value_type omega;
                // aliases and derivatives
                const std::size_t WA = this->witness_amount();
                const std::size_t six_bl_per_line = WA / 6; // 6-blocks per line
                const std::size_t two_bl_per_line = WA / 2; // 2-block per line
                const std::size_t two_blocks_count = lfit(total_bits-n,3); // number of 2-blocks

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), n, total_bits);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct result_type {
                    std::array<var,3> output; // TODO -> vector<array<var,3>>

                    result_type(const fri_cosets &component, std::size_t start_row_index) {
                        const std::size_t n = component.n;
                        const std::size_t l = component.six_bl_per_line;
                        std::size_t i = lfit(n,l) - 1; // the last of the lfit(n,l) lines, numbered from 0
                        std::size_t j = ((n % l > 0) ? n % l : l) - 1; // the last of 6-blocks numbered from 0 in every line

                        output = { var(component.W(6*j + 3), start_row_index + i, false, var::column_type::witness),
                                   var(component.W(6*j + 4), start_row_index + i, false, var::column_type::witness),
                                   var(component.W(6*j + 5), start_row_index + i, false, var::column_type::witness) };
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {output[0],output[1],output[2]};
                     // intended for future extension
                     /*
                        for(auto & e : output) {
                            res.push_back(e[0]); res.push_back(e[1]); res.push_back(e[2]);
                        }
                     */
                        return res;
                    }
                };

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                fri_cosets(WitnessContainerType witness,
                           ConstantContainerType constant,
                           PublicInputContainerType public_input,
                           std::size_t n_,
                           std::size_t total_bits_,
                           value_type omega_):
                    component_type(witness, constant, public_input, get_manifest()),
                    n(n_),
                    total_bits(total_bits_),
                    omega(omega_) {

                };

                fri_cosets(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs,
                        std::size_t n_,
                        std::size_t total_bits_,
                        value_type omega_):
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    n(n_),
                    total_bits(total_bits_),
                    omega(omega_) {

                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fri_cosets =
                fri_cosets<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t i0 = start_row_index;
                const std::size_t n = component.n;
                const std::size_t l = component.six_bl_per_line;
                const std::size_t bl2 = component.two_blocks_count;
                const std::size_t bl2_line = component.two_bl_per_line;

                typename BlueprintFieldType::integral_type x_decomp =
                               typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.x).data);

                value_type w_power = component.omega;
                value_type coset_element = 1;

                // fill the 6-blocks
                // top-down part
                for(std::size_t b = 0; b < n; b++) {
		    std::size_t i = i0 + b / l;
                    std::size_t j = b % l;
                    assignment.witness(component.W(6*j),i) = value_type(x_decomp);
                    assignment.witness(component.W(6*j+1),i) = w_power;
                    coset_element *= (x_decomp % 2 == 1 ? w_power : 1);
                    assignment.witness(component.W(6*j+2),i) = coset_element;
                    assignment.witness(component.W(6*j+5),i) = value_type(x_decomp % 2);
                    x_decomp /= 2;
                    w_power *= w_power;
                }
                // down-top part
                for(std::size_t b = n; b > 0; b--) {
		    std::size_t i = i0 + (b-1) / l;
                    std::size_t j = (b-1) % l;
                    assignment.witness(component.W(6*j+3),i) = coset_element;
                    assignment.witness(component.W(6*j+4),i) = (-1)*coset_element;
                    coset_element = coset_element * coset_element;
                }

                for(std::size_t b = 0; b < bl2; b++) {
                    std::size_t i = i0 + (3*n + b)/bl2_line;
                    std::size_t j = (3*n + b) % bl2_line;
                    assignment.witness(component.W(2*j),i) = value_type(x_decomp);
                    assignment.witness(component.W(2*j+1),i) = value_type(x_decomp % 8);
                    x_decomp = x_decomp / 8;
                }
                return typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::var;

                bp.add_copy_constraint({instance_input.x, var(component.W(0), start_row_index, false)});
                bp.add_copy_constraint({var(0, start_row_index, false, var::column_type::constant),
                                        var(component.W(1), start_row_index, false)});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

                using var = typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t WA = component.WA;

                const std::size_t l = component.six_bl_per_line;
                const std::size_t sixb_rows = lfit(component.n,l); // number of rows with 6-blocks
                const std::size_t last_l = component.n % l; // 6-blocks in transition row. If 0, no transition row exists

                const std::size_t bl2 = component.two_blocks_count;
                const std::size_t bl2_line = component.two_bl_per_line;

                std::size_t selector_index;

                std::vector<constraint_type> six_block;
                std::vector<constraint_type> two_block;
                std::vector<constraint_type> cs;
                constraint_type first_W2 = var(component.W(1),0)*var(component.W(5),0) + 1 - var(component.W(5),0) - var(component.W(2),0);

                // Store typical constraints for every column
                six_block.resize(WA);
                for(std::size_t j = 0; j < l; j++) {
                    six_block[6*j]   = var(component.W(6*j),0) - 2*var(component.W(6*((j+1) % l)),(j+1)/l) - var(component.W(6*j+5),0);
                    six_block[6*j+1] = var(component.W(6*j+1),0) -
                                       var(component.W(6*((l+j-1) % l) + 1), -(j == 0)) * var(component.W(6*((l+j-1) % l) + 1), -(j == 0));
                    six_block[6*j+2] = var(component.W(6*j + 2),0) -
                                           var(component.W(6*((l+j-1) % l) + 2), -(j == 0))*
                                           (var(component.W(6*j + 1),0)*var(component.W(6*j + 5),0) + 1 - var(component.W(6*j + 5),0));
                    six_block[6*j+3] = var(component.W(6*j + 3),0) -
                                       var(component.W(6*((j+1) % l) + 3),(j+1)/l)*var(component.W(6*((j+1) % l) + 3),(j+1)/l);
                    six_block[6*j+4] = var(component.W(6*j + 3),0) + var(component.W(6*j + 4),0);
                    six_block[6*j+5] = (1 - var(component.W(6*j + 5),0)) * var(component.W(6*j + 5),0);
                }

                two_block.resize(WA);
                for(std::size_t j = 0; j < bl2_line; j++) {
                    two_block[2*j] = var(component.W(2*j),0)
                                - 8* var(component.W(2*((j+1) % bl2_line)),(j+1)/bl2_line) - var(component.W(2*j + 1),0);
                    two_block[2*j+1] = var(component.W(2*j + 1),0) *
                                       (var(component.W(2*j + 1),0) - 1)*
                                       (var(component.W(2*j + 1),0) - 2)*
                                       (var(component.W(2*j + 1),0) - 3)*
                                       (var(component.W(2*j + 1),0) - 4)*
                                       (var(component.W(2*j + 1),0) - 5)*
                                       (var(component.W(2*j + 1),0) - 6)*
                                       (var(component.W(2*j + 1),0) - 7);
                }

                if (sixb_rows > 1) { // there is a starting row which is not final (gate type 1)
                    cs = {six_block[0]};
                    cs.push_back(first_W2);
                    cs.insert(cs.end(),std::next(six_block.begin(),3),six_block.end());
                    selector_index = bp.add_gate(cs); // type 1 gate
                    // Applying gate type 1 to line 0
                    assignment.enable_selector(selector_index, start_row_index);
                }
                if (sixb_rows > 2) { // there is a middle row (gate type 2)
                    selector_index = bp.add_gate(six_block); // type 2 gate
                    // Applying gate type 2 to lines 1--(sixb_rows - 2)
                    for(std::size_t i = 1; i < sixb_rows - 1; i++) {
                        assignment.enable_selector(selector_index, start_row_index + i);
                    }
                }

                // The gate for the line where the 6-blocks end
                std::size_t last = (last_l > 0)? last_l : l; // The number of the last 6-block in the row
                cs = {six_block[0]};
                if (sixb_rows > 1) { // if the first 6-block is a regular middle 6-block, otherwise there's no "previous"
                    cs.push_back(six_block[1]);
                    cs.push_back(six_block[2]);
                } else {
                    cs.push_back(first_W2);
                }
                cs.insert(cs.end(),std::next(six_block.begin(),3),std::next(six_block.begin(),6*(last-1)+3));
                cs.push_back(var(component.W(6*(last - 1) + 3),0) - var(component.W(6*(last - 1) + 2),0));
                cs.push_back(six_block[6*(last-1)+4]);
                cs.push_back(six_block[6*(last-1)+5]);

                if (last_l > 0) { // the 2-blocks start in the middle of the line
                    if (6*last_l + 2*bl2 <= WA) { // this is actually the last row
                        // standard constraints for all 2-blocks except the last one
                        cs.insert(cs.end(),
                                  std::next(two_block.begin(),6*last_l),
                                  std::next(two_block.begin(),6*last_l + 2*(bl2 - 1))
                                 );
                        cs.push_back(var(component.W(6*last_l + 2*(bl2 - 1)),0) -
                                     var(component.W(6*last_l + 2*(bl2 - 1) + 1),0));
                        cs.push_back(two_block[6*last_l + 2*(bl2 - 1) + 1]);
                    } else { // 2-block don't end there
                        cs.insert(cs.end(),
                                  std::next(two_block.begin(),6*last_l),
                                  two_block.end());
                    }
                }
                selector_index = bp.add_gate(cs); // type 3 gate
                // Applying gate type 3 to line (sixb_rows - 1)
                assignment.enable_selector(selector_index, start_row_index + sixb_rows - 1);

                // the number of 2-blocks not fitting on the "transition" line
                std::size_t remaining_bl2 = bl2 - (last_l > 0 ? bl2_line - 3*last_l : 0);
                if (remaining_bl2 > bl2_line) {
                    selector_index = bp.add_gate(two_block); // type 4 gate
                    // Applying gate type 4 to lines sixb_rows -- (sixb_rows + lfit(remaining_bl2,bl2_line) - 2)
                    for(std::size_t i = 0; i < lfit(remaining_bl2,bl2_line) - 1; i++) {
                        assignment.enable_selector(selector_index, start_row_index + sixb_rows + i);
                    }
                }

                std::size_t last_bl2 = remaining_bl2 % bl2_line; // number of 2-blocks in the last 2-block line
                if (last_bl2 == 0) { last_bl2 = bl2_line; }
                if (remaining_bl2 > 0) { // if 2-blocks don't all fit into transition row (gate type 5)
                    cs.clear();
                    cs.insert(cs.end(),two_block.begin(),std::next(two_block.begin(),2*(last_bl2-1)));
                    cs.push_back(var(component.W(2*(last_bl2-1)),0) - var(component.W(2*(last_bl2-1) + 1),0));
                    cs.push_back(two_block[2*last_bl2 - 1]);
                    selector_index = bp.add_gate(cs);
                    // Applying gate type 5 to line (sixb_rows + lfit(remaining_bl2, bl2_line) - 1)
                    assignment.enable_selector(selector_index,
                                               start_row_index + sixb_rows + lfit(remaining_bl2, bl2_line) - 1);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = component.omega;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_COSETS_HPP
