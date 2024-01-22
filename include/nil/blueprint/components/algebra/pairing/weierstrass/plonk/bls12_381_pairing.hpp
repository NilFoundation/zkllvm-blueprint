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
// @file Declaration of the BLS12-381 pairing component
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_381_PAIRING_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_381_PAIRING_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/miller_loop.hpp>
#include <nil/blueprint/components/algebra/pairing/weierstrass/plonk/bls12_exponentiation.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            //
            // Component for computing the pairing of
            // two points: P from E(F_p) and Q from E'(F_p^2)
            // for BLS12-381.
            // Input: P[2], Q[4] ( we assume P and Q are NOT (0,0), i.e. not the points at infinity, NOT CHECKED )
            // Output: f[12]: an element of F_p^12
            //
            // It is just the Miller loop followed by exponentiation.
            // We realize the circuit in two versions - 12-column and 24-column.
            //

            using namespace detail;

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class bls12_381_pairing;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bls12_381_pairing<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            static std::size_t gates_amount_internal(std::size_t witness_amount) {
                return 0;
            }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using bls12_miller_loop_type = miller_loop<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;
                using bls12_exponentiation_type = bls12_exponentiation<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return bls12_381_pairing::gates_amount_internal(witness_amount);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        return (witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount))
                        .merge_with(bls12_miller_loop_type::get_gate_manifest(witness_amount,lookup_column_amount))
                        .merge_with(bls12_exponentiation_type::get_gate_manifest(witness_amount,lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24,12)), // 12 or 24
                        false
                    ).merge_with(bls12_miller_loop_type::get_manifest())
                     .merge_with(bls12_exponentiation_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return bls12_miller_loop_type::get_rows_amount(witness_amount, lookup_column_amount,0xD201000000010000) +
                           bls12_exponentiation_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                const std::size_t gates_amount = gates_amount_internal(this->witness_amount());
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,2> P;
                    std::array<var,4> Q;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {P[0], P[1], Q[0], Q[1], Q[2], Q[3]};
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit bls12_381_pairing(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) { };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bls12_381_pairing(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) { };
                bls12_381_pairing(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) { };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_bls12_381_pairing =
                bls12_381_pairing<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>;
                using bls12_miller_loop_type = typename component_type::bls12_miller_loop_type;
                using bls12_exponentiation_type = typename component_type::bls12_exponentiation_type;

                bls12_miller_loop_type miller_loop_instance( component._W, component._C, component._PI, 0xD201000000010000);
                bls12_exponentiation_type exponentiation_instance( component._W, component._C, component._PI);

                typename bls12_miller_loop_type::input_type miller_loop_input = {instance_input.P, instance_input.Q};
                typename bls12_miller_loop_type::result_type miller_loop_result =
                    generate_assignments(miller_loop_instance, assignment, miller_loop_input, start_row_index);

                typename bls12_exponentiation_type::input_type exponentiation_input = {
                    miller_loop_result.output[0],
                    miller_loop_result.output[1],
                    miller_loop_result.output[2],
                    miller_loop_result.output[3],
                    miller_loop_result.output[4],
                    miller_loop_result.output[5],
                    miller_loop_result.output[6],
                    miller_loop_result.output[7],
                    miller_loop_result.output[8],
                    miller_loop_result.output[9],
                    miller_loop_result.output[10],
                    miller_loop_result.output[11]
                };
                typename bls12_exponentiation_type::result_type exp_result =
                    generate_assignments(exponentiation_instance, assignment, exponentiation_input,
                                         start_row_index + miller_loop_instance.rows_amount);

                typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::result_type res = {
                    exp_result.output[0],
                    exp_result.output[1],
                    exp_result.output[2],
                    exp_result.output[3],
                    exp_result.output[4],
                    exp_result.output[5],
                    exp_result.output[6],
                    exp_result.output[7],
                    exp_result.output[8],
                    exp_result.output[9],
                    exp_result.output[10],
                    exp_result.output[11]
                };
                return res;
	    }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                return {};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>;
                using bls12_miller_loop_type = typename component_type::bls12_miller_loop_type;
                using bls12_exponentiation_type = typename component_type::bls12_exponentiation_type;

                bls12_miller_loop_type miller_loop_instance( component._W, component._C, component._PI, 0xD201000000010000);
                bls12_exponentiation_type exponentiation_instance( component._W, component._C, component._PI);

                typename bls12_miller_loop_type::input_type miller_loop_input = {instance_input.P, instance_input.Q};
                typename bls12_miller_loop_type::result_type miller_loop_result =
                    generate_circuit(miller_loop_instance, bp, assignment, miller_loop_input, start_row_index);

                typename bls12_exponentiation_type::input_type exponentiation_input = {
                    miller_loop_result.output[0],
                    miller_loop_result.output[1],
                    miller_loop_result.output[2],
                    miller_loop_result.output[3],
                    miller_loop_result.output[4],
                    miller_loop_result.output[5],
                    miller_loop_result.output[6],
                    miller_loop_result.output[7],
                    miller_loop_result.output[8],
                    miller_loop_result.output[9],
                    miller_loop_result.output[10],
                    miller_loop_result.output[11]
                };
                typename bls12_exponentiation_type::result_type exp_result =
                    generate_circuit(exponentiation_instance, bp, assignment, exponentiation_input,
                                         start_row_index + miller_loop_instance.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                typename plonk_bls12_381_pairing<BlueprintFieldType, ArithmetizationParams>::result_type res = {
                    exp_result.output[0],
                    exp_result.output[1],
                    exp_result.output[2],
                    exp_result.output[3],
                    exp_result.output[4],
                    exp_result.output[5],
                    exp_result.output[6],
                    exp_result.output[7],
                    exp_result.output[8],
                    exp_result.output[9],
                    exp_result.output[10],
                    exp_result.output[11]
                };
                return res;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_BLS12_381_PAIRING_HPP
