//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the VARIABLE_BASE_MULTIPLICATION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication_per_bit.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/bool_scalar_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type, 
                std::uint32_t WitnessesAmount, typename NonNativePolicyType>
            class variable_base_multiplication;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            class variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType, 
                    Ed25519Type,
                    9,
                    basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 9, 1, 0> {

                constexpr static const std::uint32_t WitnessesAmount = 9;

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0>;

            public:
                using var = typename component_type::var;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using mult_per_bit_component = variable_base_multiplication_per_bit<
                    ArithmetizationType, CurveType, Ed25519Type, 9, non_native_policy_type>;

                using bit_decomposition_component = bit_decomposition<
                    ArithmetizationType, BlueprintFieldType, 9>;

                using bool_scalar_multiplication_component = bool_scalar_multiplication<
                    ArithmetizationType, Ed25519Type, 9, non_native_policy_type>;

                constexpr static const std::size_t rows_amount = bit_decomposition_component::rows_amount +
                                                                 252 * mult_per_bit_component::rows_amount +
                                                                 bool_scalar_multiplication_component::rows_amount;

                constexpr static const std::size_t gates_amount = 0;

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                    var k;
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const variable_base_multiplication &component, std::uint32_t start_row_index) {
                        using mult_per_bit_component =
                            components::variable_base_multiplication_per_bit<ArithmetizationType, 
                                CurveType, Ed25519Type, 9, non_native_policy_type>;
                        mult_per_bit_component component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {}, {});

                        auto final_mul_per_bit_res = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(
                            component_instance, start_row_index + rows_amount - mult_per_bit_component::rows_amount);   


                        output.x = {final_mul_per_bit_res.output.x[0], 
                                    final_mul_per_bit_res.output.x[1],
                                    final_mul_per_bit_res.output.x[2], 
                                    final_mul_per_bit_res.output.x[3]};
                        output.y = {final_mul_per_bit_res.output.y[0],
                                    final_mul_per_bit_res.output.y[1],
                                    final_mul_per_bit_res.output.y[2],
                                    final_mul_per_bit_res.output.y[3]};
                    }
                };

                template<typename ContainerType>
                variable_base_multiplication(ContainerType witness) : component_type(witness, {}, {}) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                variable_base_multiplication(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                variable_base_multiplication(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            using plonk_ed25519_var_base_mul = variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                typename crypto3::algebra::curves::ed25519,
                9,
                basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_assignments(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::var;
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using mult_per_bit_component = variable_base_multiplication_per_bit<
                        ArithmetizationType, CurveType, Ed25519Type, 9, non_native_policy_type>;

                    using bit_decomposition_component = bit_decomposition<
                        ArithmetizationType, BlueprintFieldType, 9>;

                    using bool_scalar_multiplication_component = bool_scalar_multiplication<
                        ArithmetizationType, Ed25519Type, 9, non_native_policy_type>;
                    
                    mult_per_bit_component mult_per_bit_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});
                    
                    bit_decomposition_component bit_decomposition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});
                    
                    bool_scalar_multiplication_component bool_scalar_multiplication_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename bit_decomposition_component::result_type bits = 
                        generate_assignments(bit_decomposition_instance, assignment,
                        typename bit_decomposition_component::input_type({instance_input.k}), row);
                    row += bit_decomposition_component::rows_amount;

                    typename bool_scalar_multiplication_component::result_type bool_mul_res = 
                        generate_assignments(bool_scalar_multiplication_instance, assignment,
                        typename bool_scalar_multiplication_component::input_type({{T_x, T_y}, bits.output[0]}), row);
                    row += bool_scalar_multiplication_component::rows_amount;

                    typename mult_per_bit_component::result_type res_per_bit = 
                        generate_assignments(mult_per_bit_instance, assignment,
                        typename mult_per_bit_component::input_type({{T_x, T_y}, 
                            {bool_mul_res.output.x, bool_mul_res.output.y}, bits.output[1]}),
                        row);
                    row += mult_per_bit_component::rows_amount;

                    for (std::size_t i = 2; i < 253; i++) {
                        res_per_bit = generate_assignments(mult_per_bit_instance, assignment,
                        typename mult_per_bit_component::input_type({{T_x, T_y}, 
                            {res_per_bit.output.x, res_per_bit.output.y}, bits.output[i]}), row);
                        row += mult_per_bit_component::rows_amount;                    
                    }

                    return typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_circuit(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::var;
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using mult_per_bit_component = variable_base_multiplication_per_bit<
                        ArithmetizationType, CurveType, Ed25519Type, 9, non_native_policy_type>;

                    using bit_decomposition_component = bit_decomposition<
                        ArithmetizationType, BlueprintFieldType, 9>;

                    using bool_scalar_multiplication_component = bool_scalar_multiplication<
                        ArithmetizationType, Ed25519Type, 9, non_native_policy_type>;
                    
                    mult_per_bit_component mult_per_bit_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});
                    
                    bit_decomposition_component bit_decomposition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});
                    
                    bool_scalar_multiplication_component bool_scalar_multiplication_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename bit_decomposition_component::result_type bits = 
                        generate_circuit(bit_decomposition_instance, bp, assignment,
                        typename bit_decomposition_component::input_type({instance_input.k}), row);
                    row += bit_decomposition_component::rows_amount;

                    typename bool_scalar_multiplication_component::result_type bool_mul_res = 
                        generate_circuit(bool_scalar_multiplication_instance, bp, assignment,
                        typename bool_scalar_multiplication_component::input_type({{T_x, T_y}, bits.output[0]}), row);
                    row += bool_scalar_multiplication_component::rows_amount;

                    typename mult_per_bit_component::result_type res_per_bit = 
                        generate_circuit(mult_per_bit_instance, bp, assignment,
                        typename mult_per_bit_component::input_type({{T_x, T_y}, 
                            {bool_mul_res.output.x, bool_mul_res.output.y}, bits.output[1]}),
                        row);
                    row += mult_per_bit_component::rows_amount;

                    for (std::size_t i = 2; i < 253; i++) {
                        res_per_bit = generate_circuit(mult_per_bit_instance, bp, assignment,
                        typename mult_per_bit_component::input_type({{T_x, T_y}, 
                            {res_per_bit.output.x, res_per_bit.output.y}, bits.output[i]}), row);
                        row += mult_per_bit_component::rows_amount;                    
                    }

                    return typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                void generate_gates(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::size_t first_selector_index) {
        
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                void generate_copy_constraints(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {
                }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP