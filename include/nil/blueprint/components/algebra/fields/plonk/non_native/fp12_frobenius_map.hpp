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
// @file Declaration of interfaces for F_p^{12} computation of p^k (k = 1,2,3)
// as a unary operation x[12] -> y[12], y = x^R
// We use towered field extension
// F_p^12 = F_p^6[w]/(w^2 - v),
// F_p^6 = F_p^2[v]/(v^3-(u+1)),
// F_p^2 = F_p[u]/(u^2 - (-1)).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FROBENIUS_MAP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FROBENIUS_MAP_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                enum small_p_power {p_one = 1, p_two = 2, p_three = 3};

                template<typename BlueprintFieldType>
                std::array<typename BlueprintFieldType::value_type,12> get_Fp12_frobenius_coefficients(small_p_power Power) {

                    using policy_type_fp2 = crypto3::algebra::fields::fp2<BlueprintFieldType>;
                    using fp2_element = typename policy_type_fp2::value_type;

                    std::array<typename BlueprintFieldType::value_type,12> res;

                    if constexpr (std::is_same_v<BlueprintFieldType, typename crypto3::algebra::fields::bls12_fq<381>>) {
                        // for BLS12-381 we have all the constants precomputed
                        if (Power == p_one) {
                            res[0] = 0x1_cppui381;
                            res[1] = 0x0_cppui381;
                            res[2] = 0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8_cppui381;
                            res[3] = 0xfc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3_cppui381;
                            res[4] = 0x0_cppui381;
                            res[5] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac_cppui381;
                            res[6] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[7] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[8] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad_cppui381;
                            res[9] = 0x0_cppui381;
                            res[10] = 0x5b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116_cppui381;
                            res[11] = 0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995_cppui381;
                        } else if (Power == p_two) {
                            res[0] = 0x1_cppui381;
                            res[1] = 0x0_cppui381;
                            res[2] = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff_cppui381;
                            res[3] = 0x0_cppui381;
                            res[4] = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe_cppui381;
                            res[5] = 0x0_cppui381;
                            res[6] = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa_cppui381;
                            res[7] = 0x0_cppui381;
                            res[8] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac_cppui381;
                            res[9] = 0x0_cppui381;
                            res[10] = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad_cppui381;
                            res[11] = 0x0_cppui381;
                        } else {
                            res[0] = 0x1_cppui381;
                            res[1] = 0x0_cppui381;
                            res[2] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                            res[3] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[4] = 0x0_cppui381;
                            res[5] = 0x1_cppui381;
                            res[6] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                            res[7] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                            res[8] = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa_cppui381;
                            res[9] = 0x0_cppui381;
                            res[10] = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09_cppui381;
                            res[11] = 0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2_cppui381;
                        }
                    } else {
                        // otherwise fallback to computation of constants
                        typename BlueprintFieldType::integral_type field_p = BlueprintFieldType::modulus,
                                                                   coef_exp = (field_p - 1)/6;
                        fp2_element frob_coef = fp2_element::one(),
                                    u_plus_1_pow = fp2_element(1,1).pow(coef_exp);
                        int k = int(Power);

                        for(std::size_t i = 0; i < 6; i++) {
                            res[2*i] = frob_coef.data[0];
                            res[2*i+1] = frob_coef.data[1];
                            frob_coef *= u_plus_1_pow;
                        }

                        if (k > 1) {
                            std::array<typename BlueprintFieldType::value_type,6> gamma_2;

                            for(std::size_t i = 0; i < 6; i++) gamma_2[i] = res[2*i].pow(2) + res[2*i+1].pow(2);

                            if (k > 2) {
                                for(std::size_t i = 0; i < 6; i++) {
                                    res[2*i] *= gamma_2[i];
                                    res[2*i+1] *= gamma_2[i];
                                }
                            } else {
                                res.fill(BlueprintFieldType::value_type::zero());
                                for(std::size_t i = 0; i < 6; i++) {
                                    res[2*i] = gamma_2[i];
                                }
                            }
                        }
                    }
                    return res;
                }
            } // namespace detail

            // F_p^12 gate for computing Frobenius maps x -> x^{p^k} for small k = 1,2,3
            // Parameter: Power = 1,2,3
            // Input: x[12], x
            // Output: y[12], y = x^{p^k} as elements of F_p^12

            using namespace detail;

            template<typename ArithmetizationType, small_p_power Power>
            class fp12_frobenius_map;

            template<typename BlueprintFieldType, small_p_power Power>
            class fp12_frobenius_map<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, Power>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fp12_frobenius_map::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(12,24)), // from 12 to 24
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1 + (witness_amount < 24); // anything that's smaller than 24 columns wide requires 2 rows
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    std::array<var,12> x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        for(auto & e : x) { res.push_back(e); }
                        return res;
                    }
                };

                struct result_type {
		    std::array<var,12> output;

                    result_type(const fp12_frobenius_map &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        for(std::size_t i = 0; i < 12; i++) {
                            output[i] = var(component.W((i+12) % WA), start_row_index + (i+12)/WA, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};

                        for(auto & e : output) { res.push_back(e); }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit fp12_frobenius_map(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fp12_frobenius_map(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fp12_frobenius_map(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, small_p_power Power>
            using plonk_fp12_frobenius_map =
                fp12_frobenius_map<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, Power>;

            template<typename BlueprintFieldType, small_p_power Power>
            typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::result_type generate_assignments(
                const plonk_fp12_frobenius_map<BlueprintFieldType, Power> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                typename BlueprintFieldType::integral_type field_p = BlueprintFieldType::modulus;
                const std::size_t WA = component.witness_amount();

                std::array<value_type,12> x;

                for(std::size_t i = 0; i < 12; i++) {
                    x[i] = var_value(assignment, instance_input.x[i]);
                    assignment.witness(component.W(i),start_row_index) = x[i];
                }

                using policy_type_fp12 = crypto3::algebra::fields::fp12_2over3over2<BlueprintFieldType>;
                using fp12_element = typename policy_type_fp12::value_type;

                fp12_element X = fp12_element({ {x[0],x[1]}, {x[2],x[3]}, {x[4],x[5]} }, { {x[6],x[7]}, {x[8],x[9]}, {x[10],x[11]} }),
                             Y = X;

                for(std::size_t i = 0; i < Power; i++) {
                    Y = Y.pow(field_p);
                }

                for(std::size_t i = 0; i < 12; i++) {
                    assignment.witness(component.W((12 + i) % WA),start_row_index + (12 + i)/WA) = Y.data[i/6].data[(i % 6)/2].data[i % 2];
                }

                return typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType, small_p_power Power>
            std::size_t generate_gates(
                const plonk_fp12_frobenius_map<BlueprintFieldType, Power> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::input_type
                    &instance_input) {

                using var = typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t WA = component.witness_amount();

                std::array<constraint_type,12> X, Y, P;
                std::array<std::array<constraint_type,2>,6> Z;
                std::array<typename BlueprintFieldType::value_type,12> C;

                for(std::size_t i = 0; i < 12; i++) {
                    X[i] = var(component.W(i), 0, true);
                    Y[i] = var(component.W((i+12) % WA), (i+12)/WA, true);
                }

                C = get_Fp12_frobenius_coefficients<BlueprintFieldType>(Power);

                for(std::size_t i = 0; i < 6; i++) {
                    // i -> i/2 + 3(i % 2) is a rearrangement of coefficients by increasing w powers, w.r.t. v = w²
                    Z[i][0] = X[2*(i/2 + 3*(i % 2))];
                    // Fp2 elements are conjugated when raising to p and p^3
                    Z[i][1] = X[2*(i/2 + 3*(i % 2)) + 1] * (Power != p_two ? -1 : 1);

                    P[2*(i/2 + 3*(i % 2))] = Z[i][0]*C[2*i] - Z[i][1]*C[2*i+1];
                    P[2*(i/2 + 3*(i % 2)) + 1] = Z[i][0]*C[2*i+1] + Z[i][1]*C[2*i];
                }

                std::vector<constraint_type> Cs = {};
                for(std::size_t i = 0; i < 12; i++) {
                    Cs.push_back(P[i] - Y[i]);
                }

                return bp.add_gate(Cs);
            }

            template<typename BlueprintFieldType, small_p_power Power>
            void generate_copy_constraints(
                const plonk_fp12_frobenius_map<BlueprintFieldType, Power> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::var;

                for(std::size_t i = 0; i < 12; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.x[i]});
                }
            }

            template<typename BlueprintFieldType, small_p_power Power>
            typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::result_type generate_circuit(
                const plonk_fp12_frobenius_map<BlueprintFieldType, Power> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fp12_frobenius_map<BlueprintFieldType, Power>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FP12_FROBENIUS_MAP_HPP
