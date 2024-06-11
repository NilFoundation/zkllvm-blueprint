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
// @file Declaration of interfaces for ECDSA public key recovery over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ECDSA_RECOVERY_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ECDSA_RECOVERY_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/detail/plonk/range_check_multi.hpp>
#include <nil/blueprint/components/detail/plonk/carry_on_addition.hpp>
#include <nil/blueprint/components/detail/plonk/choice_function.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/negation_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/check_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition_mod_p.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_full_add.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/plonk/ec_scalar_mult.hpp>
namespace nil {
    namespace blueprint {
        namespace components {
            // Parameters: curve (in Weierstrass form, y² = x³ + a), num_chunks = k, bit_size_chunk = b
            // Takes partial message hash z and extended ECDSA signature (r,s,v)
            // Outputs
            // bit c = signature is valid and
            // QA = (xQA, yQA) = the recovered public key
            //
            // Expects input as k-chunked values with b bits per chunk
            //
            // Input: z[0],...,z[k-1], r[0],...,r[k-1], s[0],...,s[k-1], v
            //
            // Output: c, xQA[0],...,xQA[k-1], yQA[0],...,yQA[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType,
                     typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ecdsa_recovery;

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            class ecdsa_recovery<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           CurveType,
                           num_chunks,
                           bit_size_chunk>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using BaseFieldType = typename CurveType::base_field_type;
                using ScalarFieldType = typename CurveType::scalar_field_type;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using range_check_component = range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk>;
                using carry_on_addition_component = carry_on_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk>;
                using choice_function_component = choice_function<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks>;
                using check_mod_p_component = check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk>;
                using check_mod_p_output_component = check_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, num_chunks, bit_size_chunk,true>;

                using neg_mod_p_component = negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, BaseFieldType, num_chunks, bit_size_chunk>;
                using add_mod_p_component = addition_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, BaseFieldType, num_chunks, bit_size_chunk>;
                using mult_mod_p_component = flexible_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, BaseFieldType, num_chunks, bit_size_chunk>;

                using neg_mod_n_component = negation_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, ScalarFieldType, num_chunks, bit_size_chunk>;
                using add_mod_n_component = addition_mod_p<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, ScalarFieldType, num_chunks, bit_size_chunk>;
                using mult_mod_n_component = flexible_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, ScalarFieldType, num_chunks, bit_size_chunk>;

                using ec_full_add_component = ec_full_add<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, BaseFieldType, num_chunks, bit_size_chunk>;
                using ec_scalar_mult_component = ec_scalar_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      BlueprintFieldType, BaseFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return ecdsa_recovery::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    // NB: this uses a workaround, as manifest cannot process intersecting sets of gates.
                    // We merge only non-intersecting sets of gates which cover all gates in the circuit.
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                       // .merge_with(range_check_component::get_gate_manifest(witness_amount))
                       // .merge_with(carry_on_addition_component::get_gate_manifest(witness_amount))
                       // .merge_with(choice_function_component::get_gate_manifest(witness_amount))
                       // .merge_with(check_mod_p_component::get_gate_manifest(witness_amount))
                       // .merge_with(check_mod_p_output_component::get_gate_manifest(witness_amount))
                       // .merge_with(neg_mod_p_component::get_gate_manifest(witness_amount))
                       // .merge_with(add_mod_p_component::get_gate_manifest(witness_amount))
                       // .merge_with(mult_mod_p_component::get_gate_manifest(witness_amount))
                       // .merge_with(ec_full_add_component::get_gate_manifest(witness_amount))
                        .merge_with(ec_scalar_mult_component::get_gate_manifest(witness_amount))
                       ;
                    return manifest;
                }

                static manifest_type get_manifest() {
                    manifest_type manifest = manifest_type(
                        // all requirements come from sub-components, the component itself has no personal requirements
                        // we need place for:
                        // 9 bits (c, c1,...,c8)
                        // the output xQA, yQA (2*num_chunks)
                        // coefs u1, u2 (2*num_chunks)
                        // the point R (2*num_chunks)
                        // 6 auxiliary values (6*num_chunks)
                        // Total = 9 + 12*num_chunks
                        std::shared_ptr<manifest_param>(new manifest_range_param(1, 9 + 12*num_chunks,1)),
                        true // constant column IS needed
                    ).merge_with(range_check_component::get_manifest())
                     .merge_with(carry_on_addition_component::get_manifest())
                     .merge_with(choice_function_component::get_manifest())
                     .merge_with(check_mod_p_component::get_manifest())
                     .merge_with(check_mod_p_output_component::get_manifest())
                     .merge_with(neg_mod_p_component::get_manifest())
                     .merge_with(add_mod_p_component::get_manifest())
                     .merge_with(mult_mod_p_component::get_manifest())
                     .merge_with(ec_full_add_component::get_manifest())
                     .merge_with(ec_scalar_mult_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    std::size_t total_cells = 9 + 12*num_chunks;
                    std::size_t num_rows = total_cells/witness_amount + (total_cells % witness_amount > 0)
                           + 12*range_check_component::get_rows_amount(witness_amount)
                           + 3*carry_on_addition_component::get_rows_amount(witness_amount)
                           + 12*choice_function_component::get_rows_amount(witness_amount)
                           + 9*check_mod_p_component::get_rows_amount(witness_amount)
                           + 2*check_mod_p_output_component::get_rows_amount(witness_amount)
                           + 2*neg_mod_p_component::get_rows_amount(witness_amount)
                           + 8*add_mod_p_component::get_rows_amount(witness_amount)
                           + 17*mult_mod_p_component::get_rows_amount(witness_amount)
                           + 1*ec_full_add_component::get_rows_amount(witness_amount)
                           + 2*ec_scalar_mult_component::get_rows_amount(witness_amount)
                           ;
std::cout << "Rows amount = " << num_rows << "\n";
                    return num_rows;
                }

                constexpr static const std::size_t gates_amount = 0;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "non-native field ECDSA recovery";

                struct input_type {
                    var z[num_chunks], r[num_chunks], s[num_chunks], v;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {v};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(z[i]);
                            res.push_back(r[i]);
                            res.push_back(s[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    var c, xQA[num_chunks], yQA[num_chunks];

                    result_type(const ecdsa_recovery &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        c = var(component.W(0),start_row_index, false, var::column_type::witness);

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            xQA[i] = var(component.W((i+1) % WA), start_row_index + (i+1)/WA, false, var::column_type::witness);
                            yQA[i] = var(component.W((1 + num_chunks + i) % WA),
                                          start_row_index + (1 + num_chunks + i)/WA, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {c};
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(xQA[i]);
                            res.push_back(yQA[i]);
                        }
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit ecdsa_recovery(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                ecdsa_recovery(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                ecdsa_recovery(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["range_16bit/full"] = 0;

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            using plonk_ecdsa_recovery =
                ecdsa_recovery<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    CurveType,
                    num_chunks,
                    bit_size_chunk>;

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::result_type generate_assignments(
                const plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>;
                using var = typename component_type::var;

                using range_check_type = typename component_type::range_check_component;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using choice_function_type = typename component_type::choice_function_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;
                using check_mod_p_output_type = typename component_type::check_mod_p_output_component;

                using neg_mod_p_type = typename component_type::neg_mod_p_component;
                using add_mod_p_type = typename component_type::add_mod_p_component;
                using mult_mod_p_type = typename component_type::mult_mod_p_component;

                using neg_mod_n_type = typename component_type::neg_mod_n_component;
                using add_mod_n_type = typename component_type::add_mod_n_component;
                using mult_mod_n_type = typename component_type::mult_mod_n_component;

                using ec_full_add_type = typename component_type::ec_full_add_component;
                using ec_scalar_mult_type = typename component_type::ec_scalar_mult_component;

                // instances of used subcomponents
                range_check_type            range_check_instance( component._W, component._C, component._PI);
                carry_on_addition_type      carry_on_addition_instance( component._W, component._C, component._PI);
                choice_function_type        choice_function_instance( component._W, component._C, component._PI);
                check_mod_p_type            check_mod_p_instance( component._W, component._C, component._PI);
                check_mod_p_output_type     check_mod_p_output_instance( component._W, component._C, component._PI);

                neg_mod_p_type              neg_mod_p_instance( component._W, component._C, component._PI);
                add_mod_p_type              add_mod_p_instance( component._W, component._C, component._PI);
                mult_mod_p_type             mult_mod_p_instance( component._W, component._C, component._PI);

                neg_mod_n_type              neg_mod_n_instance( component._W, component._C, component._PI);
                add_mod_n_type              add_mod_n_instance( component._W, component._C, component._PI);
                mult_mod_n_type             mult_mod_n_instance( component._W, component._C, component._PI);

                ec_full_add_type            ec_full_add_instance( component._W, component._C, component._PI);
                ec_scalar_mult_type         ec_scalar_mult_instance( component._W, component._C, component._PI);

                using BaseFieldType = typename CurveType::base_field_type;
                using ScalarFieldType = typename CurveType::scalar_field_type;

                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using base_value_type = typename BaseFieldType::value_type;
                using scalar_value_type = typename ScalarFieldType::value_type;
                using base_integral_type = typename BaseFieldType::integral_type;
                using scalar_basic_integral_type = typename ScalarFieldType::integral_type;
                using scalar_integral_type = typename ScalarFieldType::extended_integral_type;
                using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;

                const std::size_t WA = component.witness_amount();

                // curve constants
                base_integral_type bB = base_integral_type(1) << bit_size_chunk;

                scalar_integral_type sB = scalar_integral_type(1) << bit_size_chunk,
                                      n = ScalarFieldType::modulus,
                                      m = (n-1)/2 + 1;

                ec_point_value_type G = ec_point_value_type::one();
                base_integral_type a = CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::params_type::b;

                // values to be obtained from input NB: if z,r,s exceed n they will be reduced mod n here
                scalar_value_type z = 0,
                                  r = 0,
                                  s = 0,
                                  v = scalar_integral_type(integral_type(var_value(assignment, instance_input.v).data));
                for(std::size_t i = num_chunks; i > 0; i--) {
                    z *= sB;
                    z += scalar_integral_type(integral_type(var_value(assignment, instance_input.z[i-1]).data));
                    r *= sB;
                    r += scalar_integral_type(integral_type(var_value(assignment, instance_input.r[i-1]).data));
                    s *= sB;
                    s += scalar_integral_type(integral_type(var_value(assignment, instance_input.s[i-1]).data));
                }

                // the computations
                value_type c[9]; // the c bits, c[0] = c[1]*...*c[8]
                scalar_value_type I1, I3, I6;
                base_value_type I5, d2, I8;

                c[1] = 1 - r.is_zero();
                I1 = r.is_zero() ? 0 : r.inversed();

                c[2] = (scalar_basic_integral_type(r.data) < n) ? 1 : 0;

                c[3] = 1 - s.is_zero();
                I3 = s.is_zero() ? 0 : s.inversed();

                c[4] = (scalar_basic_integral_type(s.data) < m) ? 1 : 0;

                base_value_type x1 = scalar_basic_integral_type(r.data); // should we consider r + n also?
                base_value_type y1 = (x1*x1*x1 + a).is_square() ? (x1*x1*x1 + a).sqrt() : 1; // should be signaled as invalid signaure
                // base_value_type y1 = (x1*x1*x1 + a).sqrt(); // should be signaled as invalid signaure
                if (base_integral_type(y1.data) % 2 != scalar_basic_integral_type(v.data) % 2) {
                    y1 = -y1;
                }
                c[5] = (x1*x1*x1 + a - y1*y1).is_zero();
                I5 = (x1*x1*x1 + a - y1*y1).is_zero() ? 0 : (x1*x1*x1 + a - y1*y1).inversed();

                c[6] = (scalar_value_type(base_integral_type(x1.data)) - r).is_zero();
                I6 = (scalar_value_type(base_integral_type(x1.data)) - r).is_zero() ?
                      0 : (scalar_value_type(base_integral_type(x1.data)) - r).inversed();

                c[7] = ((base_integral_type(y1.data) % 2) == (scalar_basic_integral_type(v.data) % 2));
                d2 = (base_integral_type(y1.data) + base_integral_type(scalar_basic_integral_type(v.data)))/2;

                scalar_value_type u1 = r.is_zero() ? 2 : -z * r.inversed(), // if r = 0, the signature is invalid, but we
                                  u2 = r.is_zero() ? 2 : s * r.inversed();  // don't wanto to break the scalar multiplication
                ec_point_value_type R = ec_point_value_type(scalar_basic_integral_type(x1.data), scalar_basic_integral_type(y1.data)),
                                    QA = G*u1 + R*u2;
                c[8] = 1 - QA.is_zero();
                I8 = QA.Y.is_zero() ? 0 :  QA.Y.inversed();

                c[0] = c[1]*c[2]*c[3]*c[4]*c[5]*c[6]*c[7]*c[8];

                // fill everything into cells
                std::size_t cell_num = 0; // relative number of cell
                auto FillCell = [&assignment, &component, &start_row_index, &WA, &cell_num](value_type x) {
                    assignment.witness(component.W(cell_num % WA), start_row_index + cell_num/WA) = x;
                    cell_num++;
                };
                auto FillBChunks = [&assignment, &component, &start_row_index, &WA, &cell_num, &bB](base_value_type x) {
                    base_integral_type X = base_integral_type(x.data);
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        assignment.witness(component.W(cell_num % WA), start_row_index + cell_num/WA) = X % bB;
                        X /= bB;
                        cell_num++;
                    }
                };
                auto FillSChunks = [&assignment, &component, &start_row_index, &WA, &cell_num, &sB](scalar_value_type x) {
                    scalar_integral_type X = scalar_basic_integral_type(x.data);
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        assignment.witness(component.W(cell_num % WA), start_row_index + cell_num/WA) = X % sB;
                        X /= sB;
                        cell_num++;
                    }
                };

                FillCell(c[0]);
                FillBChunks(QA.X);
                FillBChunks(QA.Y);
                for(std::size_t i = 1; i < 9; i++) {
                    FillCell(c[i]);
                }
                FillSChunks(u1);
                FillSChunks(u2);
                FillBChunks(R.X);
                FillBChunks(R.Y);
                FillSChunks(I1);
                FillSChunks(I3);
                FillBChunks(I5);
                FillSChunks(I6);
                FillBChunks(I8);
                FillBChunks(d2);

                // store cell locations for future reference
                var p_var[num_chunks], pp_var[num_chunks], n_var[num_chunks], np_var[num_chunks], m_var[num_chunks], mp_var[num_chunks],
                    x_var[num_chunks], y_var[num_chunks], a_var[num_chunks], one_var, zero_var,
                    z_var[num_chunks], r_var[num_chunks], s_var[num_chunks], v_var,
                    c_var[9], xQA_var[num_chunks], yQA_var[num_chunks], u1_var[num_chunks], u2_var[num_chunks],
                    xR_var[num_chunks], yR_var[num_chunks],
                    I1_var[num_chunks], I3_var[num_chunks], I5_var[num_chunks], I6_var[num_chunks], I8_var[num_chunks],
                    d2_var[num_chunks];

                // store the constants
                std::size_t row = 0;
                auto ConstToVar = [&row, &component, &start_row_index](var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++ ) {
                        x[i] = var(component.C(0), start_row_index + row, false, var::column_type::constant);
                        row++;
                    }
                };

                ConstToVar(p_var);
                ConstToVar(pp_var);
                ConstToVar(n_var);
                ConstToVar(np_var);
                ConstToVar(m_var);
                ConstToVar(mp_var);
                ConstToVar(x_var);
                ConstToVar(y_var);
                ConstToVar(a_var);
                one_var = var(component.C(0), start_row_index + row, false, var::column_type::constant);
                row++;
                zero_var = var(component.C(0), start_row_index + row, false, var::column_type::constant);

                // store the input
                for(std::size_t i = 0; i < num_chunks; i++) {
                    z_var[i] = instance_input.z[i];
                    r_var[i] = instance_input.r[i];
                    s_var[i] = instance_input.s[i];
                }
                v_var = instance_input.v;

                // store the auxiliary values
                cell_num = 0; // relative number of cell
                auto CellToVar = [&component, &start_row_index, &WA, &cell_num](var &x) {
                    x = var(component.W(cell_num % WA), start_row_index + cell_num/WA, false);
                    cell_num++;
                };
                auto ChunksToVar = [&component, &start_row_index, &WA, &cell_num](var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        x[i] = var(component.W(cell_num % WA), start_row_index + cell_num/WA, false);
                        cell_num++;
                    }
                };

                CellToVar(c_var[0]);
                ChunksToVar(xQA_var);
                ChunksToVar(yQA_var);
                for(std::size_t i = 1; i < 9; i++) {
                    CellToVar(c_var[i]);
                }
                ChunksToVar(u1_var);
                ChunksToVar(u2_var);
                ChunksToVar(xR_var);
                ChunksToVar(yR_var);
                ChunksToVar(I1_var);
                ChunksToVar(I3_var);
                ChunksToVar(I5_var);
                ChunksToVar(I6_var);
                ChunksToVar(I8_var);
                ChunksToVar(d2_var);

                // the number of rows used up to now
                std::size_t total_cells = 9 + 12*num_chunks;
                std::size_t current_row_shift = total_cells/WA + (total_cells % WA > 0);

                // assignment generation lambda expressions
                auto RangeCheck = [&assignment, &range_check_instance, &start_row_index, &current_row_shift]
                                  (var x[num_chunks]) {
                    typename range_check_type::input_type range_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        range_check_input.x[i] = x[i];
                    }
                    generate_assignments(range_check_instance, assignment, range_check_input, start_row_index + current_row_shift);
                    current_row_shift += range_check_instance.rows_amount;
                };
                auto CarryOnAddition = [&carry_on_addition_instance, &assignment, &start_row_index, &current_row_shift]
                                       (var x[num_chunks], var y[num_chunks]) {
                    typename carry_on_addition_type::input_type carry_on_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        carry_on_addition_input.x[i] = x[i];
                        carry_on_addition_input.y[i] = y[i];
                    }
                    typename carry_on_addition_type::result_type res = generate_assignments(carry_on_addition_instance, assignment,
                                                                 carry_on_addition_input, start_row_index + current_row_shift);
                    current_row_shift += carry_on_addition_instance.rows_amount;
                    return res;
                };
                auto ChoiceFunction = [&assignment, &choice_function_instance, &start_row_index, &current_row_shift]
                                      (var q, var x[num_chunks], var y[num_chunks]) {
                    typename choice_function_type::input_type choice_function_input;
                    choice_function_input.q = q;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        choice_function_input.x[i] = x[i];
                        choice_function_input.y[i] = y[i];
                    }
                    typename choice_function_type::result_type res = generate_assignments(choice_function_instance, assignment,
                                                               choice_function_input, start_row_index + current_row_shift);
                    current_row_shift += choice_function_instance.rows_amount;
                    return res;
                };
                auto CheckModP = [&assignment, &check_mod_p_instance, &start_row_index, &current_row_shift, &zero_var]
                                 (var x[num_chunks], var pp[num_chunks]) {
                     typename check_mod_p_type::input_type check_mod_p_input;
                     for(std::size_t i = 0; i < num_chunks; i++) {
                         check_mod_p_input.x[i] = x[i];
                         check_mod_p_input.pp[i] = pp[i];
                     }
                     check_mod_p_input.zero = zero_var;
                     generate_assignments(check_mod_p_instance, assignment, check_mod_p_input, start_row_index + current_row_shift);
                     current_row_shift += check_mod_p_instance.rows_amount;
                };
                auto CheckModPOut = [&assignment, &check_mod_p_output_instance, &start_row_index, &current_row_shift, &zero_var]
                                 (var x[num_chunks], var pp[num_chunks]) {
                     typename check_mod_p_output_type::input_type check_mod_p_input;
                     for(std::size_t i = 0; i < num_chunks; i++) {
                         check_mod_p_input.x[i] = x[i];
                         check_mod_p_input.pp[i] = pp[i];
                     }
                     check_mod_p_input.zero = zero_var;
                     typename check_mod_p_output_type::result_type res = generate_assignments(check_mod_p_output_instance, assignment,
                                                                                check_mod_p_input, start_row_index + current_row_shift);
                     current_row_shift += check_mod_p_output_instance.rows_amount;
                     return res;
                };

                auto NegModP = [&neg_mod_p_instance, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                               (var x[num_chunks]) {
                    typename neg_mod_p_type::input_type neg_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        neg_input.x[i] = x[i];
                        neg_input.p[i] = p_var[i];
                        neg_input.pp[i] = pp_var[i];
                    }
                    neg_input.zero = zero_var;
                    typename neg_mod_p_type::result_type res = generate_assignments(neg_mod_p_instance, assignment, neg_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += neg_mod_p_instance.rows_amount;
                    return res;
                };
                auto AddModP = [&add_mod_p_instance, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                               (var x[num_chunks], var y[num_chunks]) {
                    typename add_mod_p_type::input_type add_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        add_input.x[i] = x[i];
                        add_input.y[i] = y[i];
                        add_input.p[i] = p_var[i];
                        add_input.pp[i] = pp_var[i];
                    }
                    add_input.zero = zero_var;
                    typename add_mod_p_type::result_type res = generate_assignments(add_mod_p_instance, assignment, add_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += add_mod_p_instance.rows_amount;
                    return res;
                };
                auto MultModP = [&mult_mod_p_instance, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                                (var x[num_chunks], var y[num_chunks]) {
                    typename mult_mod_p_type::input_type mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mult_input.x[i] = x[i];
                        mult_input.y[i] = y[i];
                        mult_input.p[i] = p_var[i];
                        mult_input.pp[i] = pp_var[i];
                    }
                    mult_input.zero = zero_var;
                    typename mult_mod_p_type::result_type res = generate_assignments(mult_mod_p_instance, assignment, mult_input,
                                                               start_row_index + current_row_shift);
                    current_row_shift += mult_mod_p_instance.rows_amount;
                    return res;
                };

                auto NegModN = [&neg_mod_n_instance, &assignment, &start_row_index, &current_row_shift, &n_var, &np_var, &zero_var]
                               (var x[num_chunks]) {
                    typename neg_mod_n_type::input_type neg_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        neg_input.x[i] = x[i];
                        neg_input.p[i] = n_var[i];
                        neg_input.pp[i] = np_var[i];
                    }
                    neg_input.zero = zero_var;
                    typename neg_mod_n_type::result_type res = generate_assignments(neg_mod_n_instance, assignment, neg_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += neg_mod_n_instance.rows_amount;
                    return res;
                };
                auto AddModN = [&add_mod_n_instance, &assignment, &start_row_index, &current_row_shift, &n_var, &np_var, &zero_var]
                               (var x[num_chunks], var y[num_chunks]) {
                    typename add_mod_n_type::input_type add_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        add_input.x[i] = x[i];
                        add_input.y[i] = y[i];
                        add_input.p[i] = n_var[i];
                        add_input.pp[i] = np_var[i];
                    }
                    add_input.zero = zero_var;
                    typename add_mod_n_type::result_type res = generate_assignments(add_mod_n_instance, assignment, add_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += add_mod_n_instance.rows_amount;
                    return res;
                };
                auto MultModN = [&mult_mod_n_instance, &assignment, &start_row_index, &current_row_shift, &n_var, &np_var, &zero_var]
                                (var x[num_chunks], var y[num_chunks]) {
                    typename mult_mod_n_type::input_type mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mult_input.x[i] = x[i];
                        mult_input.y[i] = y[i];
                        mult_input.p[i] = n_var[i];
                        mult_input.pp[i] = np_var[i];
                    }
                    mult_input.zero = zero_var;
                    typename mult_mod_n_type::result_type res = generate_assignments(mult_mod_n_instance, assignment, mult_input,
                                                               start_row_index + current_row_shift);
                    current_row_shift += mult_mod_n_instance.rows_amount;
                    return res;
                };

                auto ECFullAdd = [&ec_full_add_instance, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                                (var xP[num_chunks], var yP[num_chunks], var xQ[num_chunks], var yQ[num_chunks]){
                    typename ec_full_add_type::input_type ec_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_addition_input.xP[i] = xP[i];
                        ec_addition_input.yP[i] = yP[i];
                        ec_addition_input.xQ[i] = xQ[i];
                        ec_addition_input.yQ[i] = yQ[i];
                        ec_addition_input.p[i] = p_var[i];
                        ec_addition_input.pp[i] = pp_var[i];
                    }
                    ec_addition_input.zero = zero_var;
                    typename ec_full_add_type::result_type res = generate_assignments(ec_full_add_instance, assignment, ec_addition_input,
                                                                           start_row_index + current_row_shift);
                    current_row_shift += ec_full_add_instance.rows_amount;
                    return res;
                };

                auto ECScalarMult = [&ec_scalar_mult_instance, &assignment, &start_row_index, &current_row_shift,
                                     &p_var, &pp_var, &n_var, &mp_var, &zero_var]
                                    (var s[num_chunks], var x[num_chunks], var y[num_chunks]) {
                    typename ec_scalar_mult_type::input_type ec_scalar_mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_scalar_mult_input.s[i] = s[i];
                        ec_scalar_mult_input.x[i] = x[i];
                        ec_scalar_mult_input.y[i] = y[i];
                        ec_scalar_mult_input.p[i] = p_var[i];
                        ec_scalar_mult_input.pp[i] = pp_var[i];
                        ec_scalar_mult_input.n[i] = n_var[i];
                        ec_scalar_mult_input.mp[i] = mp_var[i];
                    }
                    ec_scalar_mult_input.zero = zero_var;
                    typename ec_scalar_mult_type::result_type res = generate_assignments(ec_scalar_mult_instance, assignment,
                                                                              ec_scalar_mult_input, start_row_index + current_row_shift);
                    current_row_shift += ec_scalar_mult_instance.rows_amount;
                    return res;
                };
/*
auto PrintNumber = [&assignment, &sB](var x[num_chunks]) {
    scalar_integral_type X = 0;
    for(std::size_t i = num_chunks; i > 0; i--) {
        X *= sB;
        X += integral_type(var_value(assignment, x[i-1]).data);
    }
    std::cout << X << std::endl;
};
*/
                var chunked_zero[num_chunks], chunked_one[num_chunks], chunked_bit[num_chunks];
                for(std::size_t i = 0; i < num_chunks; i++) {
                    chunked_zero[i] = zero_var;
                    chunked_one[i] = zero_var;
                    chunked_bit[i] = zero_var;
                }
                chunked_one[0] = one_var;

                // populate the assigment table with values
                // c1 = [r != 0]
                RangeCheck(I1_var);
                CheckModP(I1_var,np_var); // CheckModN
                auto t0 = AddModN(r_var,chunked_zero);
                auto t1 = MultModN(t0.z,I1_var);
                auto t2 = MultModN(t0.z,t1.r);
                // copy constrain t0 = t2
                // copy constrain t1 = (0,...,0,c1)

                // c2 = [r < n]
                auto t3 = CheckModPOut(r_var,np_var); // CheckModN
                auto t3p= ChoiceFunction(c_var[2],chunked_one,chunked_zero);
                // copy constrain (0,...,0,t3) = t3p

                // c3 = [s != 0]
                RangeCheck(I3_var);
                CheckModP(I3_var,np_var); // CheckModN
                auto t4 = AddModN(s_var,chunked_zero);
                auto t5 = MultModN(t4.z,I3_var);
                auto t6 = MultModN(t4.z,t5.r);
                // copy constrain t4 = t6
                // copy constrain t5 = (0,...,0,c3)

                // c4 = [s < (n-1)/2+1]
                auto t7 = CheckModPOut(s_var,mp_var); // CheckModM
                auto t7p= ChoiceFunction(c_var[4],chunked_one,chunked_zero);
                // copy constrain (0,...,0,t7) = t7p

                // c5 = [yR^2 = xR^3 + a]
                RangeCheck(xR_var);
                CheckModP(xR_var,pp_var);
                RangeCheck(yR_var);
                CheckModP(yR_var,pp_var);
                auto t8 = MultModP(xR_var,xR_var);
                auto t9 = MultModP(t8.r,xR_var);
                auto t10= AddModP(t9.r,a_var);
                auto t11= MultModP(yR_var,yR_var);
                auto t12= NegModP(t11.r);
                auto t13= AddModP(t10.z,t12.y);
                RangeCheck(I5_var);
                CheckModP(I5_var,pp_var);
                auto t14= MultModP(t13.z,I5_var);
                auto t14p=ChoiceFunction(c_var[5],chunked_one,chunked_zero);
                auto t15= MultModP(t13.z,t14.r);
                // copy constrain t13 = t15
                // copy constrain t14 = t14p

                // c6 = [xR = r (mod n)]
                auto t16= AddModN(xR_var,chunked_zero);
                auto t17= NegModN(t0.z);
                auto t18= AddModN(t16.z,t17.y);
                RangeCheck(I6_var);
                CheckModP(I6_var,np_var); // CheckModN
                auto t19= MultModN(t18.z,I6_var);
                auto t20= MultModN(t18.z,t19.r);
                // copy constrain t18 = t20
                auto t21= ChoiceFunction(c_var[6],chunked_one,chunked_zero);
                // copy constrain t19 = t21

                // c7 = [yR = v (mod 2)]
                chunked_bit[0] = v_var;
                RangeCheck(chunked_bit);
                auto d1 = CarryOnAddition(yR_var,chunked_bit);
                // copy constrain d1.ck = 0
                RangeCheck(d2_var);
                auto d3 = CarryOnAddition(d2_var,chunked_one);
                // copy constrain d3.ck = 0
                RangeCheck(d3.z);
                auto d4 = ChoiceFunction(c_var[7],d3.z,d2_var);
                auto t22= CarryOnAddition(d2_var,d4.z);
                // copy constrain t22.ck = 0
                // copy constrain t22 = d1

                // u1 r = -z (mod n)
                RangeCheck(u1_var);
                CheckModP(u1_var,np_var); // CheckModN
                auto t23= MultModN(u1_var,t0.z);
                auto t24= AddModN(z_var,chunked_zero);
                auto t25= MultModN(t24.z,t1.r);
                auto t26= AddModN(t23.r,t25.r);
                // copy constrain t26 = 0

                // u2 r = s (mod n)
                RangeCheck(u2_var);
                CheckModP(u2_var,np_var); // CheckModN
                auto t27= MultModN(u2_var,t0.z);
                auto t28= MultModN(s_var,t1.r);
                // copy constrain t27 = t28

                // u1 * G
                auto t29= ECScalarMult(u1_var,x_var,y_var);

                // u2 * R
                auto t30= ECScalarMult(u2_var,xR_var,yR_var);

                // QA = u1*G + u2*R
                auto t31= ECFullAdd(t29.xR,t29.yR,t30.xR,t30.yR);
                // to assure the circuit doesn't break for invalid signatures we have to place the results
                // from t31 to (xQA, yQA)
                for(std::size_t i = 0; i < num_chunks; i++) {
                    assignment.witness(component.W((i+1) % WA), start_row_index + (i+1)/WA) = var_value(assignment, t31.xR[i]);
                    assignment.witness(component.W((i+num_chunks+1) % WA), start_row_index + (i+num_chunks+1)/WA) =
                        var_value(assignment, t31.yR[i]);
                }
                base_value_type new_yQA = 0;
                for(std::size_t i = num_chunks; i > 0; i--) {
                    new_yQA *= sB;
                    new_yQA += integral_type(var_value(assignment, t31.yR[i-1]).data);
                }
                if (QA.Y != new_yQA) { // we also have to adjust I8, c8 and c0 to agree with the updated yQA
                    base_value_type new_I8 = new_yQA.is_zero() ? 0 : new_yQA.inversed();
                    base_integral_type new_I8_int = base_integral_type(new_I8.data);

                    for(std::size_t i = 0; i < num_chunks; i++) {
                        assignment.witness(component.W((i+10*num_chunks+9) % WA), start_row_index + (i+10*num_chunks+9)/WA) =
                            value_type(new_I8_int % bB);
                        new_I8_int /= bB;
                    }
                    // update c8
                    assignment.witness(component.W((2*num_chunks + 8) % WA), start_row_index + (2*num_chunks + 8)/WA) =
                        value_type(1 - new_yQA.is_zero());
                    // update c0
                    assignment.witness(component.W(0), start_row_index) = value_type(c[0] * (1 - new_yQA.is_zero()));
                }
                // copy constrain QA = t31

                // c8 = [QA != O]
                RangeCheck(I8_var);
                CheckModP(I8_var,pp_var);
                auto t32= MultModP(yQA_var,I8_var);
                auto t33= MultModP(yQA_var,t32.r);
                // copy constrain yQA = t33
                // copy constrain t32 = (0,...,0,c8)

                // c = c[1]*....*c[8]
                chunked_bit[0] = c_var[1];
                auto t34= ChoiceFunction(c_var[2],chunked_zero,chunked_bit);
                auto t35= ChoiceFunction(c_var[3],chunked_zero,t34.z);
                auto t36= ChoiceFunction(c_var[4],chunked_zero,t35.z);
                auto t37= ChoiceFunction(c_var[5],chunked_zero,t36.z);
                auto t38= ChoiceFunction(c_var[6],chunked_zero,t37.z);
                auto t39= ChoiceFunction(c_var[7],chunked_zero,t38.z);
                auto t40= ChoiceFunction(c_var[8],chunked_zero,t39.z);
                // copy constrain t40 = (0,...,0,c)

                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            std::vector<std::size_t> generate_gates(
                const plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::input_type
                    &instance_input) {

                // never actually called
                return {};
            }

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_copy_constraints(
                const plonk_ecdsa_recovery<BlueprintFieldType, CurveType, num_chunks, bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                // all copy constraints are moved to generate_circuit
            }

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::result_type generate_circuit(
                const plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>;
                using var = typename component_type::var;

                using range_check_type = typename component_type::range_check_component;
                using carry_on_addition_type = typename component_type::carry_on_addition_component;
                using choice_function_type = typename component_type::choice_function_component;
                using check_mod_p_type = typename component_type::check_mod_p_component;
                using check_mod_p_output_type = typename component_type::check_mod_p_output_component;

                using neg_mod_p_type = typename component_type::neg_mod_p_component;
                using add_mod_p_type = typename component_type::add_mod_p_component;
                using mult_mod_p_type = typename component_type::mult_mod_p_component;

                using neg_mod_n_type = typename component_type::neg_mod_n_component;
                using add_mod_n_type = typename component_type::add_mod_n_component;
                using mult_mod_n_type = typename component_type::mult_mod_n_component;

                using ec_full_add_type = typename component_type::ec_full_add_component;
                using ec_scalar_mult_type = typename component_type::ec_scalar_mult_component;

                // instances of used subcomponents
                range_check_type            range_check_instance( component._W, component._C, component._PI);
                carry_on_addition_type      carry_on_addition_instance( component._W, component._C, component._PI);
                choice_function_type        choice_function_instance( component._W, component._C, component._PI);
                check_mod_p_type            check_mod_p_instance( component._W, component._C, component._PI);
                check_mod_p_output_type     check_mod_p_output_instance( component._W, component._C, component._PI);

                neg_mod_p_type              neg_mod_p_instance( component._W, component._C, component._PI);
                add_mod_p_type              add_mod_p_instance( component._W, component._C, component._PI);
                mult_mod_p_type             mult_mod_p_instance( component._W, component._C, component._PI);

                neg_mod_n_type              neg_mod_n_instance( component._W, component._C, component._PI);
                add_mod_n_type              add_mod_n_instance( component._W, component._C, component._PI);
                mult_mod_n_type             mult_mod_n_instance( component._W, component._C, component._PI);

                ec_full_add_type            ec_full_add_instance( component._W, component._C, component._PI);
                ec_scalar_mult_type         ec_scalar_mult_instance( component._W, component._C, component._PI);

                const std::size_t WA = component.witness_amount();

                // store cell locations for future reference
                var p_var[num_chunks], pp_var[num_chunks], n_var[num_chunks], np_var[num_chunks], m_var[num_chunks], mp_var[num_chunks],
                    x_var[num_chunks], y_var[num_chunks], a_var[num_chunks], one_var, zero_var,
                    z_var[num_chunks], r_var[num_chunks], s_var[num_chunks], v_var,
                    c_var[9], xQA_var[num_chunks], yQA_var[num_chunks], u1_var[num_chunks], u2_var[num_chunks],
                    xR_var[num_chunks], yR_var[num_chunks],
                    I1_var[num_chunks], I3_var[num_chunks], I5_var[num_chunks], I6_var[num_chunks], I8_var[num_chunks],
                    d2_var[num_chunks];

                // store the constants
                std::size_t row = 0;
                auto ConstToVar = [&row, &component, &start_row_index](var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++ ) {
                        x[i] = var(component.C(0), start_row_index + row, false, var::column_type::constant);
                        row++;
                    }
                };

                ConstToVar(p_var);
                ConstToVar(pp_var);
                ConstToVar(n_var);
                ConstToVar(np_var);
                ConstToVar(m_var);
                ConstToVar(mp_var);
                ConstToVar(x_var);
                ConstToVar(y_var);
                ConstToVar(a_var);
                one_var = var(component.C(0), start_row_index + row, false, var::column_type::constant);
                row++;
                zero_var = var(component.C(0), start_row_index + row, false, var::column_type::constant);

                // store the input
                for(std::size_t i = 0; i < num_chunks; i++) {
                    z_var[i] = instance_input.z[i];
                    r_var[i] = instance_input.r[i];
                    s_var[i] = instance_input.s[i];
                }
                v_var = instance_input.v;

                // store the auxiliary values
                std::size_t cell_num = 0; // relative number of cell
                auto CellToVar = [&component, &start_row_index, &WA, &cell_num](var &x) {
                    x = var(component.W(cell_num % WA), start_row_index + cell_num/WA, false);
                    cell_num++;
                };
                auto ChunksToVar = [&component, &start_row_index, &WA, &cell_num](var x[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        x[i] = var(component.W(cell_num % WA), start_row_index + cell_num/WA, false);
                        cell_num++;
                    }
                };

                CellToVar(c_var[0]);
                ChunksToVar(xQA_var);
                ChunksToVar(yQA_var);
                for(std::size_t i = 1; i < 9; i++) {
                    CellToVar(c_var[i]);
                }
                ChunksToVar(u1_var);
                ChunksToVar(u2_var);
                ChunksToVar(xR_var);
                ChunksToVar(yR_var);
                ChunksToVar(I1_var);
                ChunksToVar(I3_var);
                ChunksToVar(I5_var);
                ChunksToVar(I6_var);
                ChunksToVar(I8_var);
                ChunksToVar(d2_var);

                // the number of rows used up to now
                std::size_t total_cells = 9 + 12*num_chunks;
                std::size_t current_row_shift = total_cells/WA + (total_cells % WA > 0);

                // assignment generation lambda expressions
                auto RangeCheck = [&assignment, &bp, &range_check_instance, &start_row_index, &current_row_shift]
                                  (var x[num_chunks]) {
                    typename range_check_type::input_type range_check_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        range_check_input.x[i] = x[i];
                    }
                    generate_circuit(range_check_instance, bp, assignment, range_check_input, start_row_index + current_row_shift);
                    current_row_shift += range_check_instance.rows_amount;
                };
                auto CarryOnAddition = [&carry_on_addition_instance, &assignment, &bp, &start_row_index, &current_row_shift]
                                       (var x[num_chunks], var y[num_chunks]) {
                    typename carry_on_addition_type::input_type carry_on_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        carry_on_addition_input.x[i] = x[i];
                        carry_on_addition_input.y[i] = y[i];
                    }
                    typename carry_on_addition_type::result_type res = generate_circuit(carry_on_addition_instance, bp, assignment,
                                                                 carry_on_addition_input, start_row_index + current_row_shift);
                    current_row_shift += carry_on_addition_instance.rows_amount;
                    return res;
                };
                auto ChoiceFunction = [&assignment, &bp, &choice_function_instance, &start_row_index, &current_row_shift]
                                      (var q, var x[num_chunks], var y[num_chunks]) {
                    typename choice_function_type::input_type choice_function_input;
                    choice_function_input.q = q;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        choice_function_input.x[i] = x[i];
                        choice_function_input.y[i] = y[i];
                    }
                    typename choice_function_type::result_type res = generate_circuit(choice_function_instance, bp, assignment,
                                                               choice_function_input, start_row_index + current_row_shift);
                    current_row_shift += choice_function_instance.rows_amount;
                    return res;
                };
                auto CheckModP = [&assignment, &bp, &check_mod_p_instance, &start_row_index, &current_row_shift, &zero_var]
                                 (var x[num_chunks], var pp[num_chunks]) {
                     typename check_mod_p_type::input_type check_mod_p_input;
                     for(std::size_t i = 0; i < num_chunks; i++) {
                         check_mod_p_input.x[i] = x[i];
                         check_mod_p_input.pp[i] = pp[i];
                     }
                     check_mod_p_input.zero = zero_var;
                     generate_circuit(check_mod_p_instance, bp, assignment, check_mod_p_input, start_row_index + current_row_shift);
                     current_row_shift += check_mod_p_instance.rows_amount;
                };
                auto CheckModPOut = [&assignment, &bp, &check_mod_p_output_instance, &start_row_index, &current_row_shift, &zero_var]
                                 (var x[num_chunks], var pp[num_chunks]) {
                     typename check_mod_p_output_type::input_type check_mod_p_input;
                     for(std::size_t i = 0; i < num_chunks; i++) {
                         check_mod_p_input.x[i] = x[i];
                         check_mod_p_input.pp[i] = pp[i];
                     }
                     check_mod_p_input.zero = zero_var;
                     typename check_mod_p_output_type::result_type res = generate_circuit(check_mod_p_output_instance, bp, assignment,
                                                                                check_mod_p_input, start_row_index + current_row_shift);
                     current_row_shift += check_mod_p_output_instance.rows_amount;
                     return res;
                };

                auto NegModP = [&neg_mod_p_instance, &bp, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                               (var x[num_chunks]) {
                    typename neg_mod_p_type::input_type neg_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        neg_input.x[i] = x[i];
                        neg_input.p[i] = p_var[i];
                        neg_input.pp[i] = pp_var[i];
                    }
                    neg_input.zero = zero_var;
                    typename neg_mod_p_type::result_type res = generate_circuit(neg_mod_p_instance, bp, assignment, neg_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += neg_mod_p_instance.rows_amount;
                    return res;
                };
                auto AddModP = [&add_mod_p_instance, &bp, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                               (var x[num_chunks], var y[num_chunks]) {
                    typename add_mod_p_type::input_type add_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        add_input.x[i] = x[i];
                        add_input.y[i] = y[i];
                        add_input.p[i] = p_var[i];
                        add_input.pp[i] = pp_var[i];
                    }
                    add_input.zero = zero_var;
                    typename add_mod_p_type::result_type res = generate_circuit(add_mod_p_instance, bp, assignment, add_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += add_mod_p_instance.rows_amount;
                    return res;
                };
                auto MultModP = [&mult_mod_p_instance, &bp, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                                (var x[num_chunks], var y[num_chunks]) {
                    typename mult_mod_p_type::input_type mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mult_input.x[i] = x[i];
                        mult_input.y[i] = y[i];
                        mult_input.p[i] = p_var[i];
                        mult_input.pp[i] = pp_var[i];
                    }
                    mult_input.zero = zero_var;
                    typename mult_mod_p_type::result_type res = generate_circuit(mult_mod_p_instance, bp, assignment, mult_input,
                                                               start_row_index + current_row_shift);
                    current_row_shift += mult_mod_p_instance.rows_amount;
                    return res;
                };

                auto NegModN = [&neg_mod_n_instance, &bp, &assignment, &start_row_index, &current_row_shift, &n_var, &np_var, &zero_var]
                               (var x[num_chunks]) {
                    typename neg_mod_n_type::input_type neg_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        neg_input.x[i] = x[i];
                        neg_input.p[i] = n_var[i];
                        neg_input.pp[i] = np_var[i];
                    }
                    neg_input.zero = zero_var;
                    typename neg_mod_n_type::result_type res = generate_circuit(neg_mod_n_instance, bp, assignment, neg_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += neg_mod_n_instance.rows_amount;
                    return res;
                };
                auto AddModN = [&add_mod_n_instance, &bp, &assignment, &start_row_index, &current_row_shift, &n_var, &np_var, &zero_var]
                               (var x[num_chunks], var y[num_chunks]) {
                    typename add_mod_n_type::input_type add_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        add_input.x[i] = x[i];
                        add_input.y[i] = y[i];
                        add_input.p[i] = n_var[i];
                        add_input.pp[i] = np_var[i];
                    }
                    add_input.zero = zero_var;
                    typename add_mod_n_type::result_type res = generate_circuit(add_mod_n_instance, bp, assignment, add_input,
                                                              start_row_index + current_row_shift);
                    current_row_shift += add_mod_n_instance.rows_amount;
                    return res;
                };
                auto MultModN = [&mult_mod_n_instance, &bp, &assignment, &start_row_index, &current_row_shift, &n_var, &np_var, &zero_var]
                                (var x[num_chunks], var y[num_chunks]) {
                    typename mult_mod_n_type::input_type mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        mult_input.x[i] = x[i];
                        mult_input.y[i] = y[i];
                        mult_input.p[i] = n_var[i];
                        mult_input.pp[i] = np_var[i];
                    }
                    mult_input.zero = zero_var;
                    typename mult_mod_n_type::result_type res = generate_circuit(mult_mod_n_instance, bp, assignment, mult_input,
                                                               start_row_index + current_row_shift);
                    current_row_shift += mult_mod_n_instance.rows_amount;
                    return res;
                };

                auto ECFullAdd = [&ec_full_add_instance, &bp, &assignment, &start_row_index, &current_row_shift, &p_var, &pp_var, &zero_var]
                                (var xP[num_chunks], var yP[num_chunks], var xQ[num_chunks], var yQ[num_chunks]){
                    typename ec_full_add_type::input_type ec_addition_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_addition_input.xP[i] = xP[i];
                        ec_addition_input.yP[i] = yP[i];
                        ec_addition_input.xQ[i] = xQ[i];
                        ec_addition_input.yQ[i] = yQ[i];
                        ec_addition_input.p[i] = p_var[i];
                        ec_addition_input.pp[i] = pp_var[i];
                    }
                    ec_addition_input.zero = zero_var;
                    typename ec_full_add_type::result_type res = generate_circuit(ec_full_add_instance, bp, assignment, ec_addition_input,
                                                                           start_row_index + current_row_shift);
                    current_row_shift += ec_full_add_instance.rows_amount;
                    return res;
                };

                auto ECScalarMult = [&ec_scalar_mult_instance, &bp, &assignment, &start_row_index, &current_row_shift,
                                     &p_var, &pp_var, &n_var, &mp_var, &zero_var]
                                    (var s[num_chunks], var x[num_chunks], var y[num_chunks]) {
                    typename ec_scalar_mult_type::input_type ec_scalar_mult_input;
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        ec_scalar_mult_input.s[i] = s[i];
                        ec_scalar_mult_input.x[i] = x[i];
                        ec_scalar_mult_input.y[i] = y[i];
                        ec_scalar_mult_input.p[i] = p_var[i];
                        ec_scalar_mult_input.pp[i] = pp_var[i];
                        ec_scalar_mult_input.n[i] = n_var[i];
                        ec_scalar_mult_input.mp[i] = mp_var[i];
                    }
                    ec_scalar_mult_input.zero = zero_var;
                    typename ec_scalar_mult_type::result_type res = generate_circuit(ec_scalar_mult_instance, bp, assignment,
                                                                              ec_scalar_mult_input, start_row_index + current_row_shift);
                    current_row_shift += ec_scalar_mult_instance.rows_amount;
                    return res;
                };

                // Copy constraint generation lambda expression
                auto CopyConstrain = [&bp](var x[num_chunks], var y[num_chunks]) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        bp.add_copy_constraint({x[i], y[i]});
                    }
                };
                auto SingleCopyConstrain = [&bp](var x, var y) {
                    bp.add_copy_constraint({x,y});
                };

                var chunked_zero[num_chunks], chunked_one[num_chunks], chunked_bit[num_chunks];
                for(std::size_t i = 0; i < num_chunks; i++) {
                    chunked_zero[i] = zero_var;
                    chunked_one[i] = zero_var;
                    chunked_bit[i] = zero_var;
                }
                chunked_one[0] = one_var;

                // c1 = [r != 0]
                RangeCheck(I1_var);
                CheckModP(I1_var,np_var); // CheckModN
                auto t0 = AddModN(r_var,chunked_zero);
                auto t1 = MultModN(t0.z,I1_var);
                auto t2 = MultModN(t0.z,t1.r);
                CopyConstrain(t0.z,t2.r); // copy constrain t0 = t2
                chunked_bit[0] = c_var[1];
                CopyConstrain(t1.r,chunked_bit); // copy constrain t1 = (0,...,0,c1)

                // c2 = [r < n]
                auto t3 = CheckModPOut(r_var,np_var); // CheckModN
                auto t3p= ChoiceFunction(c_var[2],chunked_one,chunked_zero);
                chunked_bit[0] = t3.q;
                CopyConstrain(chunked_bit,t3p.z); // copy constrain (0,...,0,t3) = t3p

                // c3 = [s != 0]
                RangeCheck(I3_var);
                CheckModP(I3_var,np_var); // CheckModN
                auto t4 = AddModN(s_var,chunked_zero);
                auto t5 = MultModN(t4.z,I3_var);
                auto t6 = MultModN(t4.z,t5.r);
                CopyConstrain(t4.z,t6.r); // copy constrain t4 = t6
                chunked_bit[0] = c_var[3];
                CopyConstrain(t5.r,chunked_bit); // copy constrain t5 = (0,...,0,c3)

                // c4 = [s < (n-1)/2+1]
                auto t7 = CheckModPOut(s_var,mp_var); // CheckModM
                auto t7p= ChoiceFunction(c_var[4],chunked_one,chunked_zero);
                chunked_bit[0] = t7.q;
                CopyConstrain(chunked_bit,t7p.z); // copy constrain (0,...,0,t7) = t7p

                // c5 = [yR^2 = xR^3 + a]
                RangeCheck(xR_var);
                CheckModP(xR_var,pp_var);
                RangeCheck(yR_var);
                CheckModP(yR_var,pp_var);
                auto t8 = MultModP(xR_var,xR_var);
                auto t9 = MultModP(t8.r,xR_var);
                auto t10= AddModP(t9.r,a_var);
                auto t11= MultModP(yR_var,yR_var);
                auto t12= NegModP(t11.r);
                auto t13= AddModP(t10.z,t12.y);
                RangeCheck(I5_var);
                CheckModP(I5_var,pp_var);
                auto t14= MultModP(t13.z,I5_var);
                auto t14p=ChoiceFunction(c_var[5],chunked_one,chunked_zero);
                auto t15= MultModP(t13.z,t14.r);
                CopyConstrain(t13.z,t15.r); // copy constrain t13 = t15
                CopyConstrain(t14.r,t14p.z); // copy constrain t14 = t14p

                // c6 = [xR = r (mod n)]
                auto t16= AddModN(xR_var,chunked_zero);
                auto t17= NegModN(t0.z);
                auto t18= AddModN(t16.z,t17.y);
                RangeCheck(I6_var);
                CheckModP(I6_var,np_var); // CheckModN
                auto t19= MultModN(t18.z,I6_var);
                auto t20= MultModN(t18.z,t19.r);
                CopyConstrain(t18.z,t20.r); // copy constrain t18 = t20
                auto t21= ChoiceFunction(c_var[6],chunked_one,chunked_zero);
                CopyConstrain(t19.r,t21.z); // copy constrain t19 = t21

                // c7 = [yR = v (mod 2)]
                chunked_bit[0] = v_var;
                RangeCheck(chunked_bit);
                auto d1 = CarryOnAddition(yR_var,chunked_bit);
                SingleCopyConstrain(d1.ck,zero_var); // copy constrain d1.ck = 0
                RangeCheck(d2_var);
                auto d3 = CarryOnAddition(d2_var,chunked_one);
                SingleCopyConstrain(d3.ck,zero_var); // copy constrain d3.ck = 0
                RangeCheck(d3.z);
                auto d4 = ChoiceFunction(c_var[7],d3.z,d2_var);
                auto t22= CarryOnAddition(d2_var,d4.z);
                SingleCopyConstrain(t22.ck,zero_var); // copy constrain t22.ck = 0
                CopyConstrain(t22.z,d1.z); // copy constrain t22 = d1

                // u1 r = -z (mod n)
                RangeCheck(u1_var);
                CheckModP(u1_var,np_var); // CheckModN
                auto t23= MultModN(u1_var,t0.z);
                auto t24= AddModN(z_var,chunked_zero);
                auto t25= MultModN(t24.z,t1.r);
                auto t26= AddModN(t23.r,t25.r);
                CopyConstrain(t26.z,chunked_zero); // copy constrain t26 = 0

                // u2 r = s (mod n)
                RangeCheck(u2_var);
                CheckModP(u2_var,np_var); // CheckModN
                auto t27= MultModN(u2_var,t0.z);
                auto t28= MultModN(s_var,t1.r);
                CopyConstrain(t27.r,t28.r); // copy constrain t27 = t28

                // u1 * G
                auto t29= ECScalarMult(u1_var,x_var,y_var);

                // u2 * R
                auto t30= ECScalarMult(u2_var,xR_var,yR_var);

                // QA = u1*G + u2*R
                auto t31= ECFullAdd(t29.xR,t29.yR,t30.xR,t30.yR);
                CopyConstrain(xQA_var,t31.xR); // copy constrain QA = t31
                CopyConstrain(yQA_var,t31.yR);

                // c8 = [QA != O]
                RangeCheck(I8_var);
                CheckModP(I8_var,pp_var);
                auto t32= MultModP(yQA_var,I8_var);
                auto t33= MultModP(yQA_var,t32.r);
                CopyConstrain(yQA_var,t33.r); // copy constrain yQA = t33
                chunked_bit[0] = c_var[8];
                CopyConstrain(t32.r,chunked_bit); // copy constrain t32 = (0,...,0,c8)

                // c = c[1]*....*c[8]
                chunked_bit[0] = c_var[1];
                auto t34= ChoiceFunction(c_var[2],chunked_zero,chunked_bit);
                auto t35= ChoiceFunction(c_var[3],chunked_zero,t34.z);
                auto t36= ChoiceFunction(c_var[4],chunked_zero,t35.z);
                auto t37= ChoiceFunction(c_var[5],chunked_zero,t36.z);
                auto t38= ChoiceFunction(c_var[6],chunked_zero,t37.z);
                auto t39= ChoiceFunction(c_var[7],chunked_zero,t38.z);
                auto t40= ChoiceFunction(c_var[8],chunked_zero,t39.z);
                chunked_bit[0] = c_var[0];
                CopyConstrain(t40.z,chunked_bit); // copy constrain t40 = (0,...,0,c)

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index); // does nothing, may be skipped?

                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk>
            void generate_assignments_constant(
                const plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_ecdsa_recovery<BlueprintFieldType,CurveType,num_chunks,bit_size_chunk>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using BaseField = typename CurveType::base_field_type;
                using ScalarField = typename CurveType::scalar_field_type;
                using base_basic_integral_type = typename BaseField::integral_type;
                using base_integral_type = typename BaseField::extended_integral_type;
                using scalar_integral_type = typename ScalarField::extended_integral_type;

                using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
                using value_type = typename BlueprintFieldType::value_type;

                std::size_t row = start_row_index;

                base_integral_type bB = base_integral_type(1) << bit_size_chunk,
                                    p = BaseField::modulus,
                            b_ext_pow = base_integral_type(1) << num_chunks*bit_size_chunk,
                                   pp = b_ext_pow - p;

                scalar_integral_type sB = scalar_integral_type(1) << bit_size_chunk,
                                      n = ScalarField::modulus,
                              s_ext_pow = scalar_integral_type(1) << num_chunks*bit_size_chunk,
                                     np = s_ext_pow - n,
                                      m = (n-1)/2 + 1,
                                     mp = s_ext_pow - m;

                ec_point_value_type G = ec_point_value_type::one();
                base_integral_type x = base_integral_type(base_basic_integral_type(G.X.data)),
                                   y = base_integral_type(base_basic_integral_type(G.Y.data)),
                                   a = CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::params_type::b;

                auto PushBaseChunks = [&assignment, &component, &row, &bB](base_integral_type &x) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        assignment.constant(component.C(0), row) = value_type(x % bB);
                        x /= bB;
                        row++;
                    }
                };

                auto PushScalarChunks = [&assignment, &component, &row, &sB](scalar_integral_type &x) {
                    for(std::size_t i = 0; i < num_chunks; i++) {
                        assignment.constant(component.C(0), row) = value_type(x % sB);
                        x /= sB;
                        row++;
                    }
                };

                PushBaseChunks(p);
                PushBaseChunks(pp);
                PushScalarChunks(n);
                PushScalarChunks(np);
                PushScalarChunks(m);
                PushScalarChunks(mp);
                PushBaseChunks(x);
                PushBaseChunks(y);
                PushBaseChunks(a);

                assignment.constant(component.C(0), row) = 1;
                row++;
                assignment.constant(component.C(0), row) = 0;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_EC_ECDSA_RECOVERY_HPP
