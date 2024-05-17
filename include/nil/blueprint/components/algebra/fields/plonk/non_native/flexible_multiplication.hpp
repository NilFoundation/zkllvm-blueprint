//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
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
// @file Declaration of interfaces for non-native multiplication with k-chunks and p > n.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_MULTIPLICATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_MULTIPLICATION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>

// #include <nil/blueprint/components/detail/plonk/range_check.hpp>
// #include <nil/blueprint/components/fields/plonk/non_native/check_mod_p.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Multiplication in non-native field with k-chunks and p > n, x * y - p * q - r = 0
            // Parameters: num_chunks = k, bit_size_chunk = b, num_bits = T
            // native field module = n, non-native field module = p, pp = 2^T - p
            // NB: 2^T * n > p^2 + p
            // Input: x[0],..., x[k-1], y[0],..., y[k-1], p[0],..., p[k-1], pp[0],...,p[k-1]
            // Output: r[0],..., r[k-1]
            //
            template<typename ArithmetizationType, typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            class flexible_mult;

            template<typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            class flexible_mult<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType,
                           NonNativeFieldType,
                           num_chunks,
                           bit_size_chunk,
                           num_bits>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                // using range_check_type = range_check<ArithmetizationType, BlueprintFieldType, bit_size_chunk>;
                // using check_mod_p_type = check_mod_p<ArithmetizationType, BlueprintFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return flexible_mult::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                        // .merge_with(range_check_type::get_gate_manifest(witness_amount, lookup_column_amount))
                        // .merge_with(check_mod_p_type::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // we need 8k-2 cells to fit into 3 rows, i.e. 8k-2 <= 3w, hence w >= ceil((8k-2)/3)
                        std::shared_ptr<manifest_param>(new manifest_range_param((8 * num_chunks - 2) / 3 + ((8*num_chunks - 2) % 3 > 0),
                                                                                 8 * num_chunks - 2, 1)),
                        false // constant column not needed
                    );
                    // .merge_with(check_mod_p_type::get_manifest())
                    // .merge_with(range_check_type::get_manifest());
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    auto nc = 8*num_chunks - 2;
                    return nc / witness_amount + (nc % witness_amount > 0);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "flexible non-native multiplication";

                struct input_type {
                    var x[num_chunks], y[num_chunks], p[num_chunks], pp[num_chunks];

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(x[i]);
                            res.push_back(y[i]);
                            res.push_back(p[i]);
                            res.push_back(pp[i]);
                        }
                        return res;
                    }
                };

                struct result_type {
                    var r[num_chunks];

                    result_type(const flexible_mult &component, std::uint32_t start_row_index) {
                        const std::size_t WA = component.witness_amount();

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            std::size_t row = start_row_index + (1 + 2*num_chunks + i)/WA;
                            std::size_t col = (1 + 2*num_chunks + i) % WA;
			    r[i] = var(component.W(col), row, false, var::column_type::witness);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            res.push_back(r[i]);
                        }
                        return res;
                    }
                };

                struct coords_class {
                    std::int32_t row;
                    std::size_t column;
                    std::size_t witness_amount;

                    coords_class(std::int32_t row, std::size_t column, std::size_t witness_amount) :
                                row(row), column(column), witness_amount(witness_amount) {}
                    coords_class() : row(0), column(0), witness_amount(1) {}

                    coords_class operator++() {
                        column++;
                        if (column == witness_amount) {
                            column = 0;
                            row++;
                        }
                        return *this;
                    }
                    coords_class operator+=(std::size_t shift) {
                        column += shift;
                        row += column / witness_amount;
                        column %= witness_amount;
                        return *this;
                    }
                    coords_class operator--() {
                        if (column == 0) {
                            column = witness_amount - 1;
                            row--;
                        } else {
                            column--;
                        }
                        return *this;
                    }
                };

                template<typename ContainerType>
                explicit flexible_mult(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,"non-native field should fit into chunks");
                    static_assert(2*bit_size_chunk < BlueprintFieldType::modulus_bits,"chunk products should fit into native field");
                    static_assert(num_bits % bit_size_chunk == 0,"num_bits should be divisible by bit_size_chunk");
                    static_assert(num_bits + BlueprintFieldType::modulus_bits > 2*NonNativeFieldType::modulus_bits,
                                  "we need 2^num_bits * native_module > non_native_module^2");
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                flexible_mult(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,"non-native field should fit into chunks");
                    static_assert(2*bit_size_chunk < BlueprintFieldType::modulus_bits,"chunk products should fit into native field");
                    static_assert(num_bits % bit_size_chunk == 0,"num_bits should be divisible by bit_size_chunk");
                    static_assert(num_bits + BlueprintFieldType::modulus_bits > 2*NonNativeFieldType::modulus_bits,
                                  "we need 2^num_bits * native_module > non_native_module^2");
                };

                flexible_mult(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {
                    static_assert(num_chunks * bit_size_chunk >= NonNativeFieldType::modulus_bits,"non-native field should fit into chunks");
                    static_assert(2*bit_size_chunk < BlueprintFieldType::modulus_bits,"chunk products should fit into native field");
                    static_assert(num_bits % bit_size_chunk == 0,"num_bits should be divisible by bit_size_chunk");
                    static_assert(num_bits + BlueprintFieldType::modulus_bits > 2*NonNativeFieldType::modulus_bits,
                                  "we need 2^num_bits * native_module > non_native_module^2");
                };
            };

            template<typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            using plonk_flexible_multiplication =
                flexible_mult<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    NonNativeFieldType,
                    num_chunks,
                    bit_size_chunk,
                    num_bits>;

            template<typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            typename plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits>::result_type generate_assignments(
                const plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                                        num_chunks, bit_size_chunk, num_bits>;
                using var = typename component_type::var;
                using native_value_type = typename BlueprintFieldType::value_type;
                using native_integral_type = typename BlueprintFieldType::integral_type;
                using foreign_extended_integral_type = typename NonNativeFieldType::extended_integral_type;

                const std::size_t WA = component.witness_amount();

                std::vector<native_value_type> x,  // chunks of x
                                               y,  // chunks of y
                                               p,  // chunks of p
                                               pp; // chunks of 2^T - p
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    x.push_back(var_value(assignment, instance_input.x[j]));
                    y.push_back(var_value(assignment, instance_input.y[j]));
                    p.push_back(var_value(assignment, instance_input.p[j]));
                    pp.push_back(var_value(assignment, instance_input.pp[j]));
                }

                //calculation
                foreign_extended_integral_type foreign_p = 0,
                                               foreign_x = 0,
                                               foreign_y = 0,
                                               pow = 1;

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    foreign_x += foreign_extended_integral_type(x[j].data) * pow;
                    foreign_y += foreign_extended_integral_type(y[j].data) * pow;
                    foreign_p += foreign_extended_integral_type(p[j].data) * pow;
                    pow <<= bit_size_chunk;
                }

                foreign_extended_integral_type foreign_r = (foreign_x * foreign_y) % foreign_p, // r = x*y % p
                                               foreign_q = (foreign_x * foreign_y - foreign_r) / foreign_p; // q = (x*y - r)/p

                std::vector<native_value_type> q;  // chunks of q
                std::vector<native_value_type> r;  // chunks of r
                native_integral_type mask = (native_integral_type(1) << bit_size_chunk) - 1;

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    q.push_back(native_value_type(foreign_q & mask));
                    r.push_back(native_value_type(foreign_r & mask));

                    foreign_q >>= bit_size_chunk;
                    foreign_r >>= bit_size_chunk;
                }

                // computation mod 2^T
                std::vector<native_value_type> z;
                for (std::size_t i = 0; i < num_chunks; ++i) {
                    z.push_back(native_value_type(0));
                    for (std::size_t j = 0; j <= i; ++j) {
                        z[i] += x[j] * y[i-j] + pp[j] * q[i-j];
                    }
                }

                std::vector<native_value_type> a;
                a.push_back(z[0] - r[0]);
                native_integral_type a_integral = native_integral_type(a[0].data) >> bit_size_chunk;
                a[0] = native_value_type(a_integral);
                for (std::size_t i = 1; i < num_chunks; ++i) {
                    a.push_back(z[i] + a[i-1] - r[i]);
                    a_integral = native_integral_type(a[i].data) >> bit_size_chunk;
                    a[i] = native_value_type(a_integral);
                }

                std::vector<native_value_type> b;
                for (std::size_t i = 0; i < num_chunks - 2; ++i) {
                    b.push_back(native_value_type(native_integral_type(a[i].data) & ((native_integral_type(1) << bit_size_chunk) - 1)));
                    b.push_back(native_value_type(native_integral_type(a[i].data) >> bit_size_chunk));
                }

                // assignment
                std::vector<var> r_var, q_var, b_var;
                typename component_type::coords_class coords(start_row_index, 0, WA);

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = x[j];
                    ++coords;
                }

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = y[j];
                    ++coords;
                }

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = r[j];
                    r_var.push_back({component.W(coords.column), coords.row});
                    ++coords;
                }

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = q[j];
                    q_var.push_back({component.W(coords.column), coords.row});
                    ++coords;
                }

                for (std::size_t j = 0; j < 2 * (num_chunks - 2); ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = b[j];
                    b_var.push_back({component.W(coords.column), coords.row});
                    ++coords;
                }

                for (std::size_t j = 0; j < 2; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = a[num_chunks - 2 + j];
                    ++coords;
                }

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = p[j];
                    ++coords;
                }

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    assignment.witness(component.W(coords.column), coords.row) = pp[j];
                    ++coords;
                }

                //TODO
                // range_check b_var, q_var, r_var
                // check_mod_p for q_var, r_var

                return typename component_type::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            std::size_t generate_gates(
                const plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                                num_chunks, bit_size_chunk, num_bits>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {

                using component_type = plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                                        num_chunks, bit_size_chunk, num_bits>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;

                const std::size_t WA = component.witness_amount();
                const std::size_t num_rows = component.get_rows_amount(WA, 0);

                int row_shift = (num_rows > 1);

                std::vector<constraint_type> constraints;
                typename component_type::coords_class coords(0, 0, WA);
                std::vector<var> x, y, r, q, b, a, p, pp;

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    x.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    y.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    r.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    q.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < 2 * (num_chunks - 2); ++j) {
                    b.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < 2; ++j) {
                    a.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    p.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    pp.push_back(var(component.W(coords.column), coords.row - row_shift, true));
                    ++coords;
                }

                // computation mod n
                constraint_type constr_0, x_n, y_n, q_n, r_n, p_n;
                integral_type pow = 1;
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    x_n += x[j] * pow;
                    y_n += y[j] * pow;
                    q_n += q[j] * pow;
                    r_n += r[j] * pow;
                    p_n += p[j] * pow;
                    pow <<= bit_size_chunk;
                }
                constr_0 = x_n * y_n - q_n * p_n - r_n;

                // computation mod 2^T
                std::vector<constraint_type> z_constr;
                for (std::size_t i = 0; i < num_chunks; ++i) {
                    constraint_type z;
                    for (std::size_t j = 0; j <= i; ++j) {
                        z += x[j] * y[i-j] + pp[j] * q[i-j];
                    }
                    z_constr.push_back(z);
                }
                std::vector<constraint_type> a_constr;
                integral_type b_shift = integral_type(1) << bit_size_chunk;
                if (num_chunks > 2) {
                    a_constr.push_back(r[0] + (b[0] + b[1] * b_shift) * b_shift);
                }
                for (std::size_t i = 1; i < num_chunks - 2; ++i) {
                    a_constr.push_back(r[i] +
                                       (num_chunks > 2 ? (b[2 * i] + b[2 * i + 1]*b_shift)*b_shift - (b[2 * i - 2] + b[2 * i - 1]*b_shift)
                                                      : 0));
                }
                a_constr.push_back(r[num_chunks - 2] + a[0] * b_shift -
                                     (num_chunks > 2 ? (b[2 * (num_chunks-2) - 2] + b[2 * (num_chunks-2) - 1] * b_shift) : 0));
                a_constr.push_back(r[num_chunks - 1] + a[1] * b_shift - a[0]);

                constraints.push_back(constr_0);
                for (std::size_t i = 0; i < num_chunks; ++i) {
                    constraints.push_back(a_constr[i] - z_constr[i]);
                }

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            void generate_copy_constraints(
                const plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits>::input_type &instance_input,
                const std::size_t start_row_index) {

                const std::size_t WA = component.witness_amount();
                using component_type = plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                                        num_chunks, bit_size_chunk, num_bits>;
                using var = typename component_type::var;

                typename component_type::coords_class coords(start_row_index, 0, WA);
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    bp.add_copy_constraint({var(component.W(coords.column), coords.row, false), instance_input.x[j]});
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    bp.add_copy_constraint({var(component.W(coords.column), coords.row, false), instance_input.y[j]});
                    ++coords;
                }

                coords += 4*num_chunks - 2; // skip q,r,b,a

                for (std::size_t j = 0; j < num_chunks; ++j) {
                    bp.add_copy_constraint({var(component.W(coords.column), coords.row, false), instance_input.p[j]});
                    ++coords;
                }
                for (std::size_t j = 0; j < num_chunks; ++j) {
                    bp.add_copy_constraint({var(component.W(coords.column), coords.row, false), instance_input.pp[j]});
                    ++coords;
                }
            }

            template<typename BlueprintFieldType, typename NonNativeFieldType,
            std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t num_bits>
            typename plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits>::result_type generate_circuit(
                const plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_flexible_multiplication<BlueprintFieldType,NonNativeFieldType,
                    num_chunks, bit_size_chunk, num_bits>;

                const std::size_t WA = component.witness_amount();
                const std::size_t num_rows = component.get_rows_amount(WA, 0);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());

                assignment.enable_selector(selector_index, start_row_index + (num_rows > 1));

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                // TODO generate circuits
                // range_check b_var, q_var, r_var
                // check_mod_p for q_var, r_var
                // use r/q/b_cells to call for appropriate cells

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_MULTIPLICATION_HPP
