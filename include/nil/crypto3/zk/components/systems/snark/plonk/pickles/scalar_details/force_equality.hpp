//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_CHECK_EQUALITY_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_CHECK_EQUALITY_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                // input: a, b
                // places constraint a = b
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class force_equality;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t W0, std::size_t W1>
                class force_equality<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, W0, W1> {
                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                public:
                    constexpr static const std::size_t rows_amount = 0;
                    constexpr static const std::size_t gates_amount = 0;

                    constexpr static const std::size_t selector_seed = 0x0fbc;

                    struct params_type {
                        var a;
                        var b;
                    };
                    // fake to make test circuit work
                    struct result_type {};

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                 blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                 const params_type &params,
                                                 const std::size_t start_row_index) {
                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                     const params_type &params,
                                                     const std::size_t start_row_index) {
                        return result_type();
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {}

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType>   public_assignment,
                                                          const params_type &params,
                                                          std::size_t component_start_row) {

                        std::size_t row = component_start_row;
                        bp.add_copy_constraint({params.a, params.b});
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif   // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_CHECK_EQUALITY_HPP
