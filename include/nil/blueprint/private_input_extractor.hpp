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

#ifndef CRYPTO3_BLUEPRINT_PRIVATE_INPUT_EXTRACTOR_HPP
#define CRYPTO3_BLUEPRINT_PRIVATE_INPUT_EXTRACTOR_HPP

#include <unordered_map>
#include <unordered_set>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace blueprint {
        // So you want to figure out where a variable you pass into the component actually gets assigned to?
        // Congratulations! You've come to the right place. You can do that in just 5 easy steps!
        // Note that step 2 and 5 are IMPORTANT, and you SHOULD read them!
        // Step 1: Instantiate your component.
        // Step 2: Fill the input variables you want to assign to with distinct variables.
        //         IMPORTANT: the variables you want to assign to MUST be distinct from all others!
        //                    They also MUST be outside of the component!
        //                    ENSURE that they are not the same as the default variable (var(0, 0, false, witness)),
        //                    (or fill all of the input values)
        //                    E.g. you could make the variable to have very large witness column number.
        //                    The variable CANNOT be with the legacy private input index: copy constraints
        //                    would not generate for it and it would not be found.
        // Step 3: Call input_assignment_variables with the component, the input and the row at which the component
        //         is going to be based.
        // Step 4: The map you got in return maps the variables from instance_input to the variables from the
        //         component.
        // Step 5: IMPORTANT! Be sure to check that the variable is in the map before assinging to it.
        //         In rare situations the variable might turn out to be unused.
        //         The map would not contain the variable in this case.
        template<typename BlueprintFieldType, typename ComponentType>
        std::unordered_map<
            crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>,
            crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> input_assignment_variables(
                const ComponentType &component,
                const crypto3::zk::snark::plonk_table_description<BlueprintFieldType> &desc,
                typename ComponentType::input_type instance_input,
                const std::size_t start_row_index) {

            using constraint_system = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            circuit<constraint_system> bp;
            assignment<constraint_system> assignment(desc);
            generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
            auto input_vars = instance_input.all_vars();
            std::unordered_set<var> input_vars_set(input_vars.begin(), input_vars.end());

            std::unordered_map<var, var> result;
            for (const auto &copy_constraint : bp.copy_constraints()) {
                auto &var1 = copy_constraint.first,
                     &var2 = copy_constraint.second;
                if (input_vars_set.find(var1) != input_vars_set.end()) {
                    result[var1] = var2;
                }
                if (input_vars_set.find(var2) != input_vars_set.end()) {
                    result[var2] = var1;
                }
            }
            return result;
        }
    }   // namespace blueprint
}   // namespace nil

#endif   // CRYPTO3_BLUEPRINT_PRIVATE_INPUT_EXTRACTOR_HPP