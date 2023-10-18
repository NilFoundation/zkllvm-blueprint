//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the LOOKUP_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PLACEHOLDER_INPUT_TYPES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PLACEHOLDER_INPUT_TYPES_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/permutation_loop.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename T>
            struct lookup_constraint {
                T table_id;
                std::vector<T> lookup_input;
            };

            template<typename T>
            struct lookup_gate {
                T selector;
                std::vector<lookup_constraint<T>> constraints;
            };

            template<typename T>
            struct lookup_table {
                T selector;
                std::vector<std::vector<T>> lookup_options;
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP