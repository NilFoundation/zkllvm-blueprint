//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <vector>

#include <boost/random.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

namespace nil {
    namespace crypto3 {
        inline std::vector<std::size_t> generate_random_step_list(
                const std::size_t r, const std::size_t max_step, const std::size_t seed = 1444) {
            typedef boost::random::mt19937 random_engine_type;
            typedef boost::random::uniform_int_distribution<std::size_t> dist_type;
            random_engine_type random_engine(seed);

            std::vector<std::size_t> step_list;
            std::size_t steps_sum = 0;
            while (steps_sum != r) {
                if (r - steps_sum <= max_step) {
                    while (r - steps_sum != 1) {
                        step_list.emplace_back(r - steps_sum - 1);
                        steps_sum += step_list.back();
                    }
                    step_list.emplace_back(1);
                    steps_sum += step_list.back();
                } else {
                    step_list.emplace_back(dist_type(1, max_step)(random_engine));
                    steps_sum += step_list.back();
                }
            }
            return step_list;
        }

        template<typename fri_type, typename FieldType>
        typename fri_type::params_type create_fri_params(
                std::size_t degree_log, const std::size_t expand_factor = 4, const std::size_t max_step = 1) {
            math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

            const std::size_t r = degree_log - 1;

            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
                math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

            typename fri_type::params_type params(
                (1 << degree_log) - 1,
                domain_set,
                generate_random_step_list(r, max_step),
                expand_factor
            );

            return params;
        }
    }    // namespace crypto3
}    // namespace nil