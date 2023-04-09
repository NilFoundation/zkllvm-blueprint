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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_VERIFICATION_KEY_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_VERIFICATION_KEY_HPP

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/plonk.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/commitment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/types/urs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename BlueprintFieldType, typename KimchiParamsType>
                struct verification_key_type {
                    /* data seems to be unused, so it's not included
                       but it would be
                      struct data_type {
                        int constarints;
                      } data; */
                    private:
                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
                    using urs_type = typename zk::components::var_urs<BlueprintFieldType,
                                                                      KimchiParamsType::commitment_params_type::srs_len>;

                    public:
                    struct commitments_type {
                        // commitments here are on Tock curve -- which is same as Pasta base, so on Vesta scalar field
                        std::array<var_ec_point, KimchiParamsType::permut_size> sigma;
                        std::array<var_ec_point, KimchiParamsType::witness_columns> coefficient;
                        var_ec_point generic;
                        var_ec_point psm;
                        var_ec_point complete_add;
                        var_ec_point var_base_mul;
                        var_ec_point endo_mul;
                        var_ec_point endo_mul_scalar;
                    } commitments;

                    struct verifier_index_type {
                        // commitments here are on base, everything eles is scalars
                        struct comm_type {
                            std::vector<var_ec_point> unshifted;
                            // option
                            var_ec_point shifted;
                        };

                        struct domain_type {
                            var domain_generator;
                            std::size_t domain_size_log2;
                        } domain;

                        std::size_t max_poly_size;
                        std::size_t max_quot_size;
                        // originally called "public", renamed to avoid C++ keyword
                        std::size_t public_input_size;
                        std::size_t prev_challenges;
    	                // srs in Mina
                        urs_type urs;
                        struct verification_evals_type {
                            // unsure with sizes here, copied from commitment_type above
                            std::array<comm_type, KimchiParamsType::permut_size> sigma;
                            std::array<comm_type, KimchiParamsType::witness_columns> coefficient;
                            comm_type generic_comm;
                            comm_type psm_comm;
                            comm_type complete_add_comm;
                            comm_type mul_comm;
                            comm_type emul_comm;
                            comm_type endomul_scalar_comm;
                            // option
                            std::vector<comm_type> chacha_comm;
                        } evals;
                        std::array<var, KimchiParamsType::permut_size> shifts;
                        // option
                        struct lookup_index_type {
                            std::vector<comm_type> lookup_table;
                            enum lookups_used_type {
                                Single, Joint
                            } lookups_used;

                            // option
                            comm_type table_ids;

                            std::size_t max_joint_size;
                            // option
                            comm_type runtime_tables_selector;
                            struct lookup_selectors_type {
                                // option
                                comm_type lookup_gate;
                            } lookup_selectors;
                        } lookup_index;
                    } verifier_index;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif   // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_VERIFICATION_KEY_HPP
