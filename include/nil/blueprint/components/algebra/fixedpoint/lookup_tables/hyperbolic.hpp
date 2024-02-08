#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HYPERBOLIC_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HYPERBOLIC_TABLE_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            ////////////////////////////////////////////////////////////////////
            //////// TRIGON 16
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_hyperb_16_table
                : public nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_hyperb_16_table";
                static constexpr const char *SINH_A = "sinh_a";
                static constexpr const char *SINH_B = "sinh_b";
                static constexpr const char *COSH_A = "cosh_a";
                static constexpr const char *COSH_B = "cosh_b";
                static constexpr const char *FULL_SINH_A = "fixedpoint_hyperb_16_table/sinh_a";
                static constexpr const char *FULL_SINH_B = "fixedpoint_hyperb_16_table/sinh_b";
                static constexpr const char *FULL_COSH_A = "fixedpoint_hyperb_16_table/cosh_a";
                static constexpr const char *FULL_COSH_B = "fixedpoint_hyperb_16_table/cosh_b";

                fixedpoint_hyperb_16_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SINH_A] = {{0, 1}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[SINH_B] = {{0, 2}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COSH_A] = {{0, 3}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COSH_B] = {{0, 4}, 0, fixedpoint_tables::SinXLen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::SinXLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto sinh_a = fixedpoint_tables::get_sinh_a_16();
                    auto sinh_b = fixedpoint_tables::get_sinh_b_16();
                    auto cosh_a = fixedpoint_tables::get_cosh_a_16();
                    auto cosh_b = fixedpoint_tables::get_cosh_b_16();
                    this->_table = {input, sinh_a, sinh_b, cosh_a, cosh_b};
                }

                virtual std::size_t get_columns_number() {
                    return 5;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::SinXLen;
                }
            };

            ////////////////////////////////////////////////////////////////////
            //////// TRIGON 32
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_hyperb_32_table
                : public nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_hyperb_32_table";
                static constexpr const char *SINH_A = "sinh_a";
                static constexpr const char *SINH_B = "sinh_b";
                static constexpr const char *SINH_C = "sinh_c";
                static constexpr const char *COSH_A = "cosh_a";
                static constexpr const char *COSH_B = "cosh_b";
                static constexpr const char *FULL_SINH_A = "fixedpoint_hyperb_32_table/sinh_a";
                static constexpr const char *FULL_SINH_B = "fixedpoint_hyperb_32_table/sinh_b";
                static constexpr const char *FULL_SINH_C = "fixedpoint_hyperb_32_table/sinh_c";
                static constexpr const char *FULL_COSH_A = "fixedpoint_hyperb_32_table/cosh_a";
                static constexpr const char *FULL_COSH_B = "fixedpoint_hyperb_32_table/cosh_b";

                fixedpoint_hyperb_32_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SINH_A] = {{0, 1}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[SINH_B] = {{0, 2}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[SINH_C] = {{0, 3}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COSH_A] = {{0, 4}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COSH_B] = {{0, 5}, 0, fixedpoint_tables::SinXLen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::SinXLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto sinh_a = fixedpoint_tables::get_sinh_a_32();
                    auto sinh_b = fixedpoint_tables::get_sinh_b_32();
                    auto sinh_c = fixedpoint_tables::get_sinh_c_32();
                    auto cosh_a = fixedpoint_tables::get_cosh_a_32();
                    auto cosh_b = fixedpoint_tables::get_cosh_b_32();
                    this->_table = {input, sinh_a, sinh_b, sinh_c, cosh_a, cosh_b};
                }

                virtual std::size_t get_columns_number() {
                    return 6;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::SinXLen;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HYPERBOLIC_TABLE_HPP
