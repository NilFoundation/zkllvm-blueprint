#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_TABLE_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/detail/lookup_table_definition.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            ////////////////////////////////////////////////////////////////////
            //////// EXP 16
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_exp_16_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_exp_16_table";

                static constexpr const char *A_SUBTABLE_NAME = "a";
                static constexpr const char *A_TABLE_NAME = "fixedpoint_exp_16_table/a";

                static constexpr const char *B_SUBTABLE_NAME = "b";
                static constexpr const char *B_TABLE_NAME = "fixedpoint_exp_16_table/b";

                fixedpoint_exp_16_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[B_SUBTABLE_NAME] = {{0, 2}, 0, fixedpoint_tables::ExpBLen - 1};
                    this->subtables[A_SUBTABLE_NAME] = {{0, 1}, 0, fixedpoint_tables::ExpALen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::ExpBLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto output_a = fixedpoint_tables::get_exp_a_16();
                    auto output_b = fixedpoint_tables::get_exp_b_16();
                    this->_table = {input, output_a, output_b};
                }

                virtual std::size_t get_columns_number() {
                    return 3;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::ExpBLen;
                }
            };

            ////////////////////////////////////////////////////////////////////
            //////// EXP 32
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_exp_32_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_exp_32_table";

                static constexpr const char *A_SUBTABLE_NAME = "a";
                static constexpr const char *A_TABLE_NAME = "fixedpoint_exp_32_table/a";

                static constexpr const char *B_SUBTABLE_NAME = "b";
                static constexpr const char *B_TABLE_NAME = "fixedpoint_exp_32_table/b";

                fixedpoint_exp_32_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[B_SUBTABLE_NAME] = {{0, 2}, 0, fixedpoint_tables::ExpBLen - 1};
                    this->subtables[A_SUBTABLE_NAME] = {{0, 1}, 0, fixedpoint_tables::ExpALen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::ExpBLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto output_a = fixedpoint_tables::get_exp_a_32();
                    auto output_b = fixedpoint_tables::get_exp_b_32();
                    this->_table = {input, output_a, output_b};
                }

                virtual std::size_t get_columns_number() {
                    return 3;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::ExpBLen;
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_TABLE_HPP
