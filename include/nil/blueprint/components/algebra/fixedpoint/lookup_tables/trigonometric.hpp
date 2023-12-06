#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TRIGONOMETRIC_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TRIGONOMETRIC_TABLE_HPP

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
            class fixedpoint_trigon_16_table
                : public nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_trigon_16_table";
                static constexpr const char *SIN_A = "sin_a";
                static constexpr const char *SIN_B = "sin_b";
                static constexpr const char *COS_A = "cos_a";
                static constexpr const char *COS_B = "cos_b";
                static constexpr const char *FULL_SIN_A = "fixedpoint_trigon_16_table/sin_a";
                static constexpr const char *FULL_SIN_B = "fixedpoint_trigon_16_table/sin_b";
                static constexpr const char *FULL_COS_A = "fixedpoint_trigon_16_table/cos_a";
                static constexpr const char *FULL_COS_B = "fixedpoint_trigon_16_table/cos_b";

                // TACEO_TODO this hardcoded, indices might be wrong, are they though?..
                fixedpoint_trigon_16_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SIN_A] = {{0, 1}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[SIN_B] = {{0, 2}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COS_A] = {{0, 3}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COS_B] = {{0, 4}, 0, fixedpoint_tables::SinXLen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::SinXLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto sin_a = fixedpoint_tables::get_sin_a_16();
                    auto sin_b = fixedpoint_tables::get_sin_b_16();
                    auto cos_a = fixedpoint_tables::get_cos_a_16();
                    auto cos_b = fixedpoint_tables::get_cos_b_16();
                    this->_table = {input, sin_a, sin_b, cos_a, cos_b};
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
            class fixedpoint_trigon_32_table
                : public nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_trigon_32_table";
                static constexpr const char *SIN_A = "sin_a";
                static constexpr const char *SIN_B = "sin_b";
                static constexpr const char *SIN_C = "sin_c";
                static constexpr const char *COS_A = "cos_a";
                static constexpr const char *COS_B = "cos_b";
                static constexpr const char *FULL_SIN_A = "fixedpoint_trigon_32_table/sin_a";
                static constexpr const char *FULL_SIN_B = "fixedpoint_trigon_32_table/sin_b";
                static constexpr const char *FULL_SIN_C = "fixedpoint_trigon_32_table/sin_c";
                static constexpr const char *FULL_COS_A = "fixedpoint_trigon_32_table/cos_a";
                static constexpr const char *FULL_COS_B = "fixedpoint_trigon_32_table/cos_b";

                // TACEO_TODO this hardcoded, indices might be wrong, are they though?..
                fixedpoint_trigon_32_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SIN_A] = {{0, 1}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[SIN_B] = {{0, 2}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[SIN_C] = {{0, 3}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COS_A] = {{0, 4}, 0, fixedpoint_tables::SinXLen - 1};
                    this->subtables[COS_B] = {{0, 5}, 0, fixedpoint_tables::SinXLen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::SinXLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto sin_a = fixedpoint_tables::get_sin_a_32();
                    auto sin_b = fixedpoint_tables::get_sin_b_32();
                    auto sin_c = fixedpoint_tables::get_sin_c_32();
                    auto cos_a = fixedpoint_tables::get_cos_a_32();
                    auto cos_b = fixedpoint_tables::get_cos_b_32();
                    this->_table = {input, sin_a, sin_b, sin_c, cos_a, cos_b};
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

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TRIGONOMETRIC_TABLE_HPP
