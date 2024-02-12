#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_TABLE_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            class fixedpoint_range_table : public nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_range_table";

                static constexpr const char *FULL_SUBTABLE_NAME = "full";
                static constexpr const char *FULL_TABLE_NAME = "fixedpoint_range_table/full";

                static constexpr const char *P256_SUBTABLE_NAME = "p256";
                static constexpr const char *P256_TABLE_NAME = "fixedpoint_range_table/p256";

                fixedpoint_range_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[FULL_SUBTABLE_NAME] = {{0}, 0, fixedpoint_tables::RangeLen - 1};
                    this->subtables[P256_SUBTABLE_NAME] = {{0}, 0, 255};
                }

                virtual void generate() override {
                    auto table = fixedpoint_tables::get_range_table();
                    this->_table = {table};
                }

                virtual std::size_t get_columns_number() override {
                    return 1;
                }

                virtual std::size_t get_rows_number() override {
                    return fixedpoint_tables::RangeLen;
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_RANGE_TABLE_HPP
