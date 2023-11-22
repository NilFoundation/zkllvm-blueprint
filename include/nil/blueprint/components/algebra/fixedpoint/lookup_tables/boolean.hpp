#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_BOOLEAN_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_BOOLEAN_TABLE_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/detail/lookup_table_definition.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            ////////////////////////////////////////////////////////////////////
            //////// BOOLEAN
            ////////////////////////////////////////////////////////////////////

            // This lookup table exists for fun, demo, and experimental reasons (because it is small).
            // (and doesn't actually use fixed point representation, just the values 0 and 1 of the underlying field)

            template<typename BlueprintFieldType>
            class fixedpoint_boolean_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_boolean_table";
                static constexpr const char *AND = "and";
                static constexpr const char *OR = "or";
                static constexpr const char *XOR = "xor";
                static constexpr const char *INVERSE = "inverse";
                static constexpr const char *FULL_AND = "fixedpoint_boolean_table/and";
                static constexpr const char *FULL_OR = "fixedpoint_boolean_table/or";
                static constexpr const char *FULL_XOR = "fixedpoint_boolean_table/xor";
                static constexpr const char *FULL_INVERSE = "fixedpoint_boolean_table/inverse";

                fixedpoint_boolean_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[AND] = {{0, 1, 2}, 0, 3};
                    this->subtables[OR] = {{0, 1, 3}, 0, 3};
                    this->subtables[XOR] = {{0, 1, 4}, 0, 3};
                    this->subtables[INVERSE] = {{1, 5}, 0, 1};
                }

                virtual void generate() {
                    std::vector<value_type> x = {0, 0, 1, 1};
                    std::vector<value_type> y = {0, 1, 0, 1};
                    std::vector<value_type> and_ = {0, 0, 0, 1};
                    std::vector<value_type> or_ = {0, 1, 1, 1};
                    std::vector<value_type> xor_ = {0, 1, 1, 0};
                    std::vector<value_type> inv_ = {1, 0};
                    this->_table = {x, y, and_, or_, xor_, inv_};
                }

                virtual std::size_t get_columns_number() {
                    return 6;
                }

                virtual std::size_t get_rows_number() {
                    return 4;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_BOOLEAN_TABLE_HPP
