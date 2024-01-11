#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_LOOKUP_TESTER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_LOOKUP_TESTER_HPP

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>

namespace nil {
    namespace blueprint {

        template<typename Type>
        constexpr bool use_custom_lookup_tables() {
            if (component_use_custom_lookup_tables<Type>::value) {
                return true;
            }
            return false;
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        bool check_lookup_constraint(
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> &constraint, int row) {

            using value_type = typename BlueprintFieldType::value_type;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            // The tables
            auto &lookup_tables = bp.get_reserved_tables();
            auto &indices = bp.get_reserved_indices();

            auto table_id = constraint.table_id;
            auto &lookup_input = constraint.lookup_input;

            // Get lookup table
            std::string name = "";
            for (auto el : indices) {
                if (el.second == table_id) {
                    name = el.first;
                    break;
                }
            }

            // Get the lookup values
            std::vector<value_type> lookup_values;
            lookup_values.reserve(lookup_input.size());
            for (auto &t : lookup_input) {
                if (t.get_expr().which() != 0) {
                    std::cout << "Skipping check of lookup table with ID \"" << name << "\" at row " << row
                              << " as there exist lookup inputs that are not a single variable" << std::endl;
                    return true;
                }
                nil::crypto3::math::term<var> term = boost::get<nil::crypto3::math::term<var>>(t.get_expr());
                BLUEPRINT_RELEASE_ASSERT(term.get_vars().size() == 1);
                var val = term.get_vars()[0];
                val.rotation += row;
                auto value = var_value(assignment, val);
                lookup_values.push_back(value);
            }

            BLUEPRINT_RELEASE_ASSERT(name != "");
            auto index = name.find("/");
            BLUEPRINT_RELEASE_ASSERT(index != -1);
            auto tab_name = name.substr(0, index);
            auto sub_name = name.substr(index + 1);

            auto &table = lookup_tables.at(tab_name);
            auto &table_vals = table->get_table();
            auto &subtable = table->subtables.at(sub_name);

            BLUEPRINT_RELEASE_ASSERT(subtable.column_indices.size() == lookup_values.size());

            // Compare to the actual table
            auto row_index = -1;
            auto first_val = lookup_values.at(0);
            for (auto i = subtable.begin; i <= subtable.end; i++) {
                if (table_vals.at(subtable.column_indices.at(0)).at(i) == first_val) {
                    row_index = i;
                    if (lookup_values.size() <= 1) {
                        break;
                    }
                    auto second_val = lookup_values.at(1);
                    for (auto j = i; j <= subtable.end; j++) {
                        if (table_vals.at(subtable.column_indices.at(0)).at(j) == first_val &&
                            table_vals.at(subtable.column_indices.at(1)).at(j) == second_val) {
                            row_index = j;
                        }
                    }
                    break;
                }
            }
            if (row_index == -1) {
                std::cout << "Lookup gates error" << std::endl;
                std::cout << "Table: " << name << std::endl;
                std::cout << "Row: " << row << std::endl;
                std::cout << "lookup(0): " << first_val << std::endl;
                return false;
            } else {
                for (auto i = 0; i < subtable.column_indices.size(); i++) {
                    auto col = subtable.column_indices.at(i);
                    auto val = table_vals.at(col).at(row_index);
                    auto lookup_val = lookup_values.at(i);
                    if (val != lookup_val) {
                        std::cout << "Lookup gates error" << std::endl;
                        std::cout << "Table: " << name << std::endl;
                        std::cout << "Row: " << row << std::endl;
                        std::cout << "Index: " << i << std::endl;
                        std::cout << "Expected: " << lookup_val << std::endl;
                        std::cout << "Actual: " << val << std::endl;
                        std::cout << "lookup(0): " << first_val << std::endl;
                        std::cout << "Note that this error might be wrong if you have more than two inputs for this "
                                     "lookup table."
                                  << std::endl;
                        return false;
                    }
                }
            }
            return true;
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        bool check_lookup_tables(
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment) {

            using value_type = typename BlueprintFieldType::value_type;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            // The tables
            auto &lookup_tables = bp.get_reserved_tables();
            auto &indices = bp.get_reserved_indices();

            auto rows = assignment.rows_amount();

            auto gates = bp.lookup_gates();

            // For each gate
            for (auto &gate : gates) {
                auto &constraints = gate.constraints;
                auto tag = bp.add_lookup_gate(constraints);
                BLUEPRINT_RELEASE_ASSERT(tag < assignment.selectors_amount());

                // Find rows in which the gate is active
                for (auto row = 0; row < rows; row++) {
                    auto selector_col = assignment.selector(tag);
                    if (row >= selector_col.size()) {
                        break;
                    }
                    auto selector = selector_col[row];

                    if (selector == 1) {
                        // Get the constraints in the gate
                        for (auto &constraint : constraints) {
                            if (!check_lookup_constraint(bp, assignment, constraint, row)) {
                                return false;
                            }
                        }
                    }
                }
            }

            return true;
        }

    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_LOOKUP_TESTER_HPP
