#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CELL_POSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CELL_POSITION_HPP

#include <cstdint>
#include <nil/blueprint/assert.hpp>

// macro for getting a variable list from a cell position
#define splat(x) x.column(), x.row()

namespace nil {
    namespace blueprint {
        namespace components {
            /**
             * Defines the position (column and row indices) of a cell for easier handling thereof in components.
             */
            class CellPosition {
                int64_t column_;
                int64_t row_;
                bool valid_;

            public:
                CellPosition() : column_(0), row_(0), valid_(false) {
                }
                CellPosition(int64_t column, int64_t row) : column_(column), row_(row), valid_(true) {
                }
                int64_t column() const {
                    BLUEPRINT_RELEASE_ASSERT(valid_ && "CellPosition is not defined");
                    return column_;
                }
                int64_t row() const {
                    BLUEPRINT_RELEASE_ASSERT(valid_ && "CellPosition is not defined");
                    return row_;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CELL_POSITION_HPP