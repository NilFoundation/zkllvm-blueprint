#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_BITWISE_OPS_HELPER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_BITWISE_OPS_HELPER_HPP

#include <cstdint>
#include <cmath>

#include <nil/blueprint/assert.hpp>
#include <nil/crypto3/multiprecision/cpp_int/divide.hpp>
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#include <nil/crypto3/multiprecision/detail/default_ops.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            class BitwiseTables {
                using value_type = typename BlueprintFieldType::value_type;

                static std::vector<value_type> fill_range_table();

                static std::vector<value_type> fill_bitwise_and_table();
                static std::vector<value_type> fill_bitwise_xor_table();
                static std::vector<value_type> fill_bitwise_or_table();

            public:
                BitwiseTables() = delete;
                BitwiseTables(const BitwiseTables &) = delete;
                BitwiseTables &operator=(const BitwiseTables &) = delete;

                static constexpr uint32_t RANGE_LEN = (1ULL << 16);
                static constexpr uint32_t SMALL_RANGE_LEN = (1ULL << 8);

                static constexpr uint16_t BITWISE_CHUNK_BITSIZE = 8;
                static constexpr uint32_t BITWISE_CHUNK_LEN = (1ULL << BITWISE_CHUNK_BITSIZE);
                static constexpr uint32_t BITWISE_TABLE_LEN = (1ULL << (2 * BITWISE_CHUNK_BITSIZE));

                static const std::vector<value_type> &get_range_table();

                static const std::vector<value_type> &get_bitwise_and_table();
                static const std::vector<value_type> &get_bitwise_xor_table();
                static const std::vector<value_type> &get_bitwise_or_table();
            };

            template<typename BlueprintFieldType>
            const std::vector<typename BitwiseTables<BlueprintFieldType>::value_type> &
                BitwiseTables<BlueprintFieldType>::get_range_table() {
                static std::vector<value_type> range = fill_range_table();
                return range;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename BitwiseTables<BlueprintFieldType>::value_type> &
                BitwiseTables<BlueprintFieldType>::get_bitwise_and_table() {
                static std::vector<value_type> bitwise_and = fill_bitwise_and_table();
                return bitwise_and;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename BitwiseTables<BlueprintFieldType>::value_type> &
                BitwiseTables<BlueprintFieldType>::get_bitwise_xor_table() {
                static std::vector<value_type> bitwise_xor = fill_bitwise_xor_table();
                return bitwise_xor;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename BitwiseTables<BlueprintFieldType>::value_type> &
                BitwiseTables<BlueprintFieldType>::get_bitwise_or_table() {
                static std::vector<value_type> bitwise_or = fill_bitwise_or_table();
                return bitwise_or;
            }

            template<typename BlueprintFieldType>
            std::vector<typename BitwiseTables<BlueprintFieldType>::value_type>
                BitwiseTables<BlueprintFieldType>::fill_range_table() {
                std::vector<value_type> range;
                range.reserve(RANGE_LEN);
                for (auto i = 0; i < RANGE_LEN; ++i) {
                    range.push_back(value_type(i));
                }
                return range;
            }

            template<typename BlueprintFieldType>
            std::vector<typename BitwiseTables<BlueprintFieldType>::value_type>
                BitwiseTables<BlueprintFieldType>::fill_bitwise_and_table() {
                BLUEPRINT_RELEASE_ASSERT(BITWISE_TABLE_LEN == RANGE_LEN);
                std::vector<value_type> bitwise_and;
                bitwise_and.reserve(BITWISE_TABLE_LEN);
                for (auto i = 0; i < BITWISE_CHUNK_LEN; ++i) {
                    for (auto j = 0; j < BITWISE_CHUNK_LEN; ++j) {
                        bitwise_and.push_back(value_type(i & j));
                    }
                }
                BLUEPRINT_RELEASE_ASSERT(bitwise_and.size() == BITWISE_TABLE_LEN);
                return bitwise_and;
            }

            template<typename BlueprintFieldType>
            std::vector<typename BitwiseTables<BlueprintFieldType>::value_type>
                BitwiseTables<BlueprintFieldType>::fill_bitwise_xor_table() {
                BLUEPRINT_RELEASE_ASSERT(BITWISE_TABLE_LEN == RANGE_LEN);
                std::vector<value_type> bitwise_xor;
                bitwise_xor.reserve(BITWISE_TABLE_LEN);
                for (auto i = 0; i < BITWISE_CHUNK_LEN; ++i) {
                    for (auto j = 0; j < BITWISE_CHUNK_LEN; ++j) {
                        bitwise_xor.push_back(value_type(i ^ j));
                    }
                }
                BLUEPRINT_RELEASE_ASSERT(bitwise_xor.size() == BITWISE_TABLE_LEN);
                return bitwise_xor;
            }

            template<typename BlueprintFieldType>
            std::vector<typename BitwiseTables<BlueprintFieldType>::value_type>
                BitwiseTables<BlueprintFieldType>::fill_bitwise_or_table() {
                BLUEPRINT_RELEASE_ASSERT(BITWISE_TABLE_LEN == RANGE_LEN);
                std::vector<value_type> bitwise_or;
                bitwise_or.reserve(BITWISE_TABLE_LEN);
                for (auto i = 0; i < BITWISE_CHUNK_LEN; ++i) {
                    for (auto j = 0; j < BITWISE_CHUNK_LEN; ++j) {
                        bitwise_or.push_back(value_type(i | j));
                    }
                }
                BLUEPRINT_RELEASE_ASSERT(bitwise_or.size() == BITWISE_TABLE_LEN);
                return bitwise_or;
            }

            template<typename BlueprintFieldType>
            class bitwise_table : public nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
                using bitwise_tables = BitwiseTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "bitwise_table";

                static constexpr const char *AND_SUBTABLE_NAME = "and";
                static constexpr const char *AND_TABLE_NAME = "bitwise_table/and";

                static constexpr const char *XOR_SUBTABLE_NAME = "xor";
                static constexpr const char *XOR_TABLE_NAME = "bitwise_table/xor";

                static constexpr const char *OR_SUBTABLE_NAME = "or";
                static constexpr const char *OR_TABLE_NAME = "bitwise_table/or";

                static constexpr const char *SMALL_RANGE_SUBTABLE_NAME = "small_range";
                static constexpr const char *SMALL_RANGE_TABLE_NAME = "bitwise_table/small_range";

                bitwise_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[AND_SUBTABLE_NAME] = {{0, 1}, 0, bitwise_tables::BITWISE_TABLE_LEN - 1};
                    this->subtables[XOR_SUBTABLE_NAME] = {{0, 2}, 0, bitwise_tables::BITWISE_TABLE_LEN - 1};
                    this->subtables[OR_SUBTABLE_NAME] = {{0, 3}, 0, bitwise_tables::BITWISE_TABLE_LEN - 1};
                    this->subtables[SMALL_RANGE_SUBTABLE_NAME] = {{0}, 0, bitwise_tables::SMALL_RANGE_LEN - 1};
                }

                virtual void generate() {
                    auto input = bitwise_tables::get_range_table();
                    auto output_and = bitwise_tables::get_bitwise_and_table();
                    auto output_xor = bitwise_tables::get_bitwise_xor_table();
                    auto output_or = bitwise_tables::get_bitwise_or_table();
                    this->_table = {input, output_and, output_xor, output_or};
                }

                virtual std::size_t get_columns_number() {
                    return 4;
                }

                virtual std::size_t get_rows_number() {
                    return bitwise_tables::BITWISE_TABLE_LEN;
                }
            };

            template<typename BlueprintFieldType>
            class BitwiseHelper {
            public:
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;

                // modulus is cpp_int_backend, so /2 is integer division and not field divison
                static constexpr value_type P_HALF = BlueprintFieldType::modulus / 2;

                // Transforms from/to montgomery representation
                static modular_backend field_to_backend(const value_type &);

                // Returns the sign bit (1 if the number is "negative" (i.e. >= P/2), 0 otherwise)
                static value_type sign(const value_type &);
                // computes n = modulus - 2^(8*m)
                static value_type get_n(uint8_t m);
                // Returns sign bit and decomposes a field element into 8-bit limbs for bitwise operations
                static value_type decompose_bitwise(const value_type &, std::vector<uint8_t> &, uint8_t);
            };

            template<typename BlueprintFieldType>
            typename BitwiseHelper<BlueprintFieldType>::modular_backend
                BitwiseHelper<BlueprintFieldType>::field_to_backend(const value_type &x) {
                modular_backend out;
                BlueprintFieldType::modulus_params.adjust_regular(out, x.data.backend().base_data());
                BLUEPRINT_RELEASE_ASSERT(out.size() != 0);
                return out;
            }

            template<typename BlueprintFieldType>
            typename BlueprintFieldType::value_type BitwiseHelper<BlueprintFieldType>::sign(const value_type &x) {
                if (x > P_HALF) {
                    return value_type(1);
                }
                return value_type(0);
            }

            template<typename BlueprintFieldType>
            typename BlueprintFieldType::value_type BitwiseHelper<BlueprintFieldType>::get_n(uint8_t m) {
                BLUEPRINT_RELEASE_ASSERT(0 < m && m <= 8);
                if (m == 8) {
                    return BlueprintFieldType::modulus - value_type(1ULL << (8 * 4)) * value_type(1ULL << (8 * 4));
                }    // else 0 < m && m <= 7
                return BlueprintFieldType::modulus - value_type(1ULL << (8 * m));
            }

            template<typename BlueprintFieldType>
            typename BlueprintFieldType::value_type
                BitwiseHelper<BlueprintFieldType>::decompose_bitwise(const value_type &inp,
                                                                     std::vector<uint8_t> &output, uint8_t m) {
                BLUEPRINT_RELEASE_ASSERT(0 < m && m <= 8);
                output.clear();
                output.reserve(m);

                value_type inp_sign = sign(inp);

                // n is zero for "positive" values of inp and modulus - 2^(8*m) for "negative" values of inp
                value_type n = inp_sign == value_type::zero() ? value_type::zero() : get_n(m);

                // need to transform input to correctly handle "negative" values of inp
                auto transformed_inp = inp - n;
                auto tmp = field_to_backend(transformed_inp);
                for (auto i = 0; i < tmp.size(); i++) {
                    for (auto j = 0; j < 4; j++) {
                        output.push_back(static_cast<uint8_t>(tmp.limbs()[i] & 0xFF));
                        output.push_back(static_cast<uint8_t>(tmp.limbs()[i] >> 8));
                        tmp.limbs()[i] >>= 16;
                    }
                }
                return inp_sign;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_BITWISE_OPS_HELPER_HPP
