#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP

#include <cstdint>
#include <cmath>

#include <nil/blueprint/assert.hpp>
#include <nil/crypto3/multiprecision/cpp_int/divide.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            struct DivMod {
                using value_type = typename BlueprintFieldType::value_type;
                value_type quotient;
                value_type remainder;
            };

            /**
             * Defines the position (column and row indices) of a cell for easier handling thereof in functions.
             *
             * Using uint64_t to be on the safe side for any computations as of today.
             */
            struct CellPosition {
                uint64_t column;
                uint64_t row;
            };

            template<typename BlueprintFieldType>
            class FixedPointHelper {
            public:
                using field_type = BlueprintFieldType;
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;

                // modulus is cpp_int_backend, so /2 is integer division and not field divison
                static constexpr value_type P_HALF = BlueprintFieldType::modulus / 2;

                // M2 is the number of post-comma 16-bit limbs
                static DivMod<BlueprintFieldType> round_div_mod(const value_type &, uint64_t);
                static DivMod<BlueprintFieldType> round_div_mod(const value_type &, const value_type &);
                static DivMod<BlueprintFieldType> div_mod(const value_type &, const value_type &);

                // Transforms from/to montgomery representation
                static modular_backend field_to_backend(const value_type &);
                static value_type backend_to_field(const modular_backend &);

                // Returns true if sign was changed
                static bool abs(value_type &);
                // Returns sign
                static bool decompose(const value_type &, std::vector<uint16_t> &);
                // Returns sign, and in = s*(a*delta + b)
                static bool split(const value_type &, uint16_t, uint64_t &, uint64_t &);
                // Returns sign, and in = s*a*delta + b
                static bool split_exp(const value_type &, uint16_t, uint64_t &, uint64_t &);
            };

            // FieldType is the representation of the proof system, whereas M1 is the number of pre-comma 16-bit limbs
            // and M2 the number of post-comma 16-bit limbs
            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            class FixedPoint {

                static_assert(M1 > 0 && M1 < 3, "Only allow one or two pre-comma limbs");
                static_assert(M2 > 0 && M2 < 3, "Only allow one or two post-comma limbs");

            public:
                using helper = FixedPointHelper<BlueprintFieldType>;
                using field_type = BlueprintFieldType;
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;

            private:
                // I need a field element to deal with larger scales, such as the one as output from exp
                value_type value;
                uint16_t scale;

            public:
                static constexpr uint8_t M_1 = M1;
                static constexpr uint8_t M_2 = M2;
                static constexpr uint16_t SCALE = 16 * M2;
                static constexpr uint64_t DELTA = (1ULL << SCALE);

                // Initiliaze from real values
                FixedPoint(double x);
                FixedPoint(int64_t x);
                // Initialize from Fixedpoint representation
                FixedPoint(const value_type &value, uint16_t scale);
                virtual ~FixedPoint() = default;
                FixedPoint(const FixedPoint &) = default;
                FixedPoint &operator=(const FixedPoint &) = default;

                FixedPoint exp() const;

                static FixedPoint max();

                bool operator==(const FixedPoint &other) const;
                bool operator!=(const FixedPoint &other) const;
                bool operator<(const FixedPoint &other) const;
                bool operator>(const FixedPoint &other) const;
                bool operator<=(const FixedPoint &other) const;
                bool operator>=(const FixedPoint &other) const;

                FixedPoint operator+(const FixedPoint &other) const;
                FixedPoint operator-(const FixedPoint &other) const;
                FixedPoint operator*(const FixedPoint &other) const;
                FixedPoint operator/(const FixedPoint &other) const;
                FixedPoint operator%(const FixedPoint &other) const;
                FixedPoint operator-() const;

                void rescale();
                static FixedPoint dot(const std::vector<FixedPoint> &, const std::vector<FixedPoint> &);

                double to_double() const;
                value_type get_value() const {
                    return value;
                }
                uint16_t get_scale() const {
                    return scale;
                }
            };

            // TypeDefs
            template<typename BlueprintFieldType>
            using FixedPoint16_16 = FixedPoint<BlueprintFieldType, 1, 1>;
            template<typename BlueprintFieldType>
            using FixedPoint32_32 = FixedPoint<BlueprintFieldType, 2, 2>;

            template<typename BlueprintFieldType>
            typename FixedPointHelper<BlueprintFieldType>::modular_backend
                FixedPointHelper<BlueprintFieldType>::field_to_backend(const value_type &x) {
                modular_backend out;
                BlueprintFieldType::modulus_params.adjust_regular(out, x.data.backend().base_data());
                BLUEPRINT_RELEASE_ASSERT(out.size() != 0);
                return out;
            }

            template<typename BlueprintFieldType>
            typename FixedPointHelper<BlueprintFieldType>::value_type
                FixedPointHelper<BlueprintFieldType>::backend_to_field(const modular_backend &x) {
                value_type out;
                out.data.backend().base_data() = x;
                BlueprintFieldType::modulus_params.adjust_modular(out.data.backend().base_data());
                return out;
            }

            template<typename BlueprintFieldType>
            bool FixedPointHelper<BlueprintFieldType>::abs(value_type &x) {
                bool sign = false;
                if (x > P_HALF) {
                    x = -x;
                    sign = true;
                }
                return sign;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(double x) : scale(SCALE) {
                if (x < 0) {
                    value = -value_type(static_cast<int64_t>(-x * DELTA));
                } else {
                    value = static_cast<int64_t>(x * DELTA);
                }
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(int64_t x) : scale(SCALE) {
                if (x < 0) {
                    value = -value_type(-x * DELTA);
                } else {
                    value = x * DELTA;
                }
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(const value_type &value, uint16_t scale) :
                value(value), scale(scale) {
                BLUEPRINT_RELEASE_ASSERT(scale % 16 == 0);
            };

            template<typename BlueprintFieldType>
            bool FixedPointHelper<BlueprintFieldType>::decompose(const value_type &inp, std::vector<uint16_t> &output) {
                auto tmp_ = inp;
                bool sign = abs(tmp_);

                output.clear();

                auto tmp = field_to_backend(tmp_);
                for (auto i = 0; i < tmp.size(); i++) {
                    for (auto j = 0; j < 4; j++) {
                        output.push_back(tmp.limbs()[i] & 0xFFFF);
                        tmp.limbs()[i] >>= 16;
                    }
                }

                return sign;
            }

            template<typename BlueprintFieldType>
            bool FixedPointHelper<BlueprintFieldType>::split(const value_type &inp,
                                                             uint16_t scale,
                                                             uint64_t &pre,
                                                             uint64_t &post) {
                BLUEPRINT_RELEASE_ASSERT(scale <= 64);
                auto tmp_ = inp;
                bool sign = abs(tmp_);

                auto tmp = field_to_backend(tmp_);
                if (scale == 64) {
                    post = tmp.limbs()[0];
                    pre = tmp.size() > 1 ? tmp.limbs()[1] : 0;

                } else {
                    auto mask = ((1ULL << scale) - 1);
                    post = tmp.limbs()[0] & mask;
                    pre = (tmp.limbs()[0] >> scale);
                    if (tmp.size() > 1) {
                        pre |= (tmp.limbs()[1] << (64 - scale));
                        BLUEPRINT_RELEASE_ASSERT((tmp.limbs()[1] >> scale) == 0);
                    }
                }
                for (auto i = 2; i < tmp.size(); i++) {
                    BLUEPRINT_RELEASE_ASSERT(tmp.limbs()[i] == 0);
                }

                return sign;
            }

            template<typename BlueprintFieldType>
            bool FixedPointHelper<BlueprintFieldType>::split_exp(const value_type &inp,
                                                                 uint16_t scale,
                                                                 uint64_t &pre,
                                                                 uint64_t &post) {
                bool sign = split(inp, scale, pre, post);
                // convert from s(a delta + b) to s a delta + b
                if (sign && post != 0) {
                    post = (1ULL << scale) - post;
                    pre += 1;
                    BLUEPRINT_RELEASE_ASSERT(pre != 0);
                }
                return sign;
            }

            // res.quotient = Round(val / div)
            // remainder required for proof
            template<typename BlueprintFieldType>
            DivMod<BlueprintFieldType>
                FixedPointHelper<BlueprintFieldType>::round_div_mod(const typename BlueprintFieldType::value_type &val,
                                                                    uint64_t div) {
                BLUEPRINT_RELEASE_ASSERT(div != 0);

                DivMod<BlueprintFieldType> res;
                auto div_2 = (div >> 1);

                modular_backend div_;
                div_.limbs()[0] = div;
                auto tmp = val + div_2;
                bool sign = abs(tmp);
                modular_backend out = field_to_backend(tmp);

                modular_backend out_;
                eval_divide(out_, out, div_);

                res.quotient = backend_to_field(out_);
                if (sign) {
                    res.quotient = -res.quotient;
                }
                // res.remainder = (val + div/2) % div;
                res.remainder = val + div_2 - res.quotient * div;
                if (res.remainder > P_HALF) {
                    // negative? artifact of eval_divide?
                    res.remainder += div;
                    res.quotient -= 1;    // div is always positive
                }
                return res;
            }

            // res.quotient = Round(val / div)
            // remainder required for proof
            template<typename BlueprintFieldType>
            DivMod<BlueprintFieldType> FixedPointHelper<BlueprintFieldType>::round_div_mod(
                const typename BlueprintFieldType::value_type &val,
                const typename BlueprintFieldType::value_type &div) {
                BLUEPRINT_RELEASE_ASSERT(div != 0);

                DivMod<BlueprintFieldType> res;

                auto div_abs = div;
                bool sign_div = abs(div_abs);
                modular_backend div_ = field_to_backend(div_abs);
                modular_backend div_2_ = div_;
                uint64_t carry = 0;
                for (auto i = div_2_.size(); i > 0; i--) {
                    auto tmp = carry;
                    carry = div_2_.limbs()[i - 1] & 1;
                    div_2_.limbs()[i - 1] >>= 1;
                    if (tmp) {
                        div_2_.limbs()[i - 1] |= 0x8000000000000000;
                    }
                }
                auto div_2 = backend_to_field(div_2_);    // = floor (abs(div) / 2)

                auto tmp = val + div_2;
                bool sign_tmp = abs(tmp);
                modular_backend out = field_to_backend(tmp);

                modular_backend out_;
                eval_divide(out_, out, div_);

                res.quotient = backend_to_field(out_);
                if (sign_div != sign_tmp) {
                    res.quotient = -res.quotient;
                }
                // res.remainder = (val + div/2) % div;
                res.remainder = val + div_2 - res.quotient * div;
                if (res.remainder > P_HALF) {
                    // negative? artifact of eval_divide?
                    res.remainder += div_abs;
                    if (sign_div)
                        res.quotient += 1;
                    else
                        res.quotient -= 1;
                }
                return res;
            }

            // res.quotient = floor(val / div)
            // remainder required for proof
            template<typename BlueprintFieldType>
            DivMod<BlueprintFieldType>
                FixedPointHelper<BlueprintFieldType>::div_mod(const typename BlueprintFieldType::value_type &val,
                                                              const typename BlueprintFieldType::value_type &div) {
                BLUEPRINT_RELEASE_ASSERT(div != 0);

                DivMod<BlueprintFieldType> res;

                auto div_abs = div;
                bool sign_div = abs(div_abs);
                modular_backend div_ = field_to_backend(div_abs);

                auto tmp = val;
                bool sign_tmp = abs(tmp);
                modular_backend out = field_to_backend(tmp);

                modular_backend out_;
                eval_divide(out_, out, div_);

                res.quotient = backend_to_field(out_);
                if (sign_div != sign_tmp) {
                    res.quotient = -res.quotient;
                }
                // res.remainder = (val + mod/2) % mod;
                res.remainder = val - res.quotient * div;
                if (res.remainder > P_HALF) {
                    // negative? artifact of eval_divide?
                    res.remainder += div_abs;
                    if (sign_div)
                        res.quotient += 1;
                    else
                        res.quotient -= 1;
                }
                return res;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            double FixedPoint<BlueprintFieldType, M1, M2>::to_double() const {
                auto tmp = value;
                bool sign = helper::abs(tmp);

                modular_backend out = helper::field_to_backend(tmp);
                BLUEPRINT_RELEASE_ASSERT(!out.sign());
                auto limbs_ptr = out.limbs();
                auto size = out.size();

                double val = 0;
                double pow64 = pow(2., 64);
                for (auto i = 0; i < size; i++) {
                    val *= pow64;
                    val += (double)(limbs_ptr[size - 1 - i]);
                }
                if (sign) {
                    val = -val;
                }
                return val / pow(2., scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator==(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                return value == other.value;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator!=(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                return !(*this == other);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator<(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                auto a_abs = value;
                auto b_abs = other.value;
                bool sign_a = helper::abs(a_abs);
                bool sign_b = helper::abs(b_abs);
                return (sign_a && !sign_b) || (sign_a && sign_b && (a_abs > b_abs)) ||
                       (!sign_a && !sign_b && (a_abs < b_abs));
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator>(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                auto a_abs = value;
                auto b_abs = other.value;
                bool sign_a = helper::abs(a_abs);
                bool sign_b = helper::abs(b_abs);
                return (!sign_a && sign_b) || (sign_a && sign_b && (a_abs < b_abs)) ||
                       (!sign_a && !sign_b && (a_abs > b_abs));
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator<=(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                return !(*this > other);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator>=(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                return !(*this < other);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::operator+(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                return FixedPoint(value + other.value, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::operator-(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                return FixedPoint(value - other.value, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::operator*(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                auto mul = value * other.value;
                auto divmod = helper::round_div_mod(mul, 1ULL << scale);
                return FixedPoint(divmod.quotient, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::operator/(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                auto mul = value * (1ULL << scale);
                auto divmod = helper::round_div_mod(mul, other.value);
                return FixedPoint(divmod.quotient, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::operator%(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) const {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                auto divmod = helper::div_mod(value, other.value);    // divmod.remainder is positiv
                if (other.value > helper::P_HALF && divmod.remainder != 0) {
                    // sign(other.value) == sign(divmod_remainder)
                    divmod.remainder += other.value;
                }

                return FixedPoint(divmod.remainder, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::max() {
                if (M1 == 2 && M2 == 2) {
                    return (FixedPoint((uint64_t)(-1), SCALE));
                } else if (M1 + M2 < 4) {
                    return (FixedPoint((uint64_t)(1ULL << (16 * (M1 + M2)) - 1), SCALE));
                }
                BLUEPRINT_RELEASE_ASSERT(false);
                return FixedPoint(0, SCALE);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::exp() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);
                auto exp_a = M2 == 1 ? FixedPointTables<BlueprintFieldType>::get_exp_a_16() :
                                       FixedPointTables<BlueprintFieldType>::get_exp_a_32();
                auto exp_b = FixedPointTables<BlueprintFieldType>::get_exp_b();

                uint64_t pre, post;
                bool sign = helper::split_exp(value, scale, pre, post);

                int32_t table_half = FixedPointTables<BlueprintFieldType>::ExpALen / 2;

                // Clip result if necessary
                if (pre > table_half) {
                    if (sign) {
                        return FixedPoint(0, SCALE);
                    }
                    pre = table_half;
                    post = (1ULL << (16 * M2)) - 1;
                }

                int64_t input_a = sign ? table_half - (int64_t)pre : table_half + pre;

                value_type res;

                if (M2 == 2) {
                    auto exp_c = FixedPointTables<BlueprintFieldType>::get_exp_c();
                    uint32_t input_b = post >> 16;
                    uint32_t input_c = post & ((1ULL << 16) - 1);

                    BLUEPRINT_RELEASE_ASSERT(input_a >= 0 && input_a < exp_a.size());
                    BLUEPRINT_RELEASE_ASSERT(input_b >= 0 && input_b < exp_b.size());
                    BLUEPRINT_RELEASE_ASSERT(input_c >= 0 && input_c < exp_c.size());
                    res = exp_a[input_a] * exp_b[input_b] * exp_c[input_c];
                } else {
                    BLUEPRINT_RELEASE_ASSERT(input_a >= 0 && input_a < exp_a.size());
                    BLUEPRINT_RELEASE_ASSERT(post >= 0 && post < exp_b.size());
                    res = exp_a[input_a] * exp_b[post];
                }

                auto fix = FixedPoint(res, FixedPointTables<BlueprintFieldType>::template get_exp_scale<M2>());
                fix.rescale();
                return fix;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::operator-() const {
                return FixedPoint(-value, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>
                FixedPoint<BlueprintFieldType, M1, M2>::dot(const std::vector<FixedPoint> &a,
                                                            const std::vector<FixedPoint> &b) {
                auto dots = a.size();
                BLUEPRINT_RELEASE_ASSERT(dots == b.size());
                if (dots == 0) {
                    return FixedPoint(0, SCALE);
                }

                value_type sum = 0;
                auto scale = a[0].scale;
                for (auto i = 0; i < dots; i++) {
                    BLUEPRINT_RELEASE_ASSERT(a[i].scale == scale);
                    BLUEPRINT_RELEASE_ASSERT(b[i].scale == scale);
                    sum += a[i].value * b[i].value;
                }
                auto divmod = helper::round_div_mod(sum, 1ULL << scale);
                return FixedPoint(divmod.quotient, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            void FixedPoint<BlueprintFieldType, M1, M2>::rescale() {
                BLUEPRINT_RELEASE_ASSERT(scale == 2 * SCALE);
                auto divmod = helper::round_div_mod(value, DELTA);
                value = divmod.quotient;
                scale = SCALE;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
