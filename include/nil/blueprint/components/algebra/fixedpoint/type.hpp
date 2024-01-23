#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP

#include <cstdint>
#include <cmath>

#include <nil/blueprint/assert.hpp>
#include <nil/crypto3/multiprecision/cpp_int/divide.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#include <nil/crypto3/multiprecision/detail/default_ops.hpp>

#include "nil/blueprint/components/cell_position.hpp"

#define SIN_COMPUTATION_1(sin0, sin1, cos0, cos1, sign_val) sign_val *(sin0 * cos1 + cos0 * sin1)
#define SIN_COMPUTATION_2(sin0, sin1, sin2, cos0, cos1, cos2, sign_val) \
    sign_val *(cos2 * (sin0 * cos1 + cos0 * sin1) + sin2 * (cos0 * cos1 - sin0 * sin1))
#define COS_COMPUTATION_1(sin0, sin1, cos0, cos1) (cos0 * cos1 - sin0 * sin1)
#define COS_COMPUTATION_2(sin0, sin1, sin2, cos0, cos1, cos2) \
    (cos2 * (cos0 * cos1 - sin0 * sin1) - sin2 * (sin0 * cos1 + cos0 * sin1))

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            struct DivMod {
                using value_type = typename BlueprintFieldType::value_type;
                value_type quotient;
                value_type remainder;
            };

            template<typename BlueprintFieldType>
            class FixedPointHelper {
            public:
                using field_type = BlueprintFieldType;
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;
                using big_float = nil::crypto3::multiprecision::cpp_bin_float_double;

                // modulus is cpp_int_backend, so /2 is integer division and not field divison
                static constexpr value_type P_HALF = BlueprintFieldType::modulus / 2;

                // M2 is the number of post-comma 16-bit limbs
                static DivMod<BlueprintFieldType> round_div_mod(const value_type &, uint64_t);
                static DivMod<BlueprintFieldType> round_div_mod(const value_type &, const value_type &);
                static DivMod<BlueprintFieldType> div_mod(const value_type &, const value_type &);

                // Transforms from/to montgomery representation
                static modular_backend field_to_backend(const value_type &);
                static value_type backend_to_field(const modular_backend &);

                static double field_to_double(const value_type &);

                // Returns true if sign was changed
                static bool abs(value_type &);
                // Returns sign
                static bool decompose(const value_type &, std::vector<uint16_t> &);
                // Returns sign, and in = s*(a*delta + b)
                static bool split(const value_type &, uint16_t, uint64_t &, uint64_t &);
                // Returns sign, and in = s*a*delta + b
                static bool split_exp(const value_type &, uint16_t, uint64_t &, uint64_t &);

                static value_type sqrt(const value_type &, bool floor = false);

                static value_type tanh_lower_range(uint8_t m2);
                static value_type tanh_upper_range(uint8_t m1, uint8_t m2);
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
                using big_float = nil::crypto3::multiprecision::cpp_bin_float_double;

            private:
                // I need a field element to deal with larger scales, such as the one as output from exp
                value_type value;
                uint16_t scale;

                void trigonometric_helper(value_type &sin0,
                                          value_type &sin1,
                                          value_type &sin2,
                                          value_type &cos0,
                                          value_type &cos1,
                                          value_type &cos2,
                                          value_type &sign_val) const;

            public:
                static constexpr uint8_t M_1 = M1;
                static constexpr uint8_t M_2 = M2;
                static constexpr uint16_t SCALE = 16 * M2;
                static constexpr uint64_t DELTA = (1ULL << SCALE);

                // Initiliaze from real values
                FixedPoint(double x);
                FixedPoint(int64_t x);
                FixedPoint(const value_type &x);
                // Initialize from Fixedpoint representation
                FixedPoint(const value_type &value, uint16_t scale);
                virtual ~FixedPoint() = default;
                FixedPoint(const FixedPoint &) = default;
                FixedPoint &operator=(const FixedPoint &) = default;

                static constexpr FixedPoint max();
                bool geq_0() const;

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

                FixedPoint abs() const;
                FixedPoint ceil() const;
                FixedPoint floor() const;
                FixedPoint exp(bool ranged = false) const;
                FixedPoint sqrt(bool floor = false) const;    // rounds per default
                FixedPoint log() const;
                FixedPoint sin() const;
                FixedPoint cos() const;
                FixedPoint tan() const;
                FixedPoint atan() const;
                FixedPoint erf() const;
                FixedPoint rescale() const;
                static FixedPoint dot(const std::vector<FixedPoint> &, const std::vector<FixedPoint> &);

                FixedPoint tanh() const;

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
            using FixedPoint16_32 = FixedPoint<BlueprintFieldType, 1, 2>;
            template<typename BlueprintFieldType>
            using FixedPoint32_16 = FixedPoint<BlueprintFieldType, 2, 1>;

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
            double FixedPointHelper<BlueprintFieldType>::field_to_double(const value_type &value) {
                auto tmp = value;
                bool sign = abs(tmp);

                modular_backend out = field_to_backend(tmp);
                BLUEPRINT_RELEASE_ASSERT(!out.sign());
                typename BlueprintFieldType::integral_type val_int(out);
                big_float val_float(val_int);
                auto out_ = val_float.convert_to<double>();
                if (sign) {
                    out_ = -out_;
                }
                return out_;
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
                BLUEPRINT_RELEASE_ASSERT(!std::isnan(x));
                // Clamp
                if (std::isinf(x)) {
                    auto max = FixedPoint::max().get_value();
                    if (x < 0) {
                        value = -max;
                    } else {
                        value = max;
                    }
                } else {
                    if (x < 0) {
                        value = -value_type(static_cast<int64_t>(-x * DELTA));
                    } else {
                        value = static_cast<int64_t>(x * DELTA);
                    }
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
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(const value_type &x) : scale(SCALE) {
                value = x * DELTA;
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

            template<typename BlueprintFieldType>
            typename FixedPointHelper<BlueprintFieldType>::value_type
                FixedPointHelper<BlueprintFieldType>::sqrt(const value_type &inp, bool floor) {
                BLUEPRINT_RELEASE_ASSERT(inp >= 0 && inp <= P_HALF);
                modular_backend val = field_to_backend(inp);
                typename BlueprintFieldType::integral_type val_int(val);
                big_float val_float(val_int);
                big_float out;
                eval_sqrt(out.backend(), val_float.backend());

                if (!floor) {
                    out += 0.5;
                }

                auto int_val = out.convert_to<nil::crypto3::multiprecision::cpp_int>();
                return value_type(int_val);
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
                BLUEPRINT_RELEASE_ASSERT(res.remainder <= P_HALF);
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
                BLUEPRINT_RELEASE_ASSERT(res.remainder <= P_HALF);
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
                BLUEPRINT_RELEASE_ASSERT(res.remainder <= P_HALF);
                return res;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            double FixedPoint<BlueprintFieldType, M1, M2>::to_double() const {
                auto val = helper::field_to_double(value);
                return val / pow(2., scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::geq_0() const {
                auto a_abs = value;
                bool sign_a = helper::abs(a_abs);
                return !sign_a;
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
            constexpr FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::max() {
                if constexpr (M1 == 2 && M2 == 2) {
                    return (FixedPoint((uint64_t)(-1), SCALE));
                } else if constexpr (M1 + M2 < 4) {
                    return (FixedPoint((uint64_t)((1ULL << (16 * (M1 + M2))) - 1), SCALE));
                }
                BLUEPRINT_RELEASE_ASSERT(false);
                return FixedPoint(0, SCALE);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::abs() const {
                auto a_abs = value;
                bool sign_a = helper::abs(a_abs);
                return FixedPoint(a_abs, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::ceil() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);
                uint64_t pre, post;
                bool sign = helper::split_exp(value + (DELTA - 1), scale, pre, post);
                auto value = FixedPoint::value_type(pre * DELTA);
                if (sign) {
                    return FixedPoint(-value, SCALE);
                } else {
                    return FixedPoint(value, SCALE);
                }
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::floor() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);
                uint64_t pre, post;
                bool sign = helper::split_exp(value, scale, pre, post);
                auto value = FixedPoint::value_type(pre * DELTA);
                if (sign) {
                    return FixedPoint(-value, SCALE);
                } else {
                    return FixedPoint(value, SCALE);
                }
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::exp(bool ranged) const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                if (ranged) {
                    if (*this >
                        FixedPoint(FixedPointTables<BlueprintFieldType>::get_highest_valid_exp_input(M1, M2), SCALE)) {
                        return FixedPoint::max();
                    }
                    if (*this < FixedPoint(FixedPointTables<BlueprintFieldType>::get_lowest_exp_input(M2), SCALE)) {
                        return FixedPoint(BlueprintFieldType::value_type::zero(), SCALE);
                    }
                }

                using value_type = typename BlueprintFieldType::value_type;

                std::vector<value_type> exp_a;
                if constexpr (M2 == 1) {
                    exp_a = FixedPointTables<BlueprintFieldType>::get_exp_a_16();
                } else {
                    exp_a = FixedPointTables<BlueprintFieldType>::get_exp_a_32();
                }

                std::vector<value_type> exp_b;
                if constexpr (M2 == 1) {
                    exp_b = FixedPointTables<BlueprintFieldType>::get_exp_b_16();
                } else {
                    exp_b = FixedPointTables<BlueprintFieldType>::get_exp_b_32();
                }

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

                if constexpr (M2 == 2) {
                    uint32_t input_b = post >> 16;
                    uint32_t input_c = post & ((1ULL << 16) - 1);

                    BLUEPRINT_RELEASE_ASSERT(input_a >= 0 && input_a < exp_a.size());
                    BLUEPRINT_RELEASE_ASSERT(input_b >= 0 && input_b < exp_b.size());
                    BLUEPRINT_RELEASE_ASSERT(input_c >= 0 && input_c < exp_b.size());
                    res = exp_a[input_a] * exp_b[input_b];
                } else {
                    BLUEPRINT_RELEASE_ASSERT(input_a >= 0 && input_a < exp_a.size());
                    BLUEPRINT_RELEASE_ASSERT(post >= 0 && post < exp_b.size());
                    res = exp_a[input_a] * exp_b[post];
                }

                auto fix = FixedPoint(res, FixedPointTables<BlueprintFieldType>::template get_exp_scale<M2>());
                return fix.rescale();
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            void FixedPoint<BlueprintFieldType, M1, M2>::trigonometric_helper(value_type &sin0,
                                                                              value_type &sin1,
                                                                              value_type &sin2,
                                                                              value_type &cos0,
                                                                              value_type &cos1,
                                                                              value_type &cos2,
                                                                              value_type &sign_val) const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                using value_type = typename BlueprintFieldType::value_type;

                auto zero = value_type::zero();
                auto one = value_type::one();
                auto delta = value_type(DELTA);

                std::vector<value_type> sin_a;
                if constexpr (M2 == 1) {
                    sin_a = FixedPointTables<BlueprintFieldType>::get_sin_a_16();
                } else {
                    sin_a = FixedPointTables<BlueprintFieldType>::get_sin_a_32();
                }

                std::vector<value_type> sin_b;
                if constexpr (M2 == 1) {
                    sin_b = FixedPointTables<BlueprintFieldType>::get_sin_b_16();
                } else {
                    sin_b = FixedPointTables<BlueprintFieldType>::get_sin_b_32();
                }

                std::vector<value_type> sin_c;
                if constexpr (M2 == 2) {
                    sin_c = FixedPointTables<BlueprintFieldType>::get_sin_c_32();
                }

                std::vector<value_type> cos_a;
                if constexpr (M2 == 1) {
                    cos_a = FixedPointTables<BlueprintFieldType>::get_cos_a_16();
                } else {
                    cos_a = FixedPointTables<BlueprintFieldType>::get_cos_a_32();
                }

                std::vector<value_type> cos_b;
                if constexpr (M2 == 1) {
                    cos_b = FixedPointTables<BlueprintFieldType>::get_cos_b_16();
                } else {
                    cos_b = FixedPointTables<BlueprintFieldType>::get_cos_b_32();
                }

                constexpr auto two_pi = value_type(26986075409ULL);

                std::vector<uint16_t> x0_val;
                auto reduced_val = value;    // x_reduced guarantees the use of only one pre-comma limb
                if constexpr (M1 == 2) {     // if two pre-comma limbs are used, x is reduced mod 2*pi
                    if constexpr (M2 == 2) {
                        reduced_val = FixedPointHelper<BlueprintFieldType>::div_mod(value, two_pi).remainder;
                    } else {    // case fixedpoint 32.16: use 32 post comma bits (2 limbs) for better precision
                        reduced_val = FixedPointHelper<BlueprintFieldType>::div_mod(value * delta, two_pi).remainder;
                    }
                }
                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(reduced_val, x0_val);
                if constexpr (M1 == 2) {
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                }
                // case fixedpoint 32.16: trash the smallest limb, as the result has one post comma limb only
                if constexpr (M1 == 2 && M2 == 1) {
                    x0_val.erase(x0_val.begin());
                }
                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= M2 + 1);
                sign_val = sign ? -one : one;

                sin0 = sin_a[x0_val[M2 - 0]];
                sin1 = sin_b[x0_val[M2 - 1]];
                sin2 = zero;
                if constexpr (M2 == 2) {
                    sin2 = sin_c[x0_val[M2 - 2]];
                }
                cos0 = cos_a[x0_val[M2 - 0]];
                cos1 = cos_b[x0_val[M2 - 1]];
                cos2 = delta;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::sin() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                using value_type = typename BlueprintFieldType::value_type;
                auto delta = value_type(DELTA);

                value_type sin0, sin1, sin2, cos0, cos1, cos2, sign_val;
                trigonometric_helper(sin0, sin1, sin2, cos0, cos1, cos2, sign_val);

                value_type actual_delta = delta;
                if constexpr (M2 == 2) {
                    actual_delta *= delta;
                }

                value_type computation;
                if constexpr (M2 == 1) {
                    computation = SIN_COMPUTATION_1(sin0, sin1, cos0, cos1, sign_val);
                } else {
                    computation = SIN_COMPUTATION_2(sin0, sin1, sin2, cos0, cos1, cos2, sign_val);
                }
                auto divmod = FixedPointHelper<BlueprintFieldType>::round_div_mod(computation, actual_delta);
                return FixedPoint(divmod.quotient, SCALE);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::cos() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                using value_type = typename BlueprintFieldType::value_type;
                auto delta = value_type(DELTA);

                value_type sin0, sin1, sin2, cos0, cos1, cos2, sign_val;
                trigonometric_helper(sin0, sin1, sin2, cos0, cos1, cos2, sign_val);

                value_type actual_delta = delta;
                if constexpr (M2 == 2) {
                    actual_delta *= delta;
                }

                value_type computation;
                if constexpr (M2 == 1) {
                    computation = COS_COMPUTATION_1(sin0, sin1, cos0, cos1);
                } else {
                    computation = COS_COMPUTATION_2(sin0, sin1, sin2, cos0, cos1, cos2);
                }
                auto divmod = FixedPointHelper<BlueprintFieldType>::round_div_mod(computation, actual_delta);
                return FixedPoint(divmod.quotient, SCALE);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::tan() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                using value_type = typename BlueprintFieldType::value_type;
                auto delta = value_type(DELTA);

                value_type sin0, sin1, sin2, cos0, cos1, cos2, sign_val;
                trigonometric_helper(sin0, sin1, sin2, cos0, cos1, cos2, sign_val);

                value_type computation_sin, computation_cos;
                if constexpr (M2 == 1) {
                    computation_sin = SIN_COMPUTATION_1(sin0, sin1, cos0, cos1, sign_val);
                    computation_cos = COS_COMPUTATION_1(sin0, sin1, cos0, cos1);
                } else {
                    computation_sin = SIN_COMPUTATION_2(sin0, sin1, sin2, cos0, cos1, cos2, sign_val);
                    computation_cos = COS_COMPUTATION_2(sin0, sin1, sin2, cos0, cos1, cos2);
                }

                value_type tan_input_sin = computation_sin;
                value_type tan_input_cos = computation_cos;

                if constexpr (M2 == 1) {
                    tan_input_sin = computation_sin * delta;
                } else { /* M2 == 2 */
                    auto divmod_cos = FixedPointHelper<BlueprintFieldType>::round_div_mod(computation_cos, delta);
                    tan_input_cos = divmod_cos.quotient;
                }

                auto divmod_tan = FixedPointHelper<BlueprintFieldType>::round_div_mod(tan_input_sin, tan_input_cos);
                return FixedPoint(divmod_tan.quotient, SCALE);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::erf() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                using value_type = typename BlueprintFieldType::value_type;
                using target_fixed_point = FixedPoint<BlueprintFieldType, M1, M2>;
                using fixed_point = FixedPoint<BlueprintFieldType, 2, 2>;
                static const constexpr uint16_t target_scale = 16 * M2;
                static const constexpr uint16_t scale = 16 * 2;
                static const constexpr auto target_delta = value_type(1ULL << target_scale);
                static const constexpr auto delta = value_type(1ULL << scale);
                static const constexpr auto zero = value_type::zero();
                static const constexpr auto one = value_type::one();

                static const constexpr value_type a[] = {value_type(302894315ULL), value_type(181599860ULL),
                                                         value_type(39816611ULL),  value_type(652896ULL),
                                                         value_type(1187847ULL),   value_type(184958ULL)};
                static const constexpr value_type h = value_type(15569256448ULL);    // == 3.625

                value_type x_abs = value;
                bool sign = FixedPointHelper<BlueprintFieldType>::abs(x_abs);
                value_type s_x = sign ? -one : one;

                if constexpr (1 == M2) {
                    x_abs *= target_delta;    // target_delta is 2^16, x currently uses 2^16, internally we need 2^32
                }

                // return -1 or 1 if x is outside [-h ,h]
                value_type d = h - x_abs;
                if (FixedPointHelper<BlueprintFieldType>::abs(d)) {
                    return target_fixed_point(s_x);
                }

                value_type xp2 = fixed_point(x_abs * x_abs, 2 * scale).rescale().get_value();
                value_type xp3 = fixed_point(xp2 * x_abs, 2 * scale).rescale().get_value();
                value_type g = fixed_point(delta * delta * delta +       // 1 +
                                               a[0] * x_abs * delta +    // a1 * x +
                                               a[1] * xp2 * delta +      // a2 * x^2 +
                                               a[2] * xp3 * delta +      // a3 * x^3 +
                                               a[3] * xp2 * xp2 +        // a4 * x^4 +
                                               a[4] * xp3 * xp2 +        // a5 * x^5 +
                                               a[5] * xp3 * xp3          // a6 * x^6
                                           ,
                                           2 * scale)
                                   .rescale()
                                   .get_value();                        // rescale asserts that scale is 2 * scale ..
                g = fixed_point(g, 2 * scale).rescale().get_value();    // .. so we need to rescale a second time
                value_type gp2 = fixed_point(g * g, 2 * scale).rescale().get_value();
                value_type gp4 = fixed_point(gp2 * gp2, 2 * scale).rescale().get_value();
                value_type gp8 = fixed_point(gp4 * gp4, 2 * scale).rescale().get_value();
                value_type gp16 = fixed_point(gp8 * gp8, 2 * scale).rescale().get_value();
                value_type gp16_inv =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(delta * target_delta, gp16).quotient;
                return target_fixed_point(s_x * (target_delta - gp16_inv), target_scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::sqrt(bool floor) const {
                auto val = this->value;
                if (scale == SCALE) {
                    val *= DELTA;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(scale == 2 * SCALE);
                }

                auto field_val = helper::sqrt(val, floor);
                return FixedPoint(field_val, SCALE);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::log() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);
                BLUEPRINT_RELEASE_ASSERT(value > 0 && value <= helper::P_HALF);

                modular_backend val = helper::field_to_backend(value);
                typename BlueprintFieldType::integral_type val_int(val);
                big_float val_float(val_int);
                val_float /= DELTA;
                big_float out;
                nil::crypto3::multiprecision::default_ops::eval_log(out.backend(), val_float.backend());
                out *= DELTA;

                auto int_val = out.convert_to<nil::crypto3::multiprecision::cpp_int>();

                if constexpr (M2 == 2) {
                    // The smallest 16 bit limb does not influence the exp output in this case
                    int_val.backend().limbs()[0] &= 0xFFFFFFFFFFFF0000;
                }

                auto field_val = value_type(int_val);
                auto fix = FixedPoint(field_val, SCALE);

                // Rounding correctly to lowest value that produces the correct exp result
                auto offset = 1ULL;
                if constexpr (M2 == 2) {
                    offset = 1ULL << 16;
                }
                auto exp = fix.exp();
                while (exp.get_value() < value) {
                    fix.value += offset;
                    exp = fix.exp();
                }

                auto exp2 = (fix - FixedPoint(1, SCALE)).exp();
                while (exp2.get_value() >= value) {
                    fix.value -= 1;
                    exp2 = (fix - FixedPoint(1, SCALE)).exp();
                }

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
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::rescale() const {
                BLUEPRINT_RELEASE_ASSERT(scale == 2 * SCALE);
                auto divmod = helper::round_div_mod(value, DELTA);
                return FixedPoint(divmod.quotient, SCALE);
            }

            template<typename BlueprintFieldType>
            typename BlueprintFieldType::value_type FixedPointHelper<BlueprintFieldType>::tanh_upper_range(uint8_t m1,
                                                                                                           uint8_t m2) {
                BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);
                // Chosen to be in [-8, 8] and such that the exp(2x) + 1 operation in tanh does not overflow
                if (m1 == 1 && m2 == 1) {
                    return 363408;
                } else if (m1 == 1 && m2 == 2) {
                    return 23816339455;
                } else {
                    return 8ULL << (16 * m2);
                }
            }

            template<typename BlueprintFieldType>
            typename BlueprintFieldType::value_type FixedPointHelper<BlueprintFieldType>::tanh_lower_range(uint8_t m2) {
                // Chosen to be in [-8, 8] and such that the exp(2x) + 1 operation in tanh does not overflow
                BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);
                return -(value_type(8ULL << (16 * m2)));
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::tanh() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                auto one = FixedPoint((int64_t)1);
                // First, we set the output if the range is outside [-min, max]
                if (*this > FixedPoint(helper::tanh_upper_range(M1, M2), SCALE)) {
                    return one;
                }
                if (*this < FixedPoint(helper::tanh_lower_range(M2), SCALE)) {
                    return -one;
                }

                // Then, we compute tanh by computing tanh(x) = (exp(2x) +1) / (exp(2x) - 1)
                auto exp = FixedPoint(2 * this->value, SCALE).exp();
                auto exp_p = exp + one;
                auto exp_m = exp - one;

                return exp_m / exp_p;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2> FixedPoint<BlueprintFieldType, M1, M2>::atan() const {
                BLUEPRINT_RELEASE_ASSERT(scale == SCALE);

                auto tmp = value;
                auto sign = helper::abs(tmp);
                modular_backend val = helper::field_to_backend(tmp);
                typename BlueprintFieldType::integral_type val_int(val);
                big_float val_float(val_int);
                val_float /= DELTA;
                big_float out;
                nil::crypto3::multiprecision::default_ops::eval_atan(out.backend(), val_float.backend());
                out *= DELTA;

                auto int_val = out.convert_to<nil::crypto3::multiprecision::cpp_int>();

                auto field_val = value_type(int_val);
                auto fix = FixedPoint(field_val, SCALE);

                if (sign) {
                    fix = -fix;
                }

                return fix;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

namespace std {
    template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
    class numeric_limits<nil::blueprint::components::FixedPoint<BlueprintFieldType, M1, M2>> {

        using FixedType = typename nil::blueprint::components::FixedPoint<BlueprintFieldType, M1, M2>;

    public:
        static constexpr FixedType max() {
            return FixedType::max();
        };
        static constexpr FixedType min() {
            return -max();
        };
    };
}    // namespace std

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
