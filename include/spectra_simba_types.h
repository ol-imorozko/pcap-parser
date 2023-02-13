#pragma once
#include <bitset>
#include <cmath>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <unordered_map>

// These are the types from Spectra Simba schema ver. FIX5SP2
namespace packet_parse::spectra_simba::types {

struct Decimal5 {
  int64_t mantissa;
  constexpr static const int8_t exponent = -5;
};

std::ostream& operator<<(std::ostream& os, Decimal5 const& val);

struct ExchangeTradingSessionID {
  uint32_t exchange_trading_session_id;
  constexpr static const uint32_t null_value = 4294967295;
};

std::ostream& operator<<(std::ostream& os, ExchangeTradingSessionID const& val);

enum class MsgFlagsSetValue {
  kLastFragment = 0,
  kStartOfSnapshot = 1,
  kEndOfSnapshot = 2,
  kIncrementalPacket = 3,
  kPossDupFlag = 4,
};

enum class MDFlagsSetValue {
  kDay = 0,
  kIOC = 1,
  kNonQuote = 2,
  kEndOfTransaction = 12,
  kSecondLeg = 14,
  kFOK = 19,
  kReplace = 20,
  kCancel = 21,
  kMassCancel = 22,
  kNegotiated = 26,
  kMultiLeg = 27,
  kCrossTrade = 29,
  kCOD = 32,
  kActiveSide = 41,
  kPassiveSide = 42,
  kSynthetic = 45,
  kRFS = 46,
  kSyntheticPassive = 57,
  kBOC = 60,
  kDuringDiscreteAuction = 62
};

enum class MDUpdateActionValue { kNew = 0, kChange = 1, kDelete = 2 };

enum class MDEntryTypeValue { kBid = 0, kOffer = 1, kEmptyBook = 2 };

extern const std::initializer_list<MDFlagsSetValue> AllMDFlagsValues;
extern const std::initializer_list<MDUpdateActionValue> AllMDUpdateActionValues;
extern const std::initializer_list<MDEntryTypeValue> AllMDEntryTypeValues;

std::string GetDescription(MDFlagsSetValue value);
std::string GetDescription(MDUpdateActionValue value);
std::string GetDescription(MDEntryTypeValue value);

using MsgFlagsSet = uint16_t;
using MDFlagsSet = uint64_t;
using MDUpdateAction = uint8_t;
using MDEntryType = char;

}  // namespace packet_parse::spectra_simba::types
