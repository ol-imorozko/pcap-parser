#include "include/spectra_simba_types.h"

namespace packet_parse::spectra_simba::types {

std::ostream& operator<<(std::ostream& os, Decimal5 const& val) {
  return os << static_cast<double>(val.mantissa) * pow(10, Decimal5::exponent);
}

std::ostream& operator<<(std::ostream& os, Decimal5NULL const& val) {
  if (val.mantissa == Decimal5NULL::null_value)
    return os << "Not present";

  return os << static_cast<double>(val.mantissa) *
                   pow(10, Decimal5NULL::exponent);
}

std::ostream& operator<<(std::ostream& os, Int64NULL const& val) {
  if (val.value == Int64NULL::null_value)
    return os << "Not present";

  return os << val.value;
}

std::ostream& operator<<(std::ostream& os,
                         ExchangeTradingSessionID const& val) {
  if (val.exchange_trading_session_id == ExchangeTradingSessionID::null_value)
    return os << "Not present";

  return os << val.exchange_trading_session_id;
}

const std::initializer_list<MDFlagsSetValue> AllMDFlagsValues = {
    MDFlagsSetValue::kDay,         MDFlagsSetValue::kIOC,
    MDFlagsSetValue::kNonQuote,    MDFlagsSetValue::kEndOfTransaction,
    MDFlagsSetValue::kSecondLeg,   MDFlagsSetValue::kFOK,
    MDFlagsSetValue::kReplace,     MDFlagsSetValue::kCancel,
    MDFlagsSetValue::kMassCancel,  MDFlagsSetValue::kNegotiated,
    MDFlagsSetValue::kMultiLeg,    MDFlagsSetValue::kCrossTrade,
    MDFlagsSetValue::kCOD,         MDFlagsSetValue::kActiveSide,
    MDFlagsSetValue::kPassiveSide, MDFlagsSetValue::kSynthetic,
    MDFlagsSetValue::kRFS,         MDFlagsSetValue::kSyntheticPassive,
    MDFlagsSetValue::kBOC,         MDFlagsSetValue::kDuringDiscreteAuction};

std::string GetDescription(MDFlagsSetValue value) {
  switch (value) {
    case MDFlagsSetValue::kDay:
      return "Orders and Trades: Day order";
    case MDFlagsSetValue::kIOC:
      return "Orders and Trades: IOC order";
    case MDFlagsSetValue::kNonQuote:
      return "Orders and Trades: Non quote entry";
    case MDFlagsSetValue::kEndOfTransaction:
      return "Orders and Trades: The end of matching transaction";
    case MDFlagsSetValue::kSecondLeg:
      return "Trades: Second leg of multileg trade";
    case MDFlagsSetValue::kFOK:
      return "Orders: FOK order";
    case MDFlagsSetValue::kReplace:
      return "Orders:The record results from replacing the order";
    case MDFlagsSetValue::kCancel:
      return "Orders:The record results from cancelling the order";
    case MDFlagsSetValue::kMassCancel:
      return "Orders: The record results from mass cancelling";
    case MDFlagsSetValue::kNegotiated:
      return "Trades: Negotiated trade";
    case MDFlagsSetValue::kMultiLeg:
      return "Trades: Multileg trade";
    case MDFlagsSetValue::kCrossTrade:
      return "Orders: Flag of cancelling the left balance of the order because "
             "of a cross-trade";
    case MDFlagsSetValue::kCOD:
      return "Orders: The record results from cancelling an order via 'Cancel "
             "on Disconnect' service";
    case MDFlagsSetValue::kActiveSide:
      return "Trades: Flag of aggressive side";
    case MDFlagsSetValue::kPassiveSide:
      return "Trades: Flag of passive side";
    case MDFlagsSetValue::kSynthetic:
      return "Orders and Trades: Flag of the synthetic order";
    case MDFlagsSetValue::kRFS:
      return "Orders and Trades: RFS is the source of entry";
    case MDFlagsSetValue::kSyntheticPassive:
      return "Orders: Flag of the passive synthetic order";
    case MDFlagsSetValue::kBOC:
      return "Orders: Book or Cancel order";
    case MDFlagsSetValue::kDuringDiscreteAuction:
      return "Orders and Trades: The record formed in the process of discrete "
             "auction";
    default:
      return "Unknown value";
  }
}

const std::initializer_list<MDUpdateActionValue> AllMDUpdateActionValues = {
    MDUpdateActionValue::kNew, MDUpdateActionValue::kChange,
    MDUpdateActionValue::kDelete};

std::string GetDescription(MDUpdateActionValue value) {
  switch (value) {
    case MDUpdateActionValue::kNew:
      return "New";
    case MDUpdateActionValue::kChange:
      return "Change";
    case MDUpdateActionValue::kDelete:
      return "Delete";
    default:
      return "Unknown value";
  }
}

const std::initializer_list<MDEntryTypeValue> AllMDEntryTypeValues = {
    MDEntryTypeValue::kBid, MDEntryTypeValue::kOffer,
    MDEntryTypeValue::kEmptyBook};

std::string GetDescription(MDEntryTypeValue value) {
  switch (value) {
    case MDEntryTypeValue::kBid:
      return "Bid";
    case MDEntryTypeValue::kOffer:
      return "Offer";
    case MDEntryTypeValue::kEmptyBook:
      return "EmptyBook";
    default:
      return "Unknown value";
  }
}

}  // namespace packet_parse::spectra_simba::types
