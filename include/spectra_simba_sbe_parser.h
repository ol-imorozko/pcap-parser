#pragma once
#include "include/base_parser.h"
#include "include/spectra_simba_types.h"

namespace packet_parse::spectra_simba::sbe {

class MessageParser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

class HeaderParser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

#pragma pack(push, 1)
struct HeaderFormat {
  uint16_t block_length;
  uint16_t template_id;
  uint16_t schema_id;
  uint16_t version;
  constexpr static const char name[] = "Spectra-Simba 2.3.5. SBE Header";
};
struct OrderUpdateFormat {
  int64_t md_entry_id;
  types::Decimal5 md_entry_px;
  int64_t md_entry_size;
  types::MDFlagsSet md_flags;
  int32_t security_id;
  uint32_t rpt_seq;
  types::MDUpdateAction md_update_action;
  types::MDEntryType md_entry_type;
  constexpr static const char name[] = "Spectra-Simba 4.1.3. OrderUpdate";
};
struct OrderExecutionFormat {
  int64_t md_entry_id;
  types::Decimal5NULL md_entry_px;
  types::Int64NULL md_entry_size;
  types::Decimal5 last_px;
  int64_t last_qty;
  int64_t trade_id;
  types::MDFlagsSet md_flags;
  int32_t security_id;
  uint32_t rpt_seq;
  types::MDUpdateAction md_update_action;
  types::MDEntryType md_entry_type;
  constexpr static const char name[] = "Spectra-Simba 4.1.4. OrderExecution";
};
struct OrderBookSnapshotFormatFirstPart {
  int32_t security_id;
  uint32_t last_msg_seq_num_processed;
  uint32_t rpt_seq;
  uint32_t exchange_trading_session_id;
  constexpr static const char name[] = "Spectra-Simba 4.1.5. OrderBookSnapshot";
};
struct RepeatingGroupDimensionsFormat {
  uint16_t block_length;
  uint8_t num_in_group;
  constexpr static const char name[] =
      "Spectra-Simba 2.3.6. Repeating group dimensions";
};
struct OrderBookSnapshotFormatGroupPart {
  types::Int64NULL md_entry_id;
  uint64_t transact_time;
  types::Decimal5NULL md_entry_px;
  types::Int64NULL md_entry_size;
  types::Int64NULL trade_id;
  types::MDFlagsSet md_flags;
  types::MDEntryType md_entry_type;
  constexpr static const char name[] =
      "Spectra-Simba 4.1.5. OrderBookSnapshot, Repeating Group Section";
};
#pragma pack(pop)

class Header : public Protocol<HeaderFormat, HeaderFormat::name> {
 private:
  RawProto GetNextProto(const HeaderFormat& header) override {
    return header.template_id;
  };

  ServiceDataPtr Operation(const HeaderFormat& header,
                           ServiceDataPtr data) override;
};

class RootBlockParser : public BaseParser {
 private:
  enum class MessageType {
    kLogon = 1000,
    kLogout = 1001,
    kHeartbeat = 1,
    kSequenceReset = 2,
    kBestPrices = 3,
    kEmptyBook = 4,
    kOrderUpdate = 5,
    kOrderExecution = 6,
    kOrderBookSnapshot = 7,
    kSecurityDefinition = 12,
    kSecurityStatus = 9,
    kSecurityDefinitionUpdateReport = 10,
    kTradingSessionStatus = 11,
    kMarketDataRequest = 1002,
    kDiscreteAuction = 13
  };

  static std::string MessageTypeToString(MessageType t);

 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

class OrderUpdate
    : public Protocol<OrderUpdateFormat, OrderUpdateFormat::name> {
 private:
  ServiceDataPtr Operation(const OrderUpdateFormat& header,
                           ServiceDataPtr data) override;
};

class OrderExecution
    : public Protocol<OrderExecutionFormat, OrderExecutionFormat::name> {
 private:
  ServiceDataPtr Operation(const OrderExecutionFormat& header,
                           ServiceDataPtr data) override;
};

class OrderBookSnapshotFirstPart
    : public Protocol<OrderBookSnapshotFormatFirstPart,
                      OrderBookSnapshotFormatFirstPart::name> {
 private:
  ServiceDataPtr Operation(const OrderBookSnapshotFormatFirstPart& header,
                           ServiceDataPtr data) override;
};

class RepeatingGroupDimensions
    : public Protocol<RepeatingGroupDimensionsFormat,
                      RepeatingGroupDimensionsFormat::name> {
 private:
  ServiceDataPtr Operation(const RepeatingGroupDimensionsFormat& header,
                           ServiceDataPtr data) override;
};

class OrderBookSnapshotGroupPart
    : public Protocol<OrderBookSnapshotFormatGroupPart,
                      OrderBookSnapshotFormatGroupPart::name> {
 private:
  ServiceDataPtr Operation(const OrderBookSnapshotFormatGroupPart& header,
                           ServiceDataPtr data) override;
};

}  // namespace packet_parse::spectra_simba::sbe
