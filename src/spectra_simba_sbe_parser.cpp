#include <bitset>
#include <ios>
#include <iostream>
#include <memory>

#include "include/spectra_simba_sbe_parser.h"
#include "include/spectra_simba_types.h"
#include "include/spectra_simba_utility.h"

namespace packet_parse::spectra_simba::sbe {

ServiceDataPtr MessageParser::Parse(Stream& packet,
                                    std::streamsize& packet_size,
                                    ServiceDataPtr data) const {
  HeaderParser hp;
  data = HandleParser(hp, packet, packet_size, std::move(data));

  // An Incremental packet of Simba Spectra could contain
  // many SBE messages. If we will do parsing as usual and some
  // message type is unsupported, the Parse() function will throw
  // UnknownProto exception, as expected, and all remaining data
  // of a packet will be hexdumped.
  // But we only want to dump data from the current SBE message
  // and continue parsing the following ones. So we're exctracting
  // the size of the following root block right here and pass it
  // to HandleParser()
  auto root_block_metadata = static_cast<RootBlockMetadata*>(data.get());

  RootBlockParser rbp;

  switch (root_block_metadata->format) {
    case PacketFormat::kIncremental: {
      auto root_block_size =
          static_cast<std::streamsize>(root_block_metadata->root_block_size);

      packet_size -= root_block_size;

      return HandleParser(rbp, packet, root_block_size, std::move(data));
    }
    case PacketFormat::kSnapshot:
      return HandleParser(rbp, packet, packet_size, std::move(data));
  }

  return data;
}

ServiceDataPtr HeaderParser::Parse(Stream& packet, std::streamsize& packet_size,
                                   ServiceDataPtr data) const {
  Header p;
  return p.Parse(packet, packet_size, std::move(data));
}

ServiceDataPtr Header::Operation(const HeaderFormat& header,
                                 ServiceDataPtr data) {
  auto format_indicator = static_cast<FormatIndicator*>(data.get());

  std::cout << "SBE Message Header:\n";
  std::cout << "  The root part length of the message in bytes: "
            << header.block_length << '\n';
  std::cout << "  Message template identifier: " << header.template_id << '\n';
  std::cout << "  Message schema identifier: " << header.schema_id << '\n';
  std::cout << "  Message schema version: " << header.version << '\n';

  return std::make_unique<RootBlockMetadata>(header.schema_id, header.version,
                                             header.block_length,
                                             format_indicator->format);
}

ServiceDataPtr RootBlockParser::Parse(Stream& packet,
                                      std::streamsize& packet_size,
                                      ServiceDataPtr data) const {
  auto message_type = static_cast<MessageType>(data->proto);
  auto metadata = static_cast<RootBlockMetadata*>(data.get());

  if (!metadata->schema_supported)
    throw UnsupportedSchema(metadata->schema_id, metadata->schema_version);

  switch (message_type) {
    case MessageType::kOrderUpdate: {
      OrderUpdate p;
      return p.Parse(packet, packet_size, std::move(data));
    }
    case MessageType::kOrderExecution: {
      OrderExecution p;
      return p.Parse(packet, packet_size, std::move(data));
    }
    case MessageType::kOrderBookSnapshot: {
      OrderBookSnapshotFirstPart fp;
      data = fp.Parse(packet, packet_size, std::move(data));

      RepeatingGroupDimensions rgd;
      data = rgd.Parse(packet, packet_size, std::move(data));

      // At this point we're already know that the data remaining will
      // be just one or more OrderBookSnapshotGroupPart headers.
      //
      // Note that we don't use HandleParser function like we did in
      // DataParser::Parse, cause if something went wrong (exception occured),
      // we want to pass it to the upper level.
      OrderBookSnapshotGroupPart gp;
      while (packet_size != 0)
        data = gp.Parse(packet, packet_size, std::move(data));

      return data;
    }
    default: {
      std::cout << MessageTypeToString(message_type) << " is unsupported\n";
      throw UnknownProto(data->proto);
    }
  }
}

ServiceDataPtr OrderUpdate::Operation(const OrderUpdateFormat& header,
                                      ServiceDataPtr data) {
  std::cout << "OrderUpdate header:\n";
  std::cout << "  Order ID: " << header.md_entry_id << '\n';
  std::cout << "  Order price: " << header.md_entry_px << '\n';
  std::cout << "  Order Volume: " << header.md_entry_size << '\n';
  std::cout << "  Order Type: \n";

  auto md_flags_bitset = std::bitset<64>(header.md_flags);
  PrintFlags(md_flags_bitset, types::AllMDFlagsValues);

  std::cout << "  Instrument numeric code: " << header.security_id << '\n';
  std::cout << "  Incremental refresh sequence number: " << header.rpt_seq
            << '\n';

  std::cout << "  Incremental refresh type:\n";
  PrintEnum(header.md_update_action, types::AllMDUpdateActionValues);

  std::cout << "  Record type:\n";
  PrintEnum(header.md_entry_type, types::AllMDEntryTypeValues);

  return data;
}

ServiceDataPtr OrderExecution::Operation(const OrderExecutionFormat& header,
                                         ServiceDataPtr data) {
  std::cout << "OrderExecution header:\n";
  std::cout << "  Order ID: " << header.md_entry_id << '\n';
  std::cout << "  Order price: " << header.md_entry_px << '\n';
  std::cout << "  Remaining quantity in the order: " << header.md_entry_size
            << '\n';
  std::cout << "  Trade price: " << header.last_px << '\n';
  std::cout << "  Trade volume: " << header.last_qty << '\n';
  std::cout << "  Trade ID: " << header.trade_id << '\n';
  std::cout << "  Trade Type: \n";

  auto md_flags_bitset = std::bitset<64>(header.md_flags);
  PrintFlags(md_flags_bitset, types::AllMDFlagsValues);

  std::cout << "  Instrument numeric code: " << header.security_id << '\n';
  std::cout << "  Incremental refresh sequence number: " << header.rpt_seq
            << '\n';

  std::cout << "  Incremental refresh type:\n";
  PrintEnum(header.md_update_action, types::AllMDUpdateActionValues);

  std::cout << "  Record type:\n";
  PrintEnum(header.md_entry_type, types::AllMDEntryTypeValues);

  return data;
}

ServiceDataPtr OrderBookSnapshotFirstPart::Operation(
    const OrderBookSnapshotFormatFirstPart& header, ServiceDataPtr data) {
  std::cout << "OrderBookSnapshot header:\n";
  std::cout << "  Instrument numeric code: " << header.security_id << '\n';
  std::cout << "  The 'MsgSeqNum' of the last message sent into incremental "
               "feed at the time of the current snapshot generation: "
            << header.last_msg_seq_num_processed << '\n';
  std::cout << "  The 'RptSeq' number of the last incremental update included "
               "in the current market data snapshot for instrument: "
            << header.rpt_seq << '\n';
  std::cout << "  Trading sesstion ID: " << header.exchange_trading_session_id
            << '\n';
  return data;
}

ServiceDataPtr RepeatingGroupDimensions::Operation(
    const RepeatingGroupDimensionsFormat& header, ServiceDataPtr data) {
  std::cout << "RepeatingGroupDimensions header:\n";
  std::cout << "  Length of 'MDEntry' records in the current message: "
            << header.block_length << '\n';
  std::cout << "  Number of 'MDEntry' records in the current message: "
            << static_cast<int>(header.num_in_group) << '\n';
  return data;
}

ServiceDataPtr OrderBookSnapshotGroupPart::Operation(
    const OrderBookSnapshotFormatGroupPart& header, ServiceDataPtr data) {
  std::cout << "OrderBookSnapshotGroup header:\n";
  std::cout << "  Order ID: " << header.md_entry_id << '\n';
  std::cout << "  The start time of the event processing: ";
  PrintTimeStamp(header.transact_time);
  std::cout << "  Order price: " << header.md_entry_px << '\n';
  std::cout << "  Order Volume: " << header.md_entry_size << '\n';
  std::cout << "  Trade ID: " << header.trade_id << '\n';
  std::cout << "  Order or trade type:\n";

  auto md_flags_bitset = std::bitset<64>(header.md_flags);
  PrintFlags(md_flags_bitset, types::AllMDFlagsValues);

  std::cout << "  Record type:\n";
  PrintEnum(header.md_entry_type, types::AllMDEntryTypeValues);
  return data;
}

std::string RootBlockParser::MessageTypeToString(MessageType t) {
  switch (t) {
    case MessageType::kLogon:
      return "Logon";
    case MessageType::kLogout:
      return "Logout";
    case MessageType::kHeartbeat:
      return "Heartbeat";
    case MessageType::kSequenceReset:
      return "SequenceReset";
    case MessageType::kBestPrices:
      return "BestPrices";
    case MessageType::kEmptyBook:
      return "EmptyBook";
    case MessageType::kOrderUpdate:
      return "OrderUpdate";
    case MessageType::kOrderExecution:
      return "OrderExecution";
    case MessageType::kOrderBookSnapshot:
      return "OrderBookSnapshot";
    case MessageType::kSecurityDefinition:
      return "SecurityDefinition";
    case MessageType::kSecurityStatus:
      return "SecurityStatus";
    case MessageType::kSecurityDefinitionUpdateReport:
      return "SecurityDefinitionUpdateReport";
    case MessageType::kTradingSessionStatus:
      return "TradingSessionStatus";
    case MessageType::kMarketDataRequest:
      return "MarketDataRequest";
    case MessageType::kDiscreteAuction:
      return "DiscreteAuction";
    default:
      return "Unknown message type";
  }
}

}  // namespace packet_parse::spectra_simba::sbe
