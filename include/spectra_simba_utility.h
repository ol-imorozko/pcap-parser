#pragma once
#include <memory>
#include "include/base_parser.h"
namespace packet_parse::spectra_simba {

void PrintTimeStamp(uint64_t ns_since_epoch);

enum class PacketFormat { kIncremental, kSnapshot };

struct FormatIndicator : ServiceData {
  PacketFormat format;

  explicit FormatIndicator(PacketFormat format) : format(format){};
};

namespace sbe {
// This parser supports only Spectra-Simba Schema with
// Version: 19780, ID: 1, Semantic Version: FIX5SP2
constexpr uint16_t kSupportedShemaId = 19780;
constexpr uint16_t kSupportedSchemaVersion = 1;

static bool SchemaSupported(uint16_t id, uint16_t version) {
  return (id == kSupportedShemaId && version == kSupportedSchemaVersion);
}

class UnsupportedSchema : public std::exception {
 private:
  std::string msg;

 public:
  explicit UnsupportedSchema(size_t id, size_t version);

  const char* what() const noexcept override { return msg.c_str(); };
};

struct RootBlockMetadata : ServiceData {
  bool schema_supported;
  uint16_t schema_version;
  uint16_t schema_id;
  size_t root_block_size;

  RootBlockMetadata(uint16_t id, uint16_t version, size_t size)
      : schema_version(version), schema_id(id), root_block_size(size) {
    schema_supported = SchemaSupported(id, version);
  };
};

}  // namespace sbe

}  // namespace packet_parse::spectra_simba
