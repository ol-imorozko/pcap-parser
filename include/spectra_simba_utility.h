#pragma once
#include <bitset>
#include <initializer_list>
#include <iostream>
#include <memory>

#include "include/base_parser.h"
#include "include/spectra_simba_types.h"
namespace packet_parse::spectra_simba {

void PrintTimeStamp(uint64_t ns_since_epoch);

enum class PacketFormat { kIncremental, kSnapshot };

struct FormatIndicator : ServiceData {
  PacketFormat format;

  explicit FormatIndicator(PacketFormat format) : format(format){};
};

template <typename Enum, size_t N>
bool Flag(Enum value, std::bitset<N> bitset) {
  return bitset[static_cast<size_t>(value)];
}

/* template <typename Enum, size_t N> */
/* void PrintFlags(std::bitset<N> bitset, std::initializer_list<Enum> enum_values); */

template <typename Enum, size_t N>
void PrintFlags(std::bitset<N> bitset,
                std::initializer_list<Enum> enum_values) {
  for (auto value : enum_values) {
    if (Flag(value, bitset))
      std::cout << "    " << types::GetDescription(value) << '\n';
  }
}

template <typename Enum, typename T>
void PrintEnum(T val, std::initializer_list<Enum> enum_values) {
  bool match = false;
  for (auto value : enum_values) {
    if (static_cast<T>(value) == val) {
      std::cout << "    " << types::GetDescription(value) << '\n';
      match = true;
    }
  }

  // Provoking default case
  if (!match)
    std::cout << "    " << types::GetDescription(static_cast<Enum>(val)) << " "
              << val << '\n';
}
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

struct RootBlockMetadata : FormatIndicator {
  bool schema_supported;
  uint16_t schema_version;
  uint16_t schema_id;
  size_t root_block_size;

  RootBlockMetadata(uint16_t id, uint16_t version, size_t size,
                    PacketFormat format)
      : FormatIndicator(format),
        schema_version(version),
        schema_id(id),
        root_block_size(size) {
    schema_supported = SchemaSupported(id, version);
  };
};

}  // namespace sbe

}  // namespace packet_parse::spectra_simba
