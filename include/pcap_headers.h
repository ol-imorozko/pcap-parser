#pragma once
#include <cstdint>

#pragma pack(push, 1)
struct PcapFileHeader {
  uint32_t magic_number;  /* magic number */
  uint16_t version_major; /* major version number */
  uint16_t version_minor; /* minor version number */
  uint32_t reserved1;     /* unused, previously was "GMT to local correction" */
  uint32_t reserved2;     /* unused, previously was "accuracy of timestamps" */
  uint32_t snaplen;       /* max length of captured packets, in octets */
  uint32_t linktype;      /* data link type */
};

struct PcapPacketHeader {
  uint32_t ts_sec;   /* timestamp seconds */
  uint32_t ts_usec;  /* timestamp micro/nanoseconds */
  uint32_t incl_len; /* number of octets of packet saved in file */
  uint32_t orig_len; /* actual length of packet */
};
#pragma pack(pop)

constexpr uint32_t kMagicMicrosecsBe = 0xA1B2C3D4;
constexpr uint32_t kMagicNanosecsBe = 0xA1B23C4D;
constexpr uint32_t kMagicMicrosecsLe = 0xD4C3B2A1;
constexpr uint32_t kMagicnanosecsLe = 0x4D3CB2A1;
