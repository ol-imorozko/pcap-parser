#include <chrono>
#include <iomanip>
#include <iostream>

#include "include/spectra_simba_utility.h"

namespace packet_parse::spectra_simba {

void PrintTimeStamp(uint64_t ns_since_epoch) {
  using namespace std::chrono;
  auto time_point = system_clock::time_point(nanoseconds(ns_since_epoch));
  auto t = system_clock::to_time_t(time_point);
  std::tm tm = *std::localtime(&t);

  std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

  auto fraction = ns_since_epoch % 1000000000;
  std::cout << "." << std::setfill('0') << std::setw(9) << fraction << '\n';
}

}  // namespace packet_parse::spectra_simba
