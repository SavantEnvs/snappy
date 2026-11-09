// libFuzzer harness for snappy::Uncompress with a framing oracle.
//
// Oracle: if the library accepts a stream, every element of that stream must have been fully
// contained in it, so the literals cannot overrun the input. The walker below follows
// format_description.txt only (tag byte, then literal data or the copy's offset bytes), with 64-bit
// lengths, and never looks at what the library did.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <string>

#include "snappy.h"

static bool WellFramed(const uint8_t* p, size_t n) {
  size_t i = 0;
  // Preamble: little-endian varint of at most 5 bytes.
  for (int k = 0;; k++) {
    if (k == 5 || i >= n) return false;
    if (!(p[i++] & 0x80)) break;
  }
  while (i < n) {
    const uint8_t tag = p[i++];
    uint64_t len;
    size_t extra;
    switch (tag & 3) {
      case 0:
        len = (tag >> 2) + uint64_t{1};
        if (len > 60) {
          extra = len - 60;
          if (n - i < extra) return false;
          len = 0;
          for (size_t b = 0; b < extra; b++) len |= uint64_t{p[i + b]} << (8 * b);
          len += 1;
          i += extra;
        }
        if (len > n - i) return false;
        i += len;
        break;
      case 1: extra = 1; goto copy;
      case 2: extra = 2; goto copy;
      default: extra = 4;
      copy:
        if (n - i < extra) return false;
        i += extra;
    }
  }
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string input(reinterpret_cast<const char*>(data), size);

  // Avoid self-crafted decompression bombs.
  size_t uncompressed_size;
  constexpr size_t kMaxUncompressedSize = 1 << 20;
  if (!snappy::GetUncompressedLength(input.data(), input.size(), &uncompressed_size) ||
      uncompressed_size > kMaxUncompressedSize) {
    return -1;
  }

  std::string uncompressed;
  const bool ok = snappy::Uncompress(input.data(), input.size(), &uncompressed);
  if (ok && !WellFramed(data, size)) abort();
  return 0;
}
