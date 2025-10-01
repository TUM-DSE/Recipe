#pragma once

static size_t convertByteArrayToInt(char *b) {
  return (b[0] << 24) + ((b[1] & 0xFF) << 16) + ((b[2] & 0xFF) << 8) +
         (b[3] & 0xFF);
}
static void convertIntToByteArray(char *dst, int sz) {
  auto tmp = dst;
  tmp[0] = (sz >> 24) & 0xFF;
  tmp[1] = (sz >> 16) & 0xFF;
  tmp[2] = (sz >> 8) & 0xFF;
  tmp[3] = sz & 0xFF;
}
