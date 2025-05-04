#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#define PNG_MNG_FEATURES_SUPPORTED  // Ensure intrapixel path is enabled
#include "png.h"

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        nullptr); \
    else \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  if (size > 8000000)
    return nullptr;
  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
}

static const int kPngHeaderSize = 8;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) return 0;

  if (png_sig_cmp(data, 0, kPngHeaderSize)) return 0;

  PngObjectHandler png_handler;
  png_handler.png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) return 0;

  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) { PNG_CLEANUP return 0; }

  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) { PNG_CLEANUP return 0; }

  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);
  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;

  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP return 0;
  }

  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP return 0;
  }

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type, filter_type;

  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                    &height, &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    PNG_CLEANUP return 0;
  }

  if (width && height > 100000000 / width) {
    PNG_CLEANUP return 0;
  }

  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);

  int passes = png_set_interlace_handling(png_handler.png_ptr);

  // 🚨 Key logic: set intrapixel flags
  png_handler.png_ptr->mng_features_permitted |= PNG_FLAG_MNG_FILTER_64;
  png_handler.png_ptr->filter_type = PNG_INTRAPIXEL_DIFFERENCING;

  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr,
      png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);
  PNG_CLEANUP
  return 0;
}
