// fuzz_png_intrapixel_fuzzer.cc
// Fuzz harness for png_do_read_intrapixel
// Build with: 
//   clang++ -g -O1 -fsanitize=fuzzer,address -I/path/to/libpng/include \
//     fuzz_png_intrapixel_fuzzer.cc -L/path/to/libpng/lib -lpng -o fuzz_png_intrapixel_fuzzer

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <png.h>

// Ensure intrapixel differencing code is available
#ifndef PNG_SEQUENTIAL_READ_SUPPORTED
#define PNG_SEQUENTIAL_READ_SUPPORTED
#endif
#ifndef PNG_MNG_FEATURES_SUPPORTED
#define PNG_MNG_FEATURES_SUPPORTED
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // We need at least 6 bytes: width (4), bit_depth (1), color_type (1)
    if (size < 6) return 0;

    // Parse width (little-endian), bit depth and color type
    uint32_t width = (uint32_t)data[0] |
                     ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 24);
    uint8_t bit_depth = data[4];
    uint8_t color_type = data[5];

    // Only valid bit depths and color types for intrapixel
    if (!(bit_depth == 8 || bit_depth == 16)) return 0;
    if (!(color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGB_ALPHA)) return 0;

    // Calculate channels and bytes per pixel
    int channels = (color_type == PNG_COLOR_TYPE_RGB) ? 3 : 4;
    int bytes_per_channel = (bit_depth == 8 ? 1 : 2);
    size_t rowbytes = (size_t)width * channels * bytes_per_channel;

    // Prevent overly large allocations
    if (width == 0 || width > 1000000 || rowbytes > size) return 0;

    // Ensure there is enough data in fuzz input for row buffer
    if (size - 6 < rowbytes) return 0;

    // Prepare png_row_info struct
    png_row_info row_info;
    std::memset(&row_info, 0, sizeof(row_info));
    row_info.width       = width;
    row_info.bit_depth   = bit_depth;
    row_info.color_type  = color_type;
    row_info.channels    = (png_byte)channels;
    row_info.pixel_depth = (png_byte)(bit_depth * channels);
    row_info.rowbytes    = rowbytes;

    // Might need to call png_permit_mng_features()
    // Allocate and populate row buffer
    png_bytep row = (png_bytep)malloc(rowbytes);
    if (!row) return 0;
    std::memcpy(row, data + 6, rowbytes);

    // Invoke intrapixel differencing
    png_do_read_intrapixel(&row_info, row);

    free(row);
    return 0;
}
