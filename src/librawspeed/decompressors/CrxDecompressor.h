/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2017 Axel Waggershauser
    Copyright (C) 2018 Roman Lebedev

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#pragma once

#include "decoders/CrxDecoder.h"                     // for CrxDecoder
#include "decoders/RawDecoderException.h"            // for ThrowRDE
#include "decompressors/AbstractLJpegDecompressor.h" // for AbstractLJpegDe...
#include <cassert>                                   // for assert
#include <cstdint>                                   // for uint16_t

namespace rawspeed {

class Buffer;
class RawImage;

class CrxDecompressor final : public AbstractDecompressor {
  const Buffer& mFileBuf;
  RawImage mRaw;

public:
  CrxDecompressor(const Buffer& file, const RawImage& img);

  void decode(const crx_data_header_t& data_hdr, Buffer& mdat_raw_image,
              uint64_t mdat_trak3_offset, uint64_t trak3_size
  );

private:
  int crxDecodePlane(void* p, uint32_t planeNumber);
  void crxLoadDecodeLoop(void* img, int nPlanes);
  int crxParseImageHeader(uint8_t* cmp1TagData, int nTrack);
  void crxConvertPlaneLineDf(void* p, int imageRow);
  void crxLoadFinalizeLoopE3(void* p, int planeHeight);
};

} // namespace rawspeed
