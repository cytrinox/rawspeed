/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2009-2014 Klaus Post
    Copyright (C) 2014 Pedro Côrte-Real

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

#include "decoders/AbstractBmffDecoder.h"   // for AbstractBmffDecoder
#include "common/RawImage.h"                // for RawImage
#include "decoders/RawDecoder.h" // for RawDecoder
#include "io/Buffer.h"           // for Buffer
#include "tiff/TiffIFD.h"        // for TiffRootIFDOwner
#include <array>                 // for array
#include <cmath>                 // for NAN
#include <cstdint>               // for uint32_t

namespace rawspeed {

class CameraMetaData;


/* LIST OF CAMS

  R5
  R6
  R
  RP
  M50
  1DXmkIII 
  SX70 HS
  G5 Mark II
  G7 Mark III
  250D
  90D
  M6 Mark II
  M200
*/

// contents of tag CMP1 for relevant track in CR3 file
struct crx_data_header_t {
  int32_t version;
  int32_t f_width;
  int32_t f_height;
  int32_t tileWidth;
  int32_t tileHeight;
  int32_t nBits;
  int32_t nPlanes;
  int32_t cfaLayout;
  int32_t encType;
  int32_t imageLevels;
  int32_t hasTileCols;
  int32_t hasTileRows;
  int32_t mdatHdrSize;
  // Not from header, but from datastream
  // uint32_t MediaSize;
  // int64_t MediaOffset;
  // uint32_t MediaType; /* 1 -> /C/RAW, 2-> JPEG */
};


class CrxDecoder final : public AbstractBmffDecoder {
  //TiffRootIFDOwner rootIFD;

  //BmffBox fileBox; // TODO remove me

  uint32_t raw_width = 0;
  uint32_t raw_height = 0;
  crx_data_header_t cmp1DataHdr;
  Buffer imageData;
  uint32_t bpp = 2;
  TiffID camId;
  std::string cr3CompressorVersion;
  //uint32_t packed = 0;
  std::array<float, 4> wb_coeffs = {{NAN, NAN, NAN, NAN}};

public:
static bool isCodecSupported(const std::string &CNCV);

  explicit CrxDecoder(const Buffer* file);
  RawImage decodeRawInternal() override;
  void checkSupportInternal(const CameraMetaData* meta) override;
  void decodeMetaDataInternal(const CameraMetaData* meta) override;
  static int isCrx(const Buffer* input);

protected:
  int getDecoderVersion() const override { return 0; }
  void parseHeader();
  
  static crx_data_header_t decodeCMP1(DataBuffer& CMP1);
  static void validateCMP1(crx_data_header_t& hdr);
};





} // namespace rawspeed
