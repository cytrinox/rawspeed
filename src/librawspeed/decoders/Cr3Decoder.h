/*
    RawSpeed - RAW file decoder.

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

#include "common/RawImage.h"     // for RawImage
#include "decoders/RawDecoder.h" // for RawDecoder
#include "tiff/IsoMBox.h"        // for IsoMRootBox
#include <memory>                // for unique_ptr
#include <utility>               // for move

namespace rawspeed {

class CameraMetaData;

class Buffer;

class Cr3Decoder final : public RawDecoder {
  std::unique_ptr<const IsoMRootBox> rootBox;

public:
  static bool isAppropriateDecoder(const IsoMRootBox& box);

  Cr3Decoder(std::unique_ptr<const IsoMRootBox> rootBox_, const Buffer* file)
      : RawDecoder(file), rootBox(std::move(rootBox_)) {}

  RawImage decodeRawInternal() override;
  void checkSupportInternal(const CameraMetaData* meta) override;
  void decodeMetaDataInternal(const CameraMetaData* meta) override;

protected:
  int getDecoderVersion() const override { return 0; }
};

} // namespace rawspeed
