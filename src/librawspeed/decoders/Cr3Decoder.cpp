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

#include "decoders/Cr3Decoder.h"
#include "decompressors/LJpegDecompressor.h"

namespace rawspeed {

bool Cr3Decoder::isAppropriateDecoder(const IsoMRootBox& box) {
  return box.ftyp->majorBrand == FourCharStr({'c', 'r', 'x', ' '});
}

RawImage Cr3Decoder::decodeRawInternal() {
  ByteStream biggestImage;

  for (const auto& track : rootBox->moov->tracks) {
    for (const auto& chunk : track.mdia->minf->stbl->chunks) {
      if (chunk->getSize() > biggestImage.getSize())
        biggestImage = *chunk;
    }
  }

  // Hardcoded for Canon M50.
  mRaw->dim = {6288, 4056};

  LJpegDecompressor d(biggestImage, mRaw);
  mRaw->createData();
  d.decode(0, 0, mRaw->dim.x, mRaw->dim.y, false);

  return mRaw;
}

void Cr3Decoder::checkSupportInternal(const CameraMetaData* meta) {}

void Cr3Decoder::decodeMetaDataInternal(const CameraMetaData* meta) {}

} // namespace rawspeed
