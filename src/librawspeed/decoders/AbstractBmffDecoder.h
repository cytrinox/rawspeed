/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2017 Axel Waggershauser

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

#include "decoders/RawDecoder.h" // for RawDecoder
#include "tiff/TiffIFD.h"        // for TiffID, TiffRootIFD, TiffRootIFDOwner
#include "tiff/TiffTag.h"        // for IMAGEWIDTH, TiffTag
#include <memory>                // for unique_ptr
#include <string>                // for string
#include <utility>               // for move

namespace rawspeed {

class CameraMetaData;

class Buffer;

struct BmffBox;

using BmffBoxOwner = std::unique_ptr<BmffBox>;

using BmffBoxUuid = std::array<uint8_t, 16>;
using BmffCustomBoxUuidList = std::vector<BmffBoxUuid>;



struct BmffBox {
public:
  uint64_t size; // box size
  uint32_t type; // box type
  uint32_t offset; // offset into file
  DataBuffer payload; // box data without box header
  std::vector<BmffBox> childs;
  std::array<uint8_t, 16> uuid;

  static std::vector<BmffBox> parse(const BmffCustomBoxUuidList &customUuids, const DataBuffer &buf, uint32_t file_offset = 0);

  const BmffBox find_first(uint32_t box_type) const;
  const BmffBox find_nth(uint32_t box_type, size_t nth) const;
  const BmffBox find_uuid_first(std::array<uint8_t, 16> uuid) const;
  const BmffBox find_uuid_nth(std::array<uint8_t, 16> uuid, size_t nth) const;
};



class AbstractBmffDecoder : public RawDecoder
{
private:
  BmffBoxOwner mFileBox;
protected:
  //TiffRootIFDOwner mRootIFD;

  BmffCustomBoxUuidList mCustomBoxContainers;

  void parseBmffInternal();

public:
  AbstractBmffDecoder(const Buffer* file)
      : RawDecoder(file), mFileBox(nullptr), mCustomBoxContainers() {}



  const BmffBoxOwner& getFileBox() const;

  /* TODO USE base clase method instead (missing tiff id)
  inline bool checkCameraSupported(const CameraMetaData* meta, const TiffID& id,
                                   const std::string& mode) {
    return RawDecoder::checkCameraSupported(meta, id.make, id.model, mode);
  }
  */

 // using RawDecoder::setMetaData;

  /*
  inline void setMetaData(const CameraMetaData* meta, const TiffID& id,
                          const std::string& mode, int iso_speed) {
    setMetaData(meta, id.make, id.model, mode, iso_speed);
  }

  inline void setMetaData(const CameraMetaData* meta, const std::string& mode,
                          int iso_speed) {
    setMetaData(meta, mRootIFD->getID(), mode, iso_speed);
  }


  inline void checkSupportInternal(const CameraMetaData* meta) override {
    checkCameraSupported(meta, mRootIFD->getID(), "");
  }
  */
};

} // namespace rawspeed
