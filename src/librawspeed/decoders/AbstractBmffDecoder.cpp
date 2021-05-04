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

#include "decoders/AbstractBmffDecoder.h"
#include "decoders/RawDecoderException.h" // for ThrowRDE
#include "tiff/TiffEntry.h"               // for TiffEntry
#include "tiff/TiffIFD.h"                 // for TiffIFD, TiffRootIFD, Tiff...
#include <cstdint>                        // for uint32_t
#include <vector>                         // for vector

#define BMFF_HDR_SIZE_LEN 4
#define BMFF_HDR_TYPE_LEN 4

namespace rawspeed {

const BmffBoxOwner& AbstractBmffDecoder::getFileBox() const { return mFileBox; }

void AbstractBmffDecoder::parseBmffInternal() {
  auto inbuf = DataBuffer(*mFile, Endianness::big);
  std::vector<BmffBox> boxes = BmffBox::parse(this->mCustomBoxContainers, inbuf);

  this->mFileBox = std::make_unique<BmffBox>(BmffBox({
    size: inbuf.getSize(),
    type: 0,
    offset: 0,
    payload: DataBuffer(inbuf.getSubView(0), inbuf.getByteOrder()),
    childs: boxes,
    uuid: std::array<uint8_t, 16>(),
  }));
}

const BmffBox BmffBox::find_first(uint32_t box_type) const { return find_nth(box_type, 1); }

const BmffBox BmffBox::find_nth(uint32_t box_type, size_t nth) const {
  auto res = childs.begin();
  do {
    res = std::find_if(res, childs.end(),
                       [box_type](auto box) { return box.type == box_type; });
    if (--nth == 0 && res != childs.end()) {
      return *res;
    }
    ++res;
  } while (res != childs.end() && nth > 0);
  ThrowRDE("Couldn't find bmff type"); // TODO: add type
}

const BmffBox BmffBox::find_uuid_first(std::array<uint8_t, 16> uuid) const {
  return find_uuid_nth(uuid, 1);
}

const BmffBox BmffBox::find_uuid_nth(std::array<uint8_t, 16> uuid, size_t nth) const {
  auto res = childs.begin();
  do {
    res = std::find_if(res, childs.end(),
                       [uuid](auto box) { return box.uuid == uuid; });
    if (--nth == 0 && res != childs.end()) {
      return *res;
    }
    ++res;
  } while (res != childs.end() && nth > 0);
  ThrowRDE("Couldn't find bmff uuid"); // TODO: add type
}

inline bool isCustomUuid(const BmffCustomBoxUuidList& customUuids,
                         const BmffBoxUuid& uuid) {
  return std::find(customUuids.begin(), customUuids.end(), uuid) !=
         customUuids.end();
}

std::vector<BmffBox> BmffBox::parse(const BmffCustomBoxUuidList& customUuids,
                                    const DataBuffer& buf,
                                    uint32_t file_offset) {
  std::vector<BmffBox> boxes;
  for (size_t i = 0; i < buf.getSize();) {
    std::array<uint8_t, 16> box_uuid;
    uint64_t box_size = buf.get<uint32_t>(i);
    uint32_t box_hdr_size = BMFF_HDR_SIZE_LEN + BMFF_HDR_TYPE_LEN;
    switch (box_size) {
    case 0: // Box expand to end of buffer
      box_size = buf.getSize();
      break;
    case 1: // Box use `largesize` field after type field
      box_size = buf.get<uint64_t>(i + BMFF_HDR_SIZE_LEN + BMFF_HDR_TYPE_LEN);
      box_hdr_size +=
          sizeof(uint64_t); // add optional largesize field to header size
      break;
    default:
      break;
    }
    uint32_t box_type = buf.get<uint32_t>(i + BMFF_HDR_SIZE_LEN);
    std::string tag(
        reinterpret_cast<const char*>(buf.getData(i + BMFF_HDR_SIZE_LEN, 4)),
        4);
    writeLog(DEBUG_PRIO_EXTRA, "Parsing hit type %s", tag.c_str());
    if ('uuid' == box_type) {
      auto uuid_buf = buf.getSubView(i + box_hdr_size, 16);
      std::copy(uuid_buf.begin(), uuid_buf.end(), box_uuid.begin());
      box_hdr_size += 16; // add optional uuid field size to header size
    }
    DataBuffer box_data(
        buf.getSubView(i + box_hdr_size, box_size - box_hdr_size),
        buf.getByteOrder());
    std::vector<BmffBox> box_childs;
    switch (box_type) {
    case 'moov':
    case 'trak':
    case 'mdia':
    case 'minf':
    case 'dinf':
    case 'stbl':
    case 'stsd':
    case 'CRAW':
      writeLog(DEBUG_PRIO_EXTRA, "Parsing down");
      box_childs = BmffBox::parse(customUuids, box_data, i + box_hdr_size);
      break;
    case 'uuid':
      // if(box_uuid == CANO) {
      if (isCustomUuid(customUuids, box_uuid)) {
        box_childs = BmffBox::parse(customUuids, box_data, i + box_hdr_size);
      }
      break;
    }
    boxes.push_back(BmffBox({
      size : box_size,
      type : box_type,
      offset : file_offset + i,
      payload : box_data,
      childs : box_childs,
      uuid : box_uuid,
    }));
    i += box_size;
  }
  return boxes;
}

} // namespace rawspeed
