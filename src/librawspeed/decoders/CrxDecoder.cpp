/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2009-2014 Klaus Post
    Copyright (C) 2014-2015 Pedro Côrte-Real
    Copyright (C) 2017 Roman Lebedev

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

#include "decoders/CrxDecoder.h"
#include "common/Point.h"                 // for iPoint2D
#include "decoders/RawDecoderException.h" // for ThrowRDE
#include "decoders/SimpleTiffDecoder.h"
#include "decompressors/CrxDecompressor.h"          // for UncompressedDeco...
#include "decompressors/UncompressedDecompressor.h" // for UncompressedDeco...
#include "io/Buffer.h"                              // for DataBuffer, Buffer
#include "io/ByteStream.h"                          // for ByteStream
#include "io/Endianness.h"                          // for Endianness, Endi...
#include "metadata/Camera.h"                        // for Hints
#include "parsers/TiffParser.h"                     // for TiffParser
#include "tiff/TiffIFD.h"                           // for TiffRootIFDOwner
#include <cassert>                                  // for assert
#include <cstring>                                  // for memcmp
#include <map>
#include <memory> // for unique_ptr

#include "io/FileWriter.h" // for ByteStream // FIXME remove me

#include <fstream>
#include <iostream>

constexpr std::array<uint8_t, 16> CANO_UUID =
    std::array<uint8_t, 16>({0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0,
                             0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48});

#define uchar uint8_t

#define BMFF_T(x) BmffBox::t(x)

namespace rawspeed {

class CameraMetaData;

std::map<int16_t, Buffer> split_ctmd_records(DataBuffer ctmd) {
  std::map<int16_t, Buffer> recs;

  for (uint32_t i = 0; i < ctmd.getSize();) {
    uint32_t rec_len = ctmd.get<uint32_t>(i);
    int16_t rec_typ = ctmd.get<int16_t>(i + 4); // skip len
    Buffer rec_payload = ctmd.getSubView(i + 12, rec_len - 12);
    recs[rec_typ] = rec_payload;
    printf("CTMD rec type: %d extracted\n", rec_typ);
    i += rec_len;
  }

  return recs;
}

CrxDecoder::CrxDecoder(const Buffer* file) : AbstractBmffDecoder(file) {
  mCustomBoxContainers.push_back(CANO_UUID); // TODO docu
  parseHeader();
}

int CrxDecoder::isCrx(const Buffer* input) {
  static const std::array<char, 8> magic = {
      {'f', 't', 'y', 'p', 'c', 'r', 'x', ' '}};
  const unsigned char* data = input->getData(4, magic.size());
  return 0 == memcmp(data, magic.data(), magic.size());
}

bool CrxDecoder::isCodecSupported(const std::string& CNCV) {
  if (CNCV == "CanonHEIF001/10.00.00/00.00.00") {
    writeLog(DEBUG_PRIO_WARNING, "HEIF CNCV: '%s' is not supported",
             CNCV.c_str());
  }
  if (CNCV == "CanonCR3_001/01.09.00/01.00.00") {
    writeLog(DEBUG_PRIO_WARNING, "Raw-burst roll CNCV: '%s' is not supported",
             CNCV.c_str());
  }
  if (CNCV == "CanonCRM0001/02.09.00/00.00.00") {
    writeLog(DEBUG_PRIO_WARNING, "CRM movies CNCV: '%s' is not supported",
             CNCV.c_str());
  }

  return CNCV == "CanonCR3_001/00.10.00/00.00.00" // EOS R5, R6 and 1DX Mark III
                                                  // (raw)
         ||
         CNCV == "CanonCR3_002/00.10.00/00.00.00" // CR3 of 1DX Mark III (craw)
         ||
         CNCV == "CanonCR3_001/00.09.00/00.00.00"; // EOS R, EOS RP, M50, 250D,
                                                   // 90D, M6 Mark II, M200
}

void CrxDecoder::parseHeader() {
  if (!isCrx(mFile))
    ThrowRDE("This isn't actually a Crx file, why are you calling me?");

  parseBmffInternal();

  if (!getFileBox())
    ThrowRDE("Filebox is not initialized, something is wrong!");

  writeLog(DEBUG_PRIO_EXTRA, "Parsing HEADER");

  auto cncv = getFileBox()
                  ->find_first(BMFF_T("moov"))
                  .find_uuid_first(CANO_UUID)
                  .find_first(BMFF_T("CNCV"));
  std::string compr_ver(cncv.payload.begin(), cncv.payload.end());

  cr3CompressorVersion = compr_ver;

  writeLog(DEBUG_PRIO_EXTRA, "CNCV compressor version: %s",
           cr3CompressorVersion.c_str());

  NORangesSet<Buffer> rs;
  auto cmt1 = getFileBox()
                  ->find_first(BMFF_T("moov"))
                  .find_uuid_first(CANO_UUID)
                  .find_first(BMFF_T("CMT1"));

  // TODO: detect endianess from file
  DataBuffer cmt1_buf = DataBuffer(
      cmt1.payload.getSubView(0, cmt1.payload.getSize()), Endianness::little);

  TiffRootIFD IFD0_cmt1(nullptr, &rs, cmt1_buf, 8); // TODO: skip TIFF header

  this->camId = IFD0_cmt1.getID();
  printf("EXIF-MAKE: %s\n", this->camId.make.c_str());
  printf("EXIF-MODEL: %s\n", this->camId.model.c_str());

  auto trak3_stbl = getFileBox()
                        ->find_first(BMFF_T("moov"))
                        .find_nth(BMFF_T("trak"), 3)
                        .find_first(BMFF_T("mdia"))
                        .find_first(BMFF_T("minf"))
                        .find_first(BMFF_T("stbl"));

  auto trak3_stsd = trak3_stbl.find_first(BMFF_T("stsd"));

  auto trak3_craw =
      DataBuffer(trak3_stsd.payload.getSubView(8),
                 trak3_stsd.payload.getByteOrder()); // skip version and flags
  auto trak3_cmp1 = DataBuffer(trak3_craw.getSubView(90),
                               trak3_craw.getByteOrder()); // extract CMP1 tag

  FileWriter trak3_cmp1_f("/tmp/test_trak3.cmp1");
  trak3_cmp1_f.writeFile(&trak3_cmp1, trak3_cmp1.getSize());

  cmp1DataHdr = decodeCMP1(trak3_cmp1);

  validateCMP1(cmp1DataHdr);

  raw_width = cmp1DataHdr.f_width;
  raw_height = cmp1DataHdr.f_height;

  mRaw->dim = iPoint2D(raw_width, raw_height);
  mRaw->setCpp(1);
}

RawImage CrxDecoder::decodeRawInternal() {

  auto trak1 =
      getFileBox()->find_first(BMFF_T("moov")).find_nth(BMFF_T("trak"), 3);

  auto thmb = getFileBox()
                  ->find_first(BMFF_T("moov"))
                  .find_uuid_first(CANO_UUID)
                  .find_first(BMFF_T("THMB"));

  FileWriter out("/tmp/test.jpg");
  out.writeFile(&thmb.payload, thmb.payload.getSize());

  auto trak1_co64 = getFileBox()
                        ->find_first(BMFF_T("moov"))
                        .find_first(BMFF_T("trak"))
                        .find_first(BMFF_T("mdia"))
                        .find_first(BMFF_T("minf"))
                        .find_first(BMFF_T("stbl"))
                        .find_first(BMFF_T("co64"));

  FileWriter out2("/tmp/test.trak1co64");
  out2.writeFile(&trak1_co64.payload, trak1_co64.payload.getSize());

  auto trak1_ptr = trak1_co64.payload.get<uint64_t>(8);

  auto jpeg_trak = getFileBox()->payload.getSubView(trak1_ptr);

  FileWriter out_jpg("/tmp/test_fulljpeg.jpg");
  out_jpg.writeFile(&jpeg_trak, jpeg_trak.getSize());

  auto trak3_stbl = getFileBox()
                        ->find_first(BMFF_T("moov"))
                        .find_nth(BMFF_T("trak"), 3)
                        .find_first(BMFF_T("mdia"))
                        .find_first(BMFF_T("minf"))
                        .find_first(BMFF_T("stbl"));

  auto trak3_co64 = trak3_stbl.find_first(BMFF_T("co64"));
  auto trak3_stsz = trak3_stbl.find_first(BMFF_T("stsz"));
  auto trak3_stsd = trak3_stbl.find_first(BMFF_T("stsd"));

  FileWriter trak3_stsz_f("/tmp/test_trak3.stsz");
  trak3_stsz_f.writeFile(&trak3_stsz.payload, trak3_stsz.payload.getSize());

  uint32_t stsz_size = trak3_stsz.payload.get<uint32_t>(4);
  uint32_t trak3_size = stsz_size;
  // uint32_t stsz_count = trak3_stsz.payload.get<uint32_t>(8); // count???
  if (stsz_size == 0) {
    trak3_size = trak3_stsz.payload.get<uint32_t>(12);
  }

  writeLog(DEBUG_PRIO_EXTRA, "stsz: %u", trak3_size);

  uint64_t trak3_media_ptr = trak3_co64.payload.get<uint64_t>(8);

  auto trak3_data =
      getFileBox()->payload.getSubView(trak3_media_ptr, trak3_size);

  FileWriter trak3_data_f("/tmp/test_trak3.data");
  trak3_data_f.writeFile(&trak3_data, trak3_data.getSize());

  auto mdat_box = getFileBox()->find_first(BMFF_T("mdat"));

  FileWriter mdat_box_f("/tmp/test.mdat");
  mdat_box_f.writeFile(&mdat_box.payload, mdat_box.payload.getSize());

  mRaw->createData();

  printf("bbp: %d\nwidth: %d\nheight: %d\npitch: %d\npadding: %d\n",
         mRaw->getBpp(), raw_width, raw_height, mRaw->pitch, mRaw->padding);

  assert(mRaw->getBpp() == 2);

  CrxDecompressor u(*mFile, mRaw);

  u.decode(cmp1DataHdr, trak3_data, trak3_media_ptr, trak3_size);

  // mRaw->calculateBlackAreas();

  return mRaw;
}

void CrxDecoder::checkSupportInternal(const CameraMetaData* meta) {
  writeLog(DEBUG_PRIO_EXTRA, "checkSupport Internal ENTRY");

  if (!isCodecSupported(cr3CompressorVersion)) {
    ThrowRDE("CR3 compressor version (CNCV: %s) is not supported",
             cr3CompressorVersion.c_str());
  }

  // load hints etc.??
  checkCameraSupported(meta, this->camId.make, this->camId.model, "");

  writeLog(DEBUG_PRIO_EXTRA, "checkSupport Internal EXIT");
}

void CrxDecoder::decodeMetaDataInternal(const CameraMetaData* meta) {
  // Default
  int iso = 0;

  auto CANO =
      getFileBox()->find_first(BMFF_T("moov")).find_uuid_first(CANO_UUID);

  auto cmt1 = CANO.find_first(BMFF_T("CMT1"));
  auto cmt2 = CANO.find_first(BMFF_T("CMT2"));
  auto cmt3 = CANO.find_first(BMFF_T("CMT3"));
  auto cmt4 = CANO.find_first(BMFF_T("CMT4"));

  auto trak4_stbl = getFileBox()
                        ->find_first(BMFF_T("moov"))
                        .find_nth(BMFF_T("trak"), 4)
                        .find_first(BMFF_T("mdia"))
                        .find_first(BMFF_T("minf"))
                        .find_first(BMFF_T("stbl"));

  auto trak4_co64 = trak4_stbl.find_first(BMFF_T("co64"));
  auto trak4_stsz = trak4_stbl.find_first(BMFF_T("stsz"));
  auto trak4_stsd = trak4_stbl.find_first(BMFF_T("stsd"));

  uint32_t stsz4_size = trak4_stsz.payload.get<uint32_t>(4);
  uint32_t trak4_size = stsz4_size;
  // uint32_t stsz4_count = trak4_stsz.payload.get<uint32_t>(8); // ignore?
  if (stsz4_size == 0) {
    trak4_size = trak4_stsz.payload.get<uint32_t>(12);
  }

  uint64_t trak4_media_ptr = trak4_co64.payload.get<uint64_t>(8);

  auto trak4_data =
      getFileBox()->payload.getSubView(trak4_media_ptr, trak4_size);

  auto trak4_recs =
      split_ctmd_records(DataBuffer(trak4_data, Endianness::little));

  Buffer ctmd_rec8 = trak4_recs[8]; // FIXME check

  DataBuffer ctmd_rec8_exif =
      DataBuffer(ctmd_rec8.getSubView(8, ctmd_rec8.getSize() - 8),
                 Endianness::little); // TODO detect from file?

  FileWriter ctmd_rec8_data_f("/tmp/test2.ctmd_rec8");
  ctmd_rec8_data_f.writeFile(&ctmd_rec8_exif, ctmd_rec8_exif.getSize());

  FileWriter trak4_data_f("/tmp/test2.trak4");
  trak4_data_f.writeFile(&trak4_data, trak4_data.getSize());

  NORangesSet<Buffer> rs;

  TiffRootIFD IFD_ctmd_rec8(nullptr, &rs, ctmd_rec8_exif,
                            8); // TODO: skip TIFF header

  // TiffRootIFDOwner root;

  // TODO: detect endianess from file
  DataBuffer cmt1_buf = DataBuffer(
      cmt1.payload.getSubView(0, cmt1.payload.getSize()), Endianness::little);
  DataBuffer cmt2_buf = DataBuffer(
      cmt2.payload.getSubView(0, cmt2.payload.getSize()), Endianness::little);
  DataBuffer cmt3_buf = DataBuffer(
      cmt3.payload.getSubView(0, cmt3.payload.getSize()), Endianness::little);
  DataBuffer cmt4_buf = DataBuffer(
      cmt4.payload.getSubView(0, cmt4.payload.getSize()), Endianness::little);

  TiffRootIFD IFD0_cmp1(nullptr, &rs, cmt1_buf, 8); // TODO: skip TIFF header
  TiffRootIFD IFD0_cmp2(nullptr, &rs, cmt2_buf, 8); // TODO: skip TIFF header
  TiffRootIFD IFD0_cmp3(nullptr, &rs, cmt3_buf, 8); // TODO: skip TIFF header
  TiffRootIFD IFD0_cmp4(nullptr, &rs, cmt4_buf, 8); // TODO: skip TIFF header

  auto id = IFD0_cmp1.getID();
  printf("EXIF-MAKE: %s\n", id.make.c_str());
  printf("EXIF-MODEL: %s\n", id.model.c_str());

  if (IFD0_cmp2.hasEntryRecursive(ISOSPEEDRATINGS))
    iso = IFD0_cmp2.getEntryRecursive(ISOSPEEDRATINGS)->getU32();

  printf("EXIF-ISO: %d\n", iso);

  // setMetaData must be called here according to rawspeed documentation to
  // finalize metadata and do crop etc.
  setMetaData(meta, this->camId.make, this->camId.model, "", iso);

  if (IFD_ctmd_rec8.hasEntryRecursive(CANONCOLORDATA)) {
    TiffEntry* wb = IFD_ctmd_rec8.getEntryRecursive(CANONCOLORDATA);
    // this entry is a big table, and different cameras store used WB in
    // different parts, so find the offset, default is the most common one
    int offset = hints.get("wb_offset", 126);

    if (wb->count ==
        3656) { // R5/R6, test others
                // https://github.com/exiftool/exiftool/blob/ceff3cbc4564e93518f3d2a2e00d8ae203ff54af/lib/Image/ExifTool/Canon.pm#L1910

      printf("HAS WB DATA, count: %d, offset: 0x%x\n", wb->count, offset);

      wb_coeffs[0] = static_cast<float>(wb->getU16(offset + 0)) / 1024.0;
      wb_coeffs[1] = static_cast<float>(wb->getU16(offset + 1)) / 1024.0;
      wb_coeffs[2] = 0; // GG
      wb_coeffs[3] = static_cast<float>(wb->getU16(offset + 3)) / 1024.0;

      writeLog(DEBUG_PRIO_EXTRA, "wb_coeffs:, 0: %f, 1: %f, 2: %f, 3: %f\n",
               wb_coeffs[0], wb_coeffs[1], wb_coeffs[2], wb_coeffs[3]);
    }

  } else {
    writeLog(DEBUG_PRIO_EXTRA, "no wb_coeffs found");
  }
  writeLog(DEBUG_PRIO_EXTRA, "Parsing METADATA DONE");

  if (hints.has("swapped_wb")) {
    mRaw->metadata.wbCoeffs[0] = wb_coeffs[2];
    mRaw->metadata.wbCoeffs[1] = wb_coeffs[0];
    mRaw->metadata.wbCoeffs[2] = wb_coeffs[1];
  } else {
    mRaw->metadata.wbCoeffs[0] = wb_coeffs[0];
    mRaw->metadata.wbCoeffs[1] = wb_coeffs[1];
    mRaw->metadata.wbCoeffs[2] = wb_coeffs[3];
  }
}

#define TAG_HDR_SIZE (4 + 4) // length + type

rawspeed::crx_data_header_t CrxDecoder::decodeCMP1(DataBuffer& CMP1) {
  rawspeed::crx_data_header_t hdr;

  hdr.version =
      CMP1.get<int16_t>(TAG_HDR_SIZE + 4); // Version is followed by 00 00
  hdr.f_width = CMP1.get<int32_t>(TAG_HDR_SIZE + 8);
  hdr.f_height = CMP1.get<int32_t>(TAG_HDR_SIZE + 12);
  hdr.tileWidth = CMP1.get<int32_t>(TAG_HDR_SIZE + 16);
  hdr.tileHeight = CMP1.get<int32_t>(TAG_HDR_SIZE + 20);
  hdr.nBits = CMP1.get<int8_t>(TAG_HDR_SIZE + 24);
  hdr.nPlanes = CMP1.get<int8_t>(TAG_HDR_SIZE + 25) >> 4;
  hdr.cfaLayout = CMP1.get<int8_t>(TAG_HDR_SIZE + 25) & 0xF;
  hdr.encType = CMP1.get<int8_t>(TAG_HDR_SIZE + 26) >> 4;
  hdr.imageLevels = CMP1.get<int8_t>(TAG_HDR_SIZE + 26) & 0xF;
  hdr.hasTileCols = CMP1.get<int8_t>(TAG_HDR_SIZE + 27) >> 7;
  hdr.hasTileRows = CMP1.get<int8_t>(TAG_HDR_SIZE + 27) & 1;
  hdr.mdatHdrSize = CMP1.get<int32_t>(TAG_HDR_SIZE + 28);

  writeLog(DEBUG_PRIO_EXTRA,
           "CMP1 Header: \n"
           "\t version %d\n"
           "\t f_width %d\n"
           "\t f_height %d\n"
           "\t tileWidth %d\n"
           "\t tileHeight %d\n"
           "\t nBits %d\n"
           "\t nPlanes %d\n"
           "\t cfaLayout %d\n"
           "\t encType %d\n"
           "\t imageLevels %d\n"
           "\t hasTileCols %d\n"
           "\t hasTileRows %d\n"
           "\t mdatHdrSize %d\n",
           hdr.version, hdr.f_width, hdr.f_height, hdr.tileWidth,
           hdr.tileHeight, hdr.nBits, hdr.nPlanes, hdr.cfaLayout, hdr.encType,
           hdr.imageLevels, hdr.hasTileCols, hdr.hasTileRows, hdr.mdatHdrSize);

  return hdr;
}

/*
0   0,
2   0,
4   8352,
6   5586,
8   1,
10  2,
12  1,
14  0,
16  144,
18  112,
20  8335,
22  5575,
24  0,
26  0,
28  131,
30  5579,
32  132,
34  0,
36  8347,
38  99,
40  132,
42  100,
44  8347,
46  5579,


*/

void CrxDecoder::validateCMP1(crx_data_header_t& hdr) {

  // validation
  if ((hdr.version != 0x100 && hdr.version != 0x200) || !hdr.mdatHdrSize)
    ThrowRDE("Invalid version or empty mdat box");
  if (hdr.encType == 1) {
    if (hdr.nBits > 15)
      ThrowRDE("Unknown encoding bit count");
  } else {
    if (hdr.encType && hdr.encType != 3)
      ThrowRDE("Unknown encoding 1 ");
    if (hdr.nBits > 14)
      ThrowRDE("Unknown encoding bit count");
  }

  if (hdr.nPlanes == 1) {
    if (hdr.cfaLayout || hdr.encType || hdr.nBits != 8)
      ThrowRDE("Unknown encoding 2");
  } else if (hdr.nPlanes != 4 || hdr.f_width & 1 || hdr.f_height & 1 ||
             hdr.tileWidth & 1 || hdr.tileHeight & 1 || hdr.cfaLayout > 3 ||
             hdr.nBits == 8)
    ThrowRDE("Unknown encoding 3");

  if (hdr.tileWidth > hdr.f_width || hdr.tileHeight > hdr.f_height)
    ThrowRDE("Unknown encoding 4");

  if (hdr.imageLevels > 3 || hdr.hasTileCols > 1 || hdr.hasTileRows > 1)
    ThrowRDE("Unknown encoding 5");
}

} // namespace rawspeed
