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
#include "common/Point.h"                           // for iPoint2D
#include "decoders/RawDecoderException.h"           // for ThrowRDE
#include "decompressors/UncompressedDecompressor.h" // for UncompressedDeco...
#include "io/Buffer.h"                              // for DataBuffer, Buffer
#include "io/ByteStream.h"                          // for ByteStream
#include "io/Endianness.h"                          // for Endianness, Endi...
#include "metadata/Camera.h"                        // for Hints
#include "parsers/TiffParser.h"                     // for TiffParser
#include "tiff/TiffIFD.h"                           // for TiffRootIFDOwner
#include <cassert>                                  // for assert
#include <cstring>                                  // for memcmp
#include <memory>                                   // for unique_ptr


#include "io/FileWriter.h"                           // for ByteStream // FIXME remove me

#include <iostream>
#include <fstream>

#define BMFF_HDR_SIZE_LEN 4
#define BMFF_HDR_TYPE_LEN 4

constexpr std::array<uint8_t, 16> CANO = std::array<uint8_t, 16>({0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48});


#define uchar uint8_t


namespace rawspeed {



// contents of tag CMP1 for relevant track in CR3 file
  struct crx_data_header_t;
}

class LibRaw {
  private:

rawspeed::Buffer &file_buf;
rawspeed::Buffer &mdat;
 rawspeed::Buffer &mdat_hdr;
 rawspeed::Buffer &mdat_raw_image;
 std::unique_ptr<const rawspeed::crx_data_header_t> &data_header;
 uint64_t mdat_trak3_offset;
 uint64_t trak3_size;

 uint64_t mdat_offset;
 uint64_t mdat_size;

    public:

    LibRaw(rawspeed::Buffer &file_buf, rawspeed::Buffer &mdat, rawspeed::Buffer &mdat_hdr, rawspeed::Buffer &mdat_raw_image, std::unique_ptr<const rawspeed::crx_data_header_t> &data_hdr,
    uint64_t mdat_trak3_offset, uint64_t trak3_size, uint64_t mdat_offset, uint64_t mdat_size)
      : file_buf(file_buf), mdat(mdat), mdat_hdr(mdat_hdr), mdat_raw_image(mdat_raw_image), data_header(data_hdr), mdat_trak3_offset(mdat_trak3_offset),
      trak3_size(trak3_size),
        mdat_offset(mdat_offset), mdat_size(mdat_size)
      {}

    int crxDecodePlane(void *p, uint32_t planeNumber);
    void crxLoadDecodeLoop(void *img, int nPlanes);
    int crxParseImageHeader(uint8_t *cmp1TagData, int nTrack);
    void crxConvertPlaneLineDf(void *p, int imageRow);

    void crxLoadFinalizeLoopE3(void *p, int planeHeight);

    void crxLoadRaw(int16_t *outbuf);


    static unsigned sgetn(int n, const uchar *s)
      {
        unsigned result = 0;
        while (n-- > 0)
          result = (result << 8) | (*s++);
        return result;
      }
};



namespace rawspeed {



// contents of tag CMP1 for relevant track in CR3 file
struct crx_data_header_t
{
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
  //uint32_t MediaSize;
  //int64_t MediaOffset;
  //uint32_t MediaType; /* 1 -> /C/RAW, 2-> JPEG */
};




std::unique_ptr<const rawspeed::crx_data_header_t> parse_cmp1_tag(DataBuffer& cmp1_buf);

void validate_header_data(std::unique_ptr<const rawspeed::crx_data_header_t> &hdr);




  BmffBox BmffBox::find_first(uint32_t box_type) {
    return find_nth(box_type, 1);
  }


  BmffBox BmffBox::find_nth(uint32_t box_type, size_t nth) {
    auto res = childs.begin();
    do {
      res = std::find_if(res,
        childs.end(),
        [box_type](auto box){ return box.type == box_type; });
      if(--nth == 0 && res != childs.end()) {
        return *res;
      }
      ++res;
    }
    while(res != childs.end() && nth > 0);
    ThrowRDE("Couldn't find bmff type"); // TODO: add type
  }


  BmffBox BmffBox::find_uuid_first(std::array<uint8_t, 16> uuid) {
    return find_uuid_nth(uuid, 1);
  }


  BmffBox BmffBox::find_uuid_nth(std::array<uint8_t, 16> uuid, size_t nth) {
    auto res = childs.begin();
    do {
      res = std::find_if(res,
        childs.end(),
        [uuid](auto box){ return box.uuid == uuid; });
      if(--nth == 0 && res != childs.end()) {
        return *res;
      }
      ++res;
    }
    while(res != childs.end() && nth > 0);
    ThrowRDE("Couldn't find bmff uuid"); // TODO: add type
  }


std::vector<BmffBox> BmffBox::parse(const DataBuffer &buf, uint32_t file_offset) {
  std::vector<BmffBox> boxes;
  for(size_t i = 0; i < buf.getSize(); ) {
    std::array<uint8_t, 16> box_uuid;
    uint64_t box_size = buf.get<uint32_t>(i);
    uint32_t box_hdr_size = BMFF_HDR_SIZE_LEN+BMFF_HDR_TYPE_LEN;
    switch (box_size)
    {
    case 0: // Box expand to end of buffer
      box_size = buf.getSize();
      break;
    case 1: // Box use `largesize` field after type field
      box_size = buf.get<uint64_t>(i+BMFF_HDR_SIZE_LEN+BMFF_HDR_TYPE_LEN);
      box_hdr_size += sizeof(uint64_t); // add optional largesize field to header size
      break;
    default:
      break;
    }
    uint32_t box_type = buf.get<uint32_t>(i+BMFF_HDR_SIZE_LEN);
    std::string tag(reinterpret_cast<const char*>(buf.getData(i+BMFF_HDR_SIZE_LEN, 4)), 4);
    writeLog(DEBUG_PRIO_EXTRA, "Parsing hit type %s", tag.c_str());
    if('uuid' == box_type) {
      auto uuid_buf = buf.getSubView(i+box_hdr_size, 16);
      std::copy(uuid_buf.begin(), uuid_buf.end(), box_uuid.begin());
      box_hdr_size += 16; // add optional uuid field size to header size
    }
    DataBuffer box_data(buf.getSubView(i+box_hdr_size, box_size-box_hdr_size), buf.getByteOrder());
    std::vector<BmffBox> box_childs;
    switch(box_type) {
    case 'moov':
    case 'trak':
    case 'mdia':
    case 'minf':
    case 'dinf':
    case 'stbl':
    case 'stsd':
    case 'CRAW':
      writeLog(DEBUG_PRIO_EXTRA, "Parsing down");
      box_childs = BmffBox::parse(box_data, i+box_hdr_size);
      break;
    case 'uuid':
      if(box_uuid == CANO) {
        box_childs = BmffBox::parse(box_data, i+box_hdr_size);
      }
      break;
    }
    boxes.push_back(BmffBox({
      size: box_size,
      type: box_type,
      offset: file_offset + i,
      payload: box_data,
      childs: box_childs,
      uuid: box_uuid,
    }));
    i += box_size;
  }
  return boxes;
}


class CameraMetaData;

CrxDecoder::CrxDecoder(const Buffer* file) : RawDecoder(file) { parseHeader(); }

int CrxDecoder::isCrx(const Buffer* input) {
  static const std::array<char, 8> magic = {{'f', 't', 'y', 'p', 'c', 'r', 'x', ' '}};
  const unsigned char* data = input->getData(4, magic.size());
  return 0 == memcmp(data, magic.data(), magic.size());
}

void CrxDecoder::parseHeader() {
  if (!isCrx(mFile))
    ThrowRDE("This isn't actually a Crx file, why are you calling me?");


      raw_height = 5464; // CCD Size Y
      raw_width = 8192;  // CCD Size X
      bpp = 14;

  wb_coeffs[0] = 1;
  wb_coeffs[1] = 1;
  wb_coeffs[2] = 1;
  wb_coeffs[3] = 1;

  auto inbuf = DataBuffer(*mFile, Endianness::big);


  writeLog(DEBUG_PRIO_EXTRA, "Parsing HEADER");


  std::vector<BmffBox> boxes = BmffBox::parse(inbuf);

  this->fileBox = BmffBox({
    size: inbuf.getSize(),
    type: 0,
    offset: 0,
    payload: DataBuffer(inbuf.getSubView(0), inbuf.getByteOrder()),
    childs: boxes,
    uuid: std::array<uint8_t, 16>(),
  });


  //thmb.payload.begin(), th

  /*

  for(size_t i = 0; i < inbuf.getSize(); ) {
    uint64_t box_size = inbuf.get<uint32_t>(i);

    if(!box_size) break;
    if(1 == box_size) {
      box_size = inbuf.get<uint64_t>(i+BMFF_HDR_SIZE_LEN+BMFF_HDR_TYPE_LEN);
    }

      const uint8_t* ftyp_box = mFile->getData(i, box_size);

      const uint32_t ftyp_type = inbuf.get<uint32_t>(i+BMFF_HDR_SIZE_LEN);

      std::string tag(reinterpret_cast<const char*>(inbuf.getData(i+BMFF_HDR_SIZE_LEN, 4)), 4);

      writeLog(DEBUG_PRIO_EXTRA, "bmff header type: %s, size: %u", tag.c_str(), box_size);

      i += box_size;
  }
  */

/*
  const uint32_t box_size = inbuf.get<uint32_t>(0);

  const uint8_t* ftyp_box = mFile->getData(0, box_size);

  const uint32_t ftyp_type = inbuf.get<uint32_t>(4);

  std::string tag(reinterpret_cast<const char*>(inbuf.getData(4, 4)), 4);

  writeLog(DEBUG_PRIO_EXTRA, "ftyp header type: %s", tag.c_str());
*/




    /*
  const DataBuffer db(*mFile, Endianness::big);
  ByteStream bs(db);

  // magic
  bs.skipBytes(4);

  // the size of the rest of the header, up to the image data
  const auto headerSize = bs.getU32();
  bs.check(headerSize);

  // ... and offset to the image data at the same time
  const auto dataOffset = bs.getPosition() + headerSize;
  assert(bs.getPosition() == 8);

  // now, let's parse rest of the header.
  bs = bs.getSubStream(0, dataOffset);
  bs.skipBytes(8);

  bool foundPRD = false;
  while (bs.getRemainSize() > 0) {
    uint32_t tag = bs.getU32();
    uint32_t len = bs.getU32();
    bs.check(len);
    if (!len)
      ThrowRDE("Found entry of zero length, MRW is corrupt.");

    const auto origPos = bs.getPosition();

    switch (tag) {
    case 0x505244: {            // PRD
      foundPRD = true;
      bs.skipBytes(8);          // Version Number
      raw_height = bs.getU16(); // CCD Size Y
      raw_width = bs.getU16();  // CCD Size X

      if (!raw_width || !raw_height || raw_width > 3280 || raw_height > 2456) {
        ThrowRDE("Unexpected image dimensions found: (%u; %u)", raw_width,
                 raw_height);
      }

      bs.skipBytes(2);          // Image Size Y
      bs.skipBytes(2);          // Image Size X

      bpp = bs.getByte(); // DataSize
      if (12 != bpp && 16 != bpp)
        ThrowRDE("Unknown data size");

      if ((raw_height * raw_width * bpp) % 8 != 0)
        ThrowRDE("Bad combination of image size and raw dimensions.");

      if (12 != bs.getByte()) // PixelSize
        ThrowRDE("Unexpected pixel size");

      const auto SM = bs.getByte(); // StorageMethod
      if (0x52 != SM && 0x59 != SM)
        ThrowRDE("Unknown storage method");
      packed = (0x59 == SM);

      if ((12 == bpp) != packed)
        ThrowRDE("Packed/BPP sanity check failed!");

      bs.skipBytes(1); // Unknown1
      bs.skipBytes(2); // Unknown2
      bs.skipBytes(2); // BayerPattern
      break;
    }
    case 0x545457: // TTW
      // Base value for offsets needs to be at the beginning of the TIFF block,
      // not the file
      rootIFD = TiffParser::parse(nullptr, bs.getBuffer(len));
      break;
    case 0x574247:     // WBG
      bs.skipBytes(4); // 4 factors
      static_assert(4 == (sizeof(wb_coeffs) / sizeof(wb_coeffs[0])),
                    "wrong coeff count");
      for (auto& wb_coeff : wb_coeffs)
        wb_coeff = static_cast<float>(bs.getU16()); // gain

      // FIXME?
      // Gf = Gr / 2^(6+F)
      break;
    default:
      // unknown block, let's just ignore
      break;
    }

    bs.setPosition(origPos + len);
  }

  if (!foundPRD)
    ThrowRDE("Did not find PRD tag. Image corrupt.");

  // processed all of the header. the image data is directly next

  const auto imageBits = raw_height * raw_width * bpp;
  assert(imageBits > 0);
  assert(imageBits % 8 == 0);

  imageData = db.getSubView(bs.getPosition(), imageBits / 8);
  */
}

RawImage CrxDecoder::decodeRawInternal() {




  auto trak1 = fileBox.find_first('moov').find_nth('trak', 3);

  auto cncv = fileBox.find_first('moov').find_uuid_first(CANO).find_first('CNCV');
  std::string compr_ver(cncv.payload.begin(), cncv.payload.end());
  writeLog(DEBUG_PRIO_EXTRA, "CNCV compressor version: %s", compr_ver.c_str());

  auto thmb = fileBox.find_first('moov').find_uuid_first(CANO).find_first('THMB');

  FileWriter out("/tmp/test.jpg");
  out.writeFile(&thmb.payload, thmb.payload.getSize());





  auto trak1_co64 = fileBox.find_first('moov').find_first('trak').find_first('mdia').find_first('minf').find_first('stbl').find_first('co64');

  FileWriter out2("/tmp/test.trak1co64");
  out2.writeFile(&trak1_co64.payload, trak1_co64.payload.getSize());

  auto trak1_ptr = trak1_co64.payload.get<uint64_t>(8);

  auto jpeg_trak = fileBox.payload.getSubView(trak1_ptr);

    FileWriter out_jpg("/tmp/test_fulljpeg.jpg");
  out_jpg.writeFile(&jpeg_trak, jpeg_trak.getSize());



  auto trak3_stbl = fileBox.find_first('moov').find_nth('trak', 3).find_first('mdia').find_first('minf').find_first('stbl');

  auto trak3_co64 = trak3_stbl.find_first('co64');
  auto trak3_stsz = trak3_stbl.find_first('stsz');
  auto trak3_stsd = trak3_stbl.find_first('stsd');

 FileWriter trak3_stsz_f("/tmp/test_trak3.stsz");
  trak3_stsz_f.writeFile(&trak3_stsz.payload, trak3_stsz.payload.getSize());


uint32_t stsz_size = trak3_stsz.payload.get<uint32_t>(4);
uint32_t trak3_size = stsz_size;
uint32_t stsz_count = trak3_stsz.payload.get<uint32_t>(8);
if(stsz_size == 0) {
  trak3_size = trak3_stsz.payload.get<uint32_t>(12);
}


  writeLog(DEBUG_PRIO_EXTRA, "stsz: %u", trak3_size);



  uint64_t trak3_media_ptr = trak3_co64.payload.get<uint64_t>(8);



  auto trak3_data = fileBox.payload.getSubView(trak3_media_ptr, trak3_size);



   FileWriter trak3_data_f("/tmp/test_trak3.data");
  trak3_data_f.writeFile(&trak3_data, trak3_data.getSize());


  auto trak3_craw = DataBuffer(trak3_stsd.payload.getSubView(8), trak3_stsd.payload.getByteOrder()); // skip version and flags
  auto trak3_cmp1 = DataBuffer(trak3_craw.getSubView(90), trak3_craw.getByteOrder()); // extract CMP1 tag


 FileWriter trak3_cmp1_f("/tmp/test_trak3.cmp2");
  trak3_cmp1_f.writeFile(&trak3_cmp1, trak3_cmp1.getSize());

  //auto cmp1_hdr = parse_cmp1_tag(trak3_cmp1);

  std::unique_ptr<const rawspeed::crx_data_header_t> cmp1_hdr = parse_cmp1_tag(trak3_cmp1);

  validate_header_data(cmp1_hdr);






  auto mdat_box = fileBox.find_first('mdat');

  FileWriter mdat_box_f("/tmp/test.mdat");
  mdat_box_f.writeFile(&mdat_box.payload, mdat_box.payload.getSize());



  //auto trak3_mdat_hdr = DataBuffer(mdat_box.payload.getSubView(90, cmp1_hdr->mdatHdrSize), mdat_box.payload.getByteOrder()); // extract HDR
  auto trak3_mdat_hdr = trak3_data.getSubView(0, cmp1_hdr->mdatHdrSize);

  raw_width = cmp1_hdr->f_width;
  raw_height = cmp1_hdr->f_height;

  /*
  if(cmp1_hdr->nPlanes == 4) {
    raw_width >>= 1;
    raw_height >>= 1;
  }
  */


  mRaw->dim = iPoint2D(raw_width, raw_height);
  mRaw->setCpp(1);
  mRaw->isCFA = true;
  mRaw->cfa.setCFA(iPoint2D(2,2), CFA_RED, CFA_GREEN, CFA_GREEN, CFA_BLUE); // TODO sRaw has other CFA!

  mRaw->createData();


  rawspeed::DataBuffer file_buf  = DataBuffer(*mFile, Endianness::big);


  LibRaw conv(file_buf,
  mdat_box.payload,
  trak3_mdat_hdr,
  trak3_data,
  cmp1_hdr,
   trak3_media_ptr,
   trak3_size,
    mdat_box.offset,
    mdat_box.size);

  conv.crxLoadRaw((int16_t*)mRaw->getData());

  FileWriter finalWriter("/tmp/final.bin");
  auto xbuf = Buffer(mRaw->getData(), mRaw->dim.x * mRaw->dim.y);
  finalWriter.writeFile(&xbuf, xbuf.getSize());



  /*

  std::ifstream file("/home/cytrinox/code/hd00_crx.bin", std::ios::binary | std::ios::ate);
std::streamsize size = file.tellg();
file.seekg(0, std::ios::beg);

std::vector<char> buffer(size);
if (file.read(buffer.data(), size))
{
  auto input = Buffer(reinterpret_cast<const uint8_t*>(buffer.data()), buffer.size());

  uint8_t* data = mRaw->getData();
  //uint32_t pitch = mRaw->pitch;
  const uint8_t* in = input.getData(0, size);
  */

 /*
  const Array2DRef<uint16_t> out5(mRaw->getU16DataAsUncroppedArray2DRef());

    for(auto i = 0; i < raw_height; ++i) {
        for(auto j = 0; j < raw_width; ++j) {
            out5(i, j) = ((float)i/(float)raw_height)*((1 << 16) -1);
        }
    }
*/
    printf("Hellxxxxo\n");

          writeLog(DEBUG_PRIO_EXTRA, "DNG Decoder: found lossy JPEG-encoded "
                                   "chunk, but the jpeg support was "
                                   "disabled at build!");





/*
  DataBuffer db(imageData, Endianness::big);
  ByteStream bs(db);
  UncompressedDecompressor u(bs, mRaw);

  if (packed)
    u.decode12BitRaw<Endianness::big>(raw_width, raw_height);
  else
    u.decodeRawUnpacked<12, Endianness::big>(raw_width, raw_height);
    */

  return mRaw;
}

void CrxDecoder::checkSupportInternal(const CameraMetaData* meta) {
    /*
  if (!rootIFD)
    ThrowRDE("Couldn't find make and model");

  auto id = rootIFD->getID();
  this->checkCameraSupported(meta, id.make, id.model, "");
  */
}

void CrxDecoder::decodeMetaDataInternal(const CameraMetaData* meta) {
  //Default
  int iso = 0;


/*
  if (!rootIFD)
    ThrowRDE("Couldn't find make and model");

  auto id = rootIFD->getID();
  setMetaData(meta, id.make, id.model, "", iso);
  */

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

#define TAG_HDR_SIZE (4+4) // length + type

std::unique_ptr<const rawspeed::crx_data_header_t> parse_cmp1_tag(DataBuffer &cmp1_buf) {
  std::unique_ptr<rawspeed::crx_data_header_t> hdr(new rawspeed::crx_data_header_t());

  hdr->version = cmp1_buf.get<int16_t>(TAG_HDR_SIZE+4); // Version is followed by 00 00
  hdr->f_width = cmp1_buf.get<int32_t>(TAG_HDR_SIZE+8);
  hdr->f_height = cmp1_buf.get<int32_t>(TAG_HDR_SIZE+12);
  hdr->tileWidth = cmp1_buf.get<int32_t>(TAG_HDR_SIZE+16);
  hdr->tileHeight = cmp1_buf.get<int32_t>(TAG_HDR_SIZE+20);
  hdr->nBits = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+24);
  hdr->nPlanes = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+25) >> 4;
  hdr->cfaLayout = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+25) & 0xF;
  hdr->encType = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+26) >> 4;
  hdr->imageLevels = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+26) & 0xF;
  hdr->hasTileCols = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+27) >> 7;
  hdr->hasTileRows = cmp1_buf.get<int8_t>(TAG_HDR_SIZE+27) & 1;
  hdr->mdatHdrSize = cmp1_buf.get<int32_t>(TAG_HDR_SIZE+28);

  writeLog(DEBUG_PRIO_EXTRA, "CMP1 Header: \n"
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
    hdr->version,
    hdr->f_width,
    hdr->f_height,
    hdr->tileWidth,
    hdr->tileHeight,
    hdr->nBits,
    hdr->nPlanes,
    hdr->cfaLayout,
    hdr->encType,
    hdr->imageLevels,
    hdr->hasTileCols,
    hdr->hasTileRows,
    hdr->mdatHdrSize
  );

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


void validate_header_data(std::unique_ptr<const rawspeed::crx_data_header_t> &hdr) {

  // validation
  if ((hdr->version != 0x100 && hdr->version != 0x200) || !hdr->mdatHdrSize)
    ThrowRDE("Invalid version or empty mdat box");
  if (hdr->encType == 1)
  {
    if (hdr->nBits > 15)
      ThrowRDE("Unknown encoding bit count");
  }
  else
  {
    if (hdr->encType && hdr->encType != 3)
      ThrowRDE("Unknown encoding 1 ");
    if (hdr->nBits > 14)
      ThrowRDE("Unknown encoding bit count");
  }

  if (hdr->nPlanes == 1)
  {
    if (hdr->cfaLayout || hdr->encType || hdr->nBits != 8)
      ThrowRDE("Unknown encoding 2");
  }
  else if (hdr->nPlanes != 4 || hdr->f_width & 1 || hdr->f_height & 1 || hdr->tileWidth & 1 || hdr->tileHeight & 1 ||
           hdr->cfaLayout > 3 || hdr->nBits == 8)
    ThrowRDE("Unknown encoding 3");

  if (hdr->tileWidth > hdr->f_width || hdr->tileHeight > hdr->f_height)
    ThrowRDE("Unknown encoding 4");

  if (hdr->imageLevels > 3 || hdr->hasTileCols > 1 || hdr->hasTileRows > 1)
    ThrowRDE("Unknown encoding 5");
}

} // namespace rawspeed





#include <math.h>
#include <errno.h>
#include <float.h>
#include <new>
#include <exception>
#include <sys/types.h>
#include <sys/stat.h>
#define LIBRAW_LIBRARY_BUILD
//#include "libraw/libraw.h"
//#include "internal/defines.h"
#ifdef USE_ZLIB
#include <zlib.h>
#endif

#ifndef LIBRAW_WIN32_CALLS
#include <netinet/in.h>
#else
#ifndef LIBRAW_NO_WINSOCK2
#include <winsock2.h>
#endif
#include <io.h>
#endif

#ifdef USE_RAWSPEED
#include <RawSpeed/StdAfx.h>
#include <RawSpeed/FileMap.h>
#include <RawSpeed/RawParser.h>
#include <RawSpeed/RawDecoder.h>
#include <RawSpeed/CameraMetaData.h>
#include <RawSpeed/ColorFilterArray.h>
extern const char *_rawspeed_data_xml[];
extern const int RAWSPEED_DATA_COUNT;
class CameraMetaDataLR : public RawSpeed::CameraMetaData
{
public:
  CameraMetaDataLR() : CameraMetaData() {}
  CameraMetaDataLR(char *filename) : RawSpeed::CameraMetaData(filename) {}
  CameraMetaDataLR(char *data, int sz);
};

CameraMetaDataLR *make_camera_metadata();

#endif

#ifdef USE_DNGSDK
#include "dng_host.h"
#include "dng_negative.h"
#include "dng_simple_image.h"
#include "dng_info.h"
#endif

#define P1 imgdata.idata
#define S  imgdata.sizes
#define O  imgdata.params
#define C  imgdata.color
#define T  imgdata.thumbnail
#define MN imgdata.makernotes
#define IO libraw_internal_data.internal_output_params
#define ID libraw_internal_data.internal_data

#define makeIs(idx) (imgdata.idata.maker_index == idx)
#define mnCamID imgdata.lens.makernotes.CamID

#define EXCEPTION_HANDLER(e)                                                   \
  do                                                                           \
  {                                                                            \
    switch (e)                                                                 \
    {                                                                          \
    case LIBRAW_EXCEPTION_MEMPOOL:                                             \
      recycle();                                                               \
      return LIBRAW_MEMPOOL_OVERFLOW;                                          \
    case LIBRAW_EXCEPTION_ALLOC:                                               \
      recycle();                                                               \
      return LIBRAW_UNSUFFICIENT_MEMORY;                                       \
    case LIBRAW_EXCEPTION_TOOBIG:                                              \
      recycle();                                                               \
      return LIBRAW_TOO_BIG;                                                   \
    case LIBRAW_EXCEPTION_DECODE_RAW:                                          \
    case LIBRAW_EXCEPTION_DECODE_JPEG:                                         \
      recycle();                                                               \
      return LIBRAW_DATA_ERROR;                                                \
    case LIBRAW_EXCEPTION_DECODE_JPEG2000:                                     \
      recycle();                                                               \
      return LIBRAW_DATA_ERROR;                                                \
    case LIBRAW_EXCEPTION_IO_EOF:                                              \
    case LIBRAW_EXCEPTION_IO_CORRUPT:                                          \
      recycle();                                                               \
      return LIBRAW_IO_ERROR;                                                  \
    case LIBRAW_EXCEPTION_CANCELLED_BY_CALLBACK:                               \
      recycle();                                                               \
      return LIBRAW_CANCELLED_BY_CALLBACK;                                     \
    case LIBRAW_EXCEPTION_BAD_CROP:                                            \
      recycle();                                                               \
      return LIBRAW_BAD_CROP;                                                  \
    default:                                                                   \
      return LIBRAW_UNSPECIFIED_ERROR;                                         \
    }                                                                          \
  } while (0)

// copy-n-paste from image pipe
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define LIM(x, min, max) MAX(min, MIN(x, max))
#ifndef CLIP
#define CLIP(x) LIM(x, 0, 65535)
#endif
#define THUMB_READ_BEYOND 16384

#define ZERO(a) memset(&a, 0, sizeof(a))






#include <string>
#include <memory>
#include <cstring>
#include <vector>


#define derror() { using namespace rawspeed; ThrowRDE("Couldn't run libRaw"); }



#define LIBRAW_CRXTRACKS_MAXCOUNT 16

#ifdef _abs
#undef _abs
#undef _min
#undef _constrain
#endif
#define _abs(x) (((x) ^ ((int32_t)(x) >> 31)) - ((int32_t)(x) >> 31))
#define _min(a, b) ((a) < (b) ? (a) : (b))
#define _constrain(x, l, u) ((x) < (l) ? (l) : ((x) > (u) ? (u) : (x)))

#if defined(__clang__) || defined(__GNUG__)
#define libraw_inline inline __attribute__((always_inline))
#elif defined(_MSC_VER) && _MSC_VER > 1400
#define libraw_inline __forceinline
#else
#define libraw_inline inline
#endif

// this should be divisible by 4
#define CRX_BUF_SIZE 0x10000
#if !defined(_WIN32) || (defined(__GNUC__) && !defined(__INTRINSIC_SPECIAL__BitScanReverse))
/* __INTRINSIC_SPECIAL__BitScanReverse found in MinGW32-W64 v7.30 headers, may be there is a better solution? */
typedef uint32_t DWORD;
libraw_inline void _BitScanReverse(DWORD *Index, unsigned long Mask)
{
  *Index = sizeof(unsigned long) * 8 - 1 - __builtin_clzl(Mask);
}
#if LibRawBigEndian
#define _byteswap_ulong(x) (x)
#else
#define _byteswap_ulong(x) __builtin_bswap32(x)
#endif
#endif

#define uchar uint8_t // FIXME
#define INT64 int64_t // FIXME


class LibRaw_abstract_datastream
{
public:
  LibRaw_abstract_datastream() { };
  virtual ~LibRaw_abstract_datastream(void) { }
  virtual int valid() = 0;
  virtual int read(void *, size_t, size_t) = 0;
  virtual int seek(INT64, int) = 0;
  virtual INT64 tell() = 0;
  virtual INT64 size() = 0;
  virtual int get_char() = 0;
  virtual char *gets(char *, int) = 0;
  virtual int scanf_one(const char *, void *) = 0;
  virtual int eof() = 0;
  //virtual int jpeg_src(void *);
  //virtual void buffering_off() {}
  /* reimplement in subclass to use parallel access in xtrans_load_raw() if
   * OpenMP is not used */
  virtual int lock() { return 1; } /* success */
  virtual void unlock() {}
  virtual const char *fname() { return NULL; };
};

class LibRaw_buffer_datastream : public LibRaw_abstract_datastream
{
public:
  LibRaw_buffer_datastream(const void *buffer, size_t bsize);
  virtual ~LibRaw_buffer_datastream();
  virtual int valid();

  virtual int jpeg_src(void *jpegdata);
  virtual int read(void *ptr, size_t sz, size_t nmemb);
  virtual int eof();
  virtual int seek(INT64 o, int whence);
  virtual INT64 tell();
  virtual INT64 size() { return streamsize; }
  virtual char *gets(char *s, int sz);
  virtual int scanf_one(const char *fmt, void *val);
  virtual int get_char()
  {
    if (streampos >= streamsize)   return -1;
    return buf[streampos++];
  }

private:
  unsigned char *buf;
  size_t streampos, streamsize;
};

// contents of tag CMP1 for relevant track in CR3 file
/*
typedef struct
{
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
  uint32_t MediaSize;
  INT64 MediaOffset;
  uint32_t MediaType;
} crx_data_header_t;
*/


enum LibRaw_exceptions
{
  LIBRAW_EXCEPTION_NONE = 0,
  LIBRAW_EXCEPTION_ALLOC = 1,
  LIBRAW_EXCEPTION_DECODE_RAW = 2,
  LIBRAW_EXCEPTION_DECODE_JPEG = 3,
  LIBRAW_EXCEPTION_IO_EOF = 4,
  LIBRAW_EXCEPTION_IO_CORRUPT = 5,
  LIBRAW_EXCEPTION_CANCELLED_BY_CALLBACK = 6,
  LIBRAW_EXCEPTION_BAD_CROP = 7,
  LIBRAW_EXCEPTION_IO_BADFILE = 8,
  LIBRAW_EXCEPTION_DECODE_JPEG2000 = 9,
  LIBRAW_EXCEPTION_TOOBIG = 10,
  LIBRAW_EXCEPTION_MEMPOOL = 11
};

struct CrxBitstream
{
  uint8_t mdatBuf[CRX_BUF_SIZE];
  uint64_t mdatSize;
  uint64_t curBufOffset;
  uint32_t curPos;
  uint32_t curBufSize;
  uint32_t bitData;
  int32_t bitsLeft;
  LibRaw_abstract_datastream *input;
};

struct CrxBandParam
{
  CrxBitstream bitStream;
  int16_t subbandWidth;
  int16_t subbandHeight;
  int32_t roundedBitsMask;
  int32_t roundedBits;
  int16_t curLine;
  int32_t *lineBuf0;
  int32_t *lineBuf1;
  int32_t *lineBuf2;
  int32_t sParam;
  int32_t kParam;
  int32_t *paramData;
  int32_t *nonProgrData;
  bool supportsPartial;
};

struct CrxWaveletTransform
{
  int32_t *subband0Buf;
  int32_t *subband1Buf;
  int32_t *subband2Buf;
  int32_t *subband3Buf;
  int32_t *lineBuf[8];
  int16_t curLine;
  int16_t curH;
  int8_t fltTapH;
  int16_t height;
  int16_t width;
};

struct CrxSubband
{
  CrxBandParam *bandParam;
  uint64_t mdatOffset;
  uint8_t *bandBuf;
  uint16_t width;
  uint16_t height;
  int32_t qParam;
  int32_t kParam;
  uint32_t qStepBase;
  uint32_t qStepMult;
  bool supportsPartial;
  int32_t bandSize;
  uint64_t dataSize;
  int64_t dataOffset;
  short rowStartAddOn;
  short rowEndAddOn;
  short colStartAddOn;
  short colEndAddOn;
  short levelShift;
};

struct CrxPlaneComp
{
  uint8_t *compBuf;
  CrxSubband *subBands;
  CrxWaveletTransform *wvltTransform;
  int8_t compNumber;
  int64_t dataOffset;
  int32_t compSize;
  bool supportsPartial;
  int32_t roundedBitsMask;
  int8_t tileFlag;
};

struct CrxQStep
{
  uint32_t *qStepTbl;
  int width;
  int height;
};

struct CrxTile
{
  CrxPlaneComp *comps;
  int8_t tileFlag;
  int8_t tileNumber;
  int64_t dataOffset;
  int32_t tileSize;
  uint16_t width;
  uint16_t height;
  bool hasQPData;
  CrxQStep *qStep;
  uint32_t mdatQPDataSize;
  uint16_t mdatExtraSize;
};

struct CrxImage
{
  uint8_t nPlanes;
  uint16_t planeWidth;
  uint16_t planeHeight;
  uint8_t samplePrecision;
  uint8_t subbandCount;
  uint8_t levels;
  uint8_t nBits;
  uint8_t encType;
  uint8_t tileCols;
  uint8_t tileRows;
  CrxTile *tiles;
  uint64_t mdatOffset;
  uint64_t mdatSize;
  int16_t *outBufs[4]; // one per plane
  int16_t *planeBuf;
  LibRaw_abstract_datastream *input;
#ifdef LIBRAW_CR3_MEMPOOL
  libraw_memmgr memmgr;
  CrxImage() : memmgr(0) {}
#endif
};

enum TileFlags
{
  E_HAS_TILES_ON_THE_RIGHT = 1,
  E_HAS_TILES_ON_THE_LEFT = 2,
  E_HAS_TILES_ON_THE_BOTTOM = 4,
  E_HAS_TILES_ON_THE_TOP = 8
};

int32_t exCoefNumTbl[144] = {1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
                             0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0,
                             0, 0, 1, 2, 2, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 2, 2,
                             1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 2, 2, 2, 2, 1, 1, 1,
                             1, 2, 2, 1, 1, 1, 1, 2, 2, 1, 1, 0, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1};

int32_t q_step_tbl[8] = {0x28, 0x2D, 0x33, 0x39, 0x40, 0x48};

uint32_t JS[32] = {1,    1,    1,     1,     2,     2,     2,      2,      4,      4,     4,
                   4,    8,    8,     8,     8,     0x10,  0x10,   0x20,   0x20,   0x40,  0x40,
                   0x80, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000};

uint32_t J[32] = {0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,    2,    3,    3,    3,    3,
                  4, 4, 5, 5, 6, 6, 7, 7, 8, 9, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

static inline void crxFillBuffer(CrxBitstream *bitStrm)
{
  if (bitStrm->curPos >= bitStrm->curBufSize && bitStrm->mdatSize)
  {
    bitStrm->curPos = 0;
    bitStrm->curBufOffset += bitStrm->curBufSize;
#ifdef LIBRAW_USE_OPENMP
#pragma omp critical
#endif
    {
#ifndef LIBRAW_USE_OPENMP
      bitStrm->input->lock();
#endif
      bitStrm->input->seek(bitStrm->curBufOffset, SEEK_SET);
      bitStrm->curBufSize = bitStrm->input->read(bitStrm->mdatBuf, 1, _min(bitStrm->mdatSize, CRX_BUF_SIZE));

     //printf(" input_data: %x \n", *(uint64_t*)bitStrm->mdatBuf);

#ifndef LIBRAW_USE_OPENMP
      bitStrm->input->unlock();
#endif
      if (bitStrm->curBufSize < 1) // nothing read
        //throw LIBRAW_EXCEPTION_IO_EOF;
        ThrowRDE("IO EOF");
      bitStrm->mdatSize -= bitStrm->curBufSize;
    }
  }
}

libraw_inline int crxBitstreamGetZeros(CrxBitstream *bitStrm)
{
  uint32_t nonZeroBit = 0;
  uint64_t nextData = 0;
  int32_t result = 0;

  if (bitStrm->bitData)
  {
    _BitScanReverse((DWORD *)&nonZeroBit, (DWORD)bitStrm->bitData);
    result = 31 - nonZeroBit;
    bitStrm->bitData <<= 32 - nonZeroBit;
    bitStrm->bitsLeft -= 32 - nonZeroBit;
  }
  else
  {
    uint32_t bitsLeft = bitStrm->bitsLeft;
    while (1)
    {
      while (bitStrm->curPos + 4 <= bitStrm->curBufSize)
      {
        nextData = _byteswap_ulong(*(uint32_t *)(bitStrm->mdatBuf + bitStrm->curPos));
        bitStrm->curPos += 4;
        crxFillBuffer(bitStrm);
        if (nextData)
        {
          _BitScanReverse((DWORD *)&nonZeroBit, (DWORD)nextData);
          result = bitsLeft + 31 - nonZeroBit;
          bitStrm->bitData = nextData << (32 - nonZeroBit);
          bitStrm->bitsLeft = nonZeroBit;
          return result;
        }
        bitsLeft += 32;
      }
      if (bitStrm->curBufSize < bitStrm->curPos + 1)
        break; // error
      nextData = bitStrm->mdatBuf[bitStrm->curPos++];
      crxFillBuffer(bitStrm);
      if (nextData)
        break;
      bitsLeft += 8;
    }
    _BitScanReverse((DWORD *)&nonZeroBit, (DWORD)nextData);
    result = (uint32_t)(bitsLeft + 7 - nonZeroBit);
    bitStrm->bitData = nextData << (32 - nonZeroBit);
    bitStrm->bitsLeft = nonZeroBit;
  }
  return result;
}

libraw_inline uint32_t crxBitstreamGetBits(CrxBitstream *bitStrm, int bits)
{
  int bitsLeft = bitStrm->bitsLeft;
  uint32_t bitData = bitStrm->bitData;
  uint32_t nextWord;
  uint8_t nextByte;
  uint32_t result;

  if (bitsLeft < bits)
  {
    // get them from stream
    if (bitStrm->curPos + 4 <= bitStrm->curBufSize)
    {
      nextWord = _byteswap_ulong(*(uint32_t *)(bitStrm->mdatBuf + bitStrm->curPos));
      bitStrm->curPos += 4;
      crxFillBuffer(bitStrm);
      bitStrm->bitsLeft = 32 - (bits - bitsLeft);
      result = ((nextWord >> bitsLeft) | bitData) >> (32 - bits);
      bitStrm->bitData = nextWord << (bits - bitsLeft);
      return result;
    }
    // less than a word left - read byte at a time
    do
    {
      if (bitStrm->curPos >= bitStrm->curBufSize)
        break; // error
      bitsLeft += 8;
      nextByte = bitStrm->mdatBuf[bitStrm->curPos++];
      crxFillBuffer(bitStrm);
      bitData |= nextByte << (32 - bitsLeft);
    } while (bitsLeft < bits);
  }
  result = bitData >> (32 - bits); // 32-bits
  bitStrm->bitData = bitData << bits;
  bitStrm->bitsLeft = bitsLeft - bits;
  return result;
}

libraw_inline int32_t crxPrediction(int32_t left, int32_t top, int32_t deltaH, int32_t deltaV)
{
  int32_t symb[4] = {left + deltaH, left + deltaH, left, top};

  return symb[(((deltaV < 0) ^ (deltaH < 0)) << 1) + ((left < top) ^ (deltaH < 0))];
}

libraw_inline int32_t crxPredictKParameter(int32_t prevK, int32_t bitCode, int32_t maxVal = 0)
{
  int32_t newKParam = prevK - (bitCode < (1 << prevK >> 1)) + ((bitCode >> prevK) > 2) + ((bitCode >> prevK) > 5);

  return !maxVal || newKParam < maxVal ? newKParam : maxVal;
}

libraw_inline void crxDecodeSymbolL1(CrxBandParam *param, int32_t doMedianPrediction, int32_t notEOL = 0)
{
  if (doMedianPrediction)
  {
    int32_t symb[4];

    int32_t delta = param->lineBuf0[1] - param->lineBuf0[0];
    symb[2] = param->lineBuf1[0];
    symb[0] = symb[1] = delta + symb[2];
    symb[3] = param->lineBuf0[1];

    param->lineBuf1[1] = symb[(((param->lineBuf0[0] < param->lineBuf1[0]) ^ (delta < 0)) << 1) +
                              ((param->lineBuf1[0] < param->lineBuf0[1]) ^ (delta < 0))];
  }
  else
    param->lineBuf1[1] = param->lineBuf0[1];

  // get next error symbol
  uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
  if (bitCode >= 41)
    bitCode = crxBitstreamGetBits(&param->bitStream, 21);
  else if (param->kParam)
    bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);

  // add converted (+/-) error code to predicted value
  param->lineBuf1[1] += -(bitCode & 1) ^ (bitCode >> 1);

  // for not end of the line - use one symbol ahead to estimate next K
  if (notEOL)
  {
    int32_t nextDelta = (param->lineBuf0[2] - param->lineBuf0[1]) << 1;
    bitCode = (bitCode + _abs(nextDelta)) >> 1;
    ++param->lineBuf0;
  }

  // update K parameter
  param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);

  ++param->lineBuf1;
}

int crxDecodeLine(CrxBandParam *param)
{
  int length = param->subbandWidth;

  param->lineBuf1[0] = param->lineBuf0[1];
  for (; length > 1; --length)
  {
    if (param->lineBuf1[0] != param->lineBuf0[1] || param->lineBuf1[0] != param->lineBuf0[2])
    {
      crxDecodeSymbolL1(param, 1, 1);
    }
    else
    {
      int nSyms = 0;
      if (crxBitstreamGetBits(&param->bitStream, 1))
      {
        nSyms = 1;
        while (crxBitstreamGetBits(&param->bitStream, 1))
        {
          nSyms += JS[param->sParam];
          if (nSyms > length)
          {
            nSyms = length;
            break;
          }
          if (param->sParam < 31)
            ++param->sParam;
          if (nSyms == length)
            break;
        }

        if (nSyms < length)
        {
          if (J[param->sParam])
            nSyms += crxBitstreamGetBits(&param->bitStream, J[param->sParam]);
          if (param->sParam > 0)
            --param->sParam;
          if (nSyms > length)
            return -1;
        }

        length -= nSyms;

        // copy symbol nSyms times
        param->lineBuf0 += nSyms;

        // copy symbol nSyms times
        while (nSyms-- > 0)
        {
          param->lineBuf1[1] = param->lineBuf1[0];
          ++param->lineBuf1;
        }
      }

      if (length > 0)
        crxDecodeSymbolL1(param, 0, (length > 1));
    }
  }

  if (length == 1)
    crxDecodeSymbolL1(param, 1, 0);

  param->lineBuf1[1] = param->lineBuf1[0] + 1;

  return 0;
}

libraw_inline void crxDecodeSymbolL1Rounded(CrxBandParam *param, int32_t doSym = 1, int32_t doCode = 1)
{
  int32_t sym = param->lineBuf0[1];

  if (doSym)
  {
    // calculate the next symbol gradient
    int32_t symb[4];
    int32_t deltaH = param->lineBuf0[1] - param->lineBuf0[0];
    symb[2] = param->lineBuf1[0];
    symb[0] = symb[1] = deltaH + symb[2];
    symb[3] = param->lineBuf0[1];
    sym = symb[(((param->lineBuf0[0] < param->lineBuf1[0]) ^ (deltaH < 0)) << 1) +
               ((param->lineBuf1[0] < param->lineBuf0[1]) ^ (deltaH < 0))];
  }

  uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
  if (bitCode >= 41)
    bitCode = crxBitstreamGetBits(&param->bitStream, 21);
  else if (param->kParam)
    bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
  int32_t code = -(bitCode & 1) ^ (bitCode >> 1);
  param->lineBuf1[1] = param->roundedBitsMask * 2 * code + (code >> 31) + sym;

  if (doCode)
  {
    if (param->lineBuf0[2] > param->lineBuf0[1])
      code = (param->lineBuf0[2] - param->lineBuf0[1] + param->roundedBitsMask - 1) >> param->roundedBits;
    else
      code = -((param->lineBuf0[1] - param->lineBuf0[2] + param->roundedBitsMask) >> param->roundedBits);

    param->kParam = crxPredictKParameter(param->kParam, (bitCode + 2 * _abs(code)) >> 1, 15);
  }
  else
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);

  ++param->lineBuf1;
}

int crxDecodeLineRounded(CrxBandParam *param)
{
  int32_t valueReached = 0;

  param->lineBuf0[0] = param->lineBuf0[1];
  param->lineBuf1[0] = param->lineBuf0[1];
  int32_t length = param->subbandWidth;

  for (; length > 1; --length)
  {
    if (_abs(param->lineBuf0[2] - param->lineBuf0[1]) > param->roundedBitsMask)
    {
      crxDecodeSymbolL1Rounded(param);
      ++param->lineBuf0;
      valueReached = 1;
    }
    else if (valueReached || _abs(param->lineBuf0[0] - param->lineBuf1[0]) > param->roundedBitsMask)
    {
      crxDecodeSymbolL1Rounded(param);
      ++param->lineBuf0;
      valueReached = 0;
    }
    else
    {
      int nSyms = 0;
      if (crxBitstreamGetBits(&param->bitStream, 1))
      {
        nSyms = 1;
        while (crxBitstreamGetBits(&param->bitStream, 1))
        {
          nSyms += JS[param->sParam];
          if (nSyms > length)
          {
            nSyms = length;
            break;
          }
          if (param->sParam < 31)
            ++param->sParam;
          if (nSyms == length)
            break;
        }
        if (nSyms < length)
        {
          if (J[param->sParam])
            nSyms += crxBitstreamGetBits(&param->bitStream, J[param->sParam]);
          if (param->sParam > 0)
            --param->sParam;
        }
        if (nSyms > length)
          return -1;
      }
      length -= nSyms;

      // copy symbol nSyms times
      param->lineBuf0 += nSyms;

      // copy symbol nSyms times
      while (nSyms-- > 0)
      {
        param->lineBuf1[1] = param->lineBuf1[0];
        ++param->lineBuf1;
      }

      if (length > 1)
      {
        crxDecodeSymbolL1Rounded(param, 0);
        ++param->lineBuf0;
        valueReached = _abs(param->lineBuf0[1] - param->lineBuf0[0]) > param->roundedBitsMask;
      }
      else if (length == 1)
        crxDecodeSymbolL1Rounded(param, 0, 0);
    }
  }
  if (length == 1)
    crxDecodeSymbolL1Rounded(param, 1, 0);

  param->lineBuf1[1] = param->lineBuf1[0] + 1;

  return 0;
}

int crxDecodeLineNoRefPrevLine(CrxBandParam *param)
{
  int32_t i = 0;

  for (; i < param->subbandWidth - 1; i++)
  {
    if (param->lineBuf0[i + 2] | param->lineBuf0[i + 1] | param->lineBuf1[i])
    {
      uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
      if (bitCode >= 41)
        bitCode = crxBitstreamGetBits(&param->bitStream, 21);
      else if (param->kParam)
        bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
      param->lineBuf1[i + 1] = -(bitCode & 1) ^ (bitCode >> 1);
      param->kParam = crxPredictKParameter(param->kParam, bitCode);
      if (param->lineBuf2[i + 1] - param->kParam <= 1)
      {
        if (param->kParam >= 15)
          param->kParam = 15;
      }
      else
        ++param->kParam;
    }
    else
    {
      int nSyms = 0;
      if (crxBitstreamGetBits(&param->bitStream, 1))
      {
        nSyms = 1;
        if (i != param->subbandWidth - 1)
        {
          while (crxBitstreamGetBits(&param->bitStream, 1))
          {
            nSyms += JS[param->sParam];
            if (i + nSyms > param->subbandWidth)
            {
              nSyms = param->subbandWidth - i;
              break;
            }
            if (param->sParam < 31)
              ++param->sParam;
            if (i + nSyms == param->subbandWidth)
              break;
          }
          if (i + nSyms < param->subbandWidth)
          {
            if (J[param->sParam])
              nSyms += crxBitstreamGetBits(&param->bitStream, J[param->sParam]);
            if (param->sParam > 0)
              --param->sParam;
          }
          if (i + nSyms > param->subbandWidth)
            return -1;
        }
      }
      else if (i > param->subbandWidth)
        return -1;

      if (nSyms > 0)
      {
        memset(param->lineBuf1 + i + 1, 0, nSyms * sizeof(int32_t));
        memset(param->lineBuf2 + i, 0, nSyms * sizeof(int32_t));
        i += nSyms;
      }

      if (i >= param->subbandWidth - 1)
      {
        if (i == param->subbandWidth - 1)
        {
          uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
          if (bitCode >= 41)
            bitCode = crxBitstreamGetBits(&param->bitStream, 21);
          else if (param->kParam)
            bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
          param->lineBuf1[i + 1] = -((bitCode + 1) & 1) ^ ((bitCode + 1) >> 1);
          param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
          param->lineBuf2[i] = param->kParam;
        }
        continue;
      }
      else
      {
        uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
        if (bitCode >= 41)
          bitCode = crxBitstreamGetBits(&param->bitStream, 21);
        else if (param->kParam)
          bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
        param->lineBuf1[i + 1] = -((bitCode + 1) & 1) ^ ((bitCode + 1) >> 1);
        param->kParam = crxPredictKParameter(param->kParam, bitCode);
        if (param->lineBuf2[i + 1] - param->kParam <= 1)
        {
          if (param->kParam >= 15)
            param->kParam = 15;
        }
        else
          ++param->kParam;
      }
    }
    param->lineBuf2[i] = param->kParam;
  }
  if (i == param->subbandWidth - 1)
  {
    int32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
    if (bitCode >= 41)
      bitCode = crxBitstreamGetBits(&param->bitStream, 21);
    else if (param->kParam)
      bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
    param->lineBuf1[i + 1] = -(bitCode & 1) ^ (bitCode >> 1);
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    param->lineBuf2[i] = param->kParam;
  }

  return 0;
}

int crxDecodeTopLine(CrxBandParam *param)
{
  param->lineBuf1[0] = 0;

  int32_t length = param->subbandWidth;

  // read the line from bitstream
  for (; length > 1; --length)
  {
    if (param->lineBuf1[0])
      param->lineBuf1[1] = param->lineBuf1[0];
    else
    {
      int nSyms = 0;
      if (crxBitstreamGetBits(&param->bitStream, 1))
      {
        nSyms = 1;
        while (crxBitstreamGetBits(&param->bitStream, 1))
        {
          nSyms += JS[param->sParam];
          if (nSyms > length)
          {
            nSyms = length;
            break;
          }
          if (param->sParam < 31)
            ++param->sParam;
          if (nSyms == length)
            break;
        }
        if (nSyms < length)
        {
          if (J[param->sParam])
            nSyms += crxBitstreamGetBits(&param->bitStream, J[param->sParam]);
          if (param->sParam > 0)
            --param->sParam;
          if (nSyms > length)
            return -1;
        }

        length -= nSyms;

        // copy symbol nSyms times
        while (nSyms-- > 0)
        {
          param->lineBuf1[1] = param->lineBuf1[0];
          ++param->lineBuf1;
        }

        if (length <= 0)
          break;
      }

      param->lineBuf1[1] = 0;
    }

    uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
    if (bitCode >= 41)
      bitCode = crxBitstreamGetBits(&param->bitStream, 21);
    else if (param->kParam)
      bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
    param->lineBuf1[1] += -(bitCode & 1) ^ (bitCode >> 1);
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    ++param->lineBuf1;
  }

  if (length == 1)
  {
    param->lineBuf1[1] = param->lineBuf1[0];
    uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
    if (bitCode >= 41)
      bitCode = crxBitstreamGetBits(&param->bitStream, 21);
    else if (param->kParam)
      bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
    param->lineBuf1[1] += -(bitCode & 1) ^ (bitCode >> 1);
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    ++param->lineBuf1;
  }

  param->lineBuf1[1] = param->lineBuf1[0] + 1;

  return 0;
}

int crxDecodeTopLineRounded(CrxBandParam *param)
{
  param->lineBuf1[0] = 0;

  int32_t length = param->subbandWidth;

  // read the line from bitstream
  for (; length > 1; --length)
  {
    if (_abs(param->lineBuf1[0]) > param->roundedBitsMask)
      param->lineBuf1[1] = param->lineBuf1[0];
    else
    {
      int nSyms = 0;
      if (crxBitstreamGetBits(&param->bitStream, 1))
      {
        nSyms = 1;
        while (crxBitstreamGetBits(&param->bitStream, 1))
        {
          nSyms += JS[param->sParam];
          if (nSyms > length)
          {
            nSyms = length;
            break;
          }
          if (param->sParam < 31)
            ++param->sParam;
          if (nSyms == length)
            break;
        }
        if (nSyms < length)
        {
          if (J[param->sParam])
            nSyms += crxBitstreamGetBits(&param->bitStream, J[param->sParam]);
          if (param->sParam > 0)
            --param->sParam;
          if (nSyms > length)
            return -1;
        }
      }

      length -= nSyms;

      // copy symbol nSyms times
      while (nSyms-- > 0)
      {
        param->lineBuf1[1] = param->lineBuf1[0];
        ++param->lineBuf1;
      }

      if (length <= 0)
        break;

      param->lineBuf1[1] = 0;
    }

    uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
    if (bitCode >= 41)
      bitCode = crxBitstreamGetBits(&param->bitStream, 21);
    else if (param->kParam)
      bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);

    int32_t sVal = -(bitCode & 1) ^ (bitCode >> 1);
    param->lineBuf1[1] += param->roundedBitsMask * 2 * sVal + (sVal >> 31);
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    ++param->lineBuf1;
  }

  if (length == 1)
  {
    uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
    if (bitCode >= 41)
      bitCode = crxBitstreamGetBits(&param->bitStream, 21);
    else if (param->kParam)
      bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
    int32_t sVal = -(bitCode & 1) ^ (bitCode >> 1);
    param->lineBuf1[1] += param->roundedBitsMask * 2 * sVal + (sVal >> 31);
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    ++param->lineBuf1;
  }

  param->lineBuf1[1] = param->lineBuf1[0] + 1;

  return 0;
}

int crxDecodeTopLineNoRefPrevLine(CrxBandParam *param)
{
  param->lineBuf0[0] = 0;
  param->lineBuf1[0] = 0;
  int32_t length = param->subbandWidth;
  for (; length > 1; --length)
  {
    if (param->lineBuf1[0])
    {
      uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
      if (bitCode >= 41)
        bitCode = crxBitstreamGetBits(&param->bitStream, 21);
      else if (param->kParam)
        bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
      param->lineBuf1[1] = -(bitCode & 1) ^ (bitCode >> 1);
      param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    }
    else
    {
      int nSyms = 0;
      if (crxBitstreamGetBits(&param->bitStream, 1))
      {
        nSyms = 1;
        while (crxBitstreamGetBits(&param->bitStream, 1))
        {
          nSyms += JS[param->sParam];
          if (nSyms > length)
          {
            nSyms = length;
            break;
          }
          if (param->sParam < 31)
            ++param->sParam;
          if (nSyms == length)
            break;
        }
        if (nSyms < length)
        {
          if (J[param->sParam])
            nSyms += crxBitstreamGetBits(&param->bitStream, J[param->sParam]);
          if (param->sParam > 0)
            --param->sParam;
          if (nSyms > length)
            return -1;
        }
      }

      length -= nSyms;

      // copy symbol nSyms times
      while (nSyms-- > 0)
      {
        param->lineBuf2[0] = 0;
        param->lineBuf1[1] = 0;
        ++param->lineBuf1;
        ++param->lineBuf2;
      }

      if (length <= 0)
        break;
      uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
      if (bitCode >= 41)
        bitCode = crxBitstreamGetBits(&param->bitStream, 21);
      else if (param->kParam)
        bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
      param->lineBuf1[1] = -((bitCode + 1) & 1) ^ ((bitCode + 1) >> 1);
      param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    }
    param->lineBuf2[0] = param->kParam;
    ++param->lineBuf2;
    ++param->lineBuf1;
  }

  if (length == 1)
  {
    uint32_t bitCode = crxBitstreamGetZeros(&param->bitStream);
    if (bitCode >= 41)
      bitCode = crxBitstreamGetBits(&param->bitStream, 21);
    else if (param->kParam)
      bitCode = crxBitstreamGetBits(&param->bitStream, param->kParam) | (bitCode << param->kParam);
    param->lineBuf1[1] = -(bitCode & 1) ^ (bitCode >> 1);
    param->kParam = crxPredictKParameter(param->kParam, bitCode, 15);
    param->lineBuf2[0] = param->kParam;
    ++param->lineBuf1;
  }

  param->lineBuf1[1] = 0;

  return 0;
}

int crxDecodeLine(CrxBandParam *param, uint8_t *bandBuf)
{
  if (!param || !bandBuf)
    return -1;
  if (param->curLine >= param->subbandHeight)
    return -1;

  if (param->curLine == 0)
  {
    int32_t lineLength = param->subbandWidth + 2;

    param->sParam = 0;
    param->kParam = 0;
    if (param->supportsPartial)
    {
      if (param->roundedBitsMask <= 0)
      {
        param->lineBuf0 = (int32_t *)param->paramData;
        param->lineBuf1 = param->lineBuf0 + lineLength;
        int32_t *lineBuf = param->lineBuf1 + 1;
        if (crxDecodeTopLine(param))
          return -1;
        memcpy(bandBuf, lineBuf, param->subbandWidth * sizeof(int32_t));
        ++param->curLine;
      }
      else
      {
        param->roundedBits = 1;
        if (param->roundedBitsMask & ~1)
        {
          while (param->roundedBitsMask >> param->roundedBits)
            ++param->roundedBits;
        }
        param->lineBuf0 = (int32_t *)param->paramData;
        param->lineBuf1 = param->lineBuf0 + lineLength;
        int32_t *lineBuf = param->lineBuf1 + 1;
        if (crxDecodeTopLineRounded(param))
          return -1;
        memcpy(bandBuf, lineBuf, param->subbandWidth * sizeof(int32_t));
        ++param->curLine;
      }
    }
    else
    {
      param->lineBuf2 = (int32_t *)param->nonProgrData;
      param->lineBuf0 = (int32_t *)param->paramData;
      param->lineBuf1 = param->lineBuf0 + lineLength;
      int32_t *lineBuf = param->lineBuf1 + 1;
      if (crxDecodeTopLineNoRefPrevLine(param))
        return -1;
      memcpy(bandBuf, lineBuf, param->subbandWidth * sizeof(int32_t));
      ++param->curLine;
    }
  }
  else if (!param->supportsPartial)
  {
    int32_t lineLength = param->subbandWidth + 2;
    param->lineBuf2 = (int32_t *)param->nonProgrData;
    if (param->curLine & 1)
    {
      param->lineBuf1 = (int32_t *)param->paramData;
      param->lineBuf0 = param->lineBuf1 + lineLength;
    }
    else
    {
      param->lineBuf0 = (int32_t *)param->paramData;
      param->lineBuf1 = param->lineBuf0 + lineLength;
    }
    int32_t *lineBuf = param->lineBuf1 + 1;
    if (crxDecodeLineNoRefPrevLine(param))
      return -1;
    memcpy(bandBuf, lineBuf, param->subbandWidth * sizeof(int32_t));
    ++param->curLine;
  }
  else if (param->roundedBitsMask <= 0)
  {
    int32_t lineLength = param->subbandWidth + 2;
    if (param->curLine & 1)
    {
      param->lineBuf1 = (int32_t *)param->paramData;
      param->lineBuf0 = param->lineBuf1 + lineLength;
    }
    else
    {
      param->lineBuf0 = (int32_t *)param->paramData;
      param->lineBuf1 = param->lineBuf0 + lineLength;
    }
    int32_t *lineBuf = param->lineBuf1 + 1;
    if (crxDecodeLine(param))
      return -1;
    memcpy(bandBuf, lineBuf, param->subbandWidth * sizeof(int32_t));
    ++param->curLine;
  }
  else
  {
    int32_t lineLength = param->subbandWidth + 2;
    if (param->curLine & 1)
    {
      param->lineBuf1 = (int32_t *)param->paramData;
      param->lineBuf0 = param->lineBuf1 + lineLength;
    }
    else
    {
      param->lineBuf0 = (int32_t *)param->paramData;
      param->lineBuf1 = param->lineBuf0 + lineLength;
    }
    int32_t *lineBuf = param->lineBuf1 + 1;
    if (crxDecodeLineRounded(param))
      return -1;
    memcpy(bandBuf, lineBuf, param->subbandWidth * sizeof(int32_t));
    ++param->curLine;
  }
  return 0;
}

int crxUpdateQparam(CrxSubband *subband)
{
  uint32_t bitCode = crxBitstreamGetZeros(&subband->bandParam->bitStream);
  if (bitCode >= 23)
    bitCode = crxBitstreamGetBits(&subband->bandParam->bitStream, 8);
  else if (subband->kParam)
    bitCode = crxBitstreamGetBits(&subband->bandParam->bitStream, subband->kParam) | (bitCode << subband->kParam);

  subband->qParam += -(bitCode & 1) ^ (bitCode >> 1); // converting encoded to signed integer
  subband->kParam = crxPredictKParameter(subband->kParam, bitCode);
  if (subband->kParam > 7)
    return -1;
  return 0;
}

libraw_inline int getSubbandRow(CrxSubband *band, int row)
{
  return row < band->rowStartAddOn
             ? 0
             : (row < band->height - band->rowEndAddOn ? row - band->rowEndAddOn
                                                       : band->height - band->rowEndAddOn - band->rowStartAddOn - 1);
}
int crxDecodeLineWithIQuantization(CrxSubband *band, CrxQStep *qStep)
{
  if (!band->dataSize)
  {
    memset(band->bandBuf, 0, band->bandSize);
    return 0;
  }

  if (band->supportsPartial && !qStep && crxUpdateQparam(band))
    return -1;
  if (crxDecodeLine(band->bandParam, band->bandBuf))
    return -1;

  if (band->width <= 0)
    return 0;

  // update band buffers
  int32_t *bandBuf = (int32_t *)band->bandBuf;
  if (qStep)
  {
    // new version
    uint32_t *qStepTblPtr = &qStep->qStepTbl[qStep->width * getSubbandRow(band, band->bandParam->curLine - 1)];

    for (int i = 0; i < band->colStartAddOn; ++i)
    {
      uint32_t quantVal = band->qStepBase + ((qStepTblPtr[0] * band->qStepMult) >> 3);
      bandBuf[i] *= _constrain(quantVal, 1, 0x168000);
    }

    for (int i = band->colStartAddOn; i < band->width - band->colEndAddOn; ++i)
    {
      uint32_t quantVal =
          band->qStepBase + ((qStepTblPtr[(i - band->colStartAddOn) >> band->levelShift] * band->qStepMult) >> 3);
      bandBuf[i] *= _constrain(quantVal, 1, 0x168000);
    }
    int lastIdx = (band->width - band->colEndAddOn - band->colStartAddOn - 1) >> band->levelShift;
    for (int i = band->width - band->colEndAddOn; i < band->width; ++i)
    {
      uint32_t quantVal = band->qStepBase + ((qStepTblPtr[lastIdx] * band->qStepMult) >> 3);
      bandBuf[i] *= _constrain(quantVal, 1, 0x168000);
    }
  }
  else
  {
    // prev. version
    int32_t qScale = q_step_tbl[band->qParam % 6] >> (6 - band->qParam / 6);
    if (band->qParam / 6 >= 6)
      qScale = q_step_tbl[band->qParam % 6] * (1 << (band->qParam / 6 + 26));

    if (qScale != 1)
      for (int32_t i = 0; i < band->width; ++i)
        bandBuf[i] *= qScale;
  }

  return 0;
}

void crxHorizontal53(int32_t *lineBufLA, int32_t *lineBufLB, CrxWaveletTransform *wavelet, uint32_t tileFlag)
{
  int32_t *band0Buf = wavelet->subband0Buf;
  int32_t *band1Buf = wavelet->subband1Buf;
  int32_t *band2Buf = wavelet->subband2Buf;
  int32_t *band3Buf = wavelet->subband3Buf;

  if (wavelet->width <= 1)
  {
    lineBufLA[0] = band0Buf[0];
    lineBufLB[0] = band2Buf[0];
  }
  else
  {
    if (tileFlag & E_HAS_TILES_ON_THE_LEFT)
    {
      lineBufLA[0] = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
      lineBufLB[0] = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
      ++band1Buf;
      ++band3Buf;
    }
    else
    {
      lineBufLA[0] = band0Buf[0] - ((band1Buf[0] + 1) >> 1);
      lineBufLB[0] = band2Buf[0] - ((band3Buf[0] + 1) >> 1);
    }
    ++band0Buf;
    ++band2Buf;

    for (int i = 0; i < wavelet->width - 3; i += 2)
    {
      int32_t delta = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
      lineBufLA[1] = band1Buf[0] + ((delta + lineBufLA[0]) >> 1);
      lineBufLA[2] = delta;

      delta = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
      lineBufLB[1] = band3Buf[0] + ((delta + lineBufLB[0]) >> 1);
      lineBufLB[2] = delta;

      ++band0Buf;
      ++band1Buf;
      ++band2Buf;
      ++band3Buf;
      lineBufLA += 2;
      lineBufLB += 2;
    }
    if (tileFlag & E_HAS_TILES_ON_THE_RIGHT)
    {
      int32_t deltaA = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
      lineBufLA[1] = band1Buf[0] + ((deltaA + lineBufLA[0]) >> 1);

      int32_t deltaB = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
      lineBufLB[1] = band3Buf[0] + ((deltaB + lineBufLB[0]) >> 1);

      if (wavelet->width & 1)
      {
        lineBufLA[2] = deltaA;
        lineBufLB[2] = deltaB;
      }
    }
    else if (wavelet->width & 1)
    {
      lineBufLA[1] = band1Buf[0] + ((lineBufLA[0] + band0Buf[0] - ((band1Buf[0] + 1) >> 1)) >> 1);
      lineBufLA[2] = band0Buf[0] - ((band1Buf[0] + 1) >> 1);

      lineBufLB[1] = band3Buf[0] + ((lineBufLB[0] + band2Buf[0] - ((band3Buf[0] + 1) >> 1)) >> 1);
      lineBufLB[2] = band2Buf[0] - ((band3Buf[0] + 1) >> 1);
    }
    else
    {
      lineBufLA[1] = lineBufLA[0] + band1Buf[0];
      lineBufLB[1] = lineBufLB[0] + band3Buf[0];
    }
  }
}

int32_t *crxIdwt53FilterGetLine(CrxPlaneComp *comp, int32_t level)
{
  int32_t *result = comp->wvltTransform[level]
                        .lineBuf[(comp->wvltTransform[level].fltTapH - comp->wvltTransform[level].curH + 5) % 5 + 3];
  comp->wvltTransform[level].curH--;
  return result;
}

int crxIdwt53FilterDecode(CrxPlaneComp *comp, int32_t level, CrxQStep *qStep)
{
  if (comp->wvltTransform[level].curH)
    return 0;

  CrxSubband *sband = comp->subBands + 3 * level;
  CrxQStep *qStepLevel = qStep ? qStep + level : 0;

  if (comp->wvltTransform[level].height - 3 <= comp->wvltTransform[level].curLine &&
      !(comp->tileFlag & E_HAS_TILES_ON_THE_BOTTOM))
  {
    if (comp->wvltTransform[level].height & 1)
    {
      if (level)
      {
        if (crxIdwt53FilterDecode(comp, level - 1, qStep))
          return -1;
      }
      else if (crxDecodeLineWithIQuantization(sband, qStepLevel))
        return -1;

      if (crxDecodeLineWithIQuantization(sband + 1, qStepLevel))
        return -1;
    }
  }
  else
  {
    if (level)
    {
      if (crxIdwt53FilterDecode(comp, level - 1, qStep))
        return -1;
    }
    else if (crxDecodeLineWithIQuantization(sband, qStepLevel)) // LL band
      return -1;

    if (crxDecodeLineWithIQuantization(sband + 1, qStepLevel) || // HL band
        crxDecodeLineWithIQuantization(sband + 2, qStepLevel) || // LH band
        crxDecodeLineWithIQuantization(sband + 3, qStepLevel))   // HH band
      return -1;
  }

  return 0;
}

int crxIdwt53FilterTransform(CrxPlaneComp *comp, uint32_t level)
{
  CrxWaveletTransform *wavelet = comp->wvltTransform + level;

  if (wavelet->curH)
    return 0;

  if (wavelet->curLine >= wavelet->height - 3)
  {
    if (!(comp->tileFlag & E_HAS_TILES_ON_THE_BOTTOM))
    {
      if (wavelet->height & 1)
      {
        if (level)
        {
          if (!wavelet[-1].curH)
            if (crxIdwt53FilterTransform(comp, level - 1))
              return -1;
          wavelet->subband0Buf = crxIdwt53FilterGetLine(comp, level - 1);
        }
        int32_t *band0Buf = wavelet->subband0Buf;
        int32_t *band1Buf = wavelet->subband1Buf;
        int32_t *lineBufH0 = wavelet->lineBuf[wavelet->fltTapH + 3];
        int32_t *lineBufH1 = wavelet->lineBuf[(wavelet->fltTapH + 1) % 5 + 3];
        int32_t *lineBufH2 = wavelet->lineBuf[(wavelet->fltTapH + 2) % 5 + 3];

        int32_t *lineBufL0 = wavelet->lineBuf[0];
        int32_t *lineBufL1 = wavelet->lineBuf[1];
        wavelet->lineBuf[1] = wavelet->lineBuf[2];
        wavelet->lineBuf[2] = lineBufL1;

        // process L bands
        if (wavelet->width <= 1)
        {
          lineBufL0[0] = band0Buf[0];
        }
        else
        {
          if (comp->tileFlag & E_HAS_TILES_ON_THE_LEFT)
          {
            lineBufL0[0] = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
            ++band1Buf;
          }
          else
          {
            lineBufL0[0] = band0Buf[0] - ((band1Buf[0] + 1) >> 1);
          }
          ++band0Buf;
          for (int i = 0; i < wavelet->width - 3; i += 2)
          {
            int32_t delta = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
            lineBufL0[1] = band1Buf[0] + ((lineBufL0[0] + delta) >> 1);
            lineBufL0[2] = delta;
            ++band0Buf;
            ++band1Buf;
            lineBufL0 += 2;
          }
          if (comp->tileFlag & E_HAS_TILES_ON_THE_RIGHT)
          {
            int32_t delta = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
            lineBufL0[1] = band1Buf[0] + ((lineBufL0[0] + delta) >> 1);
            if (wavelet->width & 1)
              lineBufL0[2] = delta;
          }
          else if (wavelet->width & 1)
          {
            int32_t delta = band0Buf[0] - ((band1Buf[0] + 1) >> 1);
            lineBufL0[1] = band1Buf[0] + ((lineBufL0[0] + delta) >> 1);
            lineBufL0[2] = delta;
          }
          else
            lineBufL0[1] = band1Buf[0] + lineBufL0[0];
        }

        // process H bands
        lineBufL0 = wavelet->lineBuf[0];
        lineBufL1 = wavelet->lineBuf[1];
        for (int32_t i = 0; i < wavelet->width; i++)
        {
          int32_t delta = lineBufL0[i] - ((lineBufL1[i] + 1) >> 1);
          lineBufH1[i] = lineBufL1[i] + ((delta + lineBufH0[i]) >> 1);
          lineBufH2[i] = delta;
        }
        wavelet->curH += 3;
        wavelet->curLine += 3;
        wavelet->fltTapH = (wavelet->fltTapH + 3) % 5;
      }
      else
      {
        int32_t *lineBufL2 = wavelet->lineBuf[2];
        int32_t *lineBufH0 = wavelet->lineBuf[wavelet->fltTapH + 3];
        int32_t *lineBufH1 = wavelet->lineBuf[(wavelet->fltTapH + 1) % 5 + 3];
        wavelet->lineBuf[1] = lineBufL2;
        wavelet->lineBuf[2] = wavelet->lineBuf[1];

        for (int32_t i = 0; i < wavelet->width; i++)
          lineBufH1[i] = lineBufH0[i] + lineBufL2[i];

        wavelet->curH += 2;
        wavelet->curLine += 2;
        wavelet->fltTapH = (wavelet->fltTapH + 2) % 5;
      }
    }
  }
  else
  {
    if (level)
    {
      if (!wavelet[-1].curH && crxIdwt53FilterTransform(comp, level - 1))
        return -1;
      wavelet->subband0Buf = crxIdwt53FilterGetLine(comp, level - 1);
    }

    int32_t *band0Buf = wavelet->subband0Buf;
    int32_t *band1Buf = wavelet->subband1Buf;
    int32_t *band2Buf = wavelet->subband2Buf;
    int32_t *band3Buf = wavelet->subband3Buf;

    int32_t *lineBufL0 = wavelet->lineBuf[0];
    int32_t *lineBufL1 = wavelet->lineBuf[1];
    int32_t *lineBufL2 = wavelet->lineBuf[2];
    int32_t *lineBufH0 = wavelet->lineBuf[wavelet->fltTapH + 3];
    int32_t *lineBufH1 = wavelet->lineBuf[(wavelet->fltTapH + 1) % 5 + 3];
    int32_t *lineBufH2 = wavelet->lineBuf[(wavelet->fltTapH + 2) % 5 + 3];

    wavelet->lineBuf[1] = wavelet->lineBuf[2];
    wavelet->lineBuf[2] = lineBufL1;

    // process L bands
    if (wavelet->width <= 1)
    {
      lineBufL0[0] = band0Buf[0];
      lineBufL1[0] = band2Buf[0];
    }
    else
    {
      if (comp->tileFlag & E_HAS_TILES_ON_THE_LEFT)
      {
        lineBufL0[0] = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
        lineBufL1[0] = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
        ++band1Buf;
        ++band3Buf;
      }
      else
      {
        lineBufL0[0] = band0Buf[0] - ((band1Buf[0] + 1) >> 1);
        lineBufL1[0] = band2Buf[0] - ((band3Buf[0] + 1) >> 1);
      }
      ++band0Buf;
      ++band2Buf;
      for (int i = 0; i < wavelet->width - 3; i += 2)
      {
        int32_t delta = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
        lineBufL0[1] = band1Buf[0] + ((delta + lineBufL0[0]) >> 1);
        lineBufL0[2] = delta;

        delta = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
        lineBufL1[1] = band3Buf[0] + ((delta + lineBufL1[0]) >> 1);
        lineBufL1[2] = delta;

        ++band0Buf;
        ++band1Buf;
        ++band2Buf;
        ++band3Buf;
        lineBufL0 += 2;
        lineBufL1 += 2;
      }
      if (comp->tileFlag & E_HAS_TILES_ON_THE_RIGHT)
      {
        int32_t deltaA = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
        lineBufL0[1] = band1Buf[0] + ((deltaA + lineBufL0[0]) >> 1);

        int32_t deltaB = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
        lineBufL1[1] = band3Buf[0] + ((deltaB + lineBufL1[0]) >> 1);

        if (wavelet->width & 1)
        {
          lineBufL0[2] = deltaA;
          lineBufL1[2] = deltaB;
        }
      }
      else if (wavelet->width & 1)
      {
        int32_t delta = band0Buf[0] - ((band1Buf[0] + 1) >> 1);
        lineBufL0[1] = band1Buf[0] + ((delta + lineBufL0[0]) >> 1);
        lineBufL0[2] = delta;

        delta = band2Buf[0] - ((band3Buf[0] + 1) >> 1);
        lineBufL1[1] = band3Buf[0] + ((delta + lineBufL1[0]) >> 1);
        lineBufL1[2] = delta;
      }
      else
      {
        lineBufL0[1] = lineBufL0[0] + band1Buf[0];
        lineBufL1[1] = lineBufL1[0] + band3Buf[0];
      }
    }

    // process H bands
    lineBufL0 = wavelet->lineBuf[0];
    lineBufL1 = wavelet->lineBuf[1];
    lineBufL2 = wavelet->lineBuf[2];
    for (int32_t i = 0; i < wavelet->width; i++)
    {
      int32_t delta = lineBufL0[i] - ((lineBufL2[i] + lineBufL1[i] + 2) >> 2);
      lineBufH1[i] = lineBufL1[i] + ((delta + lineBufH0[i]) >> 1);
      lineBufH2[i] = delta;
    }
    if (wavelet->curLine >= wavelet->height - 3 && wavelet->height & 1)
    {
      wavelet->curH += 3;
      wavelet->curLine += 3;
      wavelet->fltTapH = (wavelet->fltTapH + 3) % 5;
    }
    else
    {
      wavelet->curH += 2;
      wavelet->curLine += 2;
      wavelet->fltTapH = (wavelet->fltTapH + 2) % 5;
    }
  }

  return 0;
}

int crxIdwt53FilterInitialize(CrxPlaneComp *comp, int32_t level, CrxQStep *qStep)
{
  if (level == 0)
    return 0;

  for (int curLevel = 0, curBand = 0; curLevel < level; curLevel++, curBand += 3)
  {
    CrxQStep *qStepLevel = qStep ? qStep + curLevel : 0;
    CrxWaveletTransform *wavelet = comp->wvltTransform + curLevel;
    if (curLevel)
      wavelet[0].subband0Buf = crxIdwt53FilterGetLine(comp, curLevel - 1);
    else if (crxDecodeLineWithIQuantization(comp->subBands + curBand, qStepLevel))
      return -1;

    int32_t *lineBufH0 = wavelet->lineBuf[wavelet->fltTapH + 3];
    if (wavelet->height > 1)
    {
      if (crxDecodeLineWithIQuantization(comp->subBands + curBand + 1, qStepLevel) ||
          crxDecodeLineWithIQuantization(comp->subBands + curBand + 2, qStepLevel) ||
          crxDecodeLineWithIQuantization(comp->subBands + curBand + 3, qStepLevel))
        return -1;

      int32_t *lineBufL0 = wavelet->lineBuf[0];
      int32_t *lineBufL1 = wavelet->lineBuf[1];
      int32_t *lineBufL2 = wavelet->lineBuf[2];

      if (comp->tileFlag & E_HAS_TILES_ON_THE_TOP)
      {
        crxHorizontal53(lineBufL0, wavelet->lineBuf[1], wavelet, comp->tileFlag);
        if (crxDecodeLineWithIQuantization(comp->subBands + curBand + 3, qStepLevel) ||
            crxDecodeLineWithIQuantization(comp->subBands + curBand + 2, qStepLevel))
          return -1;

        int32_t *band2Buf = wavelet->subband2Buf;
        int32_t *band3Buf = wavelet->subband3Buf;

        // process L band
        if (wavelet->width <= 1)
          lineBufL2[0] = band2Buf[0];
        else
        {
          if (comp->tileFlag & E_HAS_TILES_ON_THE_LEFT)
          {
            lineBufL2[0] = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
            ++band3Buf;
          }
          else
            lineBufL2[0] = band2Buf[0] - ((band3Buf[0] + 1) >> 1);

          ++band2Buf;

          for (int i = 0; i < wavelet->width - 3; i += 2)
          {
            int32_t delta = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
            lineBufL2[1] = band3Buf[0] + ((lineBufL2[0] + delta) >> 1);
            lineBufL2[2] = delta;

            ++band2Buf;
            ++band3Buf;
            lineBufL2 += 2;
          }
          if (comp->tileFlag & E_HAS_TILES_ON_THE_RIGHT)
          {
            int32_t delta = band2Buf[0] - ((band3Buf[0] + band3Buf[1] + 2) >> 2);
            lineBufL2[1] = band3Buf[0] + ((lineBufL2[0] + delta) >> 1);
            if (wavelet->width & 1)
              lineBufL2[2] = delta;
          }
          else if (wavelet->width & 1)
          {
            int32_t delta = band2Buf[0] - ((band3Buf[0] + 1) >> 1);

            lineBufL2[1] = band3Buf[0] + ((lineBufL2[0] + delta) >> 1);
            lineBufL2[2] = delta;
          }
          else
          {
            lineBufL2[1] = band3Buf[0] + lineBufL2[0];
          }
        }

        // process H band
        for (int32_t i = 0; i < wavelet->width; i++)
          lineBufH0[i] = lineBufL0[i] - ((lineBufL1[i] + lineBufL2[i] + 2) >> 2);
      }
      else
      {
        crxHorizontal53(lineBufL0, wavelet->lineBuf[2], wavelet, comp->tileFlag);
        for (int i = 0; i < wavelet->width; i++)
          lineBufH0[i] = lineBufL0[i] - ((lineBufL2[i] + 1) >> 1);
      }

      if (crxIdwt53FilterDecode(comp, curLevel, qStep) || crxIdwt53FilterTransform(comp, curLevel))
        return -1;
    }
    else
    {
      if (crxDecodeLineWithIQuantization(comp->subBands + curBand + 1, qStepLevel))
        return -1;

      int32_t *band0Buf = wavelet->subband0Buf;
      int32_t *band1Buf = wavelet->subband1Buf;

      // process H band
      if (wavelet->width <= 1)
        lineBufH0[0] = band0Buf[0];
      else
      {
        if (comp->tileFlag & E_HAS_TILES_ON_THE_LEFT)
        {
          lineBufH0[0] = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
          ++band1Buf;
        }
        else
          lineBufH0[0] = band0Buf[0] - ((band1Buf[0] + 1) >> 1);

        ++band0Buf;

        for (int i = 0; i < wavelet->width - 3; i += 2)
        {
          int32_t delta = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
          lineBufH0[1] = band1Buf[0] + ((lineBufH0[0] + delta) >> 1);
          lineBufH0[2] = delta;

          ++band0Buf;
          ++band1Buf;
          lineBufH0 += 2;
        }

        if (comp->tileFlag & E_HAS_TILES_ON_THE_RIGHT)
        {
          int32_t delta = band0Buf[0] - ((band1Buf[0] + band1Buf[1] + 2) >> 2);
          lineBufH0[1] = band1Buf[0] + ((lineBufH0[0] + delta) >> 1);
          lineBufH0[2] = delta;
        }
        else if (wavelet->width & 1)
        {
          int32_t delta = band0Buf[0] - ((band1Buf[0] + 1) >> 1);
          lineBufH0[1] = band1Buf[0] + ((lineBufH0[0] + delta) >> 1);
          lineBufH0[2] = delta;
        }
        else
        {
          lineBufH0[1] = band1Buf[0] + lineBufH0[0];
        }
      }
      ++wavelet->curLine;
      ++wavelet->curH;
      wavelet->fltTapH = (wavelet->fltTapH + 1) % 5;
    }
  }

  return 0;
}

void crxFreeSubbandData(CrxImage *image, CrxPlaneComp *comp)
{
  if (comp->compBuf)
  {
    free(comp->compBuf);
    comp->compBuf = 0;
  }

  if (!comp->subBands)
    return;

  for (int32_t i = 0; i < image->subbandCount; i++)
  {
    if (comp->subBands[i].bandParam)
    {
      free(comp->subBands[i].bandParam);
      comp->subBands[i].bandParam = 0LL;
    }

    comp->subBands[i].bandBuf = 0;
    comp->subBands[i].bandSize = 0;
  }
}

void crxConvertPlaneLine(CrxImage *img, int imageRow, int imageCol = 0, int plane = 0, int32_t *lineData = 0,
                         int lineLength = 0)
{
  if (lineData)
  {
    uint64_t rawOffset = 4 * img->planeWidth * imageRow + 2 * imageCol;
    if (img->encType == 1)
    {
      int32_t maxVal = 1 << (img->nBits - 1);
      int32_t minVal = -maxVal;
      --maxVal;
      for (int i = 0; i < lineLength; i++)
        img->outBufs[plane][rawOffset + 2 * i] = _constrain(lineData[i], minVal, maxVal);
    }
    else if (img->encType == 3)
    {
      // copy to intermediate planeBuf
      rawOffset = plane * img->planeWidth * img->planeHeight + img->planeWidth * imageRow + imageCol;
      for (int i = 0; i < lineLength; i++)
        img->planeBuf[rawOffset + i] = lineData[i];
    }
    else if (img->nPlanes == 4)
    {
      int32_t median = 1 << (img->nBits - 1);
      int32_t maxVal = (1 << img->nBits) - 1;
      for (int i = 0; i < lineLength; i++)
        img->outBufs[plane][rawOffset + 2 * i] = _constrain(median + lineData[i], 0, maxVal);
    }
    else if (img->nPlanes == 1)
    {
      int32_t maxVal = (1 << img->nBits) - 1;
      int32_t median = 1 << (img->nBits - 1);
      rawOffset = img->planeWidth * imageRow + imageCol;
      for (int i = 0; i < lineLength; i++)
        img->outBufs[0][rawOffset + i] = _constrain(median + lineData[i], 0, maxVal);
    }
  }
  else if (img->encType == 3 && img->planeBuf)
  {
    int32_t planeSize = img->planeWidth * img->planeHeight;
    int16_t *plane0 = img->planeBuf + imageRow * img->planeWidth;
    int16_t *plane1 = plane0 + planeSize;
    int16_t *plane2 = plane1 + planeSize;
    int16_t *plane3 = plane2 + planeSize;

    int32_t median = 1 << (img->nBits - 1) << 10;
    int32_t maxVal = (1 << img->nBits) - 1;
    uint32_t rawLineOffset = 4 * img->planeWidth * imageRow;

    // for this stage - all except imageRow is ignored
    for (int i = 0; i < img->planeWidth; i++)
    {
      int32_t gr = median + (plane0[i] << 10) - 168 * plane1[i] - 585 * plane3[i];
      int32_t val = 0;
      if (gr < 0)
        gr = -(((_abs(gr) + 512) >> 9) & ~1);
      else
        gr = ((_abs(gr) + 512) >> 9) & ~1;

      // Essentially R = round(median + P0 + 1.474*P3)
      val = (median + (plane0[i] << 10) + 1510 * plane3[i] + 512) >> 10;
      img->outBufs[0][rawLineOffset + 2 * i] = _constrain(val, 0, maxVal);
      // Essentially G1 = round(median + P0 + P2 - 0.164*P1 - 0.571*P3)
      val = (plane2[i] + gr + 1) >> 1;
      img->outBufs[1][rawLineOffset + 2 * i] = _constrain(val, 0, maxVal);
      // Essentially G2 = round(median + P0 - P2 - 0.164*P1 - 0.571*P3)
      val = (gr - plane2[i] + 1) >> 1;
      img->outBufs[2][rawLineOffset + 2 * i] = _constrain(val, 0, maxVal);
      // Essentially B = round(median + P0 + 1.881*P1)
      val = (median + (plane0[i] << 10) + 1927 * plane1[i] + 512) >> 10;
      img->outBufs[3][rawLineOffset + 2 * i] = _constrain(val, 0, maxVal);
    }
  }
}

int crxParamInit(CrxImage *img, CrxBandParam **param, uint64_t subbandMdatOffset, uint64_t subbandDataSize,
                 uint32_t subbandWidth, uint32_t subbandHeight, bool supportsPartial, uint32_t roundedBitsMask)
{
  int32_t progrDataSize = supportsPartial ? 0 : sizeof(int32_t) * subbandWidth;
  int32_t paramLength = 2 * subbandWidth + 4;
  uint8_t *paramBuf = 0;
#if  defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
#pragma omp critical
  {
#else
  img->input->lock();
#endif
#endif
    paramBuf = (uint8_t *)
#ifdef LIBRAW_CR3_MEMPOOL
                   img->memmgr.
#endif
               calloc(1, sizeof(CrxBandParam) + sizeof(int32_t) * paramLength + progrDataSize);

#if  defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
  }
#else
  img->input->unlock();
#endif
#endif

  if (!paramBuf)
    return -1;

  *param = (CrxBandParam *)paramBuf;

  paramBuf += sizeof(CrxBandParam);

  (*param)->paramData = (int32_t *)paramBuf;
  (*param)->nonProgrData = progrDataSize ? (*param)->paramData + paramLength : 0;
  (*param)->subbandWidth = subbandWidth;
  (*param)->subbandHeight = subbandHeight;
  (*param)->roundedBits = 0;
  (*param)->curLine = 0;
  (*param)->roundedBitsMask = roundedBitsMask;
  (*param)->supportsPartial = supportsPartial;
  (*param)->bitStream.bitData = 0;
  (*param)->bitStream.bitsLeft = 0;
  (*param)->bitStream.mdatSize = subbandDataSize;
  (*param)->bitStream.curPos = 0;
  (*param)->bitStream.curBufSize = 0;
  (*param)->bitStream.curBufOffset = subbandMdatOffset;
  (*param)->bitStream.input = img->input;

  crxFillBuffer(&(*param)->bitStream);

  return 0;
}

int crxSetupSubbandData(CrxImage *img, CrxPlaneComp *planeComp, const CrxTile *tile, uint32_t mdatOffset)
{
  long compDataSize = 0;
  long waveletDataOffset = 0;
  long compCoeffDataOffset = 0;
  int32_t toSubbands = 3 * img->levels + 1;
  int32_t transformWidth = 0;

  CrxSubband *subbands = planeComp->subBands;

  // calculate sizes
  for (int32_t subbandNum = 0; subbandNum < toSubbands; subbandNum++)
  {
    subbands[subbandNum].bandSize = subbands[subbandNum].width * sizeof(int32_t); // 4bytes
    compDataSize += subbands[subbandNum].bandSize;
  }

  if (img->levels)
  {
    int32_t encLevels = img->levels ? img->levels : 1;
    waveletDataOffset = (compDataSize + 7) & ~7;
    compDataSize = (sizeof(CrxWaveletTransform) * encLevels + waveletDataOffset + 7) & ~7;
    compCoeffDataOffset = compDataSize;

    // calc wavelet line buffer sizes (always at one level up from current)
    for (int level = 0; level < img->levels; ++level)
      if (level < img->levels - 1)
        compDataSize += 8 * sizeof(int32_t) * planeComp->subBands[3 * (level + 1) + 2].width;
      else
        compDataSize += 8 * sizeof(int32_t) * tile->width;
  }
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
#pragma omp critical
  {
#else
  img->input->lock();
#endif
#endif
    // buffer allocation
    planeComp->compBuf = (uint8_t *)
#ifdef LIBRAW_CR3_MEMPOOL
                             img->memmgr.
#endif
                         malloc(compDataSize);
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
  }
#else
  img->input->unlock();
#endif
#endif
  if (!planeComp->compBuf)
    return -1;

  // subbands buffer and sizes initialisation
  uint64_t subbandMdatOffset = img->mdatOffset + mdatOffset;
  uint8_t *subbandBuf = planeComp->compBuf;

  for (int32_t subbandNum = 0; subbandNum < toSubbands; subbandNum++)
  {
    subbands[subbandNum].bandBuf = subbandBuf;
    subbandBuf += subbands[subbandNum].bandSize;
    subbands[subbandNum].mdatOffset = subbandMdatOffset + subbands[subbandNum].dataOffset;
  }

  // wavelet data initialisation
  if (img->levels)
  {
    CrxWaveletTransform *waveletTransforms = (CrxWaveletTransform *)(planeComp->compBuf + waveletDataOffset);
    int32_t *paramData = (int32_t *)(planeComp->compBuf + compCoeffDataOffset);

    planeComp->wvltTransform = waveletTransforms;
    waveletTransforms[0].subband0Buf = (int32_t *)subbands->bandBuf;

    for (int level = 0; level < img->levels; ++level)
    {
      int32_t band = 3 * level + 1;

      if (level >= img->levels - 1)
      {
        waveletTransforms[level].height = tile->height;
        transformWidth = tile->width;
      }
      else
      {
        waveletTransforms[level].height = subbands[band + 3].height;
        transformWidth = subbands[band + 4].width;
      }
      waveletTransforms[level].width = transformWidth;
      waveletTransforms[level].lineBuf[0] = paramData;
      waveletTransforms[level].lineBuf[1] = waveletTransforms[level].lineBuf[0] + transformWidth;
      waveletTransforms[level].lineBuf[2] = waveletTransforms[level].lineBuf[1] + transformWidth;
      waveletTransforms[level].lineBuf[3] = waveletTransforms[level].lineBuf[2] + transformWidth;
      waveletTransforms[level].lineBuf[4] = waveletTransforms[level].lineBuf[3] + transformWidth;
      waveletTransforms[level].lineBuf[5] = waveletTransforms[level].lineBuf[4] + transformWidth;
      waveletTransforms[level].lineBuf[6] = waveletTransforms[level].lineBuf[5] + transformWidth;
      waveletTransforms[level].lineBuf[7] = waveletTransforms[level].lineBuf[6] + transformWidth;
      waveletTransforms[level].curLine = 0;
      waveletTransforms[level].curH = 0;
      waveletTransforms[level].fltTapH = 0;
      waveletTransforms[level].subband1Buf = (int32_t *)subbands[band].bandBuf;
      waveletTransforms[level].subband2Buf = (int32_t *)subbands[band + 1].bandBuf;
      waveletTransforms[level].subband3Buf = (int32_t *)subbands[band + 2].bandBuf;

      paramData = waveletTransforms[level].lineBuf[7] + transformWidth;
    }
  }

  // decoding params and bitstream initialisation
  for (int32_t subbandNum = 0; subbandNum < toSubbands; subbandNum++)
  {
    if (subbands[subbandNum].dataSize)
    {
      bool supportsPartial = false;
      uint32_t roundedBitsMask = 0;

      if (planeComp->supportsPartial && subbandNum == 0)
      {
        roundedBitsMask = planeComp->roundedBitsMask;
        supportsPartial = true;
      }
      if (crxParamInit(img, &subbands[subbandNum].bandParam, subbands[subbandNum].mdatOffset,
                       subbands[subbandNum].dataSize, subbands[subbandNum].width, subbands[subbandNum].height,
                       supportsPartial, roundedBitsMask))
        return -1;
    }
  }

  return 0;
}

int LibRaw::crxDecodePlane(void *p, uint32_t planeNumber)
{
  CrxImage *img = (CrxImage *)p;
  int imageRow = 0;
  for (int tRow = 0; tRow < img->tileRows; tRow++)
  {
    int imageCol = 0;
    for (int tCol = 0; tCol < img->tileCols; tCol++)
    {
      CrxTile *tile = img->tiles + tRow * img->tileCols + tCol;
      CrxPlaneComp *planeComp = tile->comps + planeNumber;
      uint64_t tileMdatOffset = tile->dataOffset + tile->mdatQPDataSize + tile->mdatExtraSize + planeComp->dataOffset;

      // decode single tile
      if (crxSetupSubbandData(img, planeComp, tile, tileMdatOffset))
        return -1;

      if (img->levels)
      {
        if (crxIdwt53FilterInitialize(planeComp, img->levels, tile->qStep))
          return -1;
        for (int i = 0; i < tile->height; ++i)
        {
          if (crxIdwt53FilterDecode(planeComp, img->levels - 1, tile->qStep) ||
              crxIdwt53FilterTransform(planeComp, img->levels - 1))
            return -1;
          int32_t *lineData = crxIdwt53FilterGetLine(planeComp, img->levels - 1);
          crxConvertPlaneLine(img, imageRow + i, imageCol, planeNumber, lineData, tile->width);
        }
      }
      else
      {
        // we have the only subband in this case
        if (!planeComp->subBands->dataSize)
        {
          memset(planeComp->subBands->bandBuf, 0, planeComp->subBands->bandSize);
          return 0;
        }

        for (int i = 0; i < tile->height; ++i)
        {
          if (crxDecodeLine(planeComp->subBands->bandParam, planeComp->subBands->bandBuf))
            return -1;
          int32_t *lineData = (int32_t *)planeComp->subBands->bandBuf;
          crxConvertPlaneLine(img, imageRow + i, imageCol, planeNumber, lineData, tile->width);
        }
      }
      imageCol += tile->width;
    }
    imageRow += img->tiles[tRow * img->tileCols].height;
  }

  return 0;
}

uint32_t crxReadQP(CrxBitstream *bitStrm, int32_t kParam)
{
  uint32_t qp = crxBitstreamGetZeros(bitStrm);
  if (qp >= 23)
    qp = crxBitstreamGetBits(bitStrm, 8);
  else if (kParam)
    qp = crxBitstreamGetBits(bitStrm, kParam) | (qp << kParam);

  return qp;
}

void crxDecodeGolombTop(CrxBitstream *bitStrm, int32_t width, int32_t *lineBuf, int32_t *kParam)
{
  lineBuf[0] = 0;
  while (width-- > 0)
  {
    lineBuf[1] = lineBuf[0];
    uint32_t qp = crxReadQP(bitStrm, *kParam);
    lineBuf[1] += -(qp & 1) ^ (qp >> 1);
    *kParam = crxPredictKParameter(*kParam, qp, 7);
    ++lineBuf;
  }
  lineBuf[1] = lineBuf[0] + 1;
}

void crxDecodeGolombNormal(CrxBitstream *bitStrm, int32_t width, int32_t *lineBuf0, int32_t *lineBuf1, int32_t *kParam)
{
  lineBuf1[0] = lineBuf0[1];
  int32_t deltaH = lineBuf0[1] - lineBuf0[0];
  while (width-- > 0)
  {
    lineBuf1[1] = crxPrediction(lineBuf1[0], lineBuf0[1], deltaH, lineBuf0[0] - lineBuf1[0]);
    uint32_t qp = crxReadQP(bitStrm, *kParam);
    lineBuf1[1] += -(qp & 1) ^ (qp >> 1);
    if (width)
    {
      deltaH = lineBuf0[2] - lineBuf0[1];
      *kParam = crxPredictKParameter(*kParam, (qp + 2 * _abs(deltaH)) >> 1, 7);
      ++lineBuf0;
    }
    else
      *kParam = crxPredictKParameter(*kParam, qp, 7);
    ++lineBuf1;
  }
  lineBuf1[1] = lineBuf1[0] + 1;
}

int crxMakeQStep(CrxImage *img, CrxTile *tile, int32_t *qpTable, uint32_t totalQP)
{
  if (img->levels > 3 || img->levels < 1)
    return -1;
  int qpWidth = (tile->width >> 3) + ((tile->width & 7) != 0);
  int qpHeight = (tile->height >> 1) + (tile->height & 1);
  int qpHeight4 = (tile->height >> 2) + ((tile->height & 3) != 0);
  int qpHeight8 = (tile->height >> 3) + ((tile->height & 7) != 0);
  uint32_t totalHeight = qpHeight;
  if (img->levels > 1)
    totalHeight += qpHeight4;
  if (img->levels > 2)
    totalHeight += qpHeight8;
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
#pragma omp critical
  {
#else
  img->input->lock();
#endif
#endif
    tile->qStep = (CrxQStep *)
#ifdef LIBRAW_CR3_MEMPOOL
                      img->memmgr.
#endif
                  malloc(totalHeight * qpWidth * sizeof(uint32_t) + img->levels * sizeof(CrxQStep));
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
  }
#else
  img->input->unlock();
#endif
#endif

  if (!tile->qStep)
    return -1;
  uint32_t *qStepTbl = (uint32_t *)(tile->qStep + img->levels);
  CrxQStep *qStep = tile->qStep;
  switch (img->levels)
  {
  case 3:
    qStep->qStepTbl = qStepTbl;
    qStep->width = qpWidth;
    qStep->height = qpHeight8;
    for (int qpRow = 0; qpRow < qpHeight8; ++qpRow)
    {
      int row0Idx = qpWidth * _min(4 * qpRow, qpHeight - 1);
      int row1Idx = qpWidth * _min(4 * qpRow + 1, qpHeight - 1);
      int row2Idx = qpWidth * _min(4 * qpRow + 2, qpHeight - 1);
      int row3Idx = qpWidth * _min(4 * qpRow + 3, qpHeight - 1);

      for (int qpCol = 0; qpCol < qpWidth; ++qpCol, ++qStepTbl)
      {
        int32_t quantVal = qpTable[row0Idx++] + qpTable[row1Idx++] + qpTable[row2Idx++] + qpTable[row3Idx++];
        // not sure about this nonsense - why is it not just avg like with 2 levels?
        quantVal = ((quantVal < 0) * 3 + quantVal) >> 2;
        if (quantVal / 6 >= 6)
          *qStepTbl = q_step_tbl[quantVal % 6] * (1 << (quantVal / 6 + 26));
        else
          *qStepTbl = q_step_tbl[quantVal % 6] >> (6 - quantVal / 6);
      }
    }
    // continue to the next level - we always decode all levels
    ++qStep;
  case 2:
    qStep->qStepTbl = qStepTbl;
    qStep->width = qpWidth;
    qStep->height = qpHeight4;
    for (int qpRow = 0; qpRow < qpHeight4; ++qpRow)
    {
      int row0Idx = qpWidth * _min(2 * qpRow, qpHeight - 1);
      int row1Idx = qpWidth * _min(2 * qpRow + 1, qpHeight - 1);

      for (int qpCol = 0; qpCol < qpWidth; ++qpCol, ++qStepTbl)
      {
        int32_t quantVal = (qpTable[row0Idx++] + qpTable[row1Idx++]) / 2;
        if (quantVal / 6 >= 6)
          *qStepTbl = q_step_tbl[quantVal % 6] * (1 << (quantVal / 6 + 26));
        else
          *qStepTbl = q_step_tbl[quantVal % 6] >> (6 - quantVal / 6);
      }
    }
    // continue to the next level - we always decode all levels
    ++qStep;
  case 1:
    qStep->qStepTbl = qStepTbl;
    qStep->width = qpWidth;
    qStep->height = qpHeight;
    for (int qpRow = 0; qpRow < qpHeight; ++qpRow)
      for (int qpCol = 0; qpCol < qpWidth; ++qpCol, ++qStepTbl, ++qpTable)
        if (*qpTable / 6 >= 6)
          *qStepTbl = q_step_tbl[*qpTable % 6] * (1 << (*qpTable / 6 + 26));
        else
          *qStepTbl = q_step_tbl[*qpTable % 6] >> (6 - *qpTable / 6);

    break;
  }
  return 0;
}

libraw_inline void crxSetupSubbandIdx(rawspeed::crx_data_header_t *hdr, CrxImage *img, CrxSubband *band, int level,
                                      short colStartIdx, short bandWidthExCoef, short rowStartIdx,
                                      short bandHeightExCoef)
{
  if (hdr->version == 0x200)
  {
    band->rowStartAddOn = rowStartIdx;
    band->rowEndAddOn = bandHeightExCoef;
    band->colStartAddOn = colStartIdx;
    band->colEndAddOn = bandWidthExCoef;
    band->levelShift = 3 - level;
  }
  else
  {
    band->rowStartAddOn = 0;
    band->rowEndAddOn = 0;
    band->colStartAddOn = 0;
    band->colEndAddOn = 0;
    band->levelShift = 0;
  }
}

int crxProcessSubbands(rawspeed::crx_data_header_t *hdr, CrxImage *img, CrxTile *tile, CrxPlaneComp *comp)
{
  CrxSubband *band = comp->subBands + img->subbandCount - 1; // set to last band
  uint32_t bandHeight = tile->height;
  uint32_t bandWidth = tile->width;
  int32_t bandWidthExCoef = 0;
  int32_t bandHeightExCoef = 0;
  if (img->levels)
  {
    // Build up subband sequences to crxDecode to a level in a header

    // Coefficient structure is a bit unclear and convoluted:
    //   3 levels max - 8 groups (for tile width rounded to 8 bytes)
    //                  of 3 band per level 4 sets of coefficients for each
    int32_t *rowExCoef = exCoefNumTbl + 0x30 * (img->levels - 1) + 6 * (tile->width & 7);
    int32_t *colExCoef = exCoefNumTbl + 0x30 * (img->levels - 1) + 6 * (tile->height & 7);
    for (int level = 0; level < img->levels; ++level)
    {
      int32_t widthOddPixel = bandWidth & 1;
      int32_t heightOddPixel = bandHeight & 1;
      bandWidth = (widthOddPixel + bandWidth) >> 1;
      bandHeight = (heightOddPixel + bandHeight) >> 1;

      int32_t bandWidthExCoef0 = 0;
      int32_t bandWidthExCoef1 = 0;
      int32_t bandHeightExCoef0 = 0;
      int32_t bandHeightExCoef1 = 0;
      int32_t colStartIdx = 0;
      int32_t rowStartIdx = 0;
      if (tile->tileFlag & E_HAS_TILES_ON_THE_RIGHT)
      {
        bandWidthExCoef0 = rowExCoef[2 * level];
        bandWidthExCoef1 = rowExCoef[2 * level + 1];
      }
      if (tile->tileFlag & E_HAS_TILES_ON_THE_LEFT)
      {
        ++bandWidthExCoef0;
        colStartIdx = 1;
      }

      if (tile->tileFlag & E_HAS_TILES_ON_THE_BOTTOM)
      {
        bandHeightExCoef0 = colExCoef[2 * level];
        bandHeightExCoef1 = colExCoef[2 * level + 1];
      }
      if (tile->tileFlag & E_HAS_TILES_ON_THE_TOP)
      {
        ++bandHeightExCoef0;
        rowStartIdx = 1;
      }

      band[0].width = bandWidth + bandWidthExCoef0 - widthOddPixel;
      band[0].height = bandHeight + bandHeightExCoef0 - heightOddPixel;
      crxSetupSubbandIdx(hdr, img, band, level + 1, colStartIdx, bandWidthExCoef0 - colStartIdx, rowStartIdx,
                         bandHeightExCoef0 - rowStartIdx);

      band[-1].width = bandWidth + bandWidthExCoef1;
      band[-1].height = bandHeight + bandHeightExCoef0 - heightOddPixel;

      crxSetupSubbandIdx(hdr, img, band - 1, level + 1, 0, bandWidthExCoef1, rowStartIdx,
                         bandHeightExCoef0 - rowStartIdx);

      band[-2].width = bandWidth + bandWidthExCoef0 - widthOddPixel;
      band[-2].height = bandHeight + bandHeightExCoef1;
      crxSetupSubbandIdx(hdr, img, band - 2, level + 1, colStartIdx, bandWidthExCoef0 - colStartIdx, 0,
                         bandHeightExCoef1);

      band -= 3;
    }
    bandWidthExCoef = bandHeightExCoef = 0;
    if (tile->tileFlag & E_HAS_TILES_ON_THE_RIGHT)
      bandWidthExCoef = rowExCoef[2 * img->levels - 1];
    if (tile->tileFlag & E_HAS_TILES_ON_THE_BOTTOM)
      bandHeightExCoef = colExCoef[2 * img->levels - 1];
  }
  band->width = bandWidthExCoef + bandWidth;
  band->height = bandHeightExCoef + bandHeight;
  if (img->levels)
    crxSetupSubbandIdx(hdr, img, band, img->levels, 0, bandWidthExCoef, 0, bandHeightExCoef);

  return 0;
}

int crxReadSubbandHeaders(rawspeed::crx_data_header_t *hdr, CrxImage *img, CrxTile *tile, CrxPlaneComp *comp,
                          const uint8_t **subbandMdatPtr, int32_t *mdatSize)
{
  if (!img->subbandCount)
    return 0;
  int32_t subbandOffset = 0;
  CrxSubband *band = comp->subBands;
  for (int curSubband = 0; curSubband < img->subbandCount; curSubband++, band++)
  {
    if (*mdatSize < 4)
      return -1;

    int hdrSign = LibRaw::sgetn(2, *subbandMdatPtr);
    rawspeed::writeLog(rawspeed::DEBUG_PRIO_EXTRA, "mdat subband header %d", hdrSign);
    int hdrSize = LibRaw::sgetn(2, *subbandMdatPtr + 2);
    rawspeed::writeLog(rawspeed::DEBUG_PRIO_EXTRA, "mdat subband header size %d", hdrSize);
    if (*mdatSize < hdrSize + 4)
      return -1;
    if ((hdrSign != 0xFF03 || hdrSize != 8) && (hdrSign != 0xFF13 || hdrSize != 16))
      return -1;

    int32_t subbandSize = LibRaw::sgetn(4, *subbandMdatPtr + 4);

    if (curSubband != ((*subbandMdatPtr)[8] & 0xF0) >> 4)
    {
      band->dataSize = subbandSize;
      return -1;
    }

    band->dataOffset = subbandOffset;
    band->kParam = 0;
    band->bandParam = 0;
    band->bandBuf = 0;
    band->bandSize = 0;

    if (hdrSign == 0xFF03)
    {
      // old header
      uint32_t bitData = LibRaw::sgetn(4, *subbandMdatPtr + 8);
      band->dataSize = subbandSize - (bitData & 0x7FFFF);
      band->supportsPartial = bitData & 0x8000000;
      band->qParam = (bitData >> 19) & 0xFF;
      band->qStepBase = 0;
      band->qStepMult = 0;
    }
    else
    {
      // new header
      if (LibRaw::sgetn(2, *subbandMdatPtr + 8) & 0xFFF)
        // partial and qParam are not supported
        return -1;
      if (LibRaw::sgetn(2, *subbandMdatPtr + 18))
        // new header terninated by 2 zero bytes
        return -1;
      band->supportsPartial = false;
      band->qParam = 0;
      band->dataSize = subbandSize - LibRaw::sgetn(2, *subbandMdatPtr + 16);
      band->qStepBase = LibRaw::sgetn(4, *subbandMdatPtr + 12);
      ;
      band->qStepMult = LibRaw::sgetn(2, *subbandMdatPtr + 10);
      ;
    }

    subbandOffset += subbandSize;

    *subbandMdatPtr += hdrSize + 4;
    *mdatSize -= hdrSize + 4;
  }

  return 0;
}

int crxReadImageHeaders(rawspeed::crx_data_header_t *hdr, CrxImage *img, const uint8_t *mdatPtr, int32_t mdatHdrSize)
{
  int nTiles = img->tileRows * img->tileCols;

  if (!nTiles)
    ThrowRDE("Couldn't run libRaw");

  if (!img->tiles)
  {
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
#pragma omp critical
    {
#else
    img->input->lock();
#endif
#endif

      img->tiles = (CrxTile *)
#ifdef LIBRAW_CR3_MEMPOOL
                       img->memmgr.
#endif
                   calloc(sizeof(CrxTile) * nTiles + sizeof(CrxPlaneComp) * nTiles * img->nPlanes +
                              sizeof(CrxSubband) * nTiles * img->nPlanes * img->subbandCount,
                          1);
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
    }
#else
    img->input->unlock();
#endif
#endif

    if (!img->tiles)
      ThrowRDE("Couldn't run libRaw");

    // memory areas in allocated chunk
    CrxTile *tile = img->tiles;
    CrxPlaneComp *comps = (CrxPlaneComp *)(tile + nTiles);
    CrxSubband *bands = (CrxSubband *)(comps + img->nPlanes * nTiles);

    for (int curTile = 0; curTile < nTiles; curTile++, tile++)
    {
      tile->tileFlag = 0; // tile neighbouring flags
      tile->tileNumber = curTile;
      tile->tileSize = 0;
      tile->comps = comps + curTile * img->nPlanes;

      if ((curTile + 1) % img->tileCols)
      {
        // not the last tile in a tile row
        tile->width = hdr->tileWidth;
        if (img->tileCols > 1)
        {
          tile->tileFlag = E_HAS_TILES_ON_THE_RIGHT;
          if (curTile % img->tileCols)
            // not the first tile in tile row
            tile->tileFlag |= E_HAS_TILES_ON_THE_LEFT;
        }
      }
      else
      {
        // last tile in a tile row
        tile->width = img->planeWidth - hdr->tileWidth * (img->tileCols - 1);
        if (img->tileCols > 1)
          tile->tileFlag = E_HAS_TILES_ON_THE_LEFT;
      }
      if (curTile < nTiles - img->tileCols)
      {
        // in first tile row
        tile->height = hdr->tileHeight;
        if (img->tileRows > 1)
        {
          tile->tileFlag |= E_HAS_TILES_ON_THE_BOTTOM;
          if (curTile >= img->tileCols)
            tile->tileFlag |= E_HAS_TILES_ON_THE_TOP;
        }
      }
      else
      {
        // non first tile row
        tile->height = img->planeHeight - hdr->tileHeight * (img->tileRows - 1);
        if (img->tileRows > 1)
          tile->tileFlag |= E_HAS_TILES_ON_THE_TOP;
      }
      if (img->nPlanes)
      {
        CrxPlaneComp *comp = tile->comps;
        CrxSubband *band = bands + curTile * img->nPlanes * img->subbandCount;

        for (int curComp = 0; curComp < img->nPlanes; curComp++, comp++)
        {
          comp->compNumber = curComp;
          comp->supportsPartial = true;
          comp->tileFlag = tile->tileFlag;
          comp->subBands = band;
          comp->compBuf = 0;
          comp->wvltTransform = 0;
          if (img->subbandCount)
          {
            for (int curBand = 0; curBand < img->subbandCount; curBand++, band++)
            {
              band->supportsPartial = false;
              band->qParam = 4;
              band->bandParam = 0;
              band->dataSize = 0;
            }
          }
        }
      }
    }
  }

  uint32_t tileOffset = 0;
  int32_t dataSize = mdatHdrSize;
  const uint8_t *dataPtr = mdatPtr;
  CrxTile *tile = img->tiles;

  for (int curTile = 0; curTile < nTiles; ++curTile, ++tile)
  {
    if (dataSize < 4)
      ThrowRDE("Couldn't run libRaw");

    int hdrSign = LibRaw::sgetn(2, dataPtr);
    int hdrSize = LibRaw::sgetn(2, dataPtr + 2);
    if ((hdrSign != 0xFF01 || hdrSize != 8) && (hdrSign != 0xFF11 || (hdrSize != 8 && hdrSize != 16)))
      ThrowRDE("Couldn't run libRaw");
    if (dataSize < hdrSize + 4)
      ThrowRDE("Couldn't run libRaw");
    int tailSign = LibRaw::sgetn(2, dataPtr + 10);
    if ((hdrSize == 8 && tailSign) || (hdrSize == 16 && tailSign != 0x4000))
      ThrowRDE("Couldn't run libRaw");
    if (LibRaw::sgetn(2, dataPtr + 8) != (unsigned)curTile)
      ThrowRDE("Couldn't run libRaw");

    dataSize -= hdrSize + 4;

    tile->tileSize = LibRaw::sgetn(4, dataPtr + 4);
    tile->dataOffset = tileOffset;
    tile->qStep = 0;
    if (hdrSize == 16)
    {
      // extended header data - terminated by 0 bytes
      if (LibRaw::sgetn(2, dataPtr + 18) != 0)
        return -1;
      tile->hasQPData = true;
      tile->mdatQPDataSize = LibRaw::sgetn(4, dataPtr + 12);
      tile->mdatExtraSize = LibRaw::sgetn(2, dataPtr + 16);
    }
    else
    {
      tile->hasQPData = false;
      tile->mdatQPDataSize = 0;
      tile->mdatExtraSize = 0;
    }

    dataPtr += hdrSize + 4;
    tileOffset += tile->tileSize;

    uint32_t compOffset = 0;
    CrxPlaneComp *comp = tile->comps;

    for (int compNum = 0; compNum < img->nPlanes; ++compNum, ++comp)
    {
      if (dataSize < 0xC)
        ThrowRDE("Couldn't run libRaw");
      hdrSign = LibRaw::sgetn(2, dataPtr);
      hdrSize = LibRaw::sgetn(2, dataPtr + 2);
      if ((hdrSign != 0xFF02 && hdrSign != 0xFF12) || hdrSize != 8)
        ThrowRDE("Couldn't run libRaw");
      if (compNum != dataPtr[8] >> 4)
        ThrowRDE("Couldn't run libRaw");
      if (LibRaw::sgetn(3, dataPtr + 9) != 0)
        ThrowRDE("Couldn't run libRaw");

      comp->compSize = LibRaw::sgetn(4, dataPtr + 4);

      int32_t compHdrRoundedBits = (dataPtr[8] >> 1) & 3;
      comp->supportsPartial = (dataPtr[8] & 8) != 0;

      comp->dataOffset = compOffset;
      comp->tileFlag = tile->tileFlag;

      compOffset += comp->compSize;
      dataSize -= 0xC;
      dataPtr += 0xC;

      comp->roundedBitsMask = 0;

      if (compHdrRoundedBits)
      {
        if (img->levels || !comp->supportsPartial)
          ThrowRDE("Couldn't run libRaw");

        comp->roundedBitsMask = 1 << (compHdrRoundedBits - 1);
      }

      if (crxReadSubbandHeaders(hdr, img, tile, comp, &dataPtr, &dataSize) || crxProcessSubbands(hdr, img, tile, comp))
        ThrowRDE("Couldn't run libRaw");
    }
  }

  if (hdr->version != 0x200)
    return 0;

  tile = img->tiles;
  for (int curTile = 0; curTile < nTiles; ++curTile, ++tile)
  {
    if (tile->hasQPData)
    {
      CrxBitstream bitStrm;
      bitStrm.bitData = 0;
      bitStrm.bitsLeft = 0;
      bitStrm.curPos = 0;
      bitStrm.curBufSize = 0;
      bitStrm.mdatSize = tile->mdatQPDataSize;
      bitStrm.curBufOffset = img->mdatOffset + tile->dataOffset;
      bitStrm.input = img->input;

      crxFillBuffer(&bitStrm);

      unsigned int qpWidth = (tile->width >> 3) + ((tile->width & 7) != 0);
      unsigned int qpHeight = (tile->height >> 1) + (tile->height & 1);
      unsigned long totalQP = qpHeight * qpWidth;

      try
      {
        std::vector<int32_t> qpTable(totalQP + 2 * (qpWidth + 2));
        int32_t *qpCurElem = qpTable.data();
        // 2 lines padded with extra pixels at the start and at the end
        int32_t *qpLineBuf = qpTable.data() + totalQP;
        int32_t kParam = 0;
        for (unsigned qpRow = 0; qpRow < qpHeight; ++qpRow)
        {
          int32_t *qpLine0 = qpRow & 1 ? qpLineBuf + qpWidth + 2 : qpLineBuf;
          int32_t *qpLine1 = qpRow & 1 ? qpLineBuf : qpLineBuf + qpWidth + 2;

          if (qpRow)
            crxDecodeGolombNormal(&bitStrm, qpWidth, qpLine0, qpLine1, &kParam);
          else
            crxDecodeGolombTop(&bitStrm, qpWidth, qpLine1, &kParam);

          for (unsigned qpCol = 0; qpCol < qpWidth; ++qpCol)
            *qpCurElem++ = qpLine1[qpCol + 1] + 4;
        }

        // now we read QP data - build tile QStep
        if (crxMakeQStep(img, tile, qpTable.data(), totalQP))
          ThrowRDE("Couldn't run libRaw");
      }
      catch (...)
      {
        ThrowRDE("Couldn't run libRaw");
      }
    }
  }

  return 0;
}

int crxSetupImageData(rawspeed::crx_data_header_t *hdr, CrxImage *img, int16_t *outBuf, uint64_t mdatOffset, uint32_t mdatSize,
                      const uint8_t *mdatHdrPtr, int32_t mdatHdrSize)
{

    printf(" mdatOffeset: %u \n", mdatOffset);
        printf(" mdatSite: %u \n", mdatSize);
        printf(" mdatHdrSize: %u \n", mdatHdrSize);


  int IncrBitTable[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0};

  img->planeWidth = hdr->f_width;
  img->planeHeight = hdr->f_height;

  if (hdr->tileWidth < 0x16 || hdr->tileHeight < 0x16 || img->planeWidth > 0x7FFF || img->planeHeight > 0x7FFF)
    ThrowRDE("Couldn't run libRaw");

  img->tileCols = (img->planeWidth + hdr->tileWidth - 1) / hdr->tileWidth;
  img->tileRows = (img->planeHeight + hdr->tileHeight - 1) / hdr->tileHeight;

  if (img->tileCols > 0xFF || img->tileRows > 0xFF || img->planeWidth - hdr->tileWidth * (img->tileCols - 1) < 0x16 ||
      img->planeHeight - hdr->tileHeight * (img->tileRows - 1) < 0x16)
    ThrowRDE("Couldn't run libRaw");

  img->tiles = 0;
  img->levels = hdr->imageLevels;
  img->subbandCount = 3 * img->levels + 1; // 3 bands per level + one last LL
  img->nPlanes = hdr->nPlanes;
  img->nBits = hdr->nBits;
  img->encType = hdr->encType;
  img->samplePrecision = hdr->nBits + IncrBitTable[4 * hdr->encType + 2] + 1;
  img->mdatOffset = mdatOffset + hdr->mdatHdrSize;
  img->mdatSize = mdatSize;
  img->planeBuf = 0;
  img->outBufs[0] = img->outBufs[1] = img->outBufs[2] = img->outBufs[3] = 0;

  // The encoding type 3 needs all 4 planes to be decoded to generate row of
  // RGGB values. It seems to be using some other colour space for raw encoding
  // It is a massive buffer so ideallly it will need a different approach:
  // decode planes line by line and convert single line then without
  // intermediate plane buffer. At the moment though it's too many changes so
  // left as is.
  if (img->encType == 3 && img->nPlanes == 4 && img->nBits > 8)
  {
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
#pragma omp critical
    {
#else
    img->input->lock();
#endif
#endif
      img->planeBuf = (int16_t *)
#ifdef LIBRAW_CR3_MEMPOOL
                          img->memmgr.
#endif
                      malloc(img->planeHeight * img->planeWidth * img->nPlanes * ((img->samplePrecision + 7) >> 3));
#if defined(LIBRAW_CR3_MEMPOOL)
#if defined(LIBRAW_USE_OPENMP)
    }
#else
    img->input->unlock();
#endif
#endif
    if (!img->planeBuf)
      ThrowRDE("Couldn't run libRaw");
  }

  int32_t rowSize = 2 * img->planeWidth;

  if (img->nPlanes == 1)
    img->outBufs[0] = outBuf;
  else
    switch (hdr->cfaLayout)
    {
    case 0:
      // R G
      // G B
      img->outBufs[0] = outBuf;
      img->outBufs[1] = outBuf + 1;
      img->outBufs[2] = outBuf + rowSize;
      img->outBufs[3] = img->outBufs[2] + 1;
      break;
    case 1:
      // G R
      // B G
      img->outBufs[1] = outBuf;
      img->outBufs[0] = outBuf + 1;
      img->outBufs[3] = outBuf + rowSize;
      img->outBufs[2] = img->outBufs[3] + 1;
      break;
    case 2:
      // G B
      // R G
      img->outBufs[2] = outBuf;
      img->outBufs[3] = outBuf + 1;
      img->outBufs[0] = outBuf + rowSize;
      img->outBufs[1] = img->outBufs[0] + 1;
      break;
    case 3:
      // B G
      // G R
      img->outBufs[3] = outBuf;
      img->outBufs[2] = outBuf + 1;
      img->outBufs[1] = outBuf + rowSize;
      img->outBufs[0] = img->outBufs[1] + 1;
      break;
    }

  // read header
  return crxReadImageHeaders(hdr, img, mdatHdrPtr, mdatHdrSize);
}

int crxFreeImageData(CrxImage *img)
{
#ifdef LIBRAW_CR3_MEMPOOL
  img->memmgr.cleanup();
#else
  CrxTile *tile = img->tiles;
  int nTiles = img->tileRows * img->tileCols;

  if (img->tiles)
  {
    for (int32_t curTile = 0; curTile < nTiles; curTile++)
    {
      if (tile[curTile].comps)
        for (int32_t curPlane = 0; curPlane < img->nPlanes; curPlane++)
          crxFreeSubbandData(img, tile[curTile].comps + curPlane);
      if (tile[curTile].qStep)
        free(tile[curTile].qStep);
    }
    free(img->tiles);
    img->tiles = 0;
  }

  if (img->planeBuf)
  {
    free(img->planeBuf);
    img->planeBuf = 0;
  }
#endif
  return 0;
}
void LibRaw::crxLoadDecodeLoop(void *img, int nPlanes)
{
#ifdef LIBRAW_USE_OPENMP
  int results[4]; // nPlanes is always <= 4
#pragma omp parallel for
  for (int32_t plane = 0; plane < nPlanes; ++plane)
    results[plane] = crxDecodePlane(img, plane);

  for (int32_t plane = 0; plane < nPlanes; ++plane)
    if (results[plane])
      derror();
#else
  for (int32_t plane = 0; plane < nPlanes; ++plane)
    if (crxDecodePlane(img, plane))
      derror();
#endif
}

void LibRaw::crxConvertPlaneLineDf(void *p, int imageRow) { crxConvertPlaneLine((CrxImage *)p, imageRow); }

void LibRaw::crxLoadFinalizeLoopE3(void *p, int planeHeight)
{
#ifdef LIBRAW_USE_OPENMP
#pragma omp parallel for
#endif
  for (int i = 0; i < planeHeight; ++i)
    crxConvertPlaneLineDf(p, i);
}

void LibRaw::crxLoadRaw(int16_t *outbuf)
{
  CrxImage img;
  /* TODO
  if (libraw_internal_data.unpacker_data.crx_track_selected < 0 ||
      libraw_internal_data.unpacker_data.crx_track_selected >= LIBRAW_CRXTRACKS_MAXCOUNT)
    derror();
    */

   // TODO: try const, seems hdr gets modified?
  rawspeed::crx_data_header_t hdr = *(data_header.get());
  // = TODO
  //    libraw_internal_data.unpacker_data.crx_header[libraw_internal_data.unpacker_data.crx_track_selected];

/* TODO
  if (libraw_internal_data.unpacker_data.data_size < (unsigned)hdr.mdatHdrSize)
    derror();
    */

   //img.input = new LibRaw_buffer_datastream(mdat_raw_image.getData(0, mdat_raw_image.getSize()), mdat_raw_image.getSize());
   img.input = new LibRaw_buffer_datastream(file_buf.begin(), file_buf.getSize());

   //img.input = new LibRaw_buffer_datastream(file_buf.begin(), 36083704);



  //img.input = NULL; // libraw_internal_data.internal_data.input; // DONE

  // update sizes for the planes
  if (hdr.nPlanes == 4)
  {
    hdr.f_width >>= 1;
    hdr.f_height >>= 1;
    hdr.tileWidth >>= 1;
    hdr.tileHeight >>= 1;
  }

    // FIXME
  //imgdata.color.maximum = (1 << hdr.nBits) - 1;

  //uint8_t *hdrBuf = (uint8_t *)malloc(hdr.mdatHdrSize);

  // read image header
#ifdef LIBRAW_USE_OPENMP
#pragma omp critical
#endif
  {

/*
#ifndef LIBRAW_USE_OPENMP
    img.input->lock();
#endif
     img.input->seek(mdat_trak3_offset, SEEK_SET); // data_offset = co64 for trak3
     img.input->read(hdrBuf, 1, hdr.mdatHdrSize);
#ifndef LIBRAW_USE_OPENMP
     img.input->unlock();

#endif
*/
  }

  // parse and setup the image data
  /*
  if (crxSetupImageData(&hdr, &img, (int16_t *)imgdata.rawdata.raw_image,
                        libraw_internal_data.unpacker_data.data_offset, libraw_internal_data.unpacker_data.data_size,
                        hdrBuf, hdr.mdatHdrSize))



    derror();
    */

rawspeed::writeLog(rawspeed::DEBUG_PRIO_EXTRA, "data_offset %u", mdat_trak3_offset);
rawspeed::writeLog(rawspeed::DEBUG_PRIO_EXTRA, "data_size %u", file_buf.getSize());

printf("mdathdr value: %x\n", *(uint32_t*)mdat_raw_image.getData(0, 4));

   if (crxSetupImageData(&hdr, &img, outbuf,
                        mdat_trak3_offset, trak3_size,
                        mdat_raw_image.begin(), hdr.mdatHdrSize))
    derror();
  //free(hdrBuf);


  crxLoadDecodeLoop(&img, hdr.nPlanes);

  if (img.encType == 3)
    crxLoadFinalizeLoopE3(&img, img.planeHeight);

  crxFreeImageData(&img);

  printf("final value: %x\n", ((uint64_t*)outbuf)[0]);
  printf("final value: %x\n", ((uint64_t*)outbuf)[1]);
  printf("final value: %x\n", ((uint64_t*)outbuf)[2]);
  printf("final value: %x\n", ((uint64_t*)outbuf)[3]);

}




// == LibRaw_buffer_datastream
LibRaw_buffer_datastream::LibRaw_buffer_datastream(const void *buffer, size_t bsize)
{
  buf = (unsigned char *)buffer;
  streampos = 0;
  streamsize = bsize;
}

LibRaw_buffer_datastream::~LibRaw_buffer_datastream() {}

int LibRaw_buffer_datastream::read(void *ptr, size_t sz, size_t nmemb)
{
  size_t to_read = sz * nmemb;
  if (to_read > streamsize - streampos)
    to_read = streamsize - streampos;
  if (to_read < 1)
    return 0;
  memmove(ptr, buf + streampos, to_read);
  streampos += to_read;
  return int((to_read + sz - 1) / (sz > 0 ? sz : 1));
}

int LibRaw_buffer_datastream::seek(INT64 o, int whence)
{
  switch (whence)
  {
  case SEEK_SET:
    if (o < 0)
      streampos = 0;
    else if (size_t(o) > streamsize)
      streampos = streamsize;
    else
      streampos = size_t(o);
    return 0;
  case SEEK_CUR:
    if (o < 0)
    {
      if (size_t(-o) >= streampos)
        streampos = 0;
      else
        streampos += (size_t)o;
    }
    else if (o > 0)
    {
      if (o + streampos > streamsize)
        streampos = streamsize;
      else
        streampos += (size_t)o;
    }
    return 0;
  case SEEK_END:
    if (o > 0)
      streampos = streamsize;
    else if (size_t(-o) > streamsize)
      streampos = 0;
    else
      streampos = streamsize + (size_t)o;
    return 0;
  default:
    return 0;
  }
}

INT64 LibRaw_buffer_datastream::tell()
{
  return INT64(streampos);
}

char *LibRaw_buffer_datastream::gets(char *s, int sz)
{
  if(sz<1) return NULL;
  unsigned char *psrc, *pdest, *str;
  str = (unsigned char *)s;
  psrc = buf + streampos;
  pdest = str;
  if(streampos >= streamsize) return NULL;
  while ((size_t(psrc - buf) < streamsize) && ((pdest - str) < (sz-1)))
  {
    *pdest = *psrc;
    if (*psrc == '\n')
      break;
    psrc++;
    pdest++;
  }
  if (size_t(psrc - buf) < streamsize)
    psrc++;
  if ((pdest - str) < sz-1)
    *(++pdest) = 0;
  else
    s[sz - 1] = 0; // ensure trailing zero

  streampos = psrc - buf;
  return s;
}

int LibRaw_buffer_datastream::scanf_one(const char *fmt, void *val)
{
  int scanf_res;
  if (streampos > streamsize)
    return 0;
#ifndef WIN32SECURECALLS
  scanf_res = sscanf((char *)(buf + streampos), fmt, val);
#else
  scanf_res = sscanf_s((char *)(buf + streampos), fmt, val);
#endif
  if (scanf_res > 0)
  {
    int xcnt = 0;
    while (streampos < streamsize)
    {
      streampos++;
      xcnt++;
      if (buf[streampos] == 0 || buf[streampos] == ' ' ||
          buf[streampos] == '\t' || buf[streampos] == '\n' || xcnt > 24)
        break;
    }
  }
  return scanf_res;
}

int LibRaw_buffer_datastream::eof()
{
  return streampos >= streamsize;
}
int LibRaw_buffer_datastream::valid() { return buf ? 1 : 0; }

#ifdef LIBRAW_OLD_VIDEO_SUPPORT
void *LibRaw_buffer_datastream::make_jas_stream()
{
#ifdef NO_JASPER
  return NULL;
#else
  return jas_stream_memopen((char *)buf + streampos, streamsize - streampos);
#endif
}
#endif

int LibRaw_buffer_datastream::jpeg_src(void *jpegdata)
{
#if defined(NO_JPEG) || !defined(USE_JPEG)
  return -1;
#else
  j_decompress_ptr cinfo = (j_decompress_ptr)jpegdata;
  jpeg_mem_src(cinfo, (unsigned char *)buf + streampos, streamsize - streampos);
  return 0;
#endif
}

// int LibRaw_buffer_datastream