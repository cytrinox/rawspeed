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
#include "parsers/TiffParser.h"
#include "decompressors/LJpegDecompressor.h"
#include "parsers/IsoMParserException.h" // for ThrowIPE

#include "io/FileWriter.h" // for ByteStream // FIXME remove me

namespace rawspeed {


const FourCharStr IsoMBoxCanonTypes::CNCV;
const FourCharStr IsoMBoxCanonTypes::CCTP;
const FourCharStr IsoMBoxCanonTypes::CTBO;
const FourCharStr IsoMBoxCanonTypes::CMT1;
const FourCharStr IsoMBoxCanonTypes::CMT2;
const FourCharStr IsoMBoxCanonTypes::CMT3;
const FourCharStr IsoMBoxCanonTypes::CMT4;
const FourCharStr IsoMBoxCanonTypes::THMB;
const FourCharStr IsoMBoxCanonTypes::CRAW;

const FourCharStr IsoMBoxCanonTypes::CMP1;
const FourCharStr IsoMBoxCanonTypes::CDI1;
const FourCharStr IsoMBoxCanonTypes::IAD1;

const AbstractIsoMBox::UuidType CanonBoxUuid = {0x85,0xc0,0xb6,0x87,0x82,0x0f,0x11,0xe0,0x81,0x11,0xf4,0xce,0x46,0x2b,0x6a,0x48};


void IsoMCanonBox::parseBox(const AbstractIsoMBox& box) {
  if (IsoMCanonCodecVersionBox::BoxType == box.boxType) {
    if (cncvBox)
      ThrowIPE("duplicate cncv box found.");
    cncvBox = AbstractIsoMBox::ParseBox<IsoMCanonCodecVersionBox>(box);
    return;
  }
  if (IsoMCanonCCTPBox::BoxType == box.boxType) {
    if (cctpBox)
      ThrowIPE("duplicate CCTP box found.");
    cctpBox = AbstractIsoMBox::ParseBox<IsoMCanonCCTPBox>(box);
    return;
  }
  if (IsoMCanonCTBOBox::BoxType == box.boxType) {
    if (ctboBox)
      ThrowIPE("duplicate CTBO box found.");
    ctboBox = AbstractIsoMBox::ParseBox<IsoMCanonCTBOBox>(box);
    return;
  }
  if (IsoMCanonCMT1Box::BoxType == box.boxType) {
    if (cmt1Box)
      ThrowIPE("duplicate CMT1 box found.");
    cmt1Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT1Box>(box);
    return;
  }
  if (IsoMCanonCMT2Box::BoxType == box.boxType) {
    if (cmt2Box)
      ThrowIPE("duplicate CMT2 box found.");
    cmt2Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT2Box>(box);
    return;
  }
  if (IsoMCanonCMT3Box::BoxType == box.boxType) {
    if (cmt3Box)
      ThrowIPE("duplicate CMT3 box found.");
    cmt3Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT3Box>(box);
    return;
  }
  if (IsoMCanonCMT4Box::BoxType == box.boxType) {
    if (cmt4Box)
      ThrowIPE("duplicate CMT4 box found.");
    cmt4Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT4Box>(box);
    return;
  }

  if (IsoMCanonThumbnailBox::BoxType == box.boxType) {
    if (thmbBox)
      ThrowIPE("duplicate THMB box found.");
    thmbBox = AbstractIsoMBox::ParseBox<IsoMCanonThumbnailBox>(box);
    return;
  }
}

const std::unique_ptr<IsoMCanonCodecVersionBox>&
IsoMCanonBox::CNCV() const  {
  if(cncvBox)
    return cncvBox;
  else
    ThrowIPE("CNCV box not available");
}



const std::unique_ptr<IsoMCanonCCTPBox>&
IsoMCanonBox::CCTP() const  {
  if(cctpBox)
    return cctpBox;
  else
    ThrowIPE("CCTP box not available");
}

const std::unique_ptr<IsoMCanonCTBOBox>&
IsoMCanonBox::CTBO() const  {
  if(ctboBox)
    return ctboBox;
  else
    ThrowIPE("CTBO box not available");
}


const std::unique_ptr<IsoMCanonCMT1Box>&
IsoMCanonBox::CMT1() const  {
  if(cmt1Box)
    return cmt1Box;
  else
    ThrowIPE("CMT1 box not available");
}

const std::unique_ptr<IsoMCanonCMT2Box>&
IsoMCanonBox::CMT2() const  {
  if(cmt2Box)
    return cmt2Box;
  else
    ThrowIPE("CMT2 box not available");
}

const std::unique_ptr<IsoMCanonCMT3Box>&
IsoMCanonBox::CMT3() const  {
  if(cmt3Box)
    return cmt3Box;
  else
    ThrowIPE("CMT3 box not available");
}

const std::unique_ptr<IsoMCanonCMT4Box>&
IsoMCanonBox::CMT4() const  {
  if(cmt4Box)
    return cmt4Box;
  else
    ThrowIPE("CMT4 box not available");
}

const std::unique_ptr<IsoMCanonThumbnailBox>&
IsoMCanonBox::THMB() const  {
  if(thmbBox)
    return thmbBox;
  else
    ThrowIPE("THMB box not available");
}


IsoMCanonBox::operator bool() const {
  if (!cncvBox)
    ThrowIPE("no CNCV box found.");
  if (!cctpBox)
    ThrowIPE("no CCTP box found.");
  if (!ctboBox)
    ThrowIPE("no CTBO box found.");
  if (!cmt1Box)
    ThrowIPE("no CMT1 box found.");
  if (!cmt2Box)
    ThrowIPE("no CMT2 box found.");
  if (!cmt3Box)
    ThrowIPE("no CMT3 box found.");
  if (!cmt4Box)
    ThrowIPE("no CMT4 box found.");


  return true; // OK!
}



IsoMCanonCodecVersionBox::IsoMCanonCodecVersionBox(const AbstractIsoMBox& base) : IsoMBox(base) {
  assert(data.getRemainSize() == 30); // Payload string is exactly 30 bytes long
  auto payload = data.getBuffer(30);
  compressorVersion = std::string(payload.begin(), payload.end());
  assert(data.getRemainSize() == 0);
}






IsoMCanonCMT1Box::IsoMCanonCMT1Box(const AbstractIsoMBox& base) : IsoMBox(base){
  NORangesSet<Buffer> rs;
  auto payload = DataBuffer(data.getBuffer(data.getRemainSize()), Endianness::little);
  mRootIFD0 = TiffParser::parse(nullptr, payload);
}

IsoMCanonCMT2Box::IsoMCanonCMT2Box(const AbstractIsoMBox& base) : IsoMBox(base){
  NORangesSet<Buffer> rs;
  auto payload = DataBuffer(data.getBuffer(data.getRemainSize()), Endianness::little);
  mRootIFD0 = TiffParser::parse(nullptr, payload);
}

IsoMCanonCMT3Box::IsoMCanonCMT3Box(const AbstractIsoMBox& base) : IsoMBox(base){
  NORangesSet<Buffer> rs;
  auto payload = DataBuffer(data.getBuffer(data.getRemainSize()), Endianness::little);
  mRootIFD0 = TiffParser::parse(nullptr, payload);
}

IsoMCanonCMT4Box::IsoMCanonCMT4Box(const AbstractIsoMBox& base) : IsoMBox(base){
  NORangesSet<Buffer> rs;
  auto payload = DataBuffer(data.getBuffer(data.getRemainSize()), Endianness::little);
  mRootIFD0 = TiffParser::parse(nullptr, payload);
}





IsoMCanonCrawBox::IsoMCanonCrawBox(const AbstractIsoMBox& base)
  : IsoMBox(base) {
  // Set position after box `size` and `boxtype` fields, so we
  // can parse the custom SampleEntry ourself.
  data.setPosition(8);

  writeLog(DEBUG_PRIO_EXTRA, "Found CRAW len: %u", data.getRemainSize());
  writeLog(DEBUG_PRIO_EXTRA, "Found CRAW off: %u", data.getPosition());

  for (auto& c : reserved1)
    c = data.getByte();
  dataReferenceIndex = data.getU16();
  for (auto& c : reserved2)
    c = data.getByte();
  width = data.getU16();
  height = data.getU16();
  xResolution = static_cast<uint32_t>(data.getU16()) << 16 | data.getU16();
  yResolution = static_cast<uint32_t>(data.getU16()) << 16 | data.getU16();
  reserved3 = data.getU32();
  reserved4 = data.getU16();
  for (auto& c : reserved5)
    c = data.getByte();
  bitDepth  = data.getU16();
  reserved6  = data.getU16();
  flags = data.getU16();
  formatInd = data.getU16();

  writeLog(DEBUG_PRIO_EXTRA, "Found CRAW widttt: 0x%x, fmt: 0x%x, res: %d", width, formatInd, xResolution >> 16);

  assert(data.getPosition() == 90);

  //auto cmp1 = IsoMCanonCmp1Box(AbstractIsoMBox(&data)); // CMP1
  //writeLog(DEBUG_PRIO_EXTRA, "Found box: %s", x.boxType.str().c_str());

  cmp1Box = std::make_unique<IsoMCanonCmp1Box>(AbstractIsoMBox(&data));
  cdi1Box = std::make_unique<IsoMCanonCdi1Box>(AbstractIsoMBox(&data));

  // Validate.
  operator bool();

  /*
  x = AbstractIsoMBox(&data); // CDI1 (container box, contains IAD1)
  writeLog(DEBUG_PRIO_EXTRA, "Found box: %s", x.boxType.str().c_str());
  x = AbstractIsoMBox(&data); // free
  writeLog(DEBUG_PRIO_EXTRA, "Found box: %s", x.boxType.str().c_str());
  */

  //data.skipBytes(90-8); // TODO: parse CRAW fields, not needed for now
  }
/*
void IsoMCanonCrawBox::parseBox(const AbstractIsoMBox& box) {
  auto boxt = box.boxType;

    writeLog(DEBUG_PRIO_EXTRA, "Found CRAW box: %s", boxt.str().c_str());


  if (IsoMCanonCodecVersionBox::BoxType == box.boxType) {
    if (cncvBox)
      ThrowIPE("duplicate cncv box found.");
    cncvBox = AbstractIsoMBox::ParseBox<IsoMCanonCodecVersionBox>(box);
    return;
  }
  if (IsoMCanonCCTPBox::BoxType == box.boxType) {
    if (cctpBox)
      ThrowIPE("duplicate CCTP box found.");
    cctpBox = AbstractIsoMBox::ParseBox<IsoMCanonCCTPBox>(box);
    return;
  }
  if (IsoMCanonCTBOBox::BoxType == box.boxType) {
    if (ctboBox)
      ThrowIPE("duplicate CTBO box found.");
    ctboBox = AbstractIsoMBox::ParseBox<IsoMCanonCTBOBox>(box);
    return;
  }
  if (IsoMCanonCMT1Box::BoxType == box.boxType) {
    if (cmt1Box)
      ThrowIPE("duplicate CMT1 box found.");
    cmt1Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT1Box>(box);
    return;
  }
  if (IsoMCanonCMT2Box::BoxType == box.boxType) {
    if (cmt2Box)
      ThrowIPE("duplicate CMT2 box found.");
    cmt2Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT2Box>(box);
    return;
  }
  if (IsoMCanonCMT3Box::BoxType == box.boxType) {
    if (cmt3Box)
      ThrowIPE("duplicate CMT3 box found.");
    cmt3Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT3Box>(box);
    return;
  }
  if (IsoMCanonCMT4Box::BoxType == box.boxType) {
    if (cmt4Box)
      ThrowIPE("duplicate CMT4 box found.");
    cmt4Box = AbstractIsoMBox::ParseBox<IsoMCanonCMT4Box>(box);
    return;
  }

  if (IsoMCanonThumbnailBox::BoxType == box.boxType) {
    if (thmbBox)
      ThrowIPE("duplicate THMB box found.");
    thmbBox = AbstractIsoMBox::ParseBox<IsoMCanonThumbnailBox>(box);
    return;
  }

}
  */

IsoMCanonCrawBox::operator bool() const {

  if (!cmp1Box)
    ThrowIPE("no CMP1 box found.");
  if (!cdi1Box)
    ThrowIPE("no CDI1 box found.");

  return true; // OK!
}



const std::unique_ptr<IsoMCanonCmp1Box>&
IsoMCanonCrawBox::CMP1() const {
  if(cmp1Box)
    return cmp1Box;
  else
    ThrowIPE("CMP1 box not available");
}

const std::unique_ptr<IsoMCanonCdi1Box>&
IsoMCanonCrawBox::CDI1() const {
  if(cdi1Box)
    return cdi1Box;
  else
    ThrowIPE("CDI1 box not available");
}



IsoMCanonCmp1Box::IsoMCanonCmp1Box(const AbstractIsoMBox& base)
  : IsoMBox(base) {
  // Set position after box `size` and `boxtype` fields, so we
  // can parse the custom SampleEntry ourself.
  data.setPosition(8);
  // This fields mainly used in the decoding process.
  reserved1 = data.getU16();
  headerSize = data.getU16();
  assert(headerSize == 0x30);
  version = data.getI32();
  f_width = data.getI32();
  f_height = data.getI32();
  tileWidth = data.getI32();
  tileHeight = data.getI32();
  nBits = data.get<int8_t>();
  nPlanes = data.peek<int8_t>() >> 4;
  cfaLayout = data.get<int8_t>() & 0xF;
  encType = data.peek<int8_t>() >> 4;
  imageLevels = data.get<int8_t>() & 0xF;
  hasTileCols = data.peek<int8_t>() >> 7;
  hasTileRows =  data.get<int8_t>() & 1;
  mdatHdrSize = data.getI32();
  // Some reserved fields, unknown.
  reserved2  = data.getI32();
  for (auto& c : reserved3)
    c = data.getByte();

  // we assume this is fixed, until Canon makes CMP1 flexible
  assert(data.getPosition() == 44+16);
  // headerSize should match position
  assert((data.getPosition() - 2 - 2 - 8) == headerSize);
  assert(data.getRemainSize() == 0);



}




void IsoMCanonCdi1Box::parseBox(const AbstractIsoMBox& box) {
  if (IsoMCanonIad1Box::BoxType == box.boxType) {
    if (iad1Box)
      ThrowIPE("duplicate IAD1 box found.");
    iad1Box = AbstractIsoMBox::ParseBox<IsoMCanonIad1Box>(box);
    return;
  }
}

IsoMCanonCdi1Box::operator bool() const {
  if (!iad1Box)
    ThrowIPE("no IAD1 box found.");

  return true; // OK!
}

const std::unique_ptr<IsoMCanonIad1Box>&
IsoMCanonCdi1Box::IAD1() const {
  if(iad1Box)
    return iad1Box;
  else
    ThrowIPE("IAD1 box not available");
}





IsoMCanonIad1Box::IsoMCanonIad1Box(const AbstractIsoMBox& base)
  : IsoMFullBox(base) {
  // We ignore IAD1, not needed for decoding.

  // Validate.
  operator bool();
}


IsoMCanonIad1Box::operator bool() const {
  // No fields yet to validate, IAD1 is unused for decoding.

  return true; // OK!
}














bool Cr3Decoder::isAppropriateDecoder(const IsoMRootBox& box) {
  return box.ftyp()->majorBrand == FourCharStr({'c', 'r', 'x', ' '});
}

RawImage Cr3Decoder::decodeRawInternal() {
  ByteStream biggestImage;

  for (const auto& track : rootBox->moov()->tracks) {
    for (const auto& chunk : track.mdia->minf->stbl->chunks) {
      if (chunk->getSize() > biggestImage.getSize())
        biggestImage = *chunk;
    }
  }

  //const auto box = rootBox->moov()->boxes[0]; // find by uuid?



  // CRAW BOX
  /*
  auto& stsd = rootBox->moov()->tracks[2].mdia->minf->stbl->stsd;
  auto& stsd_data = rootBox->moov()->tracks[2].mdia->minf->stbl->stsd->data;

  Buffer buf = stsd_data.getSubView(0);

    FileWriter trak3_stsd_f("/tmp/test_trak3.stsd");
  trak3_stsd_f.writeFile(&buf, buf.getSize());
  */

  auto& stsd = rootBox->moov()->tracks[2].mdia->minf->stbl->stsd;
  auto& dscs_data = stsd->dscs[0].data;
    FileWriter trak3_dscs_f("/tmp/test_trak3.dscs");
  trak3_dscs_f.writeFile(&dscs_data, dscs_data.getSize());

  IsoMCanonCrawBox craw = IsoMCanonCrawBox(stsd->dscs[0]);

  const auto& cmp1 = craw.CMP1();
  const auto& cdi1 = craw.CDI1();


  printf("Image size: %dx%d\n", cmp1->f_width, cmp1->f_height);






  // ------ CANON BOX
  IsoMCanonBox canon = IsoMCanonBox(rootBox->moov()->getBox(CanonBoxUuid));

  canon.parse();

  writeLog(DEBUG_PRIO_EXTRA, "Compressor Version: %s", canon.CNCV()->compressorVersion.c_str());



  auto camId = canon.CMT1()->mRootIFD0->getID();
  printf("EXIF-MAKE: %s\n", camId.make.c_str());
  printf("EXIF-MODEL: %s\n", camId.model.c_str());

  uint32_t iso = 0;
 if (canon.CMT2()->mRootIFD0->hasEntryRecursive(ISOSPEEDRATINGS))
    iso = canon.CMT2()->mRootIFD0->getEntryRecursive(ISOSPEEDRATINGS)->getU32();

  printf("EXIF-ISO: %d\n", iso);

  writeLog(DEBUG_PRIO_EXTRA, "decodeRawInternal ENTER");
  // Hardcoded for Canon M50.
  mRaw->dim = {6288, 4056};

/*
  LJpegDecompressor d(biggestImage, mRaw);
  mRaw->createData();
  d.decode(0, 0, mRaw->dim.x, mRaw->dim.y, false);
*/

  writeLog(DEBUG_PRIO_EXTRA, "decodeRawInternal EXIT");

  return mRaw;
}

void Cr3Decoder::checkSupportInternal(const CameraMetaData* meta) {}

void Cr3Decoder::decodeMetaDataInternal(const CameraMetaData* meta) {}

} // namespace rawspeed
