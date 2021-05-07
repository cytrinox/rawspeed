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

namespace rawspeed {


const FourCharStr IsoMBoxCanonTypes::CNCV;
const FourCharStr IsoMBoxCanonTypes::CCTP;
const FourCharStr IsoMBoxCanonTypes::CTBO;
const FourCharStr IsoMBoxCanonTypes::CMT1;
const FourCharStr IsoMBoxCanonTypes::CMT2;
const FourCharStr IsoMBoxCanonTypes::CMT3;
const FourCharStr IsoMBoxCanonTypes::CMT4;
const FourCharStr IsoMBoxCanonTypes::THMB;

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

  IsoMCanonBox canon = IsoMCanonBox(rootBox->moov()->getBox(CanonBoxUuid));

  canon.parse();

  writeLog(DEBUG_PRIO_EXTRA, "Compressor Version: %s", canon.CNCV()->compressorVersion.c_str());



  auto camId = canon.CMT1()->mRootIFD0->getID();
  printf("EXIF-MAKE: %s\n", camId.make.c_str());
  printf("EXIF-MODEL: %s\n", camId.model.c_str());


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
