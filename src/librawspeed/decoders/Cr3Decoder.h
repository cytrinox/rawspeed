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

#include "tiff/TiffIFD.h"                           // for TiffRootIFDOwner

namespace rawspeed {

class CameraMetaData;

class Buffer;


struct IsoMBoxCanonTypes final {
  static constexpr FourCharStr CNCV = FourCharStr({'C', 'N', 'C', 'V'});
  static constexpr FourCharStr CCTP = FourCharStr({'C', 'C', 'T', 'P'});
  static constexpr FourCharStr CTBO = FourCharStr({'C', 'T', 'B', 'O'});
  static constexpr FourCharStr CMT1 = FourCharStr({'C', 'M', 'T', '1'});
  static constexpr FourCharStr CMT2 = FourCharStr({'C', 'M', 'T', '2'});
  static constexpr FourCharStr CMT3 = FourCharStr({'C', 'M', 'T', '3'});
  static constexpr FourCharStr CMT4 = FourCharStr({'C', 'M', 'T', '4'});
  static constexpr FourCharStr THMB = FourCharStr({'T', 'H', 'M', 'B'});
};




class IsoMCanonCodecVersionBox final : public IsoMBox<IsoMBoxCanonTypes::CNCV> {
public:
  std::string compressorVersion;
  explicit IsoMCanonCodecVersionBox(const AbstractIsoMBox& base);
  void parse(IsoMRootBox* root = nullptr) {}
};


class IsoMCanonCTBOBox final : public IsoMBox<IsoMBoxCanonTypes::CTBO> {
public:
  explicit IsoMCanonCTBOBox(const AbstractIsoMBox& base) : IsoMBox(base) {}
  void parse(IsoMRootBox* root = nullptr) {}
};


class IsoMCanonCCTPBox final : public IsoMBox<IsoMBoxCanonTypes::CCTP> {
public:
  explicit IsoMCanonCCTPBox(const AbstractIsoMBox& base) : IsoMBox(base){}
  void parse(IsoMRootBox* root = nullptr) {}
};



class IsoMCanonCMT1Box final : public IsoMBox<IsoMBoxCanonTypes::CMT1> {
public:
  TiffRootIFDOwner mRootIFD0;

  explicit IsoMCanonCMT1Box(const AbstractIsoMBox& base);
  void parse(IsoMRootBox* root = nullptr) {}
};

class IsoMCanonCMT2Box final : public IsoMBox<IsoMBoxCanonTypes::CMT2> {
public:
  TiffRootIFDOwner mRootIFD0;

  explicit IsoMCanonCMT2Box(const AbstractIsoMBox& base);
  void parse(IsoMRootBox* root = nullptr) {}
};


class IsoMCanonCMT3Box final : public IsoMBox<IsoMBoxCanonTypes::CMT3> {
public:
  TiffRootIFDOwner mRootIFD0;

  explicit IsoMCanonCMT3Box(const AbstractIsoMBox& base);
  void parse(IsoMRootBox* root = nullptr) {}
};

class IsoMCanonCMT4Box final : public IsoMBox<IsoMBoxCanonTypes::CMT4> {
public:
  TiffRootIFDOwner mRootIFD0;
  
  explicit IsoMCanonCMT4Box(const AbstractIsoMBox& base);
  void parse(IsoMRootBox* root = nullptr) {}
};

class IsoMCanonThumbnailBox final : public IsoMBox<IsoMBoxCanonTypes::THMB> {
public:
  explicit IsoMCanonThumbnailBox(const AbstractIsoMBox& base) : IsoMBox(base) {}
  void parse(IsoMRootBox* root = nullptr) {}
};





class IsoMCanonBox final : public IsoMContainerBox<IsoMBoxTypes::uuid> {
  void parseBox(const AbstractIsoMBox& box) override;
  explicit operator bool() const override;

public:
  std::unique_ptr<IsoMCanonCodecVersionBox> cncvBox;
  std::unique_ptr<IsoMCanonCCTPBox> cctpBox;
  std::unique_ptr<IsoMCanonCTBOBox> ctboBox;
  std::unique_ptr<IsoMCanonCMT1Box> cmt1Box;
  std::unique_ptr<IsoMCanonCMT2Box> cmt2Box;
  std::unique_ptr<IsoMCanonCMT3Box> cmt3Box;
  std::unique_ptr<IsoMCanonCMT4Box> cmt4Box;
  std::unique_ptr<IsoMCanonThumbnailBox> thmbBox;

  explicit IsoMCanonBox(const AbstractIsoMBox& base)
      : IsoMContainerBox(base) {}

  const std::unique_ptr<IsoMCanonCodecVersionBox>& CNCV() const;
  const std::unique_ptr<IsoMCanonCCTPBox>& CCTP() const;
  const std::unique_ptr<IsoMCanonCTBOBox>& CTBO() const;
  const std::unique_ptr<IsoMCanonCMT1Box>& CMT1() const;
  const std::unique_ptr<IsoMCanonCMT2Box>& CMT2() const;
  const std::unique_ptr<IsoMCanonCMT3Box>& CMT3() const;
  const std::unique_ptr<IsoMCanonCMT4Box>& CMT4() const;
  const std::unique_ptr<IsoMCanonThumbnailBox>& THMB() const;
};






















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
