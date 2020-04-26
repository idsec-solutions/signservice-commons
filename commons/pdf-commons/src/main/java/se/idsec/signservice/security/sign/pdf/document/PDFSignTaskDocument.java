/*
 * Copyright 2019-2020 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.security.sign.pdf.document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Representation of a PDF document that is to be signed or has been signed.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PDFSignTaskDocument {

  /**
   * The contents of the PDF document.
   * 
   * @param pdfDocument
   *          the contents of the document
   * @return the contents of the document
   */
  @Setter
  @Getter
  private byte[] pdfDocument;

  /**
   * The bytes of CMS Content Info holding the SignedData.
   * 
   * @param cmsSignedData
   *          the bytes of CMS Content Info holding the SignedData
   * @return the bytes of CMS Content Info holding the SignedData
   */
  @Setter
  @Getter
  private byte[] cmsSignedData;

  /**
   * Time and signature ID in milliseconds.
   * 
   * @param signTimeAndId
   *          the time and signature ID in milliseconds
   * @return the time and signature ID in milliseconds
   */
  @Setter
  @Getter
  private Long signTimeAndId;

  /**
   * ETSI AdES signature type (BES, EPES or None).
   * 
   * @param adesType
   *          the ETSI AdES signature type
   */
  @Setter
  private String adesType;

  /**
   * A Visible sign image to be included in the signature context. This object is not present in result data.
   * 
   * @param visibleSigImage
   *          sign image
   * @return sign image (or null)
   */
  @Setter
  @Getter
  private VisibleSigImage visibleSigImage;

  /**
   * ETSI AdES signature type (BES, EPES or None).
   * 
   * @return the ETSI AdES signature type
   */
  public String getAdesType() {
    return this.adesType != null ? this.adesType : "None";
  }

}
