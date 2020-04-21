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
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Dataclass holding a PDF document that is to be signed or has been signed
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PDFSignTaskDocument {

  public static final String ADES_PROFILE_BES = "BES";
  public static final String ADES_PROFILE_EPES = "EPES";
  public static final String ADES_PROFILE_NONE = "None";

  /** The bytes of the PDF document */
  private byte[] pdfDocument;

  /** The bytes of CMS Content Info holding the SignedData */
  private byte[] cmsSignedData;

  /** Time and signature ID in milliseconds. */
  private Long signTimeAndId;

  /** ETSI AdES signature type (BES, EPES or None) */
  private String adesType;

  /** A Visible sign image to be included in the signature context. This object is not resent in result data */
  private VisibleSigImage visibleSigImage;
}
