/*
 * Copyright 2019-2024 IDsec Solutions AB
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
package se.idsec.signservice.security.sign.pdf;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

/**
 * The interface for the signature generation interface. This interface extends the PDFBox {@link SignatureInterface}.
 * The purpose of this interface is to provide the functions to provide the CMS signature data for a PDF signature.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PDFBoxSignatureInterface extends SignatureInterface {

  /**
   * Gets the result of the signing process in the form of ContentInfo holding SignedData.
   *
   * @return the CMS ContentInfo holding SignedData
   */
  byte[] getCmsSignedData();

  /**
   * Gets the signed attributes from the result of the signing process.
   *
   * @return the CMS SignedAttributes
   */
  byte[] getCmsSignedAttributes();

  /**
   * Tells whether the signature should be generated according to the PAdES requirement profile.
   *
   * @return true if the signature is created as a PAdES compliant signature
   */
  boolean isPades();

}
