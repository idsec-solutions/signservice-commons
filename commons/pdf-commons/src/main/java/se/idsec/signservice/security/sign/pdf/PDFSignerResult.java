/*
 * Copyright 2019-2025 IDsec Solutions AB
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

import se.idsec.signservice.security.sign.SignerResult;

/**
 * Represents the result from an PDF signature operation.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 * @see PDFSigner
 */
public interface PDFSignerResult extends SignerResult<byte[]> {

  /**
   * Gets the signed attributes bytes signed by the generated signature. These are the bytes sent to an external
   * signature service as the to be signed bytes. These bytes may be manipulated from the signed bytes in the
   * CMSSignedData after adapting the result to requirements by the signing service. One such example is if the
   * signature is a PAdES signature, where the signing time attribute must be removed before being sent to the signing
   * service.
   *
   * @return signed attributes bytes
   */
  byte[] getSignedAttributes();

  /**
   * Gets the bytes of CMS Content Info holding the SignedData.
   *
   * @return the bytes of CMS Content Info holding the SignedData
   */
  byte[] getSignedData();

}
