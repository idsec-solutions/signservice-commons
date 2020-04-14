/*
 * Copyright 2020 IDsec Solutions AB
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

import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.Signer;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for PDF signatures.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PDFSigner extends Signer<PDFSignTaskDocument, PDFSignerResult> {

  /**
   * Completes a signature process where the actual signed attributes, signature value and signing certificates has been provided by
   * an external signing service.
   * @param document The document to be signed that was also processed by the singing service. This MUST included the signing ID used by
   *                 the singing service
   * @param signedAttributes The signed attributes bytes signed by the signing service
   * @param signatureValue The signature value bytes provided by the signing service
   * @param chain The signer certificate chain where the signer certificate is the first certificate in the chain
   * @return Signature result
   */
  PDFSignerResult completeSign(final PDFSignTaskDocument document, byte[] signedAttributes, byte[] signatureValue, List<X509Certificate> chain);

}
