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
package se.idsec.signservice.security.sign.xml;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.w3c.dom.Document;

/**
 * A validator for validing an XML message that is signed. This is a simpler validator that the
 * {@link XMLSignatureValidator} that can handle signed XML objects containing more than one signature. The
 * {@code XMLMessageSignatureValidator} is intended to be used when verifying the signature on a received XML message.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface XMLMessageSignatureValidator {

  /**
   * Validates the signature on the supplied XML document and asserts that it was signed by any of the supplied
   * certificates.
   * <p>
   * If {@code expectedSignerCertificates} is {@code null} or empty no checking of the signer certificate will be
   * performed.
   * </p>
   * <p>
   * If {@code signatureLocation} is {@code null} and the document contains more than one Signature element the
   * validation will fail.
   * </p>
   * 
   * @param document
   *          the XML document to validate
   * @param expectedSignerCertificates
   *          the expected signer certificates
   * @throws SignatureException
   *           for validation errors
   */
  void validate(final Document document,
      final List<X509Certificate> expectedSignerCertificates,
      XMLSignatureLocation signatureLocation) throws SignatureException;

}
