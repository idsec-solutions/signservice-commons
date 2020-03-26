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
package se.idsec.signservice.security.sign.xml.impl;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.xml.XMLMessageSignatureValidator;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;

/**
 * Implementation of the {@link XMLMessageSignatureValidator} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultXMLMessageSignatureValidator implements XMLMessageSignatureValidator {

  /** {@inheritDoc} */
  @Override
  public void validate(final Document document,
      final List<X509Certificate> expectedSignerCertificates,
      final XMLSignatureLocation signatureLocation) throws SignatureException {

    DefaultXMLSignatureValidator validator = new DefaultXMLSignatureValidator(expectedSignerCertificates);
    validator.setXadesProcessing(false);

    List<SignatureValidationResult> result = validator.validate(document, signatureLocation);
    if (result.size() > 1) {
      throw new SignatureException("Document contains multiple Signature elements - use XPath expression");
    }
    if (result.get(0).isSuccess()) {
      log.debug("Signature on XML message successfully validated: {}", result.get(0));
    }
    else {
      log.info("Signature validation on XML message failed: {}", result.get(0));
      throw new SignatureException(result.get(0).getStatusMessage());
    }

  }

}
