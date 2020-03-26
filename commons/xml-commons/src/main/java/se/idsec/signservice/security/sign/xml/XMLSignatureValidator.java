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
import java.util.List;

import org.w3c.dom.Document;

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.SignatureValidator;

/**
 * Specialization of the {@link SignatureValidator} for validation of XML signatures.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface XMLSignatureValidator extends SignatureValidator<Document> {

  /**
   * Validates the signature(s) of supplied document.
   * <p>
   * If the {@code signatureLocation} parameter is non null only that signature of the document will be validated, even
   * if there are more signatures.
   * </p>
   * 
   * @param document
   *          the document to validate
   * @param signatureLocation
   *          tells where the signature can be found
   * @return a validation result containing the details from a signature validation
   * @throws SignatureException
   *           for errors during the validation process (pure signature validation errors are reported in the returned
   *           result)
   */
  List<SignatureValidationResult> validate(final Document document, final XMLSignatureLocation signatureLocation)
      throws SignatureException;

}
