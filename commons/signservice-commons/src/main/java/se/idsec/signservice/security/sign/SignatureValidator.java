/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.security.sign;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

import se.idsec.signservice.security.certificate.CertificateValidator;

/**
 * Generic interface representing a signature validator instance that supports validating documents having one more
 * signatures.
 * 
 * @param <T>
 *          the type of document that is validated
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignatureValidator<T> {

  /**
   * Validates the signature(s) of supplied document.
   * 
   * @param document
   *          the document to validate
   * @return a validation result containing the details from a signature validation
   * @throws SignatureException
   *           for errors during the validation process (pure signature validation errors are reported in the returned
   *           result)
   */
  List<SignatureValidationResult> validate(final T document) throws SignatureException;

  /**
   * Predicate that tells if all the supplied result objects indicate a successful validation.
   * 
   * @param results
   *          a (non-empty) list of result objects
   * @return true if all result objects indicate success and false otherwise
   */
  static boolean isCompleteSuccess(final List<SignatureValidationResult> results) {
    return !results.stream().filter(r -> !r.isSuccess()).findAny().isPresent();
  }

  /**
   * Predicate that tells if the supplied document is signed.
   * 
   * @param document
   *          the document to check
   * @return true if the document is signed, and false otherwise
   * @throws IllegalArgumentException
   *           if the document can not be parsed
   */
  boolean isSigned(final T document) throws IllegalArgumentException;

  /**
   * Gets a list of "required signer certificates", meaning that we require the signature to be signed with a
   * certificate from this list.
   * <p>
   * If an empty list is returned this means that a complete certificate path validation up to a trusted root will be
   * performed (provided {@link #getCertificateValidator()} is non null). If no certificate validator is installed the
   * signature will be accepted without checking any certificates (provided that the signature itself is valid).
   * </p>
   * 
   * @return a (possibly empty) list of "accepted" certificates
   */
  List<X509Certificate> getRequiredSignerCertificates();

  /**
   * Gets the certificate validator instance that is to be used to validate the signer certificate up until a trusted
   * path.
   * <p>
   * If {@link #getRequiredSignerCertificates()} returns a non-empty list, no certificate path validation will be
   * performed.
   * </p>
   * <p>
   * If no certificate validator is configured the signature will be accepted without checking any certificates
   * (provided that the signature itself is valid).
   * </p>
   * 
   * @return the certificate validator or null
   */
  CertificateValidator getCertificateValidator();

}
