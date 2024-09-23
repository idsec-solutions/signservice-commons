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
package se.idsec.signservice.security.sign;

import se.idsec.signservice.security.certificate.CertificateValidationResult;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Interface representing the (successful) result of a signature validation operation.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignatureValidationResult {

  /**
   * Representation of the validation status of a signature.
   */
  enum Status {
    /** The signature validation was successful. */
    SUCCESS,

    /**
     * Signature verified correctly, but the certificate could not be verified to be correct since no revocation
     * information was available.
     */
    INTERDETERMINE,

    /** The signature was not valid. */
    ERROR_INVALID_SIGNATURE,

    /** The signature was valid, but validation of the signer certificate failed. */
    ERROR_SIGNER_INVALID,

    /** The signature was valid, but the signer certificate was not among the acceptable signer certificates. */
    ERROR_SIGNER_NOT_ACCEPTED,

    /** The signature was valid, but validation of the signer certificate did not take us to a trusted root. */
    ERROR_NOT_TRUSTED,

    /** Bad format on signature. */
    ERROR_BAD_FORMAT
  }

  /**
   * Gets the overall validation status.
   *
   * @return the validation status
   */
  Status getStatus();

  /**
   * Predicate that tells if this result object represents a successful validation.
   *
   * @return true if this result object represents a successful validation and false otherwise
   */
  boolean isSuccess();

  /**
   * Gets a status message. To be used for logging purposes.
   * <p>
   * For non-successful results a message is always returned.
   * </p>
   *
   * @return status message
   */
  String getStatusMessage();

  /**
   * If this status represents a non-successful result, this method may return an exception object describing the
   * underlying validation error.
   *
   * @return an exception describing the underlying error or null
   */
  Exception getException();

  /**
   * Gets the certificate that was used to sign the validated document.
   * <p>
   * May be {@code null} in the rare cases when the certificate is not included in the signature, and when no validation
   * certificates were supplied to the validation process.
   * </p>
   *
   * @return the signature certificate
   */
  X509Certificate getSignerCertificate();

  /**
   * In case a successful certificate validation was performed, this method returns the result from this operation.
   *
   * @return the certificate validation result
   */
  CertificateValidationResult getCertificateValidationResult();

  /**
   * Gets the URI identifier of the signature algorithm.
   *
   * @return signature algorithm URI identifier
   */
  String getSignatureAlgorithm();

  /**
   * Gets the claimed signing time.
   * <p>
   * This is a signing time asserted within the signature, not asserted by any external time stamp service.
   * </p>
   *
   * @return the claimed signing time (if available)
   */
  Date getClaimedSigningTime();

  /**
   * Predicate that tells if the signature that was validated is a signature according to the corresponding ETSI AdES
   * signature profile.
   *
   * @return true if this signature conforms to the ETSI AdES profile, and false otherwise
   */
  boolean isEtsiAdes();

}
