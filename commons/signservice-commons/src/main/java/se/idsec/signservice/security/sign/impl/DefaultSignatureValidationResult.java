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
package se.idsec.signservice.security.sign.impl;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Default implementation of the {@link SignatureValidationResult} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultSignatureValidationResult implements SignatureValidationResult {

  /** The result status. */
  private Status status;

  /** The status message. */
  private String statusMessage;

  /** Exception from validation. */
  private Exception exception;

  /** The signer certificate. */
  private X509Certificate signerCertificate;

  /** Additional certificates. */
  private List<X509Certificate> additionalCertificates;

  /** The certificate validation result. */
  private CertificateValidationResult certificateValidationResult;

  /** The URI identifier of the signature algorithm */
  private String signatureAlgorithm;

  /** The claimed signing time included in the signature, not claimed by an external time stamp authority. */
  private Date claimedSigningTime;

  /**
   * Predicate that tells if the signature that was validated is a signature according to the corresponding ETSI AdES
   * signature profile.
   */
  private boolean etsiAdes;

  /**
   * Default constructor.
   */
  public DefaultSignatureValidationResult() {
  }

  /**
   * Sets the status and status message during errors.
   *
   * @param status status code
   * @param statusMessage message
   */
  public void setError(final Status status, final String statusMessage) {
    this.setError(status, statusMessage, null);
  }

  /**
   * Sets the status, status message and exception for errors
   *
   * @param status status code
   * @param statusMessage message
   * @param exception exception
   */
  public void setError(final Status status, final String statusMessage, final Exception exception) {
    this.setStatus(status);
    this.setStatusMessage(statusMessage);
    this.setException(exception);
  }

  /**
   * Sets the error status based on the supplied {@link InternalSignatureValidationException} exception object.
   *
   * @param validationException the exception
   */
  public void setError(final InternalSignatureValidationException validationException) {
    this.setError(validationException.getStatus(), validationException.getMessage(), validationException);
  }

  /** {@inheritDoc} */
  @Override
  public Status getStatus() {
    return this.status != null ? this.status : Status.INTERDETERMINE;
  }

  /**
   * Assigns the status for the validation.
   *
   * @param status status code
   */
  public void setStatus(final Status status) {
    this.status = status;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSuccess() {
    return Status.SUCCESS == this.status;
  }

  /** {@inheritDoc} */
  @Override
  public String getStatusMessage() {
    return this.statusMessage;
  }

  /**
   * Assigns the status message.
   *
   * @param statusMessage status message
   */
  public void setStatusMessage(final String statusMessage) {
    this.statusMessage = statusMessage;
  }

  /** {@inheritDoc} */
  @Override
  public Exception getException() {
    return this.exception;
  }

  /**
   * Gets the exception that led to a non-successful status.
   *
   * @param exception underlying exception
   */
  public void setException(final Exception exception) {
    this.exception = exception;
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getSignerCertificate() {
    return this.signerCertificate;
  }

  /**
   * Assigns the signer certificate from the signature.
   *
   * @param signerCertificate signer certificate
   */
  public void setSignerCertificate(final X509Certificate signerCertificate) {
    this.signerCertificate = signerCertificate;
  }

  /**
   * Gets the certificates that are above the signer certificate in the chain (if received in the signature).
   *
   * @return a list of additional certificates
   */
  public List<X509Certificate> getAdditionalCertificates() {
    return this.additionalCertificates != null ? this.additionalCertificates : Collections.emptyList();
  }

  /**
   * Assigns the certificates that are above the signer certificate in the chain (if received in the signature).
   *
   * @param additionalCertificates a list of additional certificates
   */
  public void setAdditionalCertificates(final List<X509Certificate> additionalCertificates) {
    this.additionalCertificates = additionalCertificates;
  }

  /** {@inheritDoc} */
  @Override
  public CertificateValidationResult getCertificateValidationResult() {
    return this.certificateValidationResult;
  }

  /**
   * Assigns the certificate validation result for the signer certificate.
   *
   * @param certificateValidationResult validation result
   */
  public void setCertificateValidationResult(final CertificateValidationResult certificateValidationResult) {
    this.certificateValidationResult = certificateValidationResult;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignatureAlgorithm() {
    return this.signatureAlgorithm;
  }

  /**
   * Assigns the signature algorithm URI of the signature.
   *
   * @param signatureAlgorithm signature algorithm URI
   */
  public void setSignatureAlgorithm(final String signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public Date getClaimedSigningTime() {
    return this.claimedSigningTime;
  }

  /**
   * Assigns the claimed signing time for the signature.
   *
   * @param claimedSigningTime claimed signing time
   */
  public void setClaimedSigningTime(final Date claimedSigningTime) {
    this.claimedSigningTime = claimedSigningTime;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isEtsiAdes() {
    return this.etsiAdes;
  }

  /**
   * Assigns the ETSI AdES signature profile compliance status.
   *
   * @param etsiAdes true if this is an ETSI AdES compliant signature
   */
  public void setEtsiAdes(final boolean etsiAdes) {
    this.etsiAdes = etsiAdes;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(super.toString());
    sb.append("status='").append(this.status);
    if (this.statusMessage != null) {
      sb.append(",statusMessage='").append(this.statusMessage);
    }
    if (this.exception != null) {
      sb.append(",exception=[")
          .append(this.exception.getClass().getSimpleName())
          .append(":")
          .append(this.exception.getMessage())
          .append("]");
    }
    if (this.signerCertificate != null) {
      sb.append(",signerCertificate=[").append(CertificateUtils.toLogString(this.signerCertificate)).append("]");
    }
    if (this.certificateValidationResult != null) {
      sb.append(",certificateValidationResult=[").append(this.certificateValidationResult).append("]");
    }
    if (this.signatureAlgorithm != null) {
      sb.append(",signatureAlgorithm=").append(this.signatureAlgorithm);
    }
    if (this.claimedSigningTime != null) {
      sb.append(",claimedSigningTime=").append(this.claimedSigningTime);
    }
    sb.append("isEtsiAdes=").append(this.etsiAdes);

    return sb.toString();
  }

}
