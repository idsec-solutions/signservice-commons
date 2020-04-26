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
package se.idsec.signservice.security.sign.pdf.impl;

import java.util.Date;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import se.idsec.signservice.security.sign.impl.DefaultSignatureValidationResult;
import se.idsec.signservice.security.sign.pdf.PDFSignatureValidationResult;

/**
 * Implementation of the {@link PDFSignatureValidationResult} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPDFSignatureValidationResult extends DefaultSignatureValidationResult implements PDFSignatureValidationResult {

  /** The PDF signature. */
  private PDSignature pdfSignature;

  /** The claimed signing time. */
  private Long claimedSigningTime;

  /** The URI identifier of the signature algorithm. */
  private String signatureAlgorithm;

  /** Tells if the signature has the CMS algorithm protection signed attribute set. */
  private boolean cmsAlgorithmProtection = false;

  /** Tells if the signature that was validated is a PAdES signature. */
  private boolean pades = false;

  /**
   * Constructor.
   */
  public DefaultPDFSignatureValidationResult() {
  }

  /** {@inheritDoc} */
  @Override
  public PDSignature getPdfSignature() {
    return this.pdfSignature;
  }

  /**
   * Assigns the PDF signature object (that was validated).
   * 
   * @param pdfSignature
   *          the PDF signature object
   */
  public void setPdfSignature(final PDSignature pdfSignature) {
    this.pdfSignature = pdfSignature;
  }

  /** {@inheritDoc} */
  @Override
  public Long getClaimedSigningTime() {
    return this.claimedSigningTime;
  }

  /**
   * Assigns the claimed signing time.
   * 
   * @param claimedSigningTime
   *          the claimed signing time (in millis since epoch)
   */
  public void setClaimedSigningTime(final Long claimedSigningTime) {
    this.claimedSigningTime = claimedSigningTime;
  }

  /**
   * Assigns the claimed signing time.
   * 
   * @param claimedSigningTime
   *          the claimed signing time
   */
  public void setClaimedSigningTime(final Date claimedSigningTime) {
    this.claimedSigningTime = claimedSigningTime != null ? claimedSigningTime.getTime() : null;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignatureAlgorithm() {
    return this.signatureAlgorithm;
  }

  /**
   * Assigns the URI identifier of the signature algorithm.
   * 
   * @param signatureAlgorithm
   *          signature algorithm URI identifier
   */
  public void setSignatureAlgorithm(final String signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isCmsAlgorithmProtection() {
    return this.cmsAlgorithmProtection;
  }

  /**
   * Assigns the flag that tells if the signature has the CMS algorithm protection signed attribute set. The default is
   * {@code false}.
   * 
   * @param cmsAlgorithmProtection
   *          flag telling if the signature has the CMS algorithm protection signed attribute set
   */
  public void setCmsAlgorithmProtection(final boolean cmsAlgorithmProtection) {
    this.cmsAlgorithmProtection = cmsAlgorithmProtection;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isPades() {
    return this.pades;
  }

  /**
   * Assigns the flag that tells if the signature that was validated is a PAdES signature. Default is {@code false}.
   * 
   * @param pades
   *          true if PAdES and false otherwise
   */
  public void setPades(final boolean pades) {
    this.pades = pades;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(super.toString());
    sb.append(",pdfSignature=<").append(this.pdfSignature != null ? "set" : "not set").append(">");
    sb.append(",claimedSigningTime='").append(this.claimedSigningTime);
    sb.append("',signatureAlgorithm='").append(this.signatureAlgorithm);
    sb.append("',cmsAlgorithmProtection='").append(this.cmsAlgorithmProtection);
    sb.append("',isPades='").append(this.pades).append("'");
    return sb.toString();
  }

}
