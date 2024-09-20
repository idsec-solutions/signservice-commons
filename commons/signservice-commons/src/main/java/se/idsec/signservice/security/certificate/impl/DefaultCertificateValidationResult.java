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
package se.idsec.signservice.security.certificate.impl;

import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;

/**
 * Default implementation of the {@link SignatureValidationResult} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCertificateValidationResult implements CertificateValidationResult {

  /** Certificates used to validate the subject certificate, including the target certificate and trust anchor. */
  private final List<X509Certificate> validatedCertificatePath;

  /** Optional PKIX path validation result. */
  private PKIXCertPathValidatorResult pkixCertPathValidatorResult;

  /**
   * Constructor assigning the validated certificate path.
   * 
   * @param validatedCertificatePath
   *          the certificate path
   */
  public DefaultCertificateValidationResult(final List<X509Certificate> validatedCertificatePath) {
    if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()) {
      throw new IllegalArgumentException("validatedCertificatePath must be set and non-empty");
    }
    this.validatedCertificatePath = validatedCertificatePath;
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getValidatedCertificatePath() {
    return Collections.unmodifiableList(this.validatedCertificatePath);
  }

  /** {@inheritDoc} */
  @Override
  public PKIXCertPathValidatorResult getPKIXCertPathValidatorResult() {
    return this.pkixCertPathValidatorResult;
  }

  /**
   * Assigns the PKIX path validation result.
   * 
   * @param pkixCertPathValidatorResult
   *          PKIX path validation result
   */
  public void setPkixCertPathValidatorResult(final PKIXCertPathValidatorResult pkixCertPathValidatorResult) {
    this.pkixCertPathValidatorResult = pkixCertPathValidatorResult;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();
    sb.append("validatedCertificatePath=[");
    for (int i = 0; i < this.validatedCertificatePath.size(); i++) {
      if (i > 0) {
        sb.append(',');
      }
      sb.append("[").append(CertificateUtils.toLogString(this.validatedCertificatePath.get(i))).append("]");
    }
    sb.append("]");
    return sb.toString();
  }

}
 