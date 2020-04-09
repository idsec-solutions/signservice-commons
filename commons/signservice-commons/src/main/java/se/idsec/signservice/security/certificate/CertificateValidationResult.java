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
package se.idsec.signservice.security.certificate;

import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface representing the successful result of a signature validation operation.
 *
 * <p>
 * Failed certificate validation throws an exception with suitable information.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateValidationResult {

  /**
   * Gets the certificate path that was used to validate the subject certificate.
   * <p>
   * The certificate path starts with the subject certificate and ends with the trust anchor. Every certificate except
   * the subject certificate must validate the certificate preceding it in the list.
   * </p>
   *
   * @return the certificate chain
   */
  List<X509Certificate> getValidatedCertificatePath();

  /**
   * Gets an optional path validation result.
   * <p>
   * This result object is only relevant if the certificate validation function performed PKIX path validation from the
   * target certificate to a trusted trust anchor certificate. If method returns {@code null} does not mean that
   * certificate validation failed.
   * </p>
   * 
   * @return a PKIXCertPathValidatorResult object or null if no path validation result is available
   */
  PKIXCertPathValidatorResult getPKIXCertPathValidatorResult();

}
