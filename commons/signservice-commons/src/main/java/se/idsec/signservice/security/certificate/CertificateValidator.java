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
package se.idsec.signservice.security.certificate;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * An interface for verifying a certificate up until a trusted root.
 * <p>
 * The interface is an abstraction of the
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html">Java
 * Certification Path API</a>
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateValidator {

  /**
   * Validates the supplied subject certificate.
   *
   * @param subjectCertificate the certificate to validate
   * @param additionalCertificates other certificates that may be useful when building a certificate path (may be
   *     null or empty)
   * @param crls optional list of CRL:s that may be useful during path validation (may be null or empty)
   * @return a validator result
   * @throws CertPathBuilderException if a valid certificate path could not be built
   * @throws CertPathValidatorException if the path failed to verify
   * @throws GeneralSecurityException for general errors
   */
  CertificateValidationResult validate(final X509Certificate subjectCertificate,
      final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls)
      throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException;

  /**
   * Validates the supplied subject certificate. The supplied trust anchors overrides the trust configured for this
   * validator ({@link #getDefaultTrustAnchors()}).
   *
   * @param subjectCertificate the certificate to validate
   * @param additionalCertificates other certificates that may be useful when building a certificate path (may be
   *     null or empty)
   * @param crls optional list of CRL:s that may be useful during path validation (may be null or empty)
   * @param trustAnchors the trust anchors to use during validation (null or empty list means "trust any root")
   * @return a validator result
   * @throws CertPathBuilderException if a valid certificate path could not be built
   * @throws CertPathValidatorException if the path failed to verify
   * @throws GeneralSecurityException for general errors
   */
  CertificateValidationResult validate(final X509Certificate subjectCertificate,
      final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls,
      final List<X509Certificate> trustAnchors)
      throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException;

  /**
   * Predicate that tells whether this instance checks certificate revocation as part of the validation process.
   *
   * @return true if revocation checking is active and false otherwise
   */
  boolean isRevocationCheckingActive();

  /**
   * Gets the trusted (root) certificates for this validator. An empty list indicates "trust any root".
   * <p>
   * Note: These anchors may be overridden by supplying an alternative set to
   * {@link #validate(X509Certificate, List, List, List)}.
   * </p>
   *
   * @return trusted certificates
   */
  List<X509Certificate> getDefaultTrustAnchors();

}
