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
package se.idsec.signservice.security.certificate.impl;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidator;

/**
 * A simple validator that does not perform revocation checking and only relies upon the supplied certificates when
 * building the chain.
 * 
 * <p>
 * Note: If no trust anchors are defined, the path root must be available as the last element of the
 * {@code additionalCertificates} parameter. This certificate must be self-signed.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SimpleCertificateValidator implements CertificateValidator {

  /** The date/time when the certificate status should be determined. For testing mainly. */
  protected Date validationDate;

  /** The trust anchors. */
  protected List<X509Certificate> defaultTrustAnchors;

  /** {@inheritDoc} */
  @Override
  public PKIXCertPathValidatorResult validate(final X509Certificate subjectCertificate, final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls) throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException {
    return this.validate(subjectCertificate, additionalCertificates, crls, this.defaultTrustAnchors);
  }

  /** {@inheritDoc} */
  @Override
  public PKIXCertPathValidatorResult validate(final X509Certificate subjectCertificate, final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls, final List<X509Certificate> trustAnchors)
      throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException {

    log.debug("Validating certificate: {}", CertificateUtils.toLogString(subjectCertificate));

    // Setup trust anchors
    //
    final Set<TrustAnchor> trusted = this.setupTrustAnchors(trustAnchors, additionalCertificates);

    // Get cert stores ...
    //
    final List<CertStore> certStores = this.getCertStores(subjectCertificate, additionalCertificates, crls);

    // Setup the builder and validation params...
    //
    final PKIXBuilderParameters params = this.buildParameters(subjectCertificate, trusted, certStores);

    // Now, build a certificate chain ...
    //
    final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
    final CertPathBuilderResult builderResult = certPathBuilder.build(params);

    // Finally, validate the path ...
    //
    final CertPathValidator validator = CertPathValidator.getInstance("PKIX");
    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(builderResult.getCertPath(), params);

    log.debug("Validation result: {}", result);
    
    return result;
  }

  /**
   * The implementation creates a set of trust anchors based on the {@code trustAnchors} parameter. This parameter was
   * either supplied in a call to {@link #validate(X509Certificate, List, List, List)} or set as the default anchors
   * ({@link #setDefaultTrustAnchors(List)}).
   * <p>
   * If no trust anchors is available, this implementation uses the last certificate from the supplied
   * {@code additionalCertificates} parameter as the root.
   * </p>
   * 
   * @param trustAnchors
   *          the trust anchors
   * @param additionalCertificates
   *          additional certs
   * @return a set of trust anchors
   * @throws CertPathBuilderException
   *           if trust can not be setup
   */
  protected Set<TrustAnchor> setupTrustAnchors(final List<X509Certificate> trustAnchors,
      final List<X509Certificate> additionalCertificates) throws CertPathBuilderException {

    if (trustAnchors != null) {
      return trustAnchors.stream().map(t -> new TrustAnchor(t, null)).collect(Collectors.toSet());
    }
    else {
      if (additionalCertificates == null || additionalCertificates.isEmpty()) {
        final String msg = "No trust anchors supplied and no root set in additionalCertificates";
        log.error(msg);
        throw new CertPathBuilderException(msg);
      }
      final X509Certificate root = additionalCertificates.get(additionalCertificates.size() - 1);
      // Make sure it is self-signed
      if (root.getSubjectX500Principal().equals(root.getIssuerX500Principal())) {
        return Collections.singleton(new TrustAnchor(root, null));
      }
      else {
        final String msg = "No root supplied in additionalCertificates";
        log.error(msg);
        throw new CertPathBuilderException(msg);
      }
    }    
  }

  /**
   * Gets the certificate stores that should be used during path building and validation. The default implementation
   * builds one store holding the certificates supplied in {@code subjectCertificate} and {@code additionalCertificates}.
   * 
   * @param subjectCertificate
   *          the certificate to validate
   * @param additionalCertificates
   *          other certificates that may be useful when building a certificate path
   * @param crls
   *          optional list of CRL:s that may be useful during path validation
   * @return a list of cert stores
   * @throws GeneralSecurityException
   *           for cert store creation errors
   */
  protected List<CertStore> getCertStores(final X509Certificate subjectCertificate, final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls) throws GeneralSecurityException {

    final List<Object> list = new ArrayList<>();
    list.add(subjectCertificate);
    if (additionalCertificates != null) {
      additionalCertificates.forEach(list::add);
    }
    if (crls != null) {
      crls.forEach(list::add);
    }
    return Collections.singletonList(CertStore.getInstance("Collection", new CollectionCertStoreParameters(list)));
  }

  /**
   * Builds the parameters for path building and validation. This implementation disables revocation checking and uses
   * default settings from the {@link PKIXBuilderParameters} class.
   * 
   * @param subjectCertificate
   *          the subject certificate
   * @param trustAnchors
   *          the trust anchors
   * @param certStores
   *          the cert stores
   * @return a PKIXBuilderParameters object
   * @throws GeneralSecurityException
   *           for errors setting up the params
   */
  protected PKIXBuilderParameters buildParameters(final X509Certificate subjectCertificate, final Set<TrustAnchor> trustAnchors,
      final List<CertStore> certStores) throws GeneralSecurityException {

    final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, this.toCertSelector(subjectCertificate));
    params.setCertStores(certStores);
    params.setRevocationEnabled(false);
    if (this.validationDate != null) {
      params.setDate(this.validationDate);
    }
    return params;
  }

  /**
   * Creates a {@link X509CertSelector} for the supplied subject certificate.
   * 
   * @param subjectCertificate
   *          the certificate
   * @return a X509CertSelector
   */
  protected X509CertSelector toCertSelector(final X509Certificate subjectCertificate) {
    X509CertSelector selector = new X509CertSelector();
    selector.setCertificate(subjectCertificate);
    return selector;
  }

  /**
   * Always returns {@code false}.
   */
  @Override
  public boolean isRevocationCheckingActive() {
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getDefaultTrustAnchors() {
    return this.defaultTrustAnchors;
  }

  /**
   * Assigns the default trust anchors for this validator.
   * 
   * @param trustAnchors
   *          trusted root certificates
   */
  public void setDefaultTrustAnchors(final List<X509Certificate> defaultTrustAnchors) {
    this.defaultTrustAnchors = defaultTrustAnchors;
  }

  /**
   * The date/time when the certificate status should be determined. For testing mainly. If {@code null} is returned,
   * this indicates "now".
   * 
   * @return the validation date/time, or null for "now"
   */
  public Date getValidationDate() {
    return this.validationDate;
  }

  /**
   * Assigns the date/time when the certificate status should be determined. For testing mainly. If {@code null}, which
   * is the default, is assigned this indicates "now".
   * 
   * @param validationDate
   *          the validation date/time, or null for "now"
   */
  public void setValidationDate(final Date validationDate) {
    this.validationDate = validationDate;
  }

}
