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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidationResult;

/**
 * Test cases for SimpleCertificateValidator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SimpleCertificateValidatorTest {

  // The validation date
  private final Date validationDate;

  // Test certs (DigiCert)
  private final X509Certificate digiCertRoot;
  private final X509Certificate digiCertIntermediate;
  private final X509Certificate nist;
  private final X509Certificate nistBadSignature;

  // Test certs (Let's encrypt)
  private final X509Certificate dstRoot;

  // Dummy CRL (not used)
  private final X509CRL crl;

  public SimpleCertificateValidatorTest() throws CertificateException, CRLException, IOException {

    // Set validation date
    final Calendar c = Calendar.getInstance();
    c.set(2020, 2, 12, 19, 39, 45);
    this.validationDate = c.getTime();

    this.digiCertRoot = CertificateUtils
        .decodeCertificate(new ClassPathResource("certs/DigiCert-Global-Root-CA.crt").getInputStream());
    this.digiCertIntermediate =
        CertificateUtils
            .decodeCertificate(new ClassPathResource("certs/DigiCert-SHA2-Secure-Server-CA.crt").getInputStream());
    this.nist = CertificateUtils.decodeCertificate(new ClassPathResource("certs/nvd.nist.gov.crt").getInputStream());
    this.dstRoot =
        CertificateUtils.decodeCertificate(new ClassPathResource("certs/DST-Root-CA-X3.crt").getInputStream());

    final byte[] nistEncoding =
        FileUtils.readFileToByteArray(new ClassPathResource("certs/nvd.nist.gov.crt").getFile());
    nistEncoding[nistEncoding.length - 1] = (byte) ~nistEncoding[nistEncoding.length - 1];
    this.nistBadSignature = CertificateUtils.decodeCertificate(new ByteArrayInputStream(nistEncoding));

    this.crl = CertificateUtils.decodeCrl(new ClassPathResource("certs/sample.crl").getInputStream());
  }

  @Test
  public void testSuccess() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    Assertions.assertFalse(validator.isRevocationCheckingActive());
    Assertions.assertEquals(1, validator.getDefaultTrustAnchors().size());

    CertificateValidationResult result =
        validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), Arrays.asList(this.crl));
    Assertions.assertEquals(this.digiCertRoot,
        result.getPKIXCertPathValidatorResult().getTrustAnchor().getTrustedCert());

    // The same with several roots in trust
    validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Arrays.asList(this.dstRoot, this.digiCertRoot));

    result = validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
    Assertions.assertEquals(this.digiCertRoot,
        result.getPKIXCertPathValidatorResult().getTrustAnchor().getTrustedCert());
  }

  @Test
  public void testSuccessTrustAnyRoot() throws Exception {
    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.dstRoot));

    final CertificateValidationResult result =
        validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate, this.digiCertRoot), null, null);
    Assertions.assertEquals(this.digiCertRoot,
        result.getPKIXCertPathValidatorResult().getTrustAnchor().getTrustedCert());
  }

  @Test
  public void testRootNotFound() throws Exception {
    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.dstRoot));

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, Arrays.asList(this.digiCertRoot, this.digiCertIntermediate), null, null);
    });
  }

  @Test
  public void testNoTrustAnchorsAvailable() throws Exception {
    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);

    Assertions.assertTrue(validator.getDefaultTrustAnchors().isEmpty());
    Assertions.assertEquals(this.validationDate, validator.getValidationDate());

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, null, null, null);
    });

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, Collections.emptyList(), null, null);
    });

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null, null);
    });
  }

  @Test
  public void testBadSignature() throws Exception {
    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nistBadSignature, Arrays.asList(this.digiCertIntermediate), null);
    });
  }

  @Test
  public void testExpired() throws Exception {
    final Calendar c = Calendar.getInstance();
    c.set(2024, 2, 12, 19, 39, 45);

    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(c.getTime());
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
    });
  }

  @Test
  public void testNoRootFound() throws Exception {
    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.dstRoot));

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
    });
  }

  @Test
  public void testMissingIntermediate() throws Exception {
    final SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, Collections.emptyList(), null);
    });

    Assertions.assertThrows(CertPathBuilderException.class, () -> {
      validator.validate(this.nist, null, null);
    });
  }
}
