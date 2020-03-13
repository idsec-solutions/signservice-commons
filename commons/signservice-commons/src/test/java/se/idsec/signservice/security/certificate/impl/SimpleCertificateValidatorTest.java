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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.idsec.signservice.security.certificate.CertificateUtils;

/**
 * Test cases for SimpleCertificateValidator.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SimpleCertificateValidatorTest {

  // The validation date
  private Date validationDate;

  // Test certs (DigiCert)
  private X509Certificate digiCertRoot;
  private X509Certificate digiCertIntermediate;
  private X509Certificate nist;
  private X509Certificate nistBadSignature;

  // Test certs (Let's encrypt)
  private X509Certificate dstRoot;

  public SimpleCertificateValidatorTest() throws CertificateException, IOException {

    // Set validation date
    Calendar c = Calendar.getInstance();
    c.set(2020, 2, 12, 19, 39, 45);
    this.validationDate = c.getTime();

    this.digiCertRoot = CertificateUtils.decodeCertificate((new ClassPathResource("certs/DigiCert-Global-Root-CA.crt")).getInputStream());
    this.digiCertIntermediate =
        CertificateUtils.decodeCertificate((new ClassPathResource("certs/DigiCert-SHA2-Secure-Server-CA.crt")).getInputStream());
    this.nist = CertificateUtils.decodeCertificate((new ClassPathResource("certs/nvd.nist.gov.crt")).getInputStream());
    this.dstRoot = CertificateUtils.decodeCertificate((new ClassPathResource("certs/DST-Root-CA-X3.crt")).getInputStream());
    
    byte[] nistEncoding = FileUtils.readFileToByteArray((new ClassPathResource("certs/nvd.nist.gov.crt")).getFile());
    nistEncoding[nistEncoding.length - 1] = (byte) ~nistEncoding[nistEncoding.length - 1];
    this.nistBadSignature = CertificateUtils.decodeCertificate(new ByteArrayInputStream(nistEncoding));
  }

  @Test
  public void testSuccess() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    PKIXCertPathValidatorResult result = validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
    Assert.assertEquals(this.digiCertRoot, result.getTrustAnchor().getTrustedCert());
    
    // The same with several roots in trust
    validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Arrays.asList(this.dstRoot, this.digiCertRoot));

    result = validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
    Assert.assertEquals(this.digiCertRoot, result.getTrustAnchor().getTrustedCert());
  }

  @Test
  public void testSuccessTrustAnyRoot() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.dstRoot));

    PKIXCertPathValidatorResult result =
        validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate, this.digiCertRoot), null, null);
    Assert.assertEquals(this.digiCertRoot, result.getTrustAnchor().getTrustedCert());
  }

  @Test
  public void testSuccessTrustAnyRootNotFound() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.dstRoot));

    try {
      validator.validate(this.nist, Arrays.asList(this.digiCertRoot, this.digiCertIntermediate), null, null);
      Assert.fail("Expected CertPathBuilderException");
    }
    catch (CertPathBuilderException e) {
    }
  }

  @Test
  public void testBadSignature() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    try {
      validator.validate(this.nistBadSignature, Arrays.asList(this.digiCertIntermediate), null);
    }
    catch (CertPathBuilderException e) {
    }
  }
  
  @Test
  public void testExpired() throws Exception {
    Calendar c = Calendar.getInstance();
    c.set(2024, 2, 12, 19, 39, 45);
    
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(c.getTime());
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    try {
      validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
    }
    catch (CertPathBuilderException e) {      
    }
  } 
  
  @Test
  public void testNoRootFound() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.dstRoot));

    try {
      validator.validate(this.nist, Arrays.asList(this.digiCertIntermediate), null);
      Assert.fail("Expected CertPathBuilderException");
    }
    catch (CertPathBuilderException e) {
    }
  }

  @Test
  public void testMissingIntermediate() throws Exception {
    SimpleCertificateValidator validator = new SimpleCertificateValidator();
    validator.setValidationDate(this.validationDate);
    validator.setDefaultTrustAnchors(Collections.singletonList(this.digiCertRoot));

    try {
      validator.validate(this.nist, Collections.emptyList(), null);
      Assert.fail("Expected CertPathBuilderException");
    }
    catch (CertPathBuilderException e) {
    }
  }
}
