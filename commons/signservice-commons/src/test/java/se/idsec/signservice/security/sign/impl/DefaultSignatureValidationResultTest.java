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
package se.idsec.signservice.security.sign.impl;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.impl.DefaultCertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;

/**
 * Test cases for DefaultSignatureValidationResult.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultSignatureValidationResultTest {

  @Test
  public void testSignatureValidationResult() throws Exception {

    DefaultSignatureValidationResult result = new DefaultSignatureValidationResult();
    Assert.assertFalse(result.isSuccess());
    Assert.assertEquals(SignatureValidationResult.Status.INTERDETERMINE, result.getStatus());

    result = new DefaultSignatureValidationResult();
    result.setStatus(SignatureValidationResult.Status.SUCCESS);
    Assert.assertTrue(result.isSuccess());
//    Assert.assertTrue(result.getAdditionalCertificates().isEmpty());
    Assert.assertNotNull(result.toString());

    result = new DefaultSignatureValidationResult();
    result.setError(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, "Invalid signer");
    Assert.assertFalse(result.isSuccess());
    Assert.assertEquals(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, result.getStatus());
    Assert.assertNotNull(result.getStatusMessage());
    Assert.assertNull(result.getException());
    Assert.assertNotNull(result.toString());

    result = new DefaultSignatureValidationResult();
    result.setError(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, "Invalid signer", new SecurityException("S"));
    Assert.assertFalse(result.isSuccess());
    Assert.assertEquals(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, result.getStatus());
    Assert.assertNotNull(result.getStatusMessage());
    Assert.assertEquals(SecurityException.class.getSimpleName(), result.getException().getClass().getSimpleName());
    Assert.assertNotNull(result.toString());

    result = new DefaultSignatureValidationResult();
    result.setStatus(SignatureValidationResult.Status.SUCCESS);
    X509Certificate root = CertificateUtils.decodeCertificate((new ClassPathResource("certs/DigiCert-Global-Root-CA.crt")).getInputStream());
    X509Certificate cert = CertificateUtils.decodeCertificate((new ClassPathResource("certs/idsec.se.cer")).getInputStream());
    result.setCertificateValidationResult(new DefaultCertificateValidationResult(Arrays.asList(cert, root)));
    result.setSignerCertificate(cert);

    Assert.assertNotNull(result.getCertificateValidationResult());
    //Assert.assertEquals(1, result.getAdditionalCertificates().size());
    Assert.assertNotNull(result.getSignerCertificate());
    Assert.assertNotNull(result.toString());
  }

}
