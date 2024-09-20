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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

/**
 * Test cases for CertificateUtils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CertificateUtilsTest {

  @Test
  public void testDecodeCertFromInputStream() throws Exception {

    // Decode DER-encoded cert ...
    //
    X509Certificate cert = CertificateUtils.decodeCertificate(this.getResource("certs/idsec.se.cer"));
    Assertions.assertNotNull(cert, "Failed to decode idsec.se.cer");

    // PEM-format
    //
    cert = CertificateUtils.decodeCertificate(this.getResource("certs/swedenconnect.pem"));
    Assertions.assertNotNull(cert, "Failed to decode swedenconnect.pem");

    // Not a certificate ...
    Assertions.assertThrows(CertificateException.class, () -> {
      CertificateUtils.decodeCertificate(this.getResource("simplelogger.properties"));
    });
  }

  @Test
  public void testCertDecodeFromBytes() throws Exception {

    // Decode DER-encoded cert ...
    //
    X509Certificate cert =
        CertificateUtils.decodeCertificate(IOUtils.toByteArray(this.getResource("certs/idsec.se.cer")));
    Assertions.assertNotNull(cert, "Failed to decode idsec.se.cer");

    // PEM-format
    //
    cert = CertificateUtils.decodeCertificate(IOUtils.toByteArray(this.getResource("certs/swedenconnect.pem")));
    Assertions.assertNotNull(cert, "Failed to decode swedenconnect.pem");

    // Not a certificate ...
    Assertions.assertThrows(CertificateException.class, () -> {
      CertificateUtils.decodeCertificate(IOUtils.toByteArray(this.getResource("simplelogger.properties")));
    });
  }

  @Test
  public void testDecodeCrlFromInputStream() throws Exception {

    final X509CRL crl = CertificateUtils.decodeCrl(this.getResource("certs/sample.crl"));
    Assertions.assertNotNull(crl, "Failed to decode sample.crl");

    // Not a CRL ...
    Assertions.assertThrows(CRLException.class, () -> {
      CertificateUtils.decodeCrl(this.getResource("certs/idsec.se.cer"));
    });
  }

  @Test
  public void testDecodeCrlFromBytes() throws Exception {

    final X509CRL crl = CertificateUtils.decodeCrl(IOUtils.toByteArray(this.getResource("certs/sample.crl")));
    Assertions.assertNotNull(crl, "Failed to decode sample.crl");

    // Not a CRL ...
    Assertions.assertThrows(CRLException.class, () -> {
      CertificateUtils.decodeCrl(IOUtils.toByteArray(this.getResource("certs/idsec.se.cer")));
    });
  }

  @Test
  public void testToLogString() throws Exception {

    final X509Certificate cert = CertificateUtils.decodeCertificate(this.getResource("certs/idsec.se.cer"));
    String s = CertificateUtils.toLogString(cert);
    Assertions.assertTrue(s.contains(cert.getSubjectX500Principal().getName()));
    Assertions.assertTrue(s.contains(cert.getIssuerX500Principal().getName()));
    Assertions.assertTrue(s.contains(cert.getSerialNumber().toString()));

    s = CertificateUtils.toLogString(null);
    Assertions.assertEquals("null", s);
  }

  private InputStream getResource(final String cpResource) throws IOException {
    return new ClassPathResource(cpResource).getInputStream();
  }

}
