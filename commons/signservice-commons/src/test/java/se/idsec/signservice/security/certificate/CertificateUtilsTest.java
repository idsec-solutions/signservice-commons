/*
 * Copyright 2019-2022 IDsec Solutions AB
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
import org.junit.Assert;
import org.junit.Test;
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
    X509Certificate cert = CertificateUtils.decodeCertificate(getResource("certs/idsec.se.cer"));
    Assert.assertNotNull("Failed to decode idsec.se.cer", cert);
    
    // PEM-format
    //
    cert = CertificateUtils.decodeCertificate(getResource("certs/swedenconnect.pem"));
    Assert.assertNotNull("Failed to decode swedenconnect.pem", cert);
    
    // Not a certificate ...
    try {
      CertificateUtils.decodeCertificate(getResource("simplelogger.properties"));
      Assert.fail("Expected CertificateException");
    }
    catch (CertificateException e) {      
    }
  }
  
  @Test 
  public void testCertDecodeFromBytes() throws Exception {
    
    // Decode DER-encoded cert ...
    //
    X509Certificate cert = CertificateUtils.decodeCertificate(IOUtils.toByteArray(getResource("certs/idsec.se.cer")));
    Assert.assertNotNull("Failed to decode idsec.se.cer", cert);
    
    // PEM-format
    //
    cert = CertificateUtils.decodeCertificate(IOUtils.toByteArray(getResource("certs/swedenconnect.pem")));
    Assert.assertNotNull("Failed to decode swedenconnect.pem", cert);
    
    // Not a certificate ...
    try {
      CertificateUtils.decodeCertificate(IOUtils.toByteArray(getResource("simplelogger.properties")));
      Assert.fail("Expected CertificateException");
    }
    catch (CertificateException e) {      
    }
  }
  
  @Test 
  public void testDecodeCrlFromInputStream() throws Exception {
    
    X509CRL crl = CertificateUtils.decodeCrl(getResource("certs/sample.crl"));
    Assert.assertNotNull("Failed to decode sample.crl", crl);
        
    // Not a CRL ...
    try {
      CertificateUtils.decodeCrl(getResource("certs/idsec.se.cer"));
      Assert.fail("Expected CRLException");
    }
    catch (CRLException e) {      
    }
  }
  
  @Test 
  public void testDecodeCrlFromBytes() throws Exception {
    
    X509CRL crl = CertificateUtils.decodeCrl(IOUtils.toByteArray(getResource("certs/sample.crl")));
    Assert.assertNotNull("Failed to decode sample.crl", crl);
        
    // Not a CRL ...
    try {
      CertificateUtils.decodeCrl(IOUtils.toByteArray(getResource("certs/idsec.se.cer")));
      Assert.fail("Expected CRLException");
    }
    catch (CRLException e) {      
    }
  }  
  
  @Test
  public void testToLogString() throws Exception {
    
    X509Certificate cert = CertificateUtils.decodeCertificate(getResource("certs/idsec.se.cer"));
    String s = CertificateUtils.toLogString(cert);
    Assert.assertTrue(s.contains(cert.getSubjectX500Principal().getName()));
    Assert.assertTrue(s.contains(cert.getIssuerX500Principal().getName()));
    Assert.assertTrue(s.contains(cert.getSerialNumber().toString()));
    
    s = CertificateUtils.toLogString(null);
    Assert.assertEquals("null", s);
  }
  
  private InputStream getResource(final String cpResource) throws IOException {
    return (new ClassPathResource(cpResource)).getInputStream();
  }

}
