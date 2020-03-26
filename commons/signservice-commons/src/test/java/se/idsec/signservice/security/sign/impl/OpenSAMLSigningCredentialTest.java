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

import java.security.KeyStore;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;

/**
 * Test cases for OpenSAMLSigningCredential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLSigningCredentialTest {
  
  private Resource testJks = new ClassPathResource("test.jks");

  @BeforeClass
  public static void initializeOpenSAML() throws Exception {
    OpenSAMLInitializer.getInstance().initialize(
      new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
      new OpenSAMLSecurityExtensionConfig());
  }
  
  @Test
  public void testLoad() throws Exception {
    
    final KeyStore keystore = KeyStore.getInstance("JKS");
    keystore.load(testJks.getInputStream(), "secret".toCharArray());    
    X509Credential x509cred = new KeyStoreX509CredentialAdapter(keystore, "test", "secret".toCharArray());
    
    OpenSAMLSigningCredential cred = new OpenSAMLSigningCredential(x509cred);
    Assert.assertEquals("", cred.getName());
    Assert.assertNotNull(cred.getSigningCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertEquals(1, cred.getCertificateChain().size());
    
    cred.setName("test");
    Assert.assertEquals("test", cred.getName());
  }
  
  @Test
  public void testLoad2() throws Exception {
    KeyStoreSigningCredential c = new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "test");
    
    BasicX509Credential x509cred = new BasicX509Credential(c.getSigningCertificate(), c.getPrivateKey());
    x509cred.setEntityId("test");
    
    OpenSAMLSigningCredential cred = new OpenSAMLSigningCredential(x509cred);
    Assert.assertEquals("test", cred.getName());
    Assert.assertNotNull(cred.getSigningCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertEquals(1, cred.getCertificateChain().size());    
  }

}
