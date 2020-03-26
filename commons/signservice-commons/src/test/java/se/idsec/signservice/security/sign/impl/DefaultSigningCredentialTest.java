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

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * Test cases for DefaultSigningCredential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultSigningCredentialTest {

  private Resource testJks = new ClassPathResource("test.jks");

  @Test
  public void testInitializeKeyPair() throws Exception {
    StaticCredentials c = new StaticCredentials();

    DefaultSigningCredential cred = new DefaultSigningCredential("name", c.getRsaKeyPair());
    Assert.assertEquals("name", cred.getName());
    Assert.assertNull(cred.getSigningCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertTrue(cred.getCertificateChain().isEmpty());
  }

  @Test
  public void testInitializeKeys() throws Exception {
    StaticCredentials c = new StaticCredentials();

    DefaultSigningCredential cred = new DefaultSigningCredential("name", c.getRsaKeyPair().getPrivate(), c.getRsaKeyPair().getPublic());
    Assert.assertEquals("name", cred.getName());
    Assert.assertNull(cred.getSigningCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertTrue(cred.getCertificateChain().isEmpty());
  }
  
  @Test
  public void testInitializeCert() throws Exception {
    KeyStoreSigningCredential c = new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "test");
    
    DefaultSigningCredential cred = new DefaultSigningCredential("name", c.getPrivateKey(), c.getSigningCertificate());
    Assert.assertEquals("name", cred.getName());
    Assert.assertNotNull(cred.getSigningCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertEquals(1, cred.getCertificateChain().size());
  }
}
