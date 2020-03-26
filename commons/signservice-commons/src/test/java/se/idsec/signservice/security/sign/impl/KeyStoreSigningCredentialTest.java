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

import java.security.KeyStoreException;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * Test cases for KeyStoreSigningCredential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreSigningCredentialTest {

  private Resource testJks = new ClassPathResource("test.jks");

  @Test
  public void testLoad() throws Exception {
    KeyStoreSigningCredential c = new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "test");
    Assert.assertNotNull(c.getSigningCertificate());
    Assert.assertNotNull(c.getPublicKey());
    Assert.assertNotNull(c.getPrivateKey());
    Assert.assertEquals(1, c.getCertificateChain().size());
    Assert.assertEquals("test", c.getName());
    
    c.setName("otherName");
    Assert.assertEquals("otherName", c.getName());
    
    // Test the other constructors
    c = new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "JKS", "test");
    Assert.assertNotNull(c);
    
    c = new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "JKS", "test", "secret".toCharArray());
    Assert.assertNotNull(c);
  }
  
  @Test(expected = KeyStoreException.class)
  public void testFailBadPassword() throws Exception {
    new KeyStoreSigningCredential(this.testJks, "nosecret".toCharArray(), "test");
  }
  
  @Test(expected = KeyStoreException.class)
  public void testFailWrongAlias() throws Exception {
    new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "bad-alias");
  }
  
  @Test(expected = KeyStoreException.class)
  public void testFailWrongType() throws Exception {
    new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "PKCS12", "test");
  }
  
  @Test(expected = KeyStoreException.class)
  public void testFailBadKeyPassword() throws Exception {
    new KeyStoreSigningCredential(this.testJks, "secret".toCharArray(), "PKCS12", "test", "badpw".toCharArray());
  }

}
