/*
 * Copyright 2019 IDsec Solutions AB
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

import java.security.NoSuchAlgorithmException;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import se.idsec.signservice.security.sign.SigningCredential;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;

/**
 * Test cases for {@link StaticCredentials}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class StaticCredentialsTest {

  @BeforeClass
  public static void initializeOpenSAML() throws Exception {
    OpenSAMLInitializer.getInstance().initialize(
      new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
      new OpenSAMLSecurityExtensionConfig());
  }

  @Test
  public void generateRsa() throws Exception {

    StaticCredentials creds = new StaticCredentials();

    SigningCredential rsa = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    Assert.assertNotNull(rsa);
    SigningCredential rsa2 = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    Assert.assertNotNull(rsa2);

    // Assert that the same key is re-used.
    Assert.assertArrayEquals(rsa.getPublicKey().getEncoded(), rsa2.getPublicKey().getEncoded());
  }

  @Test
  public void generateEc() throws Exception {
    StaticCredentials creds = new StaticCredentials();

    SigningCredential ec = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    Assert.assertNotNull(ec);
    SigningCredential ec2 = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
    Assert.assertNotNull(ec2);

    // Assert that the same key is re-used.
    Assert.assertArrayEquals(ec.getPublicKey().getEncoded(), ec2.getPublicKey().getEncoded());
  }
  
  @Test(expected = NoSuchAlgorithmException.class)
  public void testUnsupported() throws Exception {
    StaticCredentials creds = new StaticCredentials();
    creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha777");
  }

}
