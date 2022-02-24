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
package se.idsec.signservice.security.sign.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import org.junit.Assert;
import org.junit.Test;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test cases for {@link StaticCredentials}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class StaticCredentialsTest {

  @Test
  public void generateRsa() throws Exception {

    StaticCredentials creds = new StaticCredentials();

    PkiCredential rsa = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    Assert.assertNotNull(rsa);
    PkiCredential rsa2 = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    Assert.assertNotNull(rsa2);

    // Assert that the same key is re-used.
    Assert.assertArrayEquals(rsa.getPublicKey().getEncoded(), rsa2.getPublicKey().getEncoded());

    // Invalid parameter
    creds = new StaticCredentials(65, null);

    try {
      creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
      Assert.fail("Expected NoSuchAlgorithmException");
    }
    catch (NoSuchAlgorithmException e) {
      Assert.assertTrue(InvalidParameterException.class.isInstance(e.getCause()));
    }
  }

  @Test
  public void generateRsaCustom() throws Exception {
    StaticCredentials creds = new StaticCredentials(StaticCredentials.DEFAULT_RSA_KEY_SIZE, null);

    Assert.assertEquals(StaticCredentials.DEFAULT_RSA_KEY_SIZE,
      ((RSAPublicKey) (creds.getRsaKeyPair().getPublic())).getModulus().bitLength());

    creds = new StaticCredentials(1024, null);
    Assert.assertEquals(1024,
      ((RSAPublicKey) (creds.getRsaKeyPair().getPublic())).getModulus().bitLength());
    creds = new StaticCredentials(4096, null);
    Assert.assertEquals(4096,
      ((RSAPublicKey) (creds.getRsaKeyPair().getPublic())).getModulus().bitLength());

    creds = new StaticCredentials(34, null);
    try {
      creds.getRsaKeyPair();
      Assert.fail("Expected InvalidParameterException");
    }
    catch (InvalidParameterException e) {
    }
  }

  @Test
  public void generateEc() throws Exception {
    StaticCredentials creds = new StaticCredentials();

    PkiCredential ec = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    Assert.assertNotNull(ec);
    PkiCredential ec2 = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
    Assert.assertNotNull(ec2);

    // Assert that the same key is re-used.
    Assert.assertArrayEquals(ec.getPublicKey().getEncoded(), ec2.getPublicKey().getEncoded());

    creds = new StaticCredentials(2048, "NotACurve");
    try {
      creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
      Assert.fail("Expected NoSuchAlgorithmException");
    }
    catch (NoSuchAlgorithmException e) {
      Assert.assertTrue(InvalidAlgorithmParameterException.class.isInstance(e.getCause()));
    }
  }

  @Test
  public void generateEcCustom() throws Exception {

    StaticCredentials creds = new StaticCredentials(2048, "NotACurve");

    try {
      creds.getEcKeyPair();
      Assert.fail("Expected InvalidAlgorithmParameterException");
    }
    catch (InvalidAlgorithmParameterException e) {
    }
  }
  
  @Test(expected = NoSuchAlgorithmException.class)
  public void testDSAUnsupported() throws Exception {
    StaticCredentials creds = new StaticCredentials();
    creds.getSigningCredential("http://www.w3.org/2000/09/xmldsig#dsa-sha1");
  }
  
  @Test(expected = NoSuchAlgorithmException.class)
  public void testNotASignatureAlgo() throws Exception {
    StaticCredentials creds = new StaticCredentials();
    creds.getSigningCredential("http://www.w3.org/2001/04/xmlenc#sha256");
  }

}
