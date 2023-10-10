/*
 * Copyright 2019-2023 IDsec Solutions AB
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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

    final StaticCredentials creds = new StaticCredentials();

    final PkiCredential rsa = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    Assertions.assertNotNull(rsa);
    final PkiCredential rsa2 = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    Assertions.assertNotNull(rsa2);

    // Assert that the same key is re-used.
    Assertions.assertArrayEquals(rsa.getPublicKey().getEncoded(), rsa2.getPublicKey().getEncoded());

    // Invalid parameter
    final Exception e = Assertions.assertThrows(NoSuchAlgorithmException.class, () -> {
      final StaticCredentials creds2 = new StaticCredentials(65, null);
      creds2.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    });
    Assertions.assertTrue(InvalidParameterException.class.isInstance(e.getCause()));
  }

  @Test
  public void generateRsaCustom() throws Exception {
    StaticCredentials creds = new StaticCredentials(StaticCredentials.DEFAULT_RSA_KEY_SIZE, null);

    Assertions.assertEquals(StaticCredentials.DEFAULT_RSA_KEY_SIZE,
        ((RSAPublicKey) creds.getRsaKeyPair().getPublic()).getModulus().bitLength());

    creds = new StaticCredentials(1024, null);
    Assertions.assertEquals(1024, ((RSAPublicKey) creds.getRsaKeyPair().getPublic()).getModulus().bitLength());
    creds = new StaticCredentials(4096, null);
    Assertions.assertEquals(4096, ((RSAPublicKey) creds.getRsaKeyPair().getPublic()).getModulus().bitLength());

    Assertions.assertThrows(InvalidParameterException.class, () -> {
      final StaticCredentials creds2 = new StaticCredentials(34, null);
      creds2.getRsaKeyPair();
    });
  }

  @Test
  public void generateEc() throws Exception {
    StaticCredentials creds = new StaticCredentials();

    final PkiCredential ec = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    Assertions.assertNotNull(ec);
    final PkiCredential ec2 = creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
    Assertions.assertNotNull(ec2);

    // Assert that the same key is re-used.
    Assertions.assertArrayEquals(ec.getPublicKey().getEncoded(), ec2.getPublicKey().getEncoded());

    creds = new StaticCredentials(2048, "NotACurve");
    try {
      creds.getSigningCredential("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
      Assertions.fail("Expected NoSuchAlgorithmException");
    }
    catch (final NoSuchAlgorithmException e) {
      Assertions.assertTrue(InvalidAlgorithmParameterException.class.isInstance(e.getCause()));
    }
  }

  @Test
  public void generateEcCustom() throws Exception {

    final StaticCredentials creds = new StaticCredentials(2048, "NotACurve");

    try {
      creds.getEcKeyPair();
      Assertions.fail("Expected InvalidAlgorithmParameterException");
    }
    catch (final InvalidAlgorithmParameterException e) {
    }
  }

  @Test
  public void testDSAUnsupported() throws Exception {
    final StaticCredentials creds = new StaticCredentials();
    Assertions.assertThrows(NoSuchAlgorithmException.class, () -> {
      creds.getSigningCredential("http://www.w3.org/2000/09/xmldsig#dsa-sha1");
    });
  }

  @Test
  public void testNotASignatureAlgo() throws Exception {
    final StaticCredentials creds = new StaticCredentials();
    Assertions.assertThrows(NoSuchAlgorithmException.class, () -> {
      creds.getSigningCredential("http://www.w3.org/2001/04/xmlenc#sha256");
    });
  }

}
