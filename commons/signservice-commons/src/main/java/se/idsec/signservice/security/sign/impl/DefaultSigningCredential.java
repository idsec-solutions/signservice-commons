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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

import se.idsec.signservice.security.sign.SigningCredential;
import se.swedenconnect.security.credential.BasicCredential;

/**
 * Default implementation of the {@link SigningCredential} interface.
 * 
 * @deprecated Use {@link BasicCredential} instead.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Deprecated(since = "1.2.0", forRemoval = true)
public class DefaultSigningCredential extends BasicCredential implements SigningCredential {

  /**
   * Constructor.
   * 
   * @param name
   *          the name of the credential
   * @param keyPair
   *          the key pair (private/public key)
   */
  public DefaultSigningCredential(final String name, final KeyPair keyPair) {
    super(Optional.ofNullable(keyPair).map(KeyPair::getPublic).orElse(null),
      Optional.ofNullable(keyPair).map(KeyPair::getPrivate).orElse(null));
    this.setName(name);
    try {
      this.init();
    }
    catch (final Exception e) {
      throw new SecurityException("Failed to initialize credential", e);
    }
  }

  /**
   * Constructor.
   * 
   * @param name
   *          the name of the credential
   * @param privateKey
   *          the private key
   * @param publicKey
   *          the public key
   */
  public DefaultSigningCredential(final String name, final PrivateKey privateKey, final PublicKey publicKey) {
    super(publicKey, privateKey);
    this.setName(name);
    try {
      this.init();
    }
    catch (final Exception e) {
      throw new SecurityException("Failed to initialize credential", e);
    }
  }

  /**
   * Constructor.
   * 
   * @param name
   *          the name of the credential
   * @param privateKey
   *          the private key
   * @param signingCertificate
   *          the signing certificate
   */
  public DefaultSigningCredential(
      final String name, final PrivateKey privateKey, final X509Certificate signingCertificate) {
    super(signingCertificate, privateKey);
    this.setName(name);
    try {
      this.init();
    }
    catch (final Exception e) {
      throw new SecurityException("Failed to initialize credential", e);
    }
  }

}
