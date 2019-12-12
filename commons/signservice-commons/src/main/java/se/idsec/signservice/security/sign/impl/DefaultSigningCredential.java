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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.idsec.signservice.security.sign.SigningCredential;

/**
 * Default implementation of the {@link SigningCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultSigningCredential implements SigningCredential {

  /** The name of the credential. */
  private String name;

  /** The private key. */
  private PrivateKey privateKey;

  /** The public key. */
  private PublicKey publicKey;

  /** The signing certificate. */
  private X509Certificate signingCertificate;

  /**
   * Constructor.
   * 
   * @param name the name of the credential
   * @param keyPair the key pair (private/public key)
   */
  public DefaultSigningCredential(@Nonnull final String name, @Nonnull final KeyPair keyPair) {
    this.name = Constraint.isNotEmpty(name, "name must be set");
    Constraint.isNotNull(keyPair, "keyPair must not be null");
    this.privateKey = keyPair.getPrivate();
    this.publicKey = keyPair.getPublic();
  }
  
  /**
   * Constructor.
   * 
   * @param name the name of the credential
   * @param privateKey the private key
   * @param publicKey the public key
   */
  public DefaultSigningCredential(@Nonnull final String name, @Nonnull final PrivateKey privateKey, @Nonnull final PublicKey publicKey) {
    this.name = Constraint.isNotEmpty(name, "name must be set");
    this.privateKey = Constraint.isNotNull(privateKey, "privateKey must not be null");
    this.publicKey = Constraint.isNotNull(publicKey, "publicKey must not be null");
  }

  /**
   * Constructor.
   * 
   * @param name the name of the credential
   * @param privateKey the private key
   * @param signingCertificate the signing certificate
   */
  public DefaultSigningCredential(
      @Nonnull final String name, @Nonnull final PrivateKey privateKey, @Nonnull final X509Certificate signingCertificate) {
    this.name = Constraint.isNotEmpty(name, "name must be set");
    this.privateKey = Constraint.isNotNull(privateKey, "privateKey must not be null");
    this.signingCertificate = Constraint.isNotNull(signingCertificate, "signingCertificate must not be null");
    this.publicKey = this.signingCertificate.getPublicKey();
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getSigningCertificate() {
    return this.signingCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.publicKey;
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  /**
   * Returns an empty list, or if the signing certificate is set, a list with this object.
   */
  @Override
  public List<X509Certificate> getCertificateChain() {
    return this.signingCertificate != null ? Collections.singletonList(this.signingCertificate) : Collections.emptyList();
  }
  
  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name;
  }

}
