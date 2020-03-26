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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.core.io.Resource;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.SigningCredential;

/**
 * A {@link SigningCredential} implementation backed by a Java keystore.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class KeyStoreSigningCredential implements SigningCredential {

  /**
   * The key entry for the credentials.
   */
  private KeyStore.PrivateKeyEntry keyEntry;
  
  /** The credential name. */
  private String name;
  
  /** The keystore alias. */
  private String alias;

  /**
   * Constructor invoking {@link #KeyStoreSigningCredential(Resource, char[], String, String, char[])} where the
   * {@code keyPassword} is the same as {@code password} and {@code type} is {@link KeyStore#getDefaultType()}.
   *
   * @param resource
   *          the keystore resource
   * @param password
   *          the keystore password
   * @param alias
   *          the alias for the key entry
   * @throws KeyStoreException
   *           for errors loading the keystore
   */
  public KeyStoreSigningCredential(final Resource resource, final char[] password, final String alias) throws KeyStoreException {
    this(resource, password, KeyStore.getDefaultType(), alias, password);
  }

  /**
   * Constructor invoking {@link #KeyStoreSigningCredential(Resource, char[], String, String, char[])} where the
   * {@code keyPassword} is the same as {@code password}.
   *
   * @param resource
   *          the keystore resource
   * @param password
   *          the keystore password
   * @param type
   *          the keystore type
   * @param alias
   *          the alias for the key entry
   * @throws KeyStoreException
   *           for errors loading the keystore
   */
  public KeyStoreSigningCredential(final Resource resource, final char[] password, final String type, final String alias)
      throws KeyStoreException {
    this(resource, password, type, alias, password);
  }

  /**
   * Constructor unlocking the keystore.
   *
   * @param resource
   *          the keystore resource
   * @param password
   *          the keystore password
   * @param type
   *          the keystore type
   * @param alias
   *          the alias for the key entry
   * @param keyPassword
   *          the password for the key entry
   * @throws KeyStoreException
   *           for errors loading the keystore
   */
  public KeyStoreSigningCredential(final Resource resource, final char[] password, final String type, 
      final String alias, final char[] keyPassword) throws KeyStoreException {

    this.alias = alias;
    final KeyStore keystore = KeyStore.getInstance(type);
    try {
      keystore.load(resource.getInputStream(), password);
      this.keyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
      if (this.keyEntry == null) {
        log.error("No entry for alias '{}' found", alias);
        throw new KeyStoreException("No entry found for alias " + alias);
      }
    }
    catch (IOException | UnrecoverableEntryException | NoSuchAlgorithmException | CertificateException e) {
      log.error("Failed to load keystore {}", e.getMessage(), e);
      throw new KeyStoreException(e.getMessage(), e);
    }
  }
  
  /** {@inheritDoc} */
  @Override
  public X509Certificate getSigningCertificate() {
    return (X509Certificate) this.keyEntry.getCertificate();
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.getSigningCertificate().getPublicKey();
  }
  
  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.keyEntry.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getCertificateChain() {
    return Arrays.stream(this.keyEntry.getCertificateChain())
        .map(X509Certificate.class::cast)
        .collect(Collectors.toList());
  }

  /**
   * Sets the credential name. If not set, {@link #getName()} returns the alias name.
   * @param name the name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name != null ? this.name : this.alias;
  }

}
