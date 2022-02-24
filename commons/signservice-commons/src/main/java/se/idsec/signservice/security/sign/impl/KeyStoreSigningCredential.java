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

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.springframework.core.io.Resource;

import se.idsec.signservice.security.sign.SigningCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;

/**
 * A {@link SigningCredential} implementation backed by a Java keystore.
 * 
 * @deprecated Use {@link KeyStoreCredential} instead.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Deprecated(since = "1.2.0", forRemoval = true)
public class KeyStoreSigningCredential extends KeyStoreCredential implements SigningCredential {

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
    super(resource, type, password, alias, keyPassword);
    try {
      this.init();      
    }
    catch (final Exception e) {
      throw new SecurityException("Failed to initialize credential", e);
    }
  }
  
}
