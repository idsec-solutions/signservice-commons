/*
 * Copyright 2019 Litsec AB
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.SigningCredential;

/**
 * Utility class that holds pre-generated key pairs.
 * <p>
 * Mainly useful for testing, but also when to-be-signed bytes are calculated.
 * </p>
 * 
 * @author Martin Lindström (martin@litsec.se)
 */
@Slf4j
public class StaticCredentials {

  /** Pre-generated RSA key pair. */
  private KeyPair rsaKeyPair;

  /** Pre-generated EC key pair. */
  private KeyPair ecKeyPair;
  
  /**
   * Constructor.
   */
  public StaticCredentials() {    
  }

  /**
   * Returns a {@link SigningCredential} that can be used to sign using the supplied algorithm.
   * 
   * @param algorithmUri
   *          the signature algorithm URI
   * @return a SigningCredential instance
   * @throws NoSuchAlgorithmException
   *           if the supplied algorithm is not supported
   */
  public SigningCredential getSigningCredential(final String algorithmUri) throws NoSuchAlgorithmException {
    final AlgorithmDescriptor descriptor = AlgorithmSupport.getGlobalAlgorithmRegistry().get(algorithmUri);
    if (descriptor == null) {
      final String msg = String.format("Algorithm '%s' is not supported", algorithmUri);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }
    if (AlgorithmDescriptor.AlgorithmType.Signature != descriptor.getType()) {
      final String msg = String.format("Algorithm '%s' is not a valid signature algorithm", algorithmUri);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }
    final String algoKey = ((SignatureAlgorithm) descriptor).getKey();
    if (JCAConstants.KEY_ALGO_RSA.equals(algoKey)) {
      synchronized (this) {
        return new DefaultSigningCredential("RSA", this.getRsaKeyPair());
      }      
    }
    else if (JCAConstants.KEY_ALGO_EC.equals(algoKey)) {
      synchronized (this) {
        return new DefaultSigningCredential("EC", this.getEcKeyPair());
      }      
    }
    else {
      final String msg = String.format("Algorithm '%s' is not supported - could not generate key pair", algorithmUri);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }
  }

  private synchronized KeyPair getRsaKeyPair() throws NoSuchAlgorithmException {
    if (this.rsaKeyPair == null) {
      log.debug("Generating RSA key pair ...");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      this.rsaKeyPair = generator.generateKeyPair();
    }
    return this.rsaKeyPair;
  }

  private synchronized KeyPair getEcKeyPair() throws NoSuchAlgorithmException {
    if (this.ecKeyPair == null) {
      log.debug("Generating EC key pair ...");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
      try {
        generator.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
      }
      catch (InvalidAlgorithmParameterException e) {
        throw new NoSuchAlgorithmException("P-256", e);
      }
      this.ecKeyPair = generator.generateKeyPair();
    }
    return this.ecKeyPair;
  }

}
