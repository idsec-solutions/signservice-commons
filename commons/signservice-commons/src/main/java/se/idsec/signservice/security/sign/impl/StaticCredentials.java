/*
 * Copyright 2019-2020 Litsec AB
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

  /** The default number of bits for RSA keys. */
  public static final int DEFAULT_RSA_KEY_SIZE = 2048;

  /** The default curve to use for EC keys. */
  public static final String DEFAULT_EC_CURVE = "P-256";

  /** Pre-generated RSA key pair. */
  private KeyPair rsaKeyPair;

  /** Pre-generated EC key pair. */
  private KeyPair ecKeyPair;

  /** The number of bits for the generated RSA keys - default is {@value #DEFAULT_RSA_KEY_SIZE}. */
  private int rsaKeySize = DEFAULT_RSA_KEY_SIZE;

  /** The curve to use for EC keys - default is {@value #DEFAULT_EC_CURVE}. */
  private String ecCurve = DEFAULT_EC_CURVE;

  /**
   * Constructor.
   */
  public StaticCredentials() {
  }

  /**
   * Constructor setting the key size for RSA and curve for EC to use.
   * 
   * @param rsaKeySize
   *          RSA key size in bits (default is {@value #DEFAULT_RSA_KEY_SIZE})
   * @param ecCurve
   *          identifier for EC curve to use (default is {@value #DEFAULT_EC_CURVE})
   */
  public StaticCredentials(final int rsaKeySize, final String ecCurve) {
    this.rsaKeySize = rsaKeySize;
    if (ecCurve != null) {
      this.ecCurve = ecCurve;
    }
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
    try {
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
    catch (InvalidParameterException | InvalidAlgorithmParameterException e) {
      throw new NoSuchAlgorithmException("Invalid parameter", e);
    }
  }

  /**
   * Gets the generated RSA key pair.
   * 
   * @return the RSA key pair.
   * @throws InvalidParameterException
   *           if the keysize is incorrect
   */
  public synchronized KeyPair getRsaKeyPair() throws InvalidParameterException {
    if (this.rsaKeyPair == null) {
      this.rsaKeyPair = this.generateRsaKeyPair(this.rsaKeySize);
    }
    return this.rsaKeyPair;
  }

  /**
   * Gets the generated EC key pair.
   * 
   * @return the EC key pair
   * @throws InvalidAlgorithmParameterException
   *           for unsupported curve
   */
  public synchronized KeyPair getEcKeyPair() throws InvalidAlgorithmParameterException {
    if (this.ecKeyPair == null) {
      this.ecKeyPair = this.generateEcKeyPair(this.ecCurve);
    }
    return this.ecKeyPair;
  }

  /**
   * Generates a RSA key pair.
   * 
   * @param keysize
   *          the keysize in bits
   * @return RSA key pair
   * @throws InvalidParameterException
   *           if the bit size is incorrect
   */
  private KeyPair generateRsaKeyPair(final int keysize) throws InvalidParameterException {
    log.debug("Generating RSA key pair ...");
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(keysize);
      return generator.generateKeyPair();
    }
    catch (NoSuchAlgorithmException e) {
      // RSA not supported? That's not happening.
      throw new SecurityException(e);
    }
  }

  /**
   * Generates an EC keypair.
   * 
   * @param ecCurve
   *          the curve
   * @return EC keypair
   * @throws InvalidAlgorithmParameterException
   *           for invalid curve
   */
  private KeyPair generateEcKeyPair(final String ecCurve) throws InvalidAlgorithmParameterException {
    log.debug("Generating EC key pair ...");
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
      generator.initialize(new ECGenParameterSpec(ecCurve), new SecureRandom());
      return generator.generateKeyPair();
    }
    catch (NoSuchAlgorithmException e) {
      throw new SecurityException(e);
    }
  }

}
