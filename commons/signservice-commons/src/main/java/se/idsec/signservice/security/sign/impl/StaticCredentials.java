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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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

  /** Certificate for RSA private key */
  private X509Certificate rsaCert;

  /** Certificate for EC private key */
  private X509Certificate ecCert;

  /**
   * Constructor.
   */
  public StaticCredentials() {
  }

  /**
   * Constructor setting the key size for RSA and curve for EC to use.
   *
   * @param rsaKeySize RSA key size in bits (default is {@value #DEFAULT_RSA_KEY_SIZE})
   * @param ecCurve    identifier for EC curve to use (default is {@value #DEFAULT_EC_CURVE})
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
   * @param algorithmUri the signature algorithm URI
   * @return a SigningCredential instance
   * @throws NoSuchAlgorithmException if the supplied algorithm is not supported
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
          KeyPair rsaKeyPair = this.getRsaKeyPair();
          return new DefaultSigningCredential("RSA", rsaKeyPair.getPrivate(), getRsaCert(rsaKeyPair));
        }
      }
      else if (JCAConstants.KEY_ALGO_EC.equals(algoKey)) {
        synchronized (this) {
          KeyPair ecKeyPair = this.getEcKeyPair();
          return new DefaultSigningCredential("EC", ecKeyPair.getPrivate(), getEcCert(ecKeyPair));
        }
      }
      else {
        final String msg = String.format("Algorithm '%s' is not supported - could not generate key pair", algorithmUri);
        log.error("{}", msg);
        throw new NoSuchAlgorithmException(msg);
      }
    }
    catch (InvalidParameterException | InvalidAlgorithmParameterException | OperatorCreationException | IOException | CertificateException e) {
      throw new NoSuchAlgorithmException("Invalid parameter", e);
    }
  }

  /**
   * Gets the generated RSA key pair.
   *
   * @return the RSA key pair.
   * @throws InvalidParameterException if the keysize is incorrect
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
   * @throws InvalidAlgorithmParameterException for unsupported curve
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
   * @param keysize the keysize in bits
   * @return RSA key pair
   * @throws InvalidParameterException if the bit size is incorrect
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
   * @param ecCurve the curve
   * @return EC keypair
   * @throws InvalidAlgorithmParameterException for invalid curve
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

  /**
   * Generates an RSA certificate if not already generated
   *
   * @param pair Key pair
   * @return Certificate
   * @throws OperatorCreationException on error
   * @throws CertificateException      on error
   * @throws IOException               on error
   */
  private X509Certificate getRsaCert(KeyPair pair) throws OperatorCreationException, CertificateException, IOException {
    if (rsaCert == null) {
      rsaCert = generateV1Certificate(pair, JCAConstants.KEY_ALGO_RSA);
    }
    return rsaCert;
  }

  /**
   * Generates an EC certificate if not already generated
   *
   * @param pair Key pair
   * @return Certificate
   * @throws OperatorCreationException on error
   * @throws CertificateException      on error
   * @throws IOException               on error
   */
  private X509Certificate getEcCert(KeyPair pair) throws OperatorCreationException, CertificateException, IOException {
    if (ecCert == null) {
      ecCert = generateV1Certificate(pair, JCAConstants.KEY_ALGO_EC);
    }
    return ecCert;
  }

  /**
   * Generates self signed certificate
   *
   * @param pair    key pair
   * @param algoKey algorithm type
   * @return Certificate for the key pair
   * @throws OperatorCreationException on error
   * @throws IOException               on error
   * @throws CertificateException      on error
   */
  private X509Certificate generateV1Certificate(KeyPair pair, String algoKey)
    throws OperatorCreationException, IOException, CertificateException {

    BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
    X500Name issuerDN = new X500Name("CN=Test Signer");
    X500Name subjectDN = new X500Name("CN=Test Signer");
    Calendar startTime = Calendar.getInstance();
    startTime.setTime(new Date());
    startTime.add(Calendar.HOUR, -2);
    Calendar expiryTime = Calendar.getInstance();
    expiryTime.setTime(new Date());
    expiryTime.add(Calendar.YEAR, 5);
    Date notBefore = startTime.getTime();
    Date notAfter = expiryTime.getTime();
    PublicKey pubKey = (pair.getPublic());
    X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(issuerDN, certSerial, notBefore, notAfter, subjectDN, pubKey);

    ContentSigner signer = null;
    if (JCAConstants.KEY_ALGO_RSA.equals(algoKey)) {
      signer = new JcaContentSignerBuilder("SHA256WITHRSA").build(pair.getPrivate());
    }
    if (JCAConstants.KEY_ALGO_EC.equals(algoKey)) {
      signer = new JcaContentSignerBuilder("SHA256WITHECDSA").build(pair.getPrivate());
    }
    byte[] encoded = certGen.build(signer).getEncoded();
    CertificateFactory fact = CertificateFactory.getInstance("X.509");
    InputStream is = new ByteArrayInputStream(encoded);
    X509Certificate certificate = (X509Certificate) fact.generateCertificate(is);
    is.close();

    return certificate;
  }

}
