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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.AlgorithmType;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Utility class that holds pre-generated key pairs.
 * <p>
 * Mainly useful for testing, but also when to-be-signed bytes are calculated.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
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

  /** Certificate for RSA private key. */
  private X509Certificate rsaCertificate;

  /** Certificate for EC private key. */
  private X509Certificate ecCertificate;

  /** The algorithm registry. */
  private AlgorithmRegistry algorithmRegistry;

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
   * Returns a {@link PkiCredential} that can be used to sign using the supplied algorithm.
   *
   * @param algorithmUri
   *          the signature algorithm URI
   * @return a PkiCredential instance
   * @throws NoSuchAlgorithmException
   *           if the supplied algorithm is not supported
   */
  public PkiCredential getSigningCredential(final String algorithmUri) throws NoSuchAlgorithmException {

    final Algorithm algorithm = this.getAlgorithmRegistry().getAlgorithm(algorithmUri);
    if (algorithm == null || algorithm.getType() != AlgorithmType.SIGNATURE) {
      final String msg = String.format("Algorithm '%s' is not a registered signature algorithm", algorithmUri);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }

    final String algoClass = SignatureAlgorithm.class.cast(algorithm).getKeyType();
    try {
      BasicCredential cred = null;
      if ("RSA".equals(algoClass)) {
        synchronized (this) {
          final KeyPair rsaKeyPair = this.getRsaKeyPair();
          cred = new BasicCredential(this.getRsaCertificate(), rsaKeyPair.getPrivate());
          cred.setName("RSA");
        }
      }
      else if ("EC".equals(algoClass)) {
        synchronized (this) {
          final KeyPair ecKeyPair = this.getEcKeyPair();
          cred = new BasicCredential(this.getEcCertificate(), ecKeyPair.getPrivate());
          cred.setName("EC");
        }
      }
      else {
        final String msg = String.format("Algorithm '%s' is not supported", algorithmUri);
        log.error("{}", msg);
        throw new NoSuchAlgorithmException(msg);
      }
      return cred;
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
   * Assigns the {@link AlgorithmRegistry} to use. If not assigned, the registry configured for
   * {@link AlgorithmRegistrySingleton} will be used.
   *
   * @param algorithmRegistry
   *          the registry to use
   */
  public void setAlgorithmRegistry(final AlgorithmRegistry algorithmRegistry) {
    this.algorithmRegistry = algorithmRegistry;
  }

  /**
   * Gets the {@link AlgorithmRegistry} to use.
   *
   * @return the AlgorithmRegistry
   */
  private AlgorithmRegistry getAlgorithmRegistry() {
    if (this.algorithmRegistry == null) {
      this.algorithmRegistry = AlgorithmRegistrySingleton.getInstance();
    }
    return this.algorithmRegistry;
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
      KeyPair kp = generator.generateKeyPair();
      this.rsaCertificate = generateV1Certificate(kp, "RSA");
      return kp;
    }
    catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | IOException e) {
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
      KeyPair kp = generator.generateKeyPair();
      this.ecCertificate = this.generateV1Certificate(kp, "EC");
      return kp;
    }
    catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | IOException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Gets the RSA certificate.
   *
   * @return the RSA certificate
   */
  private X509Certificate getRsaCertificate() {
    return this.rsaCertificate;
  }

  /**
   * Gets the EC certificate.
   *
   * @return the EC certificate
   */
  private X509Certificate getEcCertificate() {
    return this.ecCertificate;
  }

  /**
   * Generates self signed certificate.
   *
   * @param pair
   *          key pair
   * @param algoKey
   *          algorithm type
   * @return certificate for the key pair
   * @throws OperatorCreationException
   *           on error
   * @throws IOException
   *           on error
   * @throws CertificateException
   *           on error
   */
  private X509Certificate generateV1Certificate(final KeyPair pair, final String algoKey)
      throws OperatorCreationException, IOException, CertificateException {

    final X509v1CertificateBuilder certGenerator = new JcaX509v1CertificateBuilder(
      new X500Name("CN=Test Signer"), /* issuer */
      BigInteger.valueOf(System.currentTimeMillis()), /* serial */
      new Date(System.currentTimeMillis() - 7200000L), /* notBefore */
      new Date(System.currentTimeMillis() + (5 * 365 * 24 * 3600000L)), /* notAfter */
      new X500Name("CN=Test Signer"), /* subject */
      pair.getPublic());

    final ContentSigner signer = "RSA".equals(algoKey)
        ? new JcaContentSignerBuilder("SHA256WITHRSA").build(pair.getPrivate())
        : new JcaContentSignerBuilder("SHA256WITHECDSA").build(pair.getPrivate());

    return CertificateUtils.decodeCertificate(certGenerator.build(signer).getEncoded());
  }

}
