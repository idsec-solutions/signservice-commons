/*
 * Copyright 2019-2021 IDsec Solutions AB
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
package se.idsec.signservice.security.sign.pdf.configuration;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmPredicates;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.algorithms.impl.AlgorithmRegistryImpl;
import se.swedenconnect.security.algorithms.impl.StaticAlgorithmRegistry;

/**
 * Registry for supported algorithms. This class adds support for the minimum supported set of algorithms and allows new
 * algorithms to be added. By default only RSA and ECDSA with SHA 245, 384 and 512 are supported.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFAlgorithmRegistry {

  /** Mapping of algorithm IDs and signature properties. */
  private static AlgorithmRegistry algorithmRegistry;

  static {
    final Algorithm[] signatureAlgs = StaticAlgorithmRegistry.getDefaultSignatureAlgorithms();

    final Function<String, Algorithm> getAlgo = (s) -> Arrays.stream(signatureAlgs)
      .filter(a -> Objects.equals(s, a.getUri()))
      .findFirst()
      .orElseThrow(SecurityException::new);

    final AlgorithmRegistryImpl _algorithmRegistry = new AlgorithmRegistryImpl();
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384));
    _algorithmRegistry.register(getAlgo.apply(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512));

    algorithmRegistry = _algorithmRegistry;
  }

  /**
   * Test if a particular algorithm is supported.
   *
   * @param algorithm
   *          algorithm to test
   * @return true if supported, and false otherwise
   */
  public static boolean isAlgoSupported(final String algorithm) {
    return algorithmRegistry.getAlgorithm(algorithm) != null;
  }

  /**
   * Get the URI identifier for a registered signature algorithm specified by an ASN.1 algorithm identifier.
   *
   * @param algorithmIdentifier
   *          the ASN.1 algorithm identifier
   * @return URI identifier for the specified signature algorithm
   * @throws NoSuchAlgorithmException
   *           if the specified algorithm is not supported or has illegal parameters
   */
  public static String getAlgorithmURI(final AlgorithmIdentifier algorithmIdentifier) throws NoSuchAlgorithmException {
    final SignatureAlgorithm algorithm = algorithmRegistry.getAlgorithm(
      AlgorithmPredicates.fromAlgorithmIdentifierRelaxed(algorithmIdentifier), SignatureAlgorithm.class);

    return Optional.ofNullable(algorithm)
      .map(SignatureAlgorithm::getUri)
      .orElseThrow(() -> new NoSuchAlgorithmException("Non supported signature algorithm"));
  }

  /**
   * Get the URI identifier for a registered signature algorithm based on signature algorithm identifier and hash
   * algorithm identifier.
   *
   * @param sigAlgoOid
   *          signature algorithm object identifier
   * @param digestAlgoOid
   *          hash algorithm object identifier
   * @return URI identifier for the combined signature algorithm
   * @throws NoSuchAlgorithmException
   *           if the OID combinations are not supported
   */
  public static String getAlgorithmURI(final ASN1ObjectIdentifier sigAlgoOid, final ASN1ObjectIdentifier digestAlgoOid)
      throws NoSuchAlgorithmException {

    final SignatureAlgorithm algorithm =
        algorithmRegistry.getAlgorithm(fromOids(sigAlgoOid, digestAlgoOid), SignatureAlgorithm.class);

    return Optional.ofNullable(algorithm)
      .map(SignatureAlgorithm::getUri)
      .orElseThrow(() -> new NoSuchAlgorithmException("Non supported combination of signature algorithm and hash algorithm"));
  }

  /**
   * Predicate to check if a signature method in the registry matches based on signature algorithm identifier and hash
   * algorithm identifier.
   *
   * @param sigAlgoOid
   *          signature algorithm object identifier
   * @param digestAlgoOid
   *          hash algorithm object identifier
   * @return a predicate
   */
  private static Predicate<Algorithm> fromOids(final ASN1ObjectIdentifier sigAlgoOid, final ASN1ObjectIdentifier digestAlgoOid) {
    return (a) -> {
      if (!SignatureAlgorithm.class.isInstance(a)) {
        return false;
      }
      final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.class.cast(a);
      return isSigAlgoEquivalent(signatureAlgorithm.getAlgorithmIdentifier().getAlgorithm(), sigAlgoOid, digestAlgoOid)
          && signatureAlgorithm.getMessageDigestAlgorithm().getAlgorithmIdentifier().getAlgorithm().equals(digestAlgoOid);
    };
  }

  /**
   * This method is designed to allow identifiers for RSA encryption to be equivalent to identifiers for various RSA
   * combined with various hash functions
   *
   * @param signatureAlgorithmPropertyOid
   *          signature algorithm OID registered in the algorithm properties in this registry for the signature
   *          algorithm
   * @param cmsSignatureAlgorithmOid
   *          CMS signature algorithm OID matched with the registered signature algorithm
   * @param cmsDigestAlgorithmOid
   *          CMS digest algorithm used with this signature algorithm
   * @return true if the CMS algorithms are equivalent with the registered signature algorithm OID
   */
  private static boolean isSigAlgoEquivalent(final ASN1ObjectIdentifier signatureAlgorithmPropertyOid,
      final ASN1ObjectIdentifier cmsSignatureAlgorithmOid, final ASN1ObjectIdentifier cmsDigestAlgorithmOid) {
    // Allow RSA encryption identifier in place of explicit identifier for hash and public key algo
    if (cmsSignatureAlgorithmOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
      if (cmsDigestAlgorithmOid.equals(NISTObjectIdentifiers.id_sha224)
          && signatureAlgorithmPropertyOid.equals(PKCSObjectIdentifiers.sha224WithRSAEncryption)) {
        return true;
      }
      if (cmsDigestAlgorithmOid.equals(NISTObjectIdentifiers.id_sha256)
          && signatureAlgorithmPropertyOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
        return true;
      }
      if (cmsDigestAlgorithmOid.equals(NISTObjectIdentifiers.id_sha384)
          && signatureAlgorithmPropertyOid.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption)) {
        return true;
      }
      if (cmsDigestAlgorithmOid.equals(NISTObjectIdentifiers.id_sha512)
          && signatureAlgorithmPropertyOid.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption)) {
        return true;
      }
    }
    // If not then just compare OID:s
    return signatureAlgorithmPropertyOid.equals(cmsSignatureAlgorithmOid);
  }

  /**
   * Returns the algorithm parameters for a supported signature algorithm.
   *
   * @param algorithm
   *          signature algorithm
   * @return algorithm properties
   * @throws NoSuchAlgorithmException
   *           if the algorithm is not supported
   */
  public static SignatureAlgorithm getAlgorithmProperties(final String algorithm) throws NoSuchAlgorithmException {
    return Optional.ofNullable(algorithmRegistry.getAlgorithm(algorithm, SignatureAlgorithm.class))
      .orElseThrow(() -> new NoSuchAlgorithmException("Unsupported Algorithm " + algorithm));
  }

  /**
   * Get an instance of the message digest associated with the specified signature algorithm.
   *
   * @param algorithm
   *          algorithm URI identifier for signature algorithm
   * @return s MessageDigest instance
   * @throws NoSuchAlgorithmException
   *           if specified signature algorithm is not supported
   */
  public static MessageDigest getMessageDigestInstance(final String algorithm) throws NoSuchAlgorithmException {
    final String jcaName = Optional.ofNullable(algorithmRegistry.getAlgorithm(algorithm, SignatureAlgorithm.class))
      .map(SignatureAlgorithm::getMessageDigestAlgorithm)
      .map(MessageDigestAlgorithm::getJcaName)
      .orElseThrow(() -> new NoSuchAlgorithmException("Unsupported Signature Algorithm " + algorithm));

    return MessageDigest.getInstance(jcaName);
  }

  /**
   * Get the algorithm name for the digest algorithm of the signature algorithm.
   *
   * @param algorithm
   *          algorithm URI identifier
   * @return the name of the digest algorithm used to create instances of the digest algorithm
   * @throws NoSuchAlgorithmException
   *           if the algorithm is not supported
   */
  public static String getDigestName(final String algorithm) throws NoSuchAlgorithmException {
    return Optional.ofNullable(algorithmRegistry.getAlgorithm(algorithm, SignatureAlgorithm.class))
      .map(SignatureAlgorithm::getMessageDigestAlgorithm)
      .map(MessageDigestAlgorithm::getJcaName)
      .orElseThrow(() -> new NoSuchAlgorithmException("No supported digest algorithm for " + algorithm));
  }

  /**
   * Get the algorithm name for the signature algorithm.
   *
   * @param algorithm
   *          algorithm URI identifier
   * @return the name of the signature algorithm used to initiate the use of this algorithm in CMS signing
   * @throws NoSuchAlgorithmException
   *           if the algorithm is not supported
   */
  public static String getSigAlgoName(final String algorithm) throws NoSuchAlgorithmException {
    return Optional.ofNullable(algorithmRegistry.getAlgorithm(algorithm))
      .map(Algorithm::getJcaName)
      .orElseThrow(() -> new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm));
  }

  /**
   * Register a new supported signature algorithm.
   *
   * @param signatureAlgorithm
   *          the signature algorithm to register
   */
  public static void registerSupportedAlgorithm(final SignatureAlgorithm signatureAlgorithm) {
    if (signatureAlgorithm == null) {
      throw new IllegalArgumentException("signatureAlgorithm must not be null");
    }
    ((AlgorithmRegistryImpl) algorithmRegistry).register(signatureAlgorithm);
  }

  /**
   * Retrieve the algorithm family for a specific algorithm.
   *
   * @param algorithm
   *          the algorithm
   * @return the algorithm type
   * @throws IllegalArgumentException
   *           if the requested algorithm is not supported
   */
  public static String getAlgoFamilyFromAlgo(final String algorithm) throws IllegalArgumentException {
    return Optional.ofNullable(algorithmRegistry.getAlgorithm(algorithm, SignatureAlgorithm.class))
      .map(SignatureAlgorithm::getKeyType)
      .orElseThrow(() -> new IllegalArgumentException("No such algorithm"));
  }

  /**
   * Private constructor preventing this class from being instantiated
   */
  private PDFAlgorithmRegistry() {
  }

}
