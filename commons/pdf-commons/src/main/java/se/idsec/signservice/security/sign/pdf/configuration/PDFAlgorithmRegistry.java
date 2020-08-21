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
package se.idsec.signservice.security.sign.pdf.configuration;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.opensaml.security.crypto.JCAConstants;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * Registry for supported algorithms. This class adds support for the minimum supported set of algorithms and allows new
 * algorithms to be added. By default only RSA and ECDSA with SHA 245, 384 and 512 are supported.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFAlgorithmRegistry {

  /** Mapping of algorithm IDs and signature properties. */
  private static Map<String, PDFSignatureAlgorithmProperties> supportedAlgoMap;

  /** Finder for converting OIDs and AlgorithmIdentifiers into strings. */
  private static AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

  /** ECDSA-SHA256 */
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

  /** ECDSA-SHA384 */
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

  /** ECDSA-SHA512 */
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

  /** RSA-SHA256 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

  /** RSA-SHA384 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

  /** RSA-SHA512 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

  /** RSA-SHA256-MGF1 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";

  /** RSA-SHA384-MGF1 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";

  /** RSA-SHA512-MGF1 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";

  /** RSA-SHA3-256-MGF1 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";

  /** RSA-SHA3-384-MGF1 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";

  /** RSA-SHA3-512-MGF1 */
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";

  /** SHA256 */
  public static final String ALGO_ID_DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

  /** SHA384 */
  public static final String ALGO_ID_DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

  /** SHA512 */
  public static final String ALGO_ID_DIGEST_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

  /** SHA3-256 */
  public static final String ALGO_ID_DIGEST_SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";

  /** SHA3-384 */
  public static final String ALGO_ID_DIGEST_SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";

  /** SHA3-512 */
  public static final String ALGO_ID_DIGEST_SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

  /** SHA1WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA1_NAME = "SHA1WITHRSAANDMGF1";

  /** SHA224WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA224_NAME = "SHA224WITHRSAANDMGF1";

  /** SHA256WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA256_NAME = "SHA256WITHRSAANDMGF1";

  /** SHA384WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA384_NAME = "SHA384WITHRSAANDMGF1";

  /** SHA512WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA512_NAME = "SHA512WITHRSAANDMGF1";

  /** SHA3-224WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA3_224_NAME = "SHA3-224WITHRSAANDMGF1";

  /** SHA3-256WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA3_256_NAME = "SHA3-256WITHRSAANDMGF1";

  /** SHA3-384WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA3_384_NAME = "SHA3-384WITHRSAANDMGF1";

  /** SHA3-512WITHRSAANDMGF1 */
  public static final String RSAPSS_SHA3_512_NAME = "SHA3-512WITHRSAANDMGF1";

  static {
    supportedAlgoMap = new HashMap<>();
    // Standard RSA
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA256)
      .sigAlgoOID(PKCSObjectIdentifiers.sha256WithRSAEncryption)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha256WithRSAEncryption))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA384)
      .sigAlgoOID(PKCSObjectIdentifiers.sha384WithRSAEncryption)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha384WithRSAEncryption))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA512)
      .sigAlgoOID(PKCSObjectIdentifiers.sha512WithRSAEncryption)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha512WithRSAEncryption))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
    // Standard RSA-PSS
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA256_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA384_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA512_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA512_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
    // SHA 3 with RSA-PSS
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA3_256_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_256)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA3_384_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_384)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA3_512_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_512)
      .build());
    // ECDSA
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA256)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA256)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA256))
      .algoType(JCAConstants.KEY_ALGO_EC)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA384)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA384)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA384))
      .algoType(JCAConstants.KEY_ALGO_EC)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA512)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA512)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA512))
      .algoType(JCAConstants.KEY_ALGO_EC)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
  }

  /**
   * Test if a particular algorithm is supported.
   *
   * @param algorithm
   *          algorithm to test
   * @return true if supported, and false otherwise
   */
  public static boolean isAlgoSupported(final String algorithm) {
    return supportedAlgoMap.containsKey(algorithm);
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
    final ASN1ObjectIdentifier algorithmOID = algorithmIdentifier.getAlgorithm();
    if (algorithmOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
      try {
        final RSASSAPSSparams rsaPssParams = RSASSAPSSparams.getInstance(algorithmIdentifier.getParameters());
        final AlgorithmIdentifier hashAlgorithm = rsaPssParams.getHashAlgorithm();

        return supportedAlgoMap.keySet()
          .stream()
          .map(s -> supportedAlgoMap.get(s))
          .filter(algoProp -> algoProp.getSigAlgoOID().equals(algorithmOID))
          .filter(algoProp -> algoProp.getDigestAlgoOID().equals(hashAlgorithm.getAlgorithm()))
          .map(PDFSignatureAlgorithmProperties::getSigAlgoId)
          .findFirst()
          .orElseThrow(() -> new NoSuchAlgorithmException("Non supported RSA PSS algorithm parameters"));
      }
      catch (Exception e) {
        throw new NoSuchAlgorithmException("Illegal RSA PSS parameters", e);
      }
    }
    return supportedAlgoMap.keySet()
      .stream()
      .map(s -> supportedAlgoMap.get(s))
      .filter(
        algoProp -> algoProp.getSigAlgoOID().equals(algorithmOID))
      .map(PDFSignatureAlgorithmProperties::getSigAlgoId)
      .findFirst()
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

    return supportedAlgoMap.keySet()
      .stream()
      .map(s -> supportedAlgoMap.get(s))
      .filter(algoProp -> isSigAlgoEquivalent(algoProp.getSigAlgoOID(), sigAlgoOid, digestAlgoOid) &&
          algoProp.getDigestAlgoOID().equals(digestAlgoOid))
      .map(PDFSignatureAlgorithmProperties::getSigAlgoId)
      .findFirst()
      .orElseThrow(() -> new NoSuchAlgorithmException("Non supported combination of signature algorithm and hash algorithm"));
  }

  /**
   * This function is designed to allow identifiers for RSA encryption to be equivalent to identifiers for various RSA combined with various hash functions
   * @param sigAlgoPropOID
   * @param cmsSigAlgoOID
   * @return
   */
  private static boolean isSigAlgoEquivalent(ASN1ObjectIdentifier sigAlgoPropOID, ASN1ObjectIdentifier cmsSigAlgoOID, ASN1ObjectIdentifier cmsDigestAlgoOID) {
    // Allow RSA encryption identifier in place of explicit identifier for hash and public key algo
    if (cmsSigAlgoOID.equals(PKCSObjectIdentifiers.rsaEncryption)){
      if (cmsDigestAlgoOID.equals(NISTObjectIdentifiers.id_sha224) && sigAlgoPropOID.equals(PKCSObjectIdentifiers.sha224WithRSAEncryption)){
        return true;
      }
      if (cmsDigestAlgoOID.equals(NISTObjectIdentifiers.id_sha256) && sigAlgoPropOID.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)){
        return true;
      }
      if (cmsDigestAlgoOID.equals(NISTObjectIdentifiers.id_sha384) && sigAlgoPropOID.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption)){
        return true;
      }
      if (cmsDigestAlgoOID.equals(NISTObjectIdentifiers.id_sha512) && sigAlgoPropOID.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption)){
        return true;
      }
    }
    // If not then just compare OID:s
    return sigAlgoPropOID.equals(cmsSigAlgoOID);
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
  public static PDFSignatureAlgorithmProperties getAlgorithmProperties(final String algorithm) throws NoSuchAlgorithmException {
    if (!isAlgoSupported(algorithm)) {
      throw new NoSuchAlgorithmException("Unsupported Algorithm " + algorithm);
    }
    return supportedAlgoMap.get(algorithm);
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
    if (!isAlgoSupported(algorithm)) {
      throw new NoSuchAlgorithmException("Unsupported Signature Algorithm " + algorithm);
    }
    return MessageDigest.getInstance(getDigestName(algorithm));
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
    if (supportedAlgoMap.containsKey(algorithm)) {
      return algorithmNameFinder.getAlgorithmName(supportedAlgoMap.get(algorithm).getDigestAlgoOID());
    }
    throw new NoSuchAlgorithmException("No supported digest algorithm for " + algorithm);
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
    if (supportedAlgoMap.containsKey(algorithm)) {
      return supportedAlgoMap.get(algorithm).getSigAlgoName();
    }
    throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
  }

  /**
   * Register a new supported signature algorithm.
   *
   * @param pdfSignatureAlgorithmProperties
   *          the properties of the registered signature algorithm
   */
  public static void registerSupportedAlgorithm(final PDFSignatureAlgorithmProperties pdfSignatureAlgorithmProperties) {
    if (pdfSignatureAlgorithmProperties == null || pdfSignatureAlgorithmProperties.getSigAlgoId() == null) {
      throw new IllegalArgumentException("pdfSignatureAlgorithmProperties must not be null");
    }
    putAlgo(pdfSignatureAlgorithmProperties);
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
  public static String getAlgoFamilyFromAlgo(String algorithm) throws IllegalArgumentException {
    if (supportedAlgoMap.containsKey(algorithm)) {
      return supportedAlgoMap.get(algorithm).getAlgoType();
    }
    throw new IllegalArgumentException("Unsupported algorithm family");
  }

  /**
   * Private constructor preventing this class from being instantiated
   */
  private PDFAlgorithmRegistry() {
  }

  private static void putAlgo(final PDFSignatureAlgorithmProperties pdfSignatureAlgorithmProperties) {
    supportedAlgoMap.put(pdfSignatureAlgorithmProperties.getSigAlgoId(), pdfSignatureAlgorithmProperties);
  }

  /**
   * Data object for signature algorithm properties.
   */
  @Builder
  @Getter
  @AllArgsConstructor
  public static class PDFSignatureAlgorithmProperties {

    /**
     * XML URI identifier for the signature algorithm.
     * 
     * @return the XML URI identifier for the signature algorithm
     */
    private String sigAlgoId;

    /**
     * Algorithm Object Identifier.
     * 
     * @return the Algorithm Object Identifier
     */
    private ASN1ObjectIdentifier sigAlgoOID;

    /**
     * Name for creating an instance of the algorithm in JcaContentSignerBuilder.
     * 
     * @return the name for creating an instance of the algorithm in JcaContentSignerBuilder
     */
    private String sigAlgoName;

    /**
     * The family type of this algorithm.
     * 
     * @return the family type of this algorithm
     */
    private String algoType;

    /**
     * The XML URI identifier for this algorithm.
     * 
     * @return the XML URI identifier for this algorithm
     */
    private String digestAlgoId;

    /**
     * The digest algorithm ObjectIdentifier.
     * 
     * @return the digest algorithm ObjectIdentifier
     */
    private ASN1ObjectIdentifier digestAlgoOID;
  }
}
