package se.idsec.signservice.pdf.general;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.opensaml.security.crypto.JCAConstants;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Registry for SVT supported algorithms. This class adds support for the minimum supported set of algorithms and allows new algorithms
 * to be added. By default only RSA and ECDSA with SHA 245, 384 and 512 are supported.
 */
public class PDFAlgoRegistry {
  private static Map<String, AlgoProperties> supportedAlgoMap;
  private static AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";
  public static final String ALGO_ID_DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  public static final String ALGO_ID_DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
  public static final String ALGO_ID_DIGEST_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
  public static final String ALGO_ID_DIGEST_SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
  public static final String ALGO_ID_DIGEST_SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
  public static final String ALGO_ID_DIGEST_SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

  static {
    supportedAlgoMap = new HashMap<>();
    // Standard RSA
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA256)
      .sigAlgoOID(PKCSObjectIdentifiers.sha256WithRSAEncryption)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA384)
      .sigAlgoOID(PKCSObjectIdentifiers.sha384WithRSAEncryption)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA512)
      .sigAlgoOID(PKCSObjectIdentifiers.sha512WithRSAEncryption)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
    // Standard RSA-PSS
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA512)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
    // SHA 3 with RSA
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_256)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_384)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_512)
      .build());
    // ECDSA
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA256)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA256)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_256)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA384)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA384)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_384)
      .build());
    putDefaultAlgo(AlgoProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA512)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA384)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_512)
      .build());
  }

  /**
   * Test if a particular JWSAlgorithm is supported
   *
   * @param algorithm algorithm to test
   * @return true if supported
   */
  public static boolean isAlgoSupported(String algorithm) {
    return supportedAlgoMap.containsKey(algorithm);
  }

  /**
   * Returns the algorithm parameters for a supported algorithm
   *
   * @param algorithm algorithm
   * @return algorithm properties
   * @throws IllegalArgumentException if the algorithm is not supported
   */
  public static AlgoProperties getAlgorithmProperties(String algorithm) throws IllegalArgumentException {
    if (!isAlgoSupported(algorithm)) {
      throw new IllegalArgumentException("Unsupported Algorithm");
    }
    return supportedAlgoMap.get(algorithm);
  }

  /**
   * Get an instance of the message digest algorithm associated with the specified JWS algorithm
   *
   * @param algorithm algorithm
   * @return {@link MessageDigest} instance
   * @throws NoSuchAlgorithmException if specified JWS algorithm is not supported
   */
  public static MessageDigest getMessageDigestInstance(String algorithm)
    throws NoSuchAlgorithmException {
    if (!isAlgoSupported(algorithm)) {
      throw new NoSuchAlgorithmException("Unsupported Signature Algorithm");
    }
    return MessageDigest.getInstance(getDigestName(algorithm));
  }

  /**
   * Get the algorithm name for the digest algorithm of the signature algorithm
   * @param algorithm
   * @return Name of the digest algorithm
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public static String getDigestName(String algorithm) throws NoSuchAlgorithmException {
    if (supportedAlgoMap.containsKey(algorithm)){
      return algorithmNameFinder.getAlgorithmName(supportedAlgoMap.get(algorithm).getDigestAlgoOID());
    }
    throw new NoSuchAlgorithmException("No supported digest algorithm for " + algorithm);
  }
  /**
   * Get the algorithm name for the digest algorithm of the signature algorithm
   * @param algorithm
   * @return Name of the digest algorithm
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public static String getSigAlgoName(String algorithm) throws NoSuchAlgorithmException {
    if (supportedAlgoMap.containsKey(algorithm)){
      return algorithmNameFinder.getAlgorithmName(supportedAlgoMap.get(algorithm).getSigAlgoOID());
    }
    throw new NoSuchAlgorithmException("No supported algorithm: " + algorithm);
  }

  /**
   * Register a new supported JWS algorithm for signing the SVT
   *
   * @param algoProperties  The The algorithm name used to identify the algorithm in CMS
   * @return true if the algorithm registration was successful
   */
  public static boolean registerSupportedJWSAlgorithm(AlgoProperties algoProperties) {
    supportedAlgoMap.put(algoProperties.getDigestAlgoId(), algoProperties);
    return true;
  }

  /**
   * Retrieve the algorithm family for a specific JWS algorithm
   *
   * @param algorithm the algorithm
   * @return Algorithm type
   * @throws IllegalArgumentException if the requested algorithm is not supported
   */
  public static String getAlgoFamilyFromAlgo(String algorithm) throws IllegalArgumentException {
    String type = null;
    if (supportedAlgoMap.containsKey(algorithm)){
      AlgoProperties algoProperties = supportedAlgoMap.get(algorithm);
      return algoProperties.getAlgoType();
    }

    throw new IllegalArgumentException("Unsupported JWS Algorithm family");
  }


  private PDFAlgoRegistry() {
  }

  private static void putDefaultAlgo(AlgoProperties algoProperties)
    throws IllegalArgumentException {
    supportedAlgoMap.put(algoProperties.getDigestAlgoId(), algoProperties);
  }

  /**
   * Data object for signature algorithm properties
   */
  @Builder
  @Getter
  @AllArgsConstructor
  public static class AlgoProperties {
    /** XML UIR identifier for the signature algorithm */
    String sigAlgoId;
    /** Algorithm Object Identifier */
    ASN1ObjectIdentifier sigAlgoOID;
    /** The family type of this algorithm */
    String algoType;
    /** The XML URI identifier for this algorithm */
    String digestAlgoId;
    /** The digest algorithm ObjectIdentifier */
    ASN1ObjectIdentifier digestAlgoOID;
  }

}
