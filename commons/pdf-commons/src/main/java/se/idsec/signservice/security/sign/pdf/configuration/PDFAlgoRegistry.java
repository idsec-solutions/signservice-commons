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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.opensaml.security.crypto.JCAConstants;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Registry for SVT supported algorithms. This class adds support for the minimum supported set of algorithms and allows new algorithms
 * to be added. By default only RSA and ECDSA with SHA 245, 384 and 512 are supported.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFAlgoRegistry {
  private static Map<String, PDFSignatureAlgorithmProperties> supportedAlgoMap;
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

  //RSA-PSS algonames;
  public static final String RSAPSS_SHA1_NAME = "SHA1WITHRSAANDMGF1";
  public static final String RSAPSS_SHA224_NAME = "SHA224WITHRSAANDMGF1";
  public static final String RSAPSS_SHA256_NAME = "SHA256WITHRSAANDMGF1";
  public static final String RSAPSS_SHA384_NAME = "SHA384WITHRSAANDMGF1";
  public static final String RSAPSS_SHA512_NAME = "SHA512WITHRSAANDMGF1";
  public static final String RSAPSS_SHA3_224_NAME = "SHA3-224WITHRSAANDMGF1";
  public static final String RSAPSS_SHA3_256_NAME = "SHA3-256WITHRSAANDMGF1";
  public static final String RSAPSS_SHA3_384_NAME = "SHA3-384WITHRSAANDMGF1";
  public static final String RSAPSS_SHA3_512_NAME = "SHA3-512WITHRSAANDMGF1";

  static {
    supportedAlgoMap = new HashMap<>();
    // Standard RSA
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA256)
      .sigAlgoOID(PKCSObjectIdentifiers.sha256WithRSAEncryption)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha256WithRSAEncryption))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA384)
      .sigAlgoOID(PKCSObjectIdentifiers.sha384WithRSAEncryption)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha384WithRSAEncryption))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA512)
      .sigAlgoOID(PKCSObjectIdentifiers.sha512WithRSAEncryption)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha512WithRSAEncryption))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
    // Standard RSA-PSS
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA256_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA384_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA512)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA512_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
      .build());
    // SHA 3 with RSA-PSS
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA3_256_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_256)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA3_384_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_384)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1)
      .sigAlgoOID(PKCSObjectIdentifiers.id_RSASSA_PSS)
      .sigAlgoName(RSAPSS_SHA3_512_NAME)
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA3_512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha3_512)
      .build());
    // ECDSA
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA256)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA256)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA256))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA256)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha256)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA384)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA384)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA384))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA384)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha384)
      .build());
    putDefaultAlgo(PDFSignatureAlgorithmProperties.builder()
      .sigAlgoId(ALGO_ID_SIGNATURE_ECDSA_SHA512)
      .sigAlgoOID(X9ObjectIdentifiers.ecdsa_with_SHA512)
      .sigAlgoName(algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA512))
      .algoType(JCAConstants.KEY_ALGO_RSA)
      .digestAlgoId(ALGO_ID_DIGEST_SHA512)
      .digestAlgoOID(NISTObjectIdentifiers.id_sha512)
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
   * Get the URI identifier for a registered signature algorithm specified by an ASN.1 algorithm identifier
   * @param algorithmIdentifier the ASN.1 algorithm identifier
   * @return URI identifier for the specified signature algorithm
   * @throws NoSuchAlgorithmException if the specified algorithm is not supported or has illegal parameters
   */
  public static String getAlgorithmURI(AlgorithmIdentifier algorithmIdentifier) throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier algorithmOID = algorithmIdentifier.getAlgorithm();
    if (algorithmOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)){
      try {
        RSASSAPSSparams rsaPssParams = RSASSAPSSparams.getInstance(algorithmIdentifier.getParameters());
        AlgorithmIdentifier hashAlgorithm = rsaPssParams.getHashAlgorithm();
        Optional<PDFSignatureAlgorithmProperties> algoOptional = supportedAlgoMap.keySet().stream()
          .map(s -> supportedAlgoMap.get(s))
          .filter(
            algoProp -> algoProp.getSigAlgoOID().equals(algorithmOID) && algoProp.getDigestAlgoOID().equals(hashAlgorithm.getAlgorithm()))
          .findFirst();
        if (algoOptional.isPresent()){
          return algoOptional.get().sigAlgoId;
        }
        throw new NoSuchAlgorithmException("Non supported RSA PSS algorithm parameters");
      } catch (Exception ex){
        throw new NoSuchAlgorithmException("Illegal RSA PSS parameters");
      }
    }
    Optional<PDFSignatureAlgorithmProperties> algoOptional = supportedAlgoMap.keySet().stream()
      .map(s -> supportedAlgoMap.get(s))
      .filter(
        algoProp -> algoProp.getSigAlgoOID().equals(algorithmOID))
      .findFirst();
    if (algoOptional.isPresent()){
      return algoOptional.get().sigAlgoId;
    }
    throw new NoSuchAlgorithmException("Non supported signature algorithm");
  }

  /**
   * Get the URI identifier for a registered signature algorithm based on signature algorithm identifier and hash algorithm identifier
   * @param sigAlgoOid signature algorithm object identifier
   * @param digestAlgoOid hash algorithm object identifier
   * @return URI identifier for the combined signature algorithm
   * @throws NoSuchAlgorithmException if the OID combinations are not supported
   */
  public static String getAlgorithmURI(ASN1ObjectIdentifier sigAlgoOid, ASN1ObjectIdentifier digestAlgoOid)
    throws NoSuchAlgorithmException {
    Optional<PDFSignatureAlgorithmProperties> algoOptional = supportedAlgoMap.keySet().stream()
      .map(s -> supportedAlgoMap.get(s))
      .filter(algoProp ->
        algoProp.getSigAlgoOID().equals(sigAlgoOid) &&
          algoProp.getDigestAlgoOID().equals(digestAlgoOid))
      .findFirst();

    if (algoOptional.isPresent()){
      return algoOptional.get().sigAlgoId;
    }
    throw new NoSuchAlgorithmException("Non supported combination of signature algorithm and hash algorithm");
  }

  /**
   * Returns the algorithm parameters for a supported signature algorithm
   *
   * @param algorithm signature algorithm
   * @return algorithm properties
   * @throws IllegalArgumentException if the algorithm is not supported
   */
  public static PDFSignatureAlgorithmProperties getAlgorithmProperties(String algorithm) throws IllegalArgumentException {
    if (!isAlgoSupported(algorithm)) {
      throw new IllegalArgumentException("Unsupported Algorithm");
    }
    return supportedAlgoMap.get(algorithm);
  }

  /**
   * Get an instance of the message digest associated with the specified signature algorithm
   *
   * @param algorithm algorithm URI identifier for signature algorithm
   * @return {@link MessageDigest} instance
   * @throws NoSuchAlgorithmException if specified signature algorithm is not supported
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
   * @param algorithm algorithm URI identifier
   * @return the name of the digest algorithm used to create instances of the digest algorithm
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public static String getDigestName(String algorithm) throws NoSuchAlgorithmException {
    if (supportedAlgoMap.containsKey(algorithm)){
      return algorithmNameFinder.getAlgorithmName(supportedAlgoMap.get(algorithm).getDigestAlgoOID());
    }
    throw new NoSuchAlgorithmException("No supported digest algorithm for " + algorithm);
  }
  /**
   * Get the algorithm name for the signature algorithm
   * @param algorithm algorithm URI identifier
   * @return the name of the signature algorithm used to initiate the use of this algorithm in CMS signing
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public static String getSigAlgoName(String algorithm) throws NoSuchAlgorithmException {
    if (supportedAlgoMap.containsKey(algorithm)){
      return supportedAlgoMap.get(algorithm).getSigAlgoName();
    }
    throw new NoSuchAlgorithmException("No supported algorithm: " + algorithm);
  }

  /**
   * Register a new supported signature algorithm
   *
   * @param pdfSignatureAlgorithmProperties  the properties of the registered signature algorithm
   */
  public static void registerSupportedAlgorithm(PDFSignatureAlgorithmProperties pdfSignatureAlgorithmProperties) {
    supportedAlgoMap.put(pdfSignatureAlgorithmProperties.getDigestAlgoId(), pdfSignatureAlgorithmProperties);
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
      PDFSignatureAlgorithmProperties PDFSignatureAlgorithmProperties = supportedAlgoMap.get(algorithm);
      return PDFSignatureAlgorithmProperties.getAlgoType();
    }

    throw new IllegalArgumentException("Unsupported JWS Algorithm family");
  }

  /**
   * Private constructor preventing this class from being instantiated
   */
  private PDFAlgoRegistry() {
  }

  private static void putDefaultAlgo(PDFSignatureAlgorithmProperties pdfSignatureAlgorithmProperties)
    throws IllegalArgumentException {
    supportedAlgoMap.put(pdfSignatureAlgorithmProperties.getSigAlgoId(), pdfSignatureAlgorithmProperties);
  }

  /**
   * Data object for signature algorithm properties
   */
  @Builder
  @Getter
  @AllArgsConstructor
  public static class PDFSignatureAlgorithmProperties {
    /** XML UIR identifier for the signature algorithm */
    private String sigAlgoId;
    /** Algorithm Object Identifier */
    private ASN1ObjectIdentifier sigAlgoOID;
    /** Name for creating an instance of the algorithm in JcaContentSignerBuilder */
    private String sigAlgoName;
    /** The family type of this algorithm */
    private String algoType;
    /** The XML URI identifier for this algorithm */
    private String digestAlgoId;
    /** The digest algorithm ObjectIdentifier */
    private ASN1ObjectIdentifier digestAlgoOID;
  }
}
