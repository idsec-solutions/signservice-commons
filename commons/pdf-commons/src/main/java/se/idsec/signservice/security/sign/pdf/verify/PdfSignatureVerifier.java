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
package se.idsec.signservice.security.sign.pdf.verify;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.CollectionStore;
import org.opensaml.security.crypto.JCAConstants;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgoRegistry;
import se.idsec.signservice.security.sign.pdf.configuration.PdfObjectIds;
import se.idsec.signservice.security.sign.pdf.signprocess.PdfBoxSigUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * Verifies signatures on PDF documents
 *
 * @author stefan
 */
public class PdfSignatureVerifier {

  private static final Logger LOG = Logger.getLogger(PdfSignatureVerifier.class.getName());

  /**
   * Verifies the signature on a PDF document
   *
   * @param pdfDoc      The bytes of a PDF document
   * @return Signature verification result data.
   * @throws IOException
   */
  public static PdfSigVerifyResult verifyPdfSignatures(byte[] pdfDoc) throws IOException, SignatureException {
    PDDocument doc = PDDocument.load(new ByteArrayInputStream(pdfDoc));
    PdfSigVerifyResult result = new PdfSigVerifyResult();
    List<PDSignature> signatureDicts = doc.getSignatureDictionaries();
    List<CMSSigVerifyResult> individualSigResultList = new ArrayList<>();
    for (PDSignature sig : signatureDicts) {
      byte[] signedContent = sig.getSignedContent(new ByteArrayInputStream(pdfDoc));
      byte[] sigBytes = sig.getContents(new ByteArrayInputStream(pdfDoc));

      CMSSigVerifyResult sigResult = new CMSSigVerifyResult();
      individualSigResultList.add(sigResult);
      sigResult.setSignature(sig);
      try {
        verifySign(sigBytes, signedContent, sigResult);
      }
      catch (Exception ex) {
        LOG.fine(String.format("Signature validation failed with cause: %s", ex.getMessage()));
        throw new SignatureException("Error validating signatues on PDF", ex);
      }
    }

    result.setResultList(individualSigResultList);
    result.setSigCnt(signatureDicts.size());
    consolidateResults(result);
    return result;
  }

  private static void consolidateResults(PdfSigVerifyResult result) {

    AtomicBoolean allValid = new AtomicBoolean(true);
    AtomicInteger validSignatures = new AtomicInteger();

    int sigCnt = result.getSigCnt();
    if (sigCnt < 1){
      result.setAllSigsValid(false);
      result.setLastSigValid(false);
      return;
    }
    result.getResultList().stream().forEach(cmsSigVerifyResult -> {
      if (!cmsSigVerifyResult.isValid()) {
        allValid.set(false);
      } else {
        validSignatures.getAndIncrement();
      }
    });
    result.setAllSigsValid(allValid.get());

    boolean lastValid = result.getResultList().get(sigCnt -1).isValid();
    result.setLastSigValid(lastValid);

    result.setValidSignatures(validSignatures.get());

  }

  /**
   * Verifies one individual signature element of a signed PDF document
   *
   * @param signedData         The SignedData of this signature
   * @param signedContentBytes The data being signed by this signature
   * @param sigResult          The signature verification result object used to express
   *                           signature result data.
   * @throws Exception on error
   */
  public static void verifySign(byte[] signedData, byte[] signedContentBytes, CMSSigVerifyResult sigResult)
    throws Exception {
    InputStream is = new ByteArrayInputStream(signedContentBytes);
    CMSSignedDataParser sp = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new CMSTypedStream(is), signedData);
    CMSTypedStream signedContent = sp.getSignedContent();
    signedContent.drain();

    verifyCMSSignature(sp, sigResult);
  }

  private static void verifyCMSSignature(CMSSignedDataParser sp, CMSSigVerifyResult sigResult)
    throws CMSException, IOException, CertificateException,
    OperatorCreationException, NoSuchAlgorithmException, SignatureException {
    CollectionStore certStore = (CollectionStore) sp.getCertificates();
    Iterator ci = certStore.iterator();
    List<X509Certificate> certList = new ArrayList<>();
    while (ci.hasNext()) {
      X509CertificateHolder ch = (X509CertificateHolder) ci.next();
      certList.add(getCert(ch));
    }
    sigResult.setCertList(certList);

    SignerInformationStore signers = sp.getSignerInfos();
    Collection c = signers.getSigners();
    Iterator it = c.iterator();
    while (it.hasNext()) {
      SignerInformation signer = (SignerInformation) it.next();
      Date claimedSigningTime = getClaimedSigningTime(signer);
      sigResult.setClaimedSigningTime(claimedSigningTime);
      Collection certCollection = certStore.getMatches(signer.getSID());
      X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
      sigResult.setCert(getCert(certHolder));

      //Check signature
      SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder);
      sigResult.setValid(signer.verify(signerInformationVerifier));

      if (!sigResult.isValid()) {
        return;
      }

      // Collect sig algo data
      getPkParams(sigResult.getCert().getPublicKey(), sigResult);
      String digestAlgOID = signer.getDigestAlgOID();
      String encryptionAlgOID = signer.getEncryptionAlgOID();
      String algorithmURI = PDFAlgoRegistry.getAlgorithmURI(new ASN1ObjectIdentifier(encryptionAlgOID),
        new ASN1ObjectIdentifier(digestAlgOID));
      sigResult.setSigAlgo(algorithmURI);
      Attribute cmsAlgoProtAttr = signer.getSignedAttributes().get(new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_CMS_ALGORITHM_PROTECTION));
      getCMSAlgoritmProtectionData(cmsAlgoProtAttr, sigResult);

      if (!checkAlgoritmConsistency(sigResult)) {
        sigResult.setValid(false);
        throw new SignatureException("Signature was verified but with inconsistent Algoritm declarations or unsupported algoritms");
      }
      if (sigResult.isValid()) {
        verifyPadesProperties(signer, sigResult);
      }
    }
  }

  /**
   * converts an X509CertificateHolder object to an X509Certificate object.
   *
   * @param certHolder the cert holder object
   * @return X509Certificate object
   * @throws IOException
   * @throws CertificateException
   */
  public static X509Certificate getCert(X509CertificateHolder certHolder) throws IOException, CertificateException {
    X509Certificate cert = null;
    ByteArrayInputStream certIs = new ByteArrayInputStream(certHolder.getEncoded());

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate) cf.generateCertificate(certIs);

    }
    finally {
      certIs.close();
    }
    return cert;
  }

  private static Date getClaimedSigningTime(SignerInformation signer) {
    try {
      AttributeTable signedAttributes = signer.getSignedAttributes();
      Attribute sigTimeAttr = signedAttributes.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5"));
      ASN1Encodable[] attributeValues = sigTimeAttr.getAttributeValues();
      ASN1UTCTime utcTime = (ASN1UTCTime) attributeValues[0];
      return utcTime.getDate();
    }
    catch (Exception e) {
      return null;
    }
  }

  private static void verifyPadesProperties(SignerInformation signer, CMSSigVerifyResult sigResult)
    throws IOException, NoSuchAlgorithmException, CertificateEncodingException, SignatureException {
    PdfBoxSigUtil.SignedCertRef signedCertRef = PdfBoxSigUtil.getSignedCertRefAttribute(
      signer.getSignedAttributes().toASN1Structure().getEncoded("DER"));

    if (signedCertRef == null) {
      // No Pades signature
      sigResult.setPades(false);
    }
    sigResult.setPades(true);

    MessageDigest md = MessageDigest.getInstance(signedCertRef.getHashAlgorithm().getId());
    byte[] sigCertHash = md.digest(sigResult.getCert().getEncoded());
    if (!Arrays.equals(sigCertHash, signedCertRef.getSignedCertHash())) {
      sigResult.setPadesVerified(false);
      throw new SignatureException("Pades signed certificate reference mismatch");
    }
    sigResult.setPadesVerified(true);
  }

  /**
   * Retrieves Public key parameters from a public key
   *
   * @param pubKey    The public key
   * @param sigResult The data object where result data are stored
   * @throws IOException
   */
  public static void getPkParams(PublicKey pubKey, CMSSigVerifyResult sigResult) throws SignatureException {

    try {

      ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(pubKey.getEncoded()));
      //ASN1Primitive pkObject = din.readObject();
      ASN1Sequence pkSeq = ASN1Sequence.getInstance(din.readObject());
      ASN1BitString keyBits = (ASN1BitString) pkSeq.getObjectAt(1);

      String pkType = null;
      if (pubKey instanceof ECPublicKey) {
        pkType = JCAConstants.KEY_ALGO_EC;
      }
      if (pubKey instanceof RSAPublicKey) {
        pkType = JCAConstants.KEY_ALGO_RSA;
      }

      if (pkType == null) {
        throw new SignatureException("Unsupported public key type");
      }

      AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(pkSeq.getObjectAt(0));
      sigResult.setPkType(pkType);
      if (pkType.equals(JCAConstants.KEY_ALGO_EC)) {
        ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(algoId.getParameters());
        EcCurve curve = EcCurve.getEcCurveFromOid(curveOid.getId());
        sigResult.setEcCurve(curve);
        int totalKeyBits = getEcKeyLength(keyBits);
        sigResult.setKeyLength(totalKeyBits);
        return;
      }

      if (pkType.equals(JCAConstants.KEY_ALGO_RSA)) {
        ASN1InputStream keyIs = new ASN1InputStream(keyBits.getOctets());
        ASN1Sequence keyParamsSeq = ASN1Sequence.getInstance(keyIs.readObject());
        ASN1Integer modInt = ASN1Integer.getInstance(keyParamsSeq.getObjectAt(0));
        int modLen = getAsn1IntegerBitLength(modInt);
        sigResult.setKeyLength(modLen);
        return;
      }

    }
    catch (Exception e) {
      throw new SignatureException("Unable to parse public key type or parameters");
    }

  }

  private static int getAsn1IntegerBitLength(ASN1Integer modInt) throws IOException {
    byte[] encoded = modInt.getEncoded();
    int lenOctets = 0;
    int intValOffset;

    int lenType = encoded[1] & 0x80;
    int lenInLenType = encoded[1] & 0x7f; //The lengthinformation in the first lenghth byte
    if (lenType == 0) {
      //Short length encoding (Bits 1-7)
      lenOctets = lenInLenType;
      intValOffset = 2;
    }
    else {
      //Long length encoding
      if (lenInLenType > 2 || lenInLenType + 2 > encoded.length) {
        //Checks that there are enough data to provide length bytes.
        //If more than 2 bytes is used to specify the byte length of an integer. Something is clearly wrong. Abort.
        return 0;
      }
      int multiplicator = 1;
      for (int i = 0; i < lenInLenType; i++) {
        lenOctets += (encoded[2 + i] & 0x0000ff) * multiplicator;
        multiplicator *= 256;
      }
      intValOffset = lenInLenType + 2;
    }
    //remove padding byte from bit length
    if (encoded[intValOffset] == 0) {
      lenOctets--;
    }
    //Return number of bits
    return lenOctets * 8;
  }

  private static int getEcKeyLength(ASN1BitString bitString) throws IOException {
    byte[] encoded = bitString.getEncoded();
    int lenOctets = 0;
    int valOffset;

    int lenType = encoded[1] & 0x80;
    int lenInLenType = encoded[1] & 0x7f; //The lengthinformation in the first lenghth byte
    if (lenType == 0) {
      //Short length encoding (Bits 1-7)
      lenOctets = lenInLenType;
      valOffset = 2;
    }
    else {
      //Long length encoding
      if (lenInLenType > 2 || lenInLenType + 2 > encoded.length) {
        //Checks that there are enough data to provide length bytes.
        //If more than 2 bytes is used to specify the byte length of an integer. Something is clearly wrong. Abort.
        return 0;
      }
      int multiplicator = 1;
      for (int i = 0; i < lenInLenType; i++) {
        lenOctets += (encoded[2 + i] & 0x0000ff) * multiplicator;
        multiplicator *= 256;
      }
      valOffset = lenInLenType + 2;
    }

    byte[] keyBytes = Arrays.copyOfRange(encoded, valOffset, encoded.length);
    if (keyBytes.length % 2 != 0) {
      //ERROR. Key bytes should be dividable by 2. We return a best estimate
      return lenOctets * 4;
    }

    int partLen = keyBytes.length / 2;
    //check for padding
    if (keyBytes[0] == 0 || keyBytes[partLen] == 0) {
      lenOctets -= 2;
    }

    //Return number of bits
    return lenOctets * 4;
  }

  private static void getCMSAlgoritmProtectionData(Attribute cmsAlgoProtAttr, CMSSigVerifyResult sigResult) {
    if (cmsAlgoProtAttr == null) {
      sigResult.setCmsAlgoProtection(false);
      return;
    }
    sigResult.setCmsAlgoProtection(true);

    try {
      ASN1Sequence cmsapSeq = ASN1Sequence.getInstance(cmsAlgoProtAttr.getAttrValues().getObjectAt(0));

      //Get Hash algo
      AlgorithmIdentifier hashAlgoId = AlgorithmIdentifier.getInstance(cmsapSeq.getObjectAt(0));
      sigResult.setCmsAlgoProtHashAlgo(hashAlgoId);

      //GetSigAlgo
      for (int objIdx = 1; objIdx < cmsapSeq.size(); objIdx++) {
        ASN1Encodable asn1Encodable = cmsapSeq.getObjectAt(objIdx);
        if (asn1Encodable instanceof ASN1TaggedObject) {
          ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Encodable);
          if (taggedObj.getTagNo() == 1) {
            AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(taggedObj, false);
            sigResult.setCmsAlgoProtSigAlgo(algoId);
          }
        }
      }
    }
    catch (Exception e) {
      LOG.warning("Failed to parse CMSAlgoritmProtection algoritms");
    }

  }

  private static boolean checkAlgoritmConsistency(CMSSigVerifyResult sigResult) {
    if (sigResult.getSigAlgo() == null) {
      return false;
    }
    //Check if CMS Algoprotection is present.
    if (!sigResult.isCmsAlgoProtection()) {
      return true;
    }
    PDFAlgoRegistry.PDFSignatureAlgorithmProperties algorithmProperties = PDFAlgoRegistry.getAlgorithmProperties(
      sigResult.getSigAlgo());

    if (!algorithmProperties.getSigAlgoOID().equals(sigResult.getCmsAlgoProtSigAlgo().getAlgorithm())) {
      return false;
    }
    if (!algorithmProperties.getDigestAlgoOID().equals(sigResult.getCmsAlgoProtHashAlgo().getAlgorithm())) {
      return false;
    }

    return true;
  }

}
