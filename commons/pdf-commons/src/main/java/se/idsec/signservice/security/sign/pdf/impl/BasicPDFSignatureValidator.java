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
package se.idsec.signservice.security.sign.pdf.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.CollectionStore;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult.Status;
import se.idsec.signservice.security.sign.impl.InternalSignatureValidationException;
import se.idsec.signservice.security.sign.pdf.PDFSignatureException;
import se.idsec.signservice.security.sign.pdf.PDFSignatureValidationResult;
import se.idsec.signservice.security.sign.pdf.PDFSignatureValidator;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgoRegistry;
import se.idsec.signservice.security.sign.pdf.configuration.PdfObjectIds;
import se.idsec.signservice.security.sign.pdf.signprocess.PdfBoxSigUtil;
import se.idsec.signservice.utils.Pair;

/**
 * Verifies the signature(s) on a PDF document.
 *
 * <p>
 * This is a basic implementation that just verifies that the actual signatures validates correctly and reports what
 * certificates that was supplied to provide the matching public key. No attempts are made to validate the certificates
 * or any timestamps associated with the signature.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class BasicPDFSignatureValidator implements PDFSignatureValidator {

  /** A (possibly empty) list of required signer certificates. */
  private final List<X509Certificate> requiredSignerCertificates;

  /**
   * Constructor setting up the validator so that no required certificates are configured. This means that no control of
   * the signer certificate will be performed.
   */
  public BasicPDFSignatureValidator() {
    this.requiredSignerCertificates = Collections.emptyList();
  }

  /**
   * Constructor setting up the validator to require that the signature is signed using the supplied certificate.
   * 
   * @param acceptedSignerCertificate
   *          required signer certificate
   */
  public BasicPDFSignatureValidator(final X509Certificate acceptedSignerCertificate) {
    this(Collections.singletonList(acceptedSignerCertificate));
  }

  /**
   * Constructor setting up the validator to require that the signature is signed using any of the supplied
   * certificates.
   * 
   * @param acceptedSignerCertificates
   *          required signer certificates
   */
  public BasicPDFSignatureValidator(final List<X509Certificate> acceptedSignerCertificates) {
    this.requiredSignerCertificates = acceptedSignerCertificates;
  }

  /** {@inheritDoc} */
  @Override
  public List<SignatureValidationResult> validate(final byte[] document) throws SignatureException {

    PDDocument pdfDocument = null;
    try {
      pdfDocument = PDDocument.load(document);

      final List<SignatureValidationResult> results = new ArrayList<>();
      final List<PDSignature> signatureDictionaries = pdfDocument.getSignatureDictionaries();

      for (PDSignature signature : signatureDictionaries) {
        log.debug("Validating PDF signature [{}] ...", signature.getName());
        PDFSignatureValidationResult result = this.validatePdfSignature(document, signature);
        results.add(result);
        log.debug("PDF signature validation result for [{}]: {}", signature.getName(), result);
      }

      return results;
    }
    catch (IOException e) {
      final String msg = String.format("Internal error while verifying PDF signature - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new PDFSignatureException(msg, e);
    }
    finally {
      try {
        if (pdfDocument != null) {
          pdfDocument.close();
        }
      }
      catch (IOException e) {
      }
    }
  }

  protected PDFSignatureValidationResult validatePdfSignature(final byte[] document, final PDSignature signature) {
    DefaultPDFSignatureValidationResult result = new DefaultPDFSignatureValidationResult();
    result.setPdfSignature(signature);
    try {
      final byte[] signedContentBytes = signature.getSignedContent(new ByteArrayInputStream(document));
      final byte[] signedDataBytes = signature.getContents(new ByteArrayInputStream(document));

      final CMSSignedDataParser signedDataParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new CMSTypedStream(
        new ByteArrayInputStream(signedContentBytes)), signedDataBytes);
      final CMSTypedStream signedContent = signedDataParser.getSignedContent();
      signedContent.drain();

      // Get hold of all certificates found in the document.
      //
      CollectionStore<?> certStore = (CollectionStore<?>) signedDataParser.getCertificates();
      Iterator<?> ci = certStore.iterator();
      final List<X509Certificate> certList = new ArrayList<>();
      while (ci.hasNext()) {
        final X509CertificateHolder ch = (X509CertificateHolder) ci.next();
        certList.add(CertificateUtils.decodeCertificate(ch.getEncoded()));
      }
      result.setAdditionalCertificates(certList);

      // Extract the signer information
      //
      final SignerInformationStore signerInformationStore = signedDataParser.getSignerInfos();
      final Collection<SignerInformation> signerInformationCollection = signerInformationStore.getSigners();
      if (signerInformationCollection.isEmpty()) {
        throw new CMSException("No SignerInformation available");
      }
      else if (signerInformationCollection.size() > 1) {
        throw new CMSException("More than one SignerInformation available");
      }
      final SignerInformation signerInformation = signerInformationCollection.iterator().next();

      // Claimed signing time
      //
      final Date claimedSigningTime = getClaimedSigningTime(signerInformation);
      if (claimedSigningTime != null) {
        result.setClaimedSigningTime(claimedSigningTime);
      }
      else {
        final Calendar dictionarySignDate = signature.getSignDate();
        if (dictionarySignDate != null) {
          log.debug("Claimed signing time was not present in signer information using time from PDF dictionary");
          result.setClaimedSigningTime(dictionarySignDate.getTimeInMillis());
        }
        else {
          log.warn("Claimed signing time was not present in signer information OR the PDF dictionary");
        }
      }

      // Get hold of signer certificate ...
      //
      @SuppressWarnings("unchecked")
      final Collection<?> certCollection = certStore.getMatches(signerInformation.getSID());
      if (certCollection.isEmpty()) {
        throw new CMSException("No signer certificate available");
      }
      final X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
      result.setSignerCertificate(CertificateUtils.decodeCertificate(certHolder.getEncoded()));

      // Verify the signature
      //
      final SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
        .build(certHolder);

      try {
        boolean signatureVerificationResult = signerInformation.verify(signerInformationVerifier);
        if (!signatureVerificationResult) {
          result.setError(Status.ERROR_INVALID_SIGNATURE, "Invalid PDF signature");
          return result;
        }
      }
      catch (CMSVerifierCertificateNotValidException e) {
        result.setError(Status.ERROR_SIGNER_INVALID, "Signing certificate was not valid at time of signing", e);
        return result;
      }

      // Collect signature algorithm data
      //
      final String digestAlgoOid = signerInformation.getDigestAlgOID();
      final String encryptionAlgorithmOid = signerInformation.getEncryptionAlgOID();
      final String signatureAlgorithm = PDFAlgoRegistry.getAlgorithmURI(
        new ASN1ObjectIdentifier(encryptionAlgorithmOid), new ASN1ObjectIdentifier(digestAlgoOid));
      result.setSignatureAlgorithm(signatureAlgorithm);

      // Check if the CMS algorithm protection attribute has been set, and if so, assert algorithm consistency.
      //
      final Attribute cmsAlgorithmProtection = signerInformation.getSignedAttributes()
        .get(new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_CMS_ALGORITHM_PROTECTION));

      if (cmsAlgorithmProtection != null) {
        Pair<AlgorithmIdentifier, AlgorithmIdentifier> cmsAlgorithmProtectionAlgs = getCmsAlgoritmProtectionData(cmsAlgorithmProtection);
        final AlgorithmIdentifier protSignAlgo = cmsAlgorithmProtectionAlgs.getFirst();
        final AlgorithmIdentifier protHashAlgo = cmsAlgorithmProtectionAlgs.getSecond();

        result.setCmsAlgorithmProtection(true);

        // Make sure the algorithms are consistent with our signature algorithm.
        //
        final PDFAlgoRegistry.PDFSignatureAlgorithmProperties algorithmProperties = PDFAlgoRegistry.getAlgorithmProperties(
          signatureAlgorithm);

        if (!algorithmProperties.getSigAlgoOID().equals(protSignAlgo.getAlgorithm())) {
          final String msg = String.format(
            "CMS algorithm protection signature algorithm (%s) is not consistent with signature algorithm used to sign data (%s)",
            protSignAlgo.getAlgorithm().getId(), signatureAlgorithm);
          result.setError(Status.ERROR_INVALID_SIGNATURE, msg);
          return result;
        }
        if (!algorithmProperties.getDigestAlgoOID().equals(protHashAlgo.getAlgorithm())) {
          final String msg = String.format(
            "CMS algorithm protection hash algorithm (%s) is not consistent with signature algorithm used to sign data (%s)",
            protHashAlgo.getAlgorithm().getId(), signatureAlgorithm);
          result.setError(Status.ERROR_INVALID_SIGNATURE, msg);
          return result;
        }
        log.debug("CMS algorithm protection attribute attributes ('{}', '{}') are consistent with signature algorithm used ('{}')",
          protSignAlgo.getAlgorithm().getId(), protHashAlgo.getAlgorithm().getId(), signatureAlgorithm);
      }

      // Check if this is a PAdES signature, and if so, validate the PAdES properties.
      //
      result.setPades(this.verifyPadesProperties(signature, signerInformation, result.getSignerCertificate()));

      result.setStatus(Status.SUCCESS);
    }
    catch (InternalSignatureValidationException e) {
      log.error("{}", e.getMessage(), e);
      result.setError(e);
    }
    catch (IOException | CMSException | CertificateException | NoSuchAlgorithmException | OperatorCreationException e) {
      final String msg = String.format("PDF signature validation processing error - %s", e.getMessage());
      log.error("{}", msg, e);
      result.setError(Status.ERROR_BAD_FORMAT, msg, e);
    }

    return result;
  }

  /**
   * Verifies PAdES properties.
   * 
   * @param signature
   *          the PDF signature
   * @param signerInformation
   *          the signer information
   * @param signerCertificate
   *          the signer certificate
   * @return true if this is a PAdES signature and it was successfully validated and false if this is not a PAdES
   *         signature
   * @throws InternalSignatureValidationException
   *           for PAdES validation errors
   */
  private boolean verifyPadesProperties(final PDSignature signature, final SignerInformation signerInformation,
      final X509Certificate signerCertificate) throws InternalSignatureValidationException {

    try {
      final String subFilter = signature.getSubFilter();

      if (PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName().equals(subFilter)) {
        PdfBoxSigUtil.SignedCertRef signedCertificateRef = PdfBoxSigUtil.getSignedCertRefAttribute(
          signerInformation.getSignedAttributes().toASN1Structure().getEncoded(ASN1Encoding.DER));

        if (signedCertificateRef == null) {
          throw new InternalSignatureValidationException(Status.ERROR_BAD_FORMAT,
            "Signature subfilter indicates that the signature is a PAdES signature but no signed certificate reference is present");
        }
        final MessageDigest md = MessageDigest.getInstance(signedCertificateRef.getHashAlgorithm().getId());
        final byte[] certificateHash = md.digest(signerCertificate.getEncoded());
        if (!Arrays.equals(certificateHash, signedCertificateRef.getSignedCertHash())) {
          throw new InternalSignatureValidationException(Status.ERROR_INVALID_SIGNATURE, "PAdES signed certificate reference mismatch");
        }
        log.debug("PAdES signature successfully verified");
        return true;
      }
      else {
        log.debug("No PAdES signature available");
        return false;
      }
    }
    catch (IOException | NoSuchAlgorithmException | CertificateEncodingException e) {
      final String msg = String.format("Failure verifying PAdES signature - %s", e.getMessage());
      throw new InternalSignatureValidationException(Status.ERROR_BAD_FORMAT, msg, e);
    }
  }

  /**
   * Obtains the claimed signing time from signed attributes.
   * 
   * @param signer
   *          signer information
   * @return claimed signing time if present or null if absent
   */
  private static Date getClaimedSigningTime(final SignerInformation signer) {
    final AttributeTable signedAttributes = signer.getSignedAttributes();
    final Attribute sigTimeAttr = signedAttributes.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5"));
    if (sigTimeAttr == null) {
      return null;
    }
    final ASN1Encodable[] attributeValues = sigTimeAttr.getAttributeValues();
    if (attributeValues.length > 0 && ASN1UTCTime.class.isInstance(attributeValues[0])) {
      try {
        return ASN1UTCTime.class.cast(attributeValues[0]).getDate();
      }
      catch (ParseException e) {
        log.error("Imvalid format for claimed signing time - {}", e.getMessage(), e);
        return null;
      }
    }
    else {
      return null;
    }
  }

  /**
   * Gets the signature and hash algorithms from the CMS algorithm protection attribute.
   * 
   * @param cmsAlgorithmProtectionAttribute
   * @return a pair of the signature algorithm ID and the hash algoritm id
   * @throws InternalSignatureValidationException
   *           for invalid CMS algorithm protection attributes
   */
  private static Pair<AlgorithmIdentifier, AlgorithmIdentifier> getCmsAlgoritmProtectionData(
      final Attribute cmsAlgorithmProtectionAttribute) throws InternalSignatureValidationException {

    try {
      ASN1Sequence cmsapSeq = ASN1Sequence.getInstance(cmsAlgorithmProtectionAttribute.getAttrValues().getObjectAt(0));

      // Get Hash algorithm
      final AlgorithmIdentifier hashAlgorithmId = AlgorithmIdentifier.getInstance(cmsapSeq.getObjectAt(0));
      if (hashAlgorithmId == null) {
        throw new InternalSignatureValidationException(
          Status.ERROR_BAD_FORMAT, "Missing hash algorithm in CMS algorithm protection attribute");
      }

      // Get Signature algorithm
      AlgorithmIdentifier signatureAlgorithmId = null;
      for (int objIdx = 1; objIdx < cmsapSeq.size(); objIdx++) {
        final ASN1Encodable asn1Encodable = cmsapSeq.getObjectAt(objIdx);
        if (asn1Encodable instanceof ASN1TaggedObject) {
          final ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Encodable);
          if (taggedObj.getTagNo() == 1) {
            signatureAlgorithmId = AlgorithmIdentifier.getInstance(taggedObj, false);
            break;
          }
        }
      }
      if (signatureAlgorithmId == null) {
        throw new InternalSignatureValidationException(
          Status.ERROR_BAD_FORMAT, "Missing signature algorithm in CMS algorithm protection attribute");
      }
      return new Pair<>(signatureAlgorithmId, hashAlgorithmId);
    }
    catch (IllegalArgumentException e) {
      throw new InternalSignatureValidationException(
        Status.ERROR_BAD_FORMAT, "Error processing CMS algorithm protection attribute - " + e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSigned(final byte[] document) throws IllegalArgumentException {
    PDDocument pdfDocument = null;
    try {
      pdfDocument = PDDocument.load(document);
      return !pdfDocument.getSignatureDictionaries().isEmpty();
    }
    catch (IOException e) {
      throw new IllegalArgumentException("Invalid document", e);
    }
    finally {
      try {
        if (pdfDocument != null) {
          pdfDocument.close();
        }
      }
      catch (IOException e) {
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getRequiredSignerCertificates() {
    return this.requiredSignerCertificates;
  }

  /**
   * This basic implementation will always return {@code null}.
   */
  @Override
  public CertificateValidator getCertificateValidator() {
    return null;
  }

}
