/*
 * Copyright 2019-2025 IDsec Solutions AB
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
package se.idsec.signservice.security.sign.pdf.utils;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.sign.pdf.configuration.PDFObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Static utilities for signed PDF documents.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFBoxSignatureUtils {

  /**
   * This method extracts signed attribute data from a CMS signature
   *
   * @param signedData CMSSignedData object holding signature data
   * @return The signed attributes of a PDF signature
   * @throws CMSException If the provided input has no signed attribute data
   */
  public static byte[] getCmsSignedAttributes(final CMSSignedData signedData) throws CMSException {
    byte[] cmsSignedAttributes = null;
    try {
      if (signedData.getSignerInfos() != null || signedData.getSignerInfos().size() > 0) {
        cmsSignedAttributes = signedData.getSignerInfos().iterator().next().getEncodedSignedAttributes();
      }
    }
    catch (final IOException e) {
      throw new CMSException("No CMS signed attributes are available", e);
    }
    if (cmsSignedAttributes != null) {
      return cmsSignedAttributes;
    }
    else {
      throw new CMSException("No CMS signed attributes are available");
    }
  }

  /**
   * This method extracts signed attribute data from a CMS signature.
   *
   * @param contentInfoBytes the CMS Content info bytes holding CMS SignedData content
   * @return The signed attributes of a PDF signature
   * @throws CMSException If the provided input has no signed attribute data
   */
  public static byte[] getCmsSignedAttributes(final byte[] contentInfoBytes) throws CMSException {
    try {
      final ContentInfo contentInfo = ContentInfo.getInstance(contentInfoBytes);
      final ASN1ObjectIdentifier contentType = contentInfo.getContentType();
      if (!contentType.getId().equals(PDFObjectIdentifiers.ID_PKCS7_SIGNED_DATA)) {
        throw new IOException("No SignedData present in input");
      }
      final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
      final SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
      return signerInfo.getAuthenticatedAttributes().getEncoded("DER");
    }
    catch (final IllegalArgumentException | NullPointerException | IOException e) {
      throw new CMSException("No CMS signed attributes are available", e);
    }
  }

  /**
   * A method that updates the PDF SignedData object (Actually a CMS ContentInfo) with a new signature, certificates and
   * SignedAttributes obtained from an external signing service.
   *
   * @param cmsSignedData Input CMS SignedData
   * @param newTbsBytes The new signed attributes bytes signed by the new signature
   * @param newSigValue The new signature value
   * @param chain The new certificate chain
   * @return The bytes of an updated PDF signature (Encoded Content info)
   * @throws CMSException for errors
   */
  public static byte[] updatePdfPKCS7(final byte[] cmsSignedData, final byte[] newTbsBytes,
      final byte[] newSigValue, final List<X509Certificate> chain) throws CMSException {

    try {
      //
      // Basic checks to make sure it's a PKCS#7 SignedData Object
      //
      final ASN1Primitive pkcs7;
      try (final ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(cmsSignedData))) {
        pkcs7 = din.readObject();
      }
      catch (final IOException e) {
        throw new CMSException("Illegal PKCS7");
      }

      if (!(pkcs7 instanceof final ASN1Sequence signedData)) {
        throw new CMSException("Illegal PKCS7");
      }
      final ASN1ObjectIdentifier objId = (ASN1ObjectIdentifier) signedData.getObjectAt(0);
      if (!PDFObjectIdentifiers.ID_PKCS7_SIGNED_DATA.equals(objId.getId())) {
        throw new CMSException("No SignedData available");
      }

      // Add Signed data content type to new PKCS7
      final ASN1EncodableVector npkcs7 = new ASN1EncodableVector();
      npkcs7.add(objId);

      /*
       * SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms DigestAlgorithmIdentifiers, encapContentInfo
       * EncapsulatedContentInfo, certificates [0] IMPLICIT CertificateSet OPTIONAL, crls [1] IMPLICIT
       * RevocationInfoChoices OPTIONAL, signerInfos SignerInfos }
       */

      // Get the SignedData sequence
      final ASN1Sequence signedDataSeq = (ASN1Sequence) ((ASN1TaggedObject) signedData.getObjectAt(1)).getBaseObject();
      int sdObjCount = 0;

      final ASN1EncodableVector nsd = new ASN1EncodableVector();

      // The version
      nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

      // The digestAlgorithms
      nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

      // The possible ecapsulated content info
      nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

      // The certificates. The certs are taken from the input parameters to the method
      final ASN1Encodable[] newCerts = new ASN1Encodable[chain.size()];
      for (int i = 0; i < chain.size(); i++) {
        try (final ASN1InputStream cin = new ASN1InputStream(new ByteArrayInputStream(chain.get(i).getEncoded()))) {
          newCerts[i] = cin.readObject();
        }
      }
      nsd.add(new DERTaggedObject(false, 0, new DERSet(newCerts)));

      // Step counter past tagged objects
      while (signedDataSeq.getObjectAt(sdObjCount) instanceof ASN1TaggedObject) {
        ++sdObjCount;
      }

      // SignerInfos is the next object in the sequence of Signed Data (first untagged after certs)
      final ASN1Set signerInfos = (ASN1Set) signedDataSeq.getObjectAt(sdObjCount);
      if (signerInfos.size() != 1) {
        throw new CMSException("Unsupported multiple signer infos");
      }
      final ASN1Sequence signerInfo = (ASN1Sequence) signerInfos.getObjectAt(0);
      int siCounter = 0;

      // SignerInfo sequence
      //
      // 0 - CMSVersion
      // 1 - SignerIdentifier (CHOICE IssuerAndSerialNumber SEQUENCE)
      // 2 - DigestAglorithmIdentifier
      // 3 - [0] IMPLICIT SignedAttributes SET
      // 3 - Signature AlgorithmIdentifier
      // 4 - Signature Value OCTET STRING
      // 5 - [1] IMPLICIT UnsignedAttributes
      //

      final ASN1EncodableVector nsi = new ASN1EncodableVector();

      // version
      nsi.add(signerInfo.getObjectAt(siCounter++));

      // signing certificate issuer and serial number
      final Certificate sigCert = chain.get(0);
      final ASN1EncodableVector issuerAndSerial = PDFBoxSignatureUtils.getIssuerAndSerial(sigCert);
      nsi.add(new DERSequence(issuerAndSerial));
      siCounter++;

      // Digest AlgorithmIdentifier
      nsi.add(signerInfo.getObjectAt(siCounter++));

      // Add signed attributes from signature service
      try (final ASN1InputStream sigAttrIs = new ASN1InputStream(newTbsBytes)) {
        nsi.add(new DERTaggedObject(false, 0, sigAttrIs.readObject()));
      }

      // Step counter past tagged objects (because signedAttrs i optional in the input data)
      while (signerInfo.getObjectAt(siCounter) instanceof ASN1TaggedObject) {
        siCounter++;
      }

      // Signature Alg identifier
      nsi.add(signerInfo.getObjectAt(siCounter++));

      // Add new signature value from signing service
      nsi.add(new DEROctetString(newSigValue));
      siCounter++;

      // Add unsigned Attributes if present
      if (signerInfo.size() > siCounter && signerInfo.getObjectAt(siCounter) instanceof ASN1TaggedObject) {
        nsi.add(signerInfo.getObjectAt(siCounter));
      }

      /*
       * Final Assembly
       */
      // Add the SignerInfo sequence to the SignerInfos set and add this to the SignedData sequence
      nsd.add(new DERSet(new DERSequence(nsi)));
      // Add the SignedData sequence as an eplicitly tagged object to the pkcs7 object
      npkcs7.add(new DERTaggedObject(true, 0, new DERSequence(nsd)));

      byte[] pkcs7Bytes;
      try (final ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
        final ASN1OutputStream dout = ASN1OutputStream.create(bout, ASN1Encoding.DER);
        try {
          dout.writeObject(new DERSequence(npkcs7));
          pkcs7Bytes = bout.toByteArray();
        }
        finally {
          dout.close();
        }
      }

      return pkcs7Bytes;
    }
    catch (final IOException | CertificateEncodingException | NullPointerException | IllegalArgumentException e) {
      throw new CMSException("Failed to update PKCS7 - " + e.getMessage(), e);
    }
  }

  /**
   * Internal helper method that constructs an IssuerAndSerial object for SignerInfo based on a signer certificate
   *
   * @param sigCert the certificate
   * @return an ASN1EncodableVector holding the IssuerAndSerial ASN.1 sequence.
   * @throws CertificateEncodingException for errors encoding the certificate
   * @throws IOException for Bouncy castle errors
   */
  private static ASN1EncodableVector getIssuerAndSerial(final Certificate sigCert)
      throws CertificateEncodingException, IOException {

    final ASN1Sequence certSeq;
    try (final ASN1InputStream ain = new ASN1InputStream(sigCert.getEncoded())) {
      certSeq = (ASN1Sequence) ain.readObject();
    }

    final ASN1Sequence tbsSeq = (ASN1Sequence) certSeq.getObjectAt(0);

    int counter = 0;
    while (tbsSeq.getObjectAt(counter) instanceof ASN1TaggedObject) {
      counter++;
    }

    // Get serial and issuer DN
    final ASN1Integer serial = (ASN1Integer) tbsSeq.getObjectAt(counter);
    counter += 2;
    final ASN1Sequence issuerDn = (ASN1Sequence) tbsSeq.getObjectAt(counter);

    // Return the issuer field
    final ASN1EncodableVector issuerAndSerial = new ASN1EncodableVector();
    issuerAndSerial.add(issuerDn);
    issuerAndSerial.add(serial);

    return issuerAndSerial;
  }

  /**
   * Sets the signer name and location from the signer certificate subject DN.
   *
   * @param signature the signature object to be updated
   * @param sigCert the certificate being source of data
   * @throws IOException for errors getting the subject attributes from the certificate
   */
  public static void setSubjectNameAndLocality(final PDSignature signature, final Certificate sigCert)
      throws IOException {

    final Map<SubjectDnAttribute, String> subjectDnAttributeMap = PDFBoxSignatureUtils.getSubjectAttributes(sigCert);
    signature.setName(PDFBoxSignatureUtils.getName(subjectDnAttributeMap));
    signature.setLocation(PDFBoxSignatureUtils.getLocation(subjectDnAttributeMap));
  }

  /**
   * Gets a map of recognized subject DN attributes.
   *
   * @param cert X.509 certificate
   * @return subject DN attribute map
   * @throws IOException for errors getting the subject attributes from the certificate
   */
  public static Map<SubjectDnAttribute, String> getSubjectAttributes(final Certificate cert) throws IOException {

    try {
      final ASN1Sequence certSeq;
      try (final ASN1InputStream ain = new ASN1InputStream(cert.getEncoded())) {
        certSeq = (ASN1Sequence) ain.readObject();
      }
      final ASN1Sequence tbsSeq = (ASN1Sequence) certSeq.getObjectAt(0);

      int counter = 0;
      while (tbsSeq.getObjectAt(counter) instanceof ASN1TaggedObject) {
        counter++;
      }
      // Get subject
      final ASN1Sequence subjectDn = (ASN1Sequence) tbsSeq.getObjectAt(counter + 4);

      return PDFBoxSignatureUtils.getSubjectAttributes(subjectDn);
    }
    catch (final CertificateEncodingException e) {
      throw new IOException("Failed to get subject attributes from certificate - " + e.getMessage(), e);
    }
  }

  /**
   * Gets a map of recognized subject DN attributes.
   *
   * @param subjectDn subject DN
   * @return subject DN attribute map
   */
  public static Map<SubjectDnAttribute, String> getSubjectAttributes(final ASN1Sequence subjectDn) {
    final Map<SubjectDnAttribute, String> subjectDnAttributeMap = new EnumMap<>(SubjectDnAttribute.class);

    for (final ASN1Encodable asn1Encodable : subjectDn) {
      final ASN1Set rdnSet = (ASN1Set) asn1Encodable;
      for (final ASN1Encodable encodable : rdnSet) {
        final ASN1Sequence rdnSeq = (ASN1Sequence) encodable;
        final ASN1ObjectIdentifier rdnOid = (ASN1ObjectIdentifier) rdnSeq.getObjectAt(0);
        final String oidStr = rdnOid.getId();
        final ASN1Encodable rdnVal = rdnSeq.getObjectAt(1);
        final String rdnValStr = PDFBoxSignatureUtils.getStringValue(rdnVal);
        final SubjectDnAttribute subjectDnAttr = SubjectDnAttribute.getSubjectDnFromOid(oidStr);
        if (subjectDnAttr != SubjectDnAttribute.unknown) {
          subjectDnAttributeMap.put(subjectDnAttr, rdnValStr);
        }
      }
    }

    return subjectDnAttributeMap;
  }

  /**
   * Gets the RSA PKCS#10 digest info.
   *
   * @param digestAlgo digest algorithm
   * @param hashValue the hash value
   * @return the digest info
   * @throws IOException for errors
   */
  public static byte[] getRSAPkcs1DigestInfo(final AlgorithmIdentifier digestAlgo, final byte[] hashValue)
      throws IOException {
    final ASN1EncodableVector digestInfoSeq = new ASN1EncodableVector();
    digestInfoSeq.add(digestAlgo);
    digestInfoSeq.add(new DEROctetString(hashValue));

    try (final ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      final ASN1OutputStream dout = ASN1OutputStream.create(bout, ASN1Encoding.DER);
      try {
        dout.writeObject(new DERSequence(digestInfoSeq));
        return bout.toByteArray();
      }
      finally {
        dout.close();
      }
    }
  }

  private static String getStringValue(final ASN1Encodable rdnVal) {
    if (rdnVal instanceof final DERUTF8String utf8Str) {
      return utf8Str.getString();
    }
    if (rdnVal instanceof final DERPrintableString str) {
      return str.getString();
    }
    return rdnVal.toString();
  }

  private static String getName(final Map<SubjectDnAttribute, String> subjectDnAttributeMap) {

    final String commonName = subjectDnAttributeMap.getOrDefault(SubjectDnAttribute.cn, null);

    if (commonName != null) {
      return commonName;
    }

    final String surname = subjectDnAttributeMap.getOrDefault(SubjectDnAttribute.surname, null);

    final String givenName = subjectDnAttributeMap.getOrDefault(SubjectDnAttribute.givenName, null);

    if (surname != null && givenName != null) {
      return givenName + " " + surname;
    }

    if (givenName != null) {
      return givenName;
    }

    if (surname != null) {
      return surname;
    }

    return "unknown";
  }

  private static String getLocation(final Map<SubjectDnAttribute, String> subjectDnAttributeMap) {

    final String country = subjectDnAttributeMap.getOrDefault(SubjectDnAttribute.country, null);

    final String locality = subjectDnAttributeMap.getOrDefault(SubjectDnAttribute.locality, null);

    if (country != null && locality != null) {
      return locality + ", " + country;
    }
    if (country != null) {
      return country;
    }
    if (locality != null) {
      return locality;
    }

    return "unknown";
  }

  public static DefaultSignedAttributeTableGenerator getPadesSignerInfoGenerator(
      final Certificate signerCert, final ASN1ObjectIdentifier digestAlgo, final boolean includeIssuerSerial)
      throws CertificateException, NoSuchAlgorithmException {

    final ASN1EncodableVector signedCertAttr = PDFBoxSignatureUtils.getSignedCertAttr(
        digestAlgo, CertificateUtils.decodeCertificate(signerCert.getEncoded()), includeIssuerSerial);
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DERSequence(signedCertAttr));

    return new DefaultSignedAttributeTableGenerator(new AttributeTable(v));
  }

  public static ASN1EncodableVector getSignedCertAttr(
      final ASN1ObjectIdentifier digestAlgo, final X509Certificate certificate, final boolean includeIssuerSerial)
      throws NoSuchAlgorithmException, CertificateException {

    try {
      final GeneralNames generalNames = new GeneralNames(
          new GeneralName(new X509CertificateHolder(certificate.getEncoded()).getIssuer()));
      final BigInteger serialNumber = certificate.getSerialNumber();
      final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);

      final ASN1EncodableVector signedCert = new ASN1EncodableVector();

      final boolean essSigCertV2;
      final ASN1ObjectIdentifier signedCertOid;

      if (digestAlgo.equals(CMSAlgorithm.SHA1)) {
        signedCertOid = new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V1);
        essSigCertV2 = false;
      }
      else {
        signedCertOid = new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V2);
        essSigCertV2 = true;
      }

      final MessageDigest md = MessageDigest.getInstance(digestAlgo.getId(), BouncyCastleProvider.PROVIDER_NAME);
      md.update(certificate.getEncoded());
      final byte[] certHash = md.digest();

      signedCert.add(signedCertOid);

      final ASN1EncodableVector attrValSet = new ASN1EncodableVector();
      final ASN1EncodableVector signingCertObjSeq = new ASN1EncodableVector();
      final ASN1EncodableVector essCertV2Seq = new ASN1EncodableVector();
      final ASN1EncodableVector certSeq = new ASN1EncodableVector();
      final ASN1EncodableVector algoSeq = new ASN1EncodableVector();
      algoSeq.add(digestAlgo);
      algoSeq.add(DERNull.INSTANCE);
      if (essSigCertV2) {
        certSeq.add(new DERSequence(algoSeq));
      }
      // Add cert hash
      certSeq.add(new DEROctetString(certHash));
      if (includeIssuerSerial) {
        certSeq.add(issuerSerial);
      }

      // Finalize assembly
      essCertV2Seq.add(new DERSequence(certSeq));
      signingCertObjSeq.add(new DERSequence(essCertV2Seq));
      attrValSet.add(new DERSequence(signingCertObjSeq));
      signedCert.add(new DERSet(attrValSet));

      return signedCert;
    }
    catch (final NoSuchProviderException e) {
      throw new SecurityException("The BC provider is not installed", e);
    }
    catch (final IOException e) {
      throw new CertificateException("Failed to encode certificate - " + e.getMessage(), e);
    }
  }

  public static byte[] removeSignedAttr(final byte[] signedAttrBytes, final ASN1ObjectIdentifier[] attrOid)
      throws IOException {

    final ASN1Set inAttrSet;
    try (final ASN1InputStream ais = new ASN1InputStream(signedAttrBytes)) {
      inAttrSet = ASN1Set.getInstance(ais.readObject());
    }

    final ASN1EncodableVector newSigAttrSet = new ASN1EncodableVector();
    final List<ASN1ObjectIdentifier> attrOidList = Arrays.asList(attrOid);

    for (int i = 0; i < inAttrSet.size(); i++) {
      final Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));
      if (!attrOidList.contains(attr.getAttrType())) {
        newSigAttrSet.add(attr);
      }
    }

    // Der encode the new signed attributes set
    try (final ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      final ASN1OutputStream dout = ASN1OutputStream.create(bout, ASN1Encoding.DER);
      try {
        dout.writeObject(new DERSet(newSigAttrSet));
        return bout.toByteArray();
      }
      finally {
        dout.close();
      }
    }
  }

  public static SignedCertRef getSignedCertRefAttribute(final byte[] signedAttrBytes) throws IOException {

    final ASN1Set inAttrSet;
    try (final ASN1InputStream ais = new ASN1InputStream(signedAttrBytes)) {
      inAttrSet = ASN1Set.getInstance(ais.readObject());
    }

    for (int i = 0; i < inAttrSet.size(); i++) {
      final Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));

      if (attr.getAttrType().equals(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V2))) {
        final ASN1Encodable[] attributeValues = attr.getAttributeValues();
        final SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(attributeValues[0]);
        final ESSCertIDv2[] certsRefs = signingCertificateV2.getCerts();
        final ESSCertIDv2 certsRef = certsRefs[0];
        final AlgorithmIdentifier hashAlgorithm = certsRef.getHashAlgorithm();
        // According to CMS, the hash algorithm is optional and defaults to SHA256
        final ASN1ObjectIdentifier hashAlgoOid =
            hashAlgorithm == null ? NISTObjectIdentifiers.id_sha256 : hashAlgorithm.getAlgorithm();

        return SignedCertRef.builder()
            .hashAlgorithm(hashAlgoOid)
            .signedCertHash(certsRef.getCertHash())
            .build();
      }
      if (attr.getAttrType().equals(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V1))) {
        final ASN1Encodable[] attributeValues = attr.getAttributeValues();
        final SigningCertificate signingCertificate = SigningCertificate.getInstance(attributeValues[0]);
        final ESSCertID[] certsRefs = signingCertificate.getCerts();
        final ESSCertID certsRef = certsRefs[0];
        return SignedCertRef.builder()
            .hashAlgorithm(OIWObjectIdentifiers.idSHA1)
            .signedCertHash(certsRef.getCertHash())
            .build();
      }
    }
    return null;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class SignedCertRef {
    private byte[] signedCertHash;
    private ASN1ObjectIdentifier hashAlgorithm;
  }

}
