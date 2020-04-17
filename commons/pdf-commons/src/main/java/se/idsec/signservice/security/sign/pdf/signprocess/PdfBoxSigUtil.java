/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.signservice.security.sign.pdf.signprocess;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import se.idsec.signservice.security.sign.pdf.configuration.PdfObjectIds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.*;

/**
 * @author stefan
 */
public class PdfBoxSigUtil {

  /**
   * This method extracts signed attribute data from a CMS signature
   *
   * @param signedData
   * @return The signed attributes of a PDF signature
   * @throws IOException If the provided input has no signed attribute data
   */
  public static byte[] getCmsSignedAttributes(CMSSignedData signedData) throws IOException {
    try {
      return signedData.getSignerInfos().iterator().next().getEncodedSignedAttributes();
    } catch (Exception ex){
      throw new IOException("No CMS signed attributes are available");
    }
  }

  /**
   * This method extracts signed attribute data from a CMS signature
   *
   * @param contentInfoBytes the CMS Content info bytes holding CMSSignedData content
   * @return The signed attributes of a PDF signature
   * @throws IllegalArgumentException If the provided input has no signed attribute data
   */
  public static byte[] getCmsSignedAttributes(byte[] contentInfoBytes) throws IOException {
    try {
      ContentInfo contentInfo = ContentInfo.getInstance(contentInfoBytes);
      ASN1ObjectIdentifier contentType = contentInfo.getContentType();
      if (!contentType.getId().equals(PdfObjectIds.ID_PKCS7_SIGNED_DATA)){
        throw new IOException("No SignedData present in input");
      }
      SignedData signedData = SignedData.getInstance(contentInfo.getContent());
      SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
      return signerInfo.getAuthenticatedAttributes().getEncoded("DER");
    } catch (Exception ex){
      throw new IOException("No CMS signed attributes are available");
    }
  }




  /**
   * A method that updates the PDF SignedData object (Actually a CMS ContentInfo) with a new
   * signature, certificates and SignedAttributes obtained from an external
   * signing service.
   *
   * @param cmsSignedData Input CMS SignedData
   * @param newTbsBytes The new signed attributes bytes signed by the new signature
   * @param newSigValue The new signature value
   * @param chain The new certificate chain
   * @return The bytes of an updated PDF signature (Encoded Content info).
   */

  /**
   *
   * @param cmsSignedData
   * @param newTbsBytes
   * @param newSigValue
   * @param chain
   * @return
   */
  public static byte[] updatePdfPKCS7(byte[] cmsSignedData,byte[] newTbsBytes, byte[] newSigValue, List<X509Certificate> chain) {

    //New variables
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    DEROutputStream dout = new DEROutputStream(bout);
    ASN1EncodableVector npkcs7 = new ASN1EncodableVector();
    ASN1EncodableVector nsd = new ASN1EncodableVector();
    ASN1EncodableVector nsi = new ASN1EncodableVector();

    try {
      ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(cmsSignedData));

      //
      // Basic checks to make sure it's a PKCS#7 SignedData Object
      //
      ASN1Primitive pkcs7;

      try {
        pkcs7 = din.readObject();
      }
      catch (IOException e) {
        throw new IllegalArgumentException("Illegal PKCS7");
      }
      if (!(pkcs7 instanceof ASN1Sequence)) {
        throw new IllegalArgumentException("Illegal PKCS7");
      }
      ASN1Sequence signedData = (ASN1Sequence) pkcs7;
      ASN1ObjectIdentifier objId = (ASN1ObjectIdentifier) signedData.getObjectAt(0);
      if (!objId.getId().equals(PdfObjectIds.ID_PKCS7_SIGNED_DATA)) {
        throw new IllegalArgumentException("No SignedData");
      }

      //Add Signed data content type to new PKCS7
      npkcs7.add(objId);

      /**
       * SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms
       * DigestAlgorithmIdentifiers, encapContentInfo
       * EncapsulatedContentInfo, certificates [0] IMPLICIT CertificateSet
       * OPTIONAL, crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
       * signerInfos SignerInfos }
       */
      //Get the SignedData sequence
      ASN1Sequence signedDataSeq = (ASN1Sequence) ((ASN1TaggedObject) signedData.getObjectAt(1)).getObject();
      int sdObjCount = 0;

      // the version
      nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

      // the digestAlgorithms
      nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

      // the possible ecapsulated content info
      nsd.add(signedDataSeq.getObjectAt(sdObjCount++));
      // the certificates. The certs are taken from the input parameters to the method
      //ASN1EncodableVector newCerts = new ASN1EncodableVector();
      //Certificate[] chain = model.getChain();
      ASN1Encodable[] newCerts = new ASN1Encodable[chain.size()];
      //for (Certificate nCert : model.getCertChain()) {
      for (int i = 0; i < chain.size(); i++) {
        ASN1InputStream cin = new ASN1InputStream(new ByteArrayInputStream(chain.get(i).getEncoded()));
        newCerts[i] = cin.readObject();

      }
      nsd.add(new DERTaggedObject(false, 0, new DERSet(newCerts)));

      //Step counter past tagged objects
      while (signedDataSeq.getObjectAt(sdObjCount) instanceof ASN1TaggedObject) {
        ++sdObjCount;
      }

      //SignerInfos is the next object in the sequence of Signed Data (first untagged after certs)
      ASN1Set signerInfos = (ASN1Set) signedDataSeq.getObjectAt(sdObjCount);
      if (signerInfos.size() != 1) {
        throw new IllegalArgumentException("Unsupported multiple signer infos");
      }
      ASN1Sequence signerInfo = (ASN1Sequence) signerInfos.getObjectAt(0);
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
      //version
      nsi.add(signerInfo.getObjectAt(siCounter++));

      // signing certificate issuer and serial number
      Certificate sigCert = chain.get(0);
      ASN1EncodableVector issuerAndSerial = getIssuerAndSerial(sigCert);
      nsi.add(new DERSequence(issuerAndSerial));
      siCounter++;

      //Digest AlgorithmIdentifier
      nsi.add(signerInfo.getObjectAt(siCounter++));

      //Add signed attributes from signature service
      ASN1InputStream sigAttrIs = new ASN1InputStream(newTbsBytes);
      nsi.add(new DERTaggedObject(false, 0, sigAttrIs.readObject()));

      //Step counter past tagged objects (because signedAttrs i optional in the input data)
      while (signerInfo.getObjectAt(siCounter) instanceof ASN1TaggedObject) {
        siCounter++;
      }

      //Signature Alg identifier
      nsi.add(signerInfo.getObjectAt(siCounter++));

      //Add new signature value from signing service
      nsi.add(new DEROctetString(newSigValue));
      siCounter++;

      //Add unsigned Attributes if present
      if (signerInfo.size() > siCounter && signerInfo.getObjectAt(siCounter) instanceof ASN1TaggedObject) {
        nsi.add(signerInfo.getObjectAt(siCounter));
      }

      /*
       * Final Assembly
       */
      // Add the SignerInfo sequence to the SignerInfos set and add this to the SignedData sequence
      nsd.add(new DERSet(new DERSequence(nsi)));
      // Add the SignedData sequence as a eplicitly tagged object to the pkcs7 object
      npkcs7.add(new DERTaggedObject(true, 0, new DERSequence(nsd)));

      dout.writeObject((new DERSequence(npkcs7)));
      byte[] pkcs7Bytes = bout.toByteArray();
      dout.close();
      bout.close();

      return pkcs7Bytes;

    }
    catch (Exception e) {
      throw new IllegalArgumentException(e.toString());
    }
  }

  /**
   * Internal helper method that constructs an IssuerAndSerial object for
   * SignerInfo based on a signer certificate.
   *
   * @param sigCert
   * @return An ASN1EncodableVector holding the IssuerAndSerial ASN.1
   * sequence.
   * @throws CertificateEncodingException
   * @throws IOException
   */
  private static ASN1EncodableVector getIssuerAndSerial(Certificate sigCert) throws CertificateEncodingException, IOException {
    ASN1EncodableVector issuerAndSerial = new ASN1EncodableVector();
    ASN1InputStream ain = new ASN1InputStream(sigCert.getEncoded());
    ASN1Sequence certSeq = (ASN1Sequence) ain.readObject();
    ASN1Sequence tbsSeq = (ASN1Sequence) certSeq.getObjectAt(0);

    int counter = 0;
    while (tbsSeq.getObjectAt(counter) instanceof ASN1TaggedObject) {
      counter++;
    }
    //Get serial
    ASN1Integer serial = (ASN1Integer) tbsSeq.getObjectAt(counter);
    counter += 2;

    ASN1Sequence issuerDn = (ASN1Sequence) tbsSeq.getObjectAt(counter);
    //Return the issuer field
    issuerAndSerial.add(issuerDn);
    issuerAndSerial.add(serial);

    return issuerAndSerial;
  }

  /**
   * Sets the signer name and location from the signer certificate subject DN
   *
   * @param signature The signature object to be updated
   * @param sigCert   The certificate being source of data
   * @throws CertificateEncodingException
   * @throws IOException
   */
  public static void setSubjectNameAndLocality(PDSignature signature, Certificate sigCert)
    throws CertificateEncodingException, IOException {
    Map<SubjectDnAttribute, String> subjectDnAttributeMap = getSubjectAttributes(sigCert);
    signature.setName(getName(subjectDnAttributeMap));
    signature.setLocation(getLocation(subjectDnAttributeMap));
  }

  /**
   * Gets a map of recognized subject DN attributes
   *
   * @param cert X.509 certificate
   * @return Subject DN attribute map
   * @throws CertificateEncodingException
   * @throws IOException
   */
  public static Map<SubjectDnAttribute, String> getSubjectAttributes(Certificate cert) throws CertificateEncodingException, IOException {
    ASN1InputStream ain = new ASN1InputStream(cert.getEncoded());
    ASN1Sequence certSeq = (ASN1Sequence) ain.readObject();
    ASN1Sequence tbsSeq = (ASN1Sequence) certSeq.getObjectAt(0);

    int counter = 0;
    while (tbsSeq.getObjectAt(counter) instanceof ASN1TaggedObject) {
      counter++;
    }
    //Get subject
    ASN1Sequence subjectDn = (ASN1Sequence) tbsSeq.getObjectAt(counter + 4);
    Map<SubjectDnAttribute, String> subjectDnAttributeMap = getSubjectAttributes(subjectDn);

    return subjectDnAttributeMap;
  }

  /**
   * Gets a map of recognized subject DN attributes
   *
   * @param subjectDn subhect Dn
   * @return Subject DN attribute map
   */
  public static Map<SubjectDnAttribute, String> getSubjectAttributes(ASN1Sequence subjectDn) {
    Map<SubjectDnAttribute, String> subjectDnAttributeMap = new EnumMap<SubjectDnAttribute, String>(SubjectDnAttribute.class);
    try {
      Iterator<ASN1Encodable> subjDnIt = subjectDn.iterator();
      while (subjDnIt.hasNext()) {
        ASN1Set rdnSet = (ASN1Set) subjDnIt.next();
        Iterator<ASN1Encodable> rdnSetIt = rdnSet.iterator();
        while (rdnSetIt.hasNext()) {
          ASN1Sequence rdnSeq = (ASN1Sequence) rdnSetIt.next();
          ASN1ObjectIdentifier rdnOid = (ASN1ObjectIdentifier) rdnSeq.getObjectAt(0);
          String oidStr = rdnOid.getId();
          ASN1Encodable rdnVal = rdnSeq.getObjectAt(1);
          String rdnValStr = getStringValue(rdnVal);
          SubjectDnAttribute subjectDnAttr = SubjectDnAttribute.getSubjectDnFromOid(oidStr);
          if (!subjectDnAttr.equals(SubjectDnAttribute.unknown)) {
            subjectDnAttributeMap.put(subjectDnAttr, rdnValStr);
          }
        }
      }

    }
    catch (Exception e) {
    }

    return subjectDnAttributeMap;
  }

  public static byte[] getRSAPkcs1DigestInfo(AlgorithmIdentifier digestAlgo, byte[] hashValue) throws IOException {
    ASN1EncodableVector digestInfoSeq = new ASN1EncodableVector();
    digestInfoSeq.add(digestAlgo);
    digestInfoSeq.add(new DEROctetString(hashValue));

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    DEROutputStream dout = new DEROutputStream(bout);
    dout.writeObject((new DERSequence(digestInfoSeq)));
    byte[] digestInfoBytes = bout.toByteArray();
    dout.close();
    bout.close();

    return digestInfoBytes;
  }

  private static String getStringValue(ASN1Encodable rdnVal) {
    if (rdnVal instanceof DERUTF8String) {
      DERUTF8String utf8Str = (DERUTF8String) rdnVal;
      return utf8Str.getString();
    }
    if (rdnVal instanceof DERPrintableString) {
      DERPrintableString str = (DERPrintableString) rdnVal;
      return str.getString();
    }
    return rdnVal.toString();
  }

  private static String getName(Map<SubjectDnAttribute, String> subjectDnAttributeMap) {
    String commonName = subjectDnAttributeMap.containsKey(SubjectDnAttribute.cn) ? subjectDnAttributeMap.get(SubjectDnAttribute.cn) : null;
    String surname = subjectDnAttributeMap.containsKey(SubjectDnAttribute.surname) ?
      subjectDnAttributeMap.get(SubjectDnAttribute.surname) :
      null;
    String givenName = subjectDnAttributeMap.containsKey(SubjectDnAttribute.givenName) ?
      subjectDnAttributeMap.get(SubjectDnAttribute.givenName) :
      null;

    if (commonName != null) {
      return commonName;
    }

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

  private static String getLocation(Map<SubjectDnAttribute, String> subjectDnAttributeMap) {
    String country = subjectDnAttributeMap.containsKey(SubjectDnAttribute.country) ?
      subjectDnAttributeMap.get(SubjectDnAttribute.country) :
      null;
    String locality = subjectDnAttributeMap.containsKey(SubjectDnAttribute.locality) ?
      subjectDnAttributeMap.get(SubjectDnAttribute.locality) :
      null;

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

  public static DefaultSignedAttributeTableGenerator getPadesSignerInfoGenerator(Certificate signerCert, ASN1ObjectIdentifier digestAlgo,
    boolean includeIssuerSerial)
    throws IOException, CertificateEncodingException, OperatorCreationException, NoSuchAlgorithmException, CertificateException,
    NoSuchProviderException {

    ASN1EncodableVector signedCertAttr = PdfBoxSigUtil.getSignedCertAttr(digestAlgo, getCert(signerCert), includeIssuerSerial);
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DERSequence(signedCertAttr));

    DefaultSignedAttributeTableGenerator signedSignerCertAttrGenerator = new DefaultSignedAttributeTableGenerator(new AttributeTable(v));
    return signedSignerCertAttrGenerator;

  }

  public static X509Certificate getCert(Certificate inCert) throws IOException, CertificateException {
    X509Certificate cert = null;
    ByteArrayInputStream certIs = new ByteArrayInputStream(inCert.getEncoded());

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate) cf.generateCertificate(certIs);

    }
    finally {
      certIs.close();
    }
    return cert;
  }

  public static ASN1EncodableVector getSignedCertAttr(ASN1ObjectIdentifier digestAlgo, X509Certificate certificate, boolean includeIssuerSerial)
    throws NoSuchAlgorithmException, CertificateEncodingException, IOException, NoSuchProviderException {
    final X500Name issuerX500Name = new X509CertificateHolder(certificate.getEncoded()).getIssuer();
    final GeneralName generalName = new GeneralName(issuerX500Name);
    final GeneralNames generalNames = new GeneralNames(generalName);
    final BigInteger serialNumber = certificate.getSerialNumber();
    final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);

    ASN1EncodableVector signedCert = new ASN1EncodableVector();

    boolean essSigCertV2;
    ASN1ObjectIdentifier signedCertOid;

    if (digestAlgo.equals(CMSAlgorithm.SHA1)){
      signedCertOid = new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V1);
      essSigCertV2 = false;
    } else {
      signedCertOid = new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V2);
      essSigCertV2 = true;
    }

    MessageDigest md = MessageDigest.getInstance(digestAlgo.getId(), BouncyCastleProvider.PROVIDER_NAME);
    md.update(certificate.getEncoded());
    byte[] certHash = md.digest();
    DEROctetString certHashOctetStr = new DEROctetString(certHash);

    signedCert.add(signedCertOid);

    ASN1EncodableVector attrValSet = new ASN1EncodableVector();
    ASN1EncodableVector signingCertObjSeq = new ASN1EncodableVector();
    ASN1EncodableVector essCertV2Seq = new ASN1EncodableVector();
    ASN1EncodableVector certSeq = new ASN1EncodableVector();
    ASN1EncodableVector algoSeq = new ASN1EncodableVector();
    algoSeq.add(digestAlgo);
    algoSeq.add(DERNull.INSTANCE);
    if (essSigCertV2) {
      certSeq.add(new DERSequence(algoSeq));
    }
    //Add cert hash
    certSeq.add(new DEROctetString(certHash));
    if (includeIssuerSerial) {
      certSeq.add(issuerSerial);
    }

    //Finalize assembly
    essCertV2Seq.add(new DERSequence(certSeq));
    signingCertObjSeq.add(new DERSequence(essCertV2Seq));
    attrValSet.add(new DERSequence(signingCertObjSeq));
    signedCert.add(new DERSet(attrValSet));

    return signedCert;
  }

  public static byte[] removeSignedAttr(byte[] signedAttrBytes, ASN1ObjectIdentifier[] attrOid)
    throws IOException, NoSuchAlgorithmException, CertificateException {
    ASN1Set inAttrSet = ASN1Set.getInstance(new ASN1InputStream(signedAttrBytes).readObject());
    ASN1EncodableVector newSigAttrSet = new ASN1EncodableVector();
    List<ASN1ObjectIdentifier> attrOidList = Arrays.asList(attrOid);

    for (int i = 0; i < inAttrSet.size(); i++) {
      Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));

      if (!attrOidList.contains(attr.getAttrType())) {
        newSigAttrSet.add(attr);
      }
    }

    //Der encode the new signed attributes set
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    DEROutputStream dout = new DEROutputStream(bout);
    dout.writeObject(new DERSet(newSigAttrSet));
    byte[] newSigAttr = bout.toByteArray();
    dout.close();
    bout.close();
    return newSigAttr;
  }


  public static SignedCertRef getSignedCertRefAttribute(byte[] signedAttrBytes) throws IOException {
    try {
      ASN1Set inAttrSet = ASN1Set.getInstance(new ASN1InputStream(signedAttrBytes).readObject());
      for (int i = 0; i < inAttrSet.size(); i++) {
        Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));

        if (attr.getAttrType().equals(new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V2))) {
          ASN1Encodable[] attributeValues = attr.getAttributeValues();
          SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(attributeValues[0]);
          ESSCertIDv2[] certsRefs= signingCertificateV2.getCerts();
          ESSCertIDv2 certsRef = certsRefs[0];
          return SignedCertRef.builder()
            .hashAlgorithm(certsRef.getHashAlgorithm().getAlgorithm())
            .signedCertHash(certsRef.getCertHash())
            .build();
        }
        if (attr.getAttrType().equals(new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V1))) {
          ASN1Encodable[] attributeValues = attr.getAttributeValues();
          SigningCertificate signingCertificate = SigningCertificate.getInstance(attributeValues[0]);
          ESSCertID[] certsRefs= signingCertificate.getCerts();
          ESSCertID certsRef = certsRefs[0];
          return SignedCertRef.builder()
            .hashAlgorithm(OIWObjectIdentifiers.idSHA1)
            .signedCertHash(certsRef.getCertHash())
            .build();
        }
      }
    } catch (Exception ex){
      throw new IOException("Error parsing PAdES signed attributes - " + ex.getMessage());
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
