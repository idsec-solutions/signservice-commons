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
package se.idsec.signservice.security.sign.pdf.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import se.idsec.signservice.security.sign.AdesProfileType;
import se.idsec.signservice.security.sign.pdf.PDFBoxSignatureInterface;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.signservice.security.sign.pdf.configuration.PDFObjectIdentifiers;
import se.idsec.signservice.security.sign.pdf.utils.CMSProcessableInputStream;
import se.idsec.signservice.security.sign.pdf.utils.PDFBoxSignatureUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Implementation of the PDF box signing interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPDFBoxSignatureInterface implements PDFBoxSignatureInterface {

  /** Private key used to perform the signature. */
  private final PrivateKey privateKey;

  /** The certificates of the signer. */
  private final List<X509Certificate> certificates;

  /** The signature algorithm to used, specified as a URI identifier. */
  private final String algorithm;

  /** Set to true if processing is done according to the PAdES profile. */
  private final boolean pades;

  /** Set to true if PAdES issuer serial information should be included in the PAdES data. */
  @Setter
  private boolean includePadesIssuerSerial = false;

  /** CMS Signed data result. */
  private byte[] cmsSignedData;

  /** The CMS Signed attributes result. */
  private byte[] cmsSignedAttributes;

  /**
   * Constructor.
   *
   * @param privateKey private signing key
   * @param certificates signing certificate chain
   * @param algorithm signing algorithm
   * @param pades PAdES type (may be null)
   */
  public DefaultPDFBoxSignatureInterface(final PrivateKey privateKey, final List<X509Certificate> certificates,
      final String algorithm, final AdesProfileType pades) {
    this.privateKey = privateKey;
    this.certificates = certificates;
    this.algorithm = algorithm;
    this.pades = pades != null && AdesProfileType.None != pades;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getCmsSignedData() {
    return this.cmsSignedData;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getCmsSignedAttributes() {
    return this.cmsSignedAttributes;
  }

  /**
   * SignatureInterface implementation.
   * <p>
   * This method will be called from inside of the pdfbox and creates the PKCS #7 signature (CMS ContentInfo). The given
   * InputStream contains the bytes that are given by the byte range.
   * </p>
   *
   * @param content the message bytes being signed (specified by ByteRange in the signature dictionary)
   * @return CMS ContentInfo bytes holding the complete PKCS#7 signature structure
   * @throws IOException error during signature creation
   */
  @Override
  public byte[] sign(final InputStream content) throws IOException {
    try {
      final Store<?> certs = new JcaCertStore(this.certificates);
      final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      final org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(
          ASN1Primitive.fromByteArray(this.certificates.get(0).getEncoded()));
      final ContentSigner signer =
          new JcaContentSignerBuilder(PDFAlgorithmRegistry.getSigAlgoName(this.algorithm)).build(this.privateKey);
      final JcaSignerInfoGeneratorBuilder builder =
          new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
      if (this.pades) {
        // Add signed signer certificate signed attribute
        builder.setSignedAttributeGenerator(PDFBoxSignatureUtils.getPadesSignerInfoGenerator(
            this.certificates.get(0),
            PDFAlgorithmRegistry.getAlgorithmProperties(this.algorithm).getMessageDigestAlgorithm()
                .getAlgorithmIdentifier().getAlgorithm(),
            this.includePadesIssuerSerial));
      }
      gen.addSignerInfoGenerator(builder.build(signer, new X509CertificateHolder(cert)));
      gen.addCertificates(certs);
      final CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
      final CMSSignedData resultSignedData = gen.generate(msg, false);

      // Get signed attributes according to PAdES profile requirements
      this.cmsSignedAttributes = PDFBoxSignatureUtils.getCmsSignedAttributes(resultSignedData);
      if (this.pades) {
        // Signing time is not allowed in PAdES signatures. Remove it
        this.cmsSignedAttributes = PDFBoxSignatureUtils.removeSignedAttr(this.cmsSignedAttributes,
            new ASN1ObjectIdentifier[] { new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_SIGNING_TIME) });
      }
      this.cmsSignedData = resultSignedData.toASN1Structure().getEncoded(ASN1Encoding.DL);
      return this.cmsSignedData;
    }
    catch (final GeneralSecurityException | CMSException | OperatorCreationException e) {
      final String msg = String.format("Failed to sign PDF content - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new IOException(msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isPades() {
    return this.pades;
  }

}
