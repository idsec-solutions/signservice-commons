/*
 * Copyright 2015 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.pdf.sign;

import lombok.Getter;
import lombok.Setter;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
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
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.Store;
import se.idsec.signservice.pdf.general.CMSProcessableInputStream;
import se.idsec.signservice.pdf.general.PDFAlgoRegistry;
import se.idsec.signservice.pdf.utils.PdfBoxSigUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class DefaultSignatureInterfaceImpl implements SignatureInterface {

  private final PrivateKey privateKey;

  private final List<X509Certificate> certificates;

  private final String algorithm;

  @Setter
  private boolean pades = false;

  @Setter
  private boolean padesIssuerSerial = false;

  @Getter
  private CMSSignedData resultSignedData;

  /**
   * Constructor
   * @param privateKey private signing key
   * @param certificates signing certificate chain
   * @param algorithm signing algorithm
   */
  public DefaultSignatureInterfaceImpl(PrivateKey privateKey, List<X509Certificate> certificates, String algorithm) {
    this.privateKey = privateKey;
    this.certificates = certificates;
    this.algorithm = algorithm;
  }

  /**
   * Does nothing. Override this if needed.
   *
   * @param signedData Generated CMS signed data
   * @return CMSSignedData Extended CMS signed data
   */
  protected CMSSignedData signTimeStamps(CMSSignedData signedData) throws IOException, TSPException {
    return signedData;
  }

  /**
   * SignatureInterface implementation.
   * <p>
   * This method will be called from inside of the pdfbox and create the PKCS
   * #7 signature. The given InputStream contains the bytes that are given by
   * the byte range.
   * <p>
   * This method is for internal use only. <-- TODO this method should be
   * private
   * <p>
   * Use your favorite cryptographic library to implement PKCS #7 signature
   * creation.
   */
  @Override
  public byte[] sign(InputStream content) throws IOException {
    try {
      Store certs = new JcaCertStore(certificates);
      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(
        ASN1Primitive.fromByteArray(certificates.get(0).getEncoded()));
      ContentSigner signer = new JcaContentSignerBuilder(PDFAlgoRegistry.getSigAlgoName(algorithm)).build(privateKey);
      JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
      if (pades) {
        // Add signed signer certificate signed attribute
        builder.setSignedAttributeGenerator(
          PdfBoxSigUtil.getPadesSignerInfoGenerator(certificates.get(0),
            PDFAlgoRegistry.getAlgorithmProperties(algorithm).getDigestAlgoOID(), padesIssuerSerial));
      }
      gen.addSignerInfoGenerator(builder.build(signer, new X509CertificateHolder(cert)));
      gen.addCertificates(certs);
      CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
      resultSignedData = gen.generate(msg, false);

      return resultSignedData.getEncoded();
    }
    catch (GeneralSecurityException | CMSException | OperatorCreationException e) {
      throw new IOException(e);
    }
  }

}
