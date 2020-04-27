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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.SigningCredential;
import se.idsec.signservice.security.sign.pdf.PDFSigner;
import se.idsec.signservice.security.sign.pdf.PDFSignerParameters;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.signservice.security.sign.pdf.utils.PDFSigningProcessor;

/**
 * Default PDF Signer for signing PDF documents
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPDFSigner implements PDFSigner {

  /** The signing credential. */
  private final SigningCredential signingCredential;

  /** The signature algorithm. */
  private final String signatureAlgorithm;

  /**
   * Should the certificate chain/path be included in the signature (if available from
   * {@link SigningCredential#getCertificateChain()}). The default is {@code false} (only the entity certificate is
   * included).
   */
  private boolean includeCertificateChain = false;

  /**
   * Constructor.
   *
   * @param signingCredential
   *          the signing credential to use
   * @param signatureAlgorithm
   *          the URI identifier for the requested signature algorithm
   * @throws NoSuchAlgorithmException
   *           if the supplied signature algorithm is not supported
   */
  public DefaultPDFSigner(final SigningCredential signingCredential, final String signatureAlgorithm) throws NoSuchAlgorithmException {
    this.signingCredential = signingCredential;
    if (PDFAlgorithmRegistry.isAlgoSupported(signatureAlgorithm)) {
      this.signatureAlgorithm = signatureAlgorithm;
    }
    else {
      throw new NoSuchAlgorithmException("Signature algorithm is not supported");
    }
  }

  /**
   * Constructor.
   *
   * @param signingCredential
   *          the signing credential to use
   * @param signatureAlgorithm
   *          the object identifier for the requested signature algorithm
   * @throws NoSuchAlgorithmException
   *           if the supplied signature algorithm is not supported
   */
  public DefaultPDFSigner(final SigningCredential signingCredential, final AlgorithmIdentifier signatureAlgorithm)
      throws NoSuchAlgorithmException {
    this.signingCredential = signingCredential;
    this.signatureAlgorithm = PDFAlgorithmRegistry.getAlgorithmURI(signatureAlgorithm);
  }

  /**
   * Sets whether the certificate chain/path be included in the signature (if available from
   * {@link SigningCredential#getCertificateChain()}). The default is {@code false} (only the entity certificate is
   * included).
   *
   * @param includeCertificateChain
   *          whether the certificate chain should be included
   */
  public void setIncludeCertificateChain(final boolean includeCertificateChain) {
    this.includeCertificateChain = includeCertificateChain;
  }

  /** {@inheritDoc} */
  @Override
  public SigningCredential getSigningCredential() {
    return this.signingCredential;
  }

  /** {@inheritDoc} */
  @Override
  public PDFSignerResult sign(final byte[] document) throws SignatureException {
    return this.sign(document, new PDFSignerParameters());
  }

  /** {@inheritDoc} */
  @Override
  public PDFSignerResult sign(final byte[] document, final PDFSignerParameters parameters) throws SignatureException {

    if (parameters == null) {
      return this.sign(document);
    }

    PDDocument pdfDocument = null;
    try {
      pdfDocument = PDDocument.load(document);

      final List<X509Certificate> signingCertChain = this.includeCertificateChain
          ? this.signingCredential.getCertificateChain()
          : Arrays.asList(this.signingCredential.getSigningCertificate());

      final DefaultPDFBoxSignatureInterface signatureProvider = new DefaultPDFBoxSignatureInterface(
        this.signingCredential.getPrivateKey(),
        signingCertChain,
        this.signatureAlgorithm,
        parameters.getPadesType());

      final long signingTime = System.currentTimeMillis();

      final PDFSigningProcessor.Result signatureResult = PDFSigningProcessor.signPdfDocument(pdfDocument, signatureProvider, signingTime,
        parameters.getVisibleSignatureImage());

      final DefaultPDFSignerResult result = new DefaultPDFSignerResult();
      result.setSignedDocument(signatureResult.getDocument());
      result.setSignerCertificate(this.signingCredential.getSigningCertificate());
      if (this.includeCertificateChain) {
        result.setSignerCertificateChain(signingCertChain);
      }
      result.setSigningTime(signingTime);
      result.setSignedAttributes(signatureResult.getCmsSignedAttributes());
      result.setSignedData(signatureResult.getCmsSignedData());
      return result;
    }
    catch (IOException e) {
      final String msg = String.format("Failed to load PDF document to sign - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new SignatureException(msg, e);
    }
    finally {
      if (pdfDocument != null) {
        try {
          // Closing an already closed document is a no-op
          pdfDocument.close();
        }
        catch (IOException e) {
        }
      }
    }
  }

}
