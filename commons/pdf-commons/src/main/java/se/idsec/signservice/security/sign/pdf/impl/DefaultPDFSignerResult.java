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

import se.idsec.signservice.security.sign.pdf.document.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Default implementation of the signature result interface
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPDFSignerResult implements PDFSignerResult {

  private byte[] signedAttributes;
  private X509Certificate signerCertificate;
  private List<X509Certificate> signerCertificateChain;
  private PDFSignTaskDocument pdfSignTaskDocument;
  private boolean success;
  private Exception exception;

  /** {@inheritDoc} */
  @Override public byte[] getSignedAttributes() {
    return signedAttributes;
  }

  /** {@inheritDoc} */
  @Override public X509Certificate getSignerCertificate() {
    return signerCertificate;
  }

  /** {@inheritDoc} */
  @Override public List<X509Certificate> getSignerCertificateChain() {
    return signerCertificateChain;
  }

  /** {@inheritDoc} */
  @Override public boolean isSuccess() {
    return success;
  }

  /** {@inheritDoc} */
  @Override public Exception getException() {
    return exception;
  }

  /** {@inheritDoc} */
  @Override public PDFSignTaskDocument getSignedDocument() {
    return pdfSignTaskDocument;
  }

  /** {@inheritDoc} */
  @Override public long getSigningTime() {
    return this.pdfSignTaskDocument.getSignTimeAndId();
  }


  /**
   * Assigns signer certificate
   * @param signerCertificate signer certificate
   */
  public void setSignerCertificate(X509Certificate signerCertificate) {
    this.signerCertificate = signerCertificate;
  }

  /**
   * Assigned signer certificate chain
   * @param signerCertificateChain signer certificate chain
   */
  public void setSignerCertificateChain(List<X509Certificate> signerCertificateChain) {
    this.signerCertificateChain = signerCertificateChain;
  }

  /**
   * Assigns signed document data
   * @param pdfSignTaskDocument signed document data
   */
  public void setPdfSignTaskDocument(PDFSignTaskDocument pdfSignTaskDocument) {
    this.pdfSignTaskDocument = pdfSignTaskDocument;
  }

  /**
   * Assigns whether the signing process was successful
   * @param success true if signing process was successful
   */
  public void setSuccess(boolean success) {
    this.success = success;
  }

  /**
   * Assigns an exception thrown during the signing process
   * @param exception exception
   */
  public void setException(Exception exception) {
    this.exception = exception;
  }

  /**
   * Assigns the signed attributes bytes.
   * @param signedAttributes CMS signed attributes
   */
  public void setSignedAttributes(byte[] signedAttributes) {
    this.signedAttributes = signedAttributes;
  }
}
