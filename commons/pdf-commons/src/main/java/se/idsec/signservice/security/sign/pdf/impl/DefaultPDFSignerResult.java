package se.idsec.signservice.security.sign.pdf.impl;

import org.bouncycastle.cms.CMSSignedData;
import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;

import java.security.cert.X509Certificate;
import java.util.List;

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
    return false;
  }

  /** {@inheritDoc} */
  @Override public Exception getException() {
    return null;
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
   * @param signerCertificateChain
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
   * @param signedAttributes
   */
  public void setSignedAttributes(byte[] signedAttributes) {
    this.signedAttributes = signedAttributes;
  }
}
