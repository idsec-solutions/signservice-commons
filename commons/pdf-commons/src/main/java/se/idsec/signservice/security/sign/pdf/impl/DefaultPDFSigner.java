package se.idsec.signservice.security.sign.pdf.impl;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgoRegistry;
import se.idsec.signservice.security.sign.pdf.document.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.pdf.signprocess.PDFSigningProcessor;
import se.idsec.signservice.security.sign.SigningCredential;
import se.idsec.signservice.security.sign.pdf.PDFSigner;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Default PDF Signer
 */
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
   * @param signingCredential  the signing credential to use
   * @param signatureAlgorithm the URI identifier for the requested signature algorithm
   * @throws NoSuchAlgorithmException on error
   */
  public DefaultPDFSigner(final SigningCredential signingCredential, String signatureAlgorithm) throws NoSuchAlgorithmException {
    this.signingCredential = signingCredential;
    if (PDFAlgoRegistry.isAlgoSupported(signatureAlgorithm)) {
      this.signatureAlgorithm = signatureAlgorithm;
    }
    else {
      throw new NoSuchAlgorithmException("Signature algorithm is not supported");
    }
  }

  /**
   * Constructor.
   *
   * @param signingCredential  the signing credential to use
   * @param signatureAlgorithm the object identifier for the requested signature algorithm
   * @throws NoSuchAlgorithmException on error
   */
  public DefaultPDFSigner(final SigningCredential signingCredential, AlgorithmIdentifier signatureAlgorithm)
    throws NoSuchAlgorithmException {
    this.signingCredential = signingCredential;
    this.signatureAlgorithm = PDFAlgoRegistry.getAlgorithmURI(signatureAlgorithm);
  }

  /**
   * Sets whether the certificate chain/path be included in the signature (if available from
   * {@link SigningCredential#getCertificateChain()}). The default is {@code false} (only the entity certificate is
   * included).
   *
   * @param includeCertificateChain whether the certificate chain should be included
   */
  public void setIncludeCertificateChain(boolean includeCertificateChain) {
    this.includeCertificateChain = includeCertificateChain;
  }

  /** {@inheritDoc} */
  @Override public SigningCredential getSigningCredential() {
    return signingCredential;
  }

  /** {@inheritDoc} */
  @Override public PDFSignerResult sign(PDFSignTaskDocument document) throws SignatureException {
    try {
      PDDocument pdfDocument = PDDocument.load(document.getPdfDocument());
      List<X509Certificate> signingCertChain = includeCertificateChain
        ? signingCredential.getCertificateChain()
        : Arrays.asList(signingCredential.getSigningCertificate());

      DefaultSignatureInterfaceImpl defaultSigner = new DefaultSignatureInterfaceImpl(
        signingCredential.getPrivateKey(),
        signingCertChain,
        signatureAlgorithm
      );

      PDFSigningProcessor pdfSigningProcessor = PDFSigningProcessor.builder()
        .chain(signingCertChain)
        .document(document)
        .pdfDocument(pdfDocument)
        .signTimeAndID(System.currentTimeMillis())
        .signatureInterface(defaultSigner)
        .build();

      DefaultPDFSignerResult result = pdfSigningProcessor.signPdf();

      return result;
    }
    catch (IOException e) {
      DefaultPDFSignerResult result = new DefaultPDFSignerResult();
      result.setSuccess(false);
      result.setException(e);
      return result;
    }
  }
}
