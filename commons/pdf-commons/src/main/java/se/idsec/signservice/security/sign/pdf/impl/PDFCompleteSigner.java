package se.idsec.signservice.security.sign.pdf.impl;

import lombok.Setter;
import org.apache.pdfbox.pdmodel.PDDocument;
import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

public class PDFCompleteSigner {

  /**
   * Default max time offset from current time used to generate the PDF signature.
   * This value is generated at presign and is reused at completesign
   * The value at completesign must not deviate from current time with more milliseconds than set by this parameter.
   * <p>
   * Default value set to 10 minutes
   * </p>
   */
  @Setter
  private int signTimeAllowedOffsetMillisec = 1000 * 60 * 60 * 10;

  /**
   * Completes a signature process where the actual signed attributes, signature value and signing certificates has been provided by
   * an external signing service.
   *
   * @param document         The document to be signed that was also processed by the singing service. This MUST included the signing ID used by
   *                         the singing service
   * @param signedAttributes The signed attributes bytes signed by the signing service
   * @param signatureValue   The signature value bytes provided by the signing service
   * @param chain            The signer certificate chain where the signer certificate is the first certificate in the chain
   * @return Signature result
   */
  public PDFSignerResult completeSign(final PDFSignTaskDocument document, byte[] signedAttributes, byte[] signatureValue,
    List<X509Certificate> chain) {

    try {
      ReplaceSignatureInterfaceImpl replaceSignatureInterface = new ReplaceSignatureInterfaceImpl(
        document.getCmsSignedData(),
        signedAttributes,
        signatureValue,
        chain
      );

      PDDocument pdfDocument = validateDocument(document);

      PDFSigningProcessor pdfSigningProcessor = PDFSigningProcessor.builder()
        .chain(chain)
        .document(document)
        .pdfDocument(pdfDocument)
        .signTimeAndID(document.getSignTimeAndId())
        .signatureInterface(replaceSignatureInterface)
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

  private PDDocument validateDocument(PDFSignTaskDocument document) throws IOException, IllegalArgumentException {
    try {
      long signTimeAndID = document.getSignTimeAndId();
      if (System.currentTimeMillis() - signTimeAndID > signTimeAllowedOffsetMillisec) {
        throw new IllegalArgumentException("The basic sign request is too old");
      }
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Missing signing time and ID extension in the to be signed document");
    }
    return PDDocument.load(document.getPdfDocument());
  }

}
