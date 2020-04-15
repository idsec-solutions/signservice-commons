package se.idsec.signservice.pdf.sign;

import lombok.Setter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import se.idsec.signservice.pdf.utils.PdfBoxSigUtil;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.impl.DefaultPDFSignerResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
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
        document.cmsSignedData,
        signedAttributes,
        signatureValue,
        chain
      );

      PDDocument pdfDocument = validateDocument(document);

      boolean pades = false;
      String adesRequirement = document.getAdesType();
      if (adesRequirement != null) {
        pades =
          adesRequirement.equals(PDFSignTaskDocument.ADES_PROFILE_BES) || adesRequirement.equals(PDFSignTaskDocument.ADES_PROFILE_EPES);
      }

      // create signature dictionary
      PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      if (pades) {
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
      }
      else {
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      }

      // Sets signing time and document ID to the signing time value set during pr-signing
      // These values must match for the signature to match the signed document
      long signTimeAndID = document.getSignTimeAndId();
      Calendar signingTime = Calendar.getInstance();
      signingTime.setTime(new Date(signTimeAndID));
      signature.setSignDate(signingTime);
      pdfDocument.setDocumentId(signTimeAndID);

      // register signature dictionary and sign interface
      if (document.getVisibleSigImage() != null) {
        SignatureOptions visibleSignatureOptions = document.getVisibleSigImage()
          .getVisibleSignatureOptions(pdfDocument, signingTime.getTime());
        pdfDocument.addSignature(signature, replaceSignatureInterface, visibleSignatureOptions);
      }
      else {
        pdfDocument.addSignature(signature, replaceSignatureInterface);
      }

      // Execute signing operation and get resulting PDF document
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // This is where the signing process is invoked
      pdfDocument.saveIncremental(output);
      output.close();
      pdfDocument.close();

      byte[] pdfDocumentBytes = output.toByteArray();

      //Set results
      DefaultPDFSignerResult result = new DefaultPDFSignerResult();
      result.setSuccess(true);
      result.setPdfSignTaskDocument(PDFSignTaskDocument.builder()
        .pdfDocument(pdfDocumentBytes)
        .adesType(document.getAdesType())
        .signTimeAndId(signTimeAndID)
        .cmsSignedData(replaceSignatureInterface.getUpdatedCmsSignedData())
        .build());
      result.setSignerCertificate(chain.get(0));
      result.setSignerCertificateChain(chain);
      result.setSignedAttributes(PdfBoxSigUtil.getCmsSignedAttributes(replaceSignatureInterface.getUpdatedCmsSignedData()));

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
