package se.idsec.signservice.security.sign.pdf.impl;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import se.idsec.signservice.pdf.general.PDFAlgoRegistry;
import se.idsec.signservice.pdf.general.PdfObjectIds;
import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;
import se.idsec.signservice.pdf.utils.PdfBoxSigUtil;
import se.idsec.signservice.security.sign.SigningCredential;
import se.idsec.signservice.security.sign.pdf.PDFSigner;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
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

/*      defaultSigner.setPades(pades);

      boolean pades = false;
      String adesRequirement = document.getAdesType();
      if (adesRequirement != null) {
        pades = adesRequirement.equals(PDFSignTaskDocument.ADES_PROFILE_BES) || adesRequirement.equals(PDFSignTaskDocument.ADES_PROFILE_EPES);
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

      long signTimeAndID = System.currentTimeMillis();
      Calendar signingTime = Calendar.getInstance();
      signingTime.setTime(new Date(signTimeAndID));
      signature.setSignDate(signingTime);
      pdfDocument.setDocumentId(signTimeAndID);

      if (document.getVisibleSigImage() != null){
        SignatureOptions visibleSignatureOptions = document.getVisibleSigImage().getVisibleSignatureOptions(pdfDocument, signingTime.getTime());
        pdfDocument.addSignature(signature, defaultSigner, visibleSignatureOptions);
      } else {
        // register signature dictionary and sign interface
        pdfDocument.addSignature(signature, defaultSigner);
      }

      // write incremental (only for signing purpose)
      ByteArrayOutputStream output = new ByteArrayOutputStream();
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
        .cmsSignedData(defaultSigner.getUpdatedCmsSignedData())
        .build());
      result.setSignerCertificate(signingCredential.getSigningCertificate());
      result.setSignerCertificateChain(signingCertChain);
      // Prepare and store the signed attributes
      byte[] cmsSignedAttributes = PdfBoxSigUtil.getCmsSignedAttributes(defaultSigner.getUpdatedCmsSignedData());
      if (pades){
        // Signing time is not allowed in PAdES signatures
        cmsSignedAttributes = PdfBoxSigUtil.removeSignedAttr(cmsSignedAttributes, new ASN1ObjectIdentifier[]{new ASN1ObjectIdentifier(PdfObjectIds.ID_SIGNING_TIME)});
      }
      result.setSignedAttributes(cmsSignedAttributes);*/


      return result;
    }
    catch (IOException e) {
      DefaultPDFSignerResult result = new DefaultPDFSignerResult();
      result.setSuccess(false);
      result.setException(e);
      return result;
    }
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
}
