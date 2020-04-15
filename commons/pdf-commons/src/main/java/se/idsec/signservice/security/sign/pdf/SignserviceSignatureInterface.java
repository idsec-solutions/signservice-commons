package se.idsec.signservice.security.sign.pdf;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

/**
 * The interface for the signature generation interface. This interface extends the PDFBox SignatureInterface.
 * The purpose of this interface is to provide the functions to provide the CMS signature data for a PDF signature.
 */
public interface SignserviceSignatureInterface extends SignatureInterface {

  /**
   * Gets the result of the signing process in the form of ContentInfo holding SignedData
   * @return CMS ContentInfo holding SignedData
   */
  byte[] getCmsSignedData();

  /**
   * Gets the signed attributes from the result of the signing process
   * @return CMS SignedAttributes
   */
  byte[] getCmsSignedAttributes();

  /**
   * Sets wether the signature should be generated according to the PAdES requirement profile
   * @param pades
   */
  void setPades(boolean pades);

}
