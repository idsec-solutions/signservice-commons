package se.idsec.signservice.security.sign.pdf;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

public interface SignserviceSignatureInterface extends SignatureInterface {

  /** The updated Content Info holding SignedData */
  byte[] getUpdatedCmsSignedData();

}
