package se.idsec.signservice.security.sign.pdf.document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Dataclass holding a PDF document that is to be signed or has been signed
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PDFSignTaskDocument {

  public static final String ADES_PROFILE_BES = "BES";
  public static final String ADES_PROFILE_EPES = "EPES";
  public static final String ADES_PROFILE_NONE = "None";

  /** The bytes of the PDF document */
  private byte[] pdfDocument;

  /** The bytes of CMS Content Info holding the SignedData */
  private byte[] cmsSignedData;

  /** Time and signature ID in milliseconds. */
  private Long signTimeAndId;

  /** ETSI AdES signature type (BES, EPES or None) */
  private String adesType;

  /** A Visible sign image to be included in the signature context. This object is not resent in result data */
  private VisibleSigImage visibleSigImage;
}