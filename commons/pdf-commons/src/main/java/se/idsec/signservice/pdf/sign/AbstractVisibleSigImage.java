package se.idsec.signservice.pdf.sign;

import org.apache.batik.transcoder.TranscoderException;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.PNGTranscoder;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.logging.Logger;

public abstract class AbstractVisibleSigImage {
  public static final Logger LOG = Logger.getLogger(AbstractVisibleSigImage.class.getName());
  public static final SimpleDateFormat BASIC_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm");
  public static final int FIRST_PAGE = 1;
  public static final int LAST_PAGE = 0;

  protected int page;
  protected int xOffset;
  protected int yOffset;
  protected int zoomPercent;
  protected Map<String, String> personalizationParams;

  /**
   * Creates a visible image object which has the capability to generate a personalized PDF visible signature image
   * @param page page where the signature object is to be placed where first page is represented by 1. Any value below 1 indicates the last page.
   * @param xOffset x coordinate where the signature image will be placed
   * @param yOffset y coordinate where the signature image will be placed
   * @param zoomPercent Zoom percentage. From -100 to any positive integer. 0 indicates no zoom effect.
   */
  public AbstractVisibleSigImage(int page, int xOffset, int yOffset, int zoomPercent, Map<String, String> personalizationParams) {
    this.page = page;
    this.xOffset = xOffset;
    this.yOffset = yOffset;
    this.zoomPercent = zoomPercent;
    this.personalizationParams = personalizationParams;
  }

  /**
   * Return the personalized svg image which incorporates any representation of signer, sign time, location and reason in the image.
   * @param svg The personalized svg image
   * @param signTime Time of signing
   * @return Personalized SVG image
   */
  protected abstract String getPersonalizedSvgImage(String svg, Date signTime);

  /**
   * Retrun the width of the final PNG image used as visible signature image
   * @return Width in pixels
   */
  protected abstract int getImageWidth();
  /**
   * Retrun the height of the final PNG image used as visible signature image
   * @return Height in pixels
   */
  protected abstract int getImageHeight();

  /**
   * Provide the SVG image
   * @return SVG image data as XML string
   */
  protected abstract String getSVGImage();


  public SignatureOptions getVisibleSignatureOptions(PDDocument doc, Date signTime){
    return getVisibleSignatureOptions(doc, signTime, 0);
  }

  /**
   * Generates signature options that includes the visible signature
   * @param doc PDF document where the visible signature will be added.
   * @param signatureSize The preferred size of the signature data content (0 will use default size)
   * @return Signature options with visible signature.
   */
  public SignatureOptions getVisibleSignatureOptions(PDDocument doc, Date signTime, int signatureSize){

    SignatureOptions sigOptons = new SignatureOptions();
    sigOptons.setPreferredSignatureSize(signatureSize);

    // If page is less than 1, set to last page.
    page = page < 1 ? doc.getNumberOfPages() : page;

    try {
      String svg = getSVGImage();
      InputStream imageStream = createImageFromSVG(getPersonalizedSvgImage(svg, signTime));
      PDVisibleSignDesigner visibleSignDesigner = new PDVisibleSignDesigner(doc, imageStream, page);
      visibleSignDesigner.xAxis(xOffset).yAxis(yOffset).zoom(zoomPercent).adjustForRotation();
      imageStream.close();

      PDVisibleSigProperties visibleSignatureProperties = new PDVisibleSigProperties();
      //visibleSignatureProperties.signerName(name).signerLocation(location).signatureReason(reason).
      visibleSignatureProperties.page(page).visualSignEnabled(true).setPdVisibleSignature(visibleSignDesigner).buildSignature();

      // Set signature in signature options
      sigOptons.setVisualSignature(visibleSignatureProperties.getVisibleSignature());
      sigOptons.setPage(page - 1);
    }
    catch (Exception e) {
      LOG.warning("Failed to generate requested visible signature image");
      e.printStackTrace();
    }

    return sigOptons;
  }


  private InputStream createImageFromSVG(String svg) throws TranscoderException, FileNotFoundException {
    Reader reader = new BufferedReader(new StringReader(svg));
    TranscoderInput svgImage = new TranscoderInput(reader);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    TranscoderOutput tcOut = new TranscoderOutput(bos);

    PNGTranscoder pngTranscoder = new PNGTranscoder();
    pngTranscoder.addTranscodingHint(PNGTranscoder.KEY_WIDTH, Float.valueOf(String.valueOf(getImageWidth())));
    pngTranscoder.addTranscodingHint(PNGTranscoder.KEY_HEIGHT, Float.valueOf(String.valueOf(getImageHeight())));
    pngTranscoder.transcode(svgImage, tcOut);
    return new ByteArrayInputStream(bos.toByteArray());
  }

}
