/*
 * Copyright 2019-2024 IDsec Solutions AB
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
package se.idsec.signservice.security.sign.pdf.document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.batik.transcoder.SVGAbstractTranscoder;
import org.apache.batik.transcoder.TranscoderException;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.PNGTranscoder;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * Data object holding the parameters necessary to provide a signature image to a PDF document.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
public class VisibleSignatureImage {

  /** Default date format. */
  public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd HH:mm z";

  /** Constant representing "first page" (1). */
  public static final int FIRST_PAGE = 1;

  /** Contants representing "last page" (0). */
  public static final int LAST_PAGE = 0;

  /**
   * The page number where the image should be inserted. 0 means last page.
   *
   * @param page the page number where the image should be inserted
   * @return the page number where the image should be inserted
   */
  private int page;

  /**
   * The x-axis offset in pixels where the image should be inserted.
   *
   * @param xOffset the x-axis offset in pixels where the image should be inserted
   * @return the x-axis offset in pixels where the image should be inserted
   */
  private int xOffset;

  /**
   * The y-axis offset in pixels where the image should be inserted.
   *
   * @param yOffset the y-axis offset in pixels where the image should be inserted
   * @return the y-axis offset in pixels where the image should be inserted
   */
  private int yOffset;

  /**
   * The zoom percentagy of the image, where 0 means original size.
   *
   * @param zoomPercent the zoom percentagy of the image
   * @return the zoom percentagy of the image
   */
  private int zoomPercent;

  /**
   * A map of name value pairs that will be included in the image (if it supports it).
   *
   * @param personalizationParams name-value pairs
   * @return name-value pairs
   */
  private Map<String, String> personalizationParams;

  /**
   * The width of the image in pixels.
   *
   * @param pixelImageWidth the width of the image in pixels
   * @return the width of the image in pixels
   */
  private int pixelImageWidth;

  /**
   * The height of the image in pixels.
   *
   * @param pixelImageHeight the height of the image in pixels
   * @return the height of the image in pixels
   */
  private int pixelImageHeight;

  /**
   * Tells whether the sign date should be included in the image.
   *
   * @param includeDate tells whether the sign date should be included in the image
   * @return tells whether the sign date should be included in the image
   */
  private boolean includeDate;

  /**
   * Date format for signing time. The default is {@link #DEFAULT_DATE_FORMAT}.
   *
   * @param dateFormat the date format for signing time
   * @return date format for signing time
   */
  private String dateFormat;

  /**
   * The contents of the SVG image.
   *
   * @param svgImage the contents of the SVG image
   * @return the contents of the SVG image
   */
  private String svgImage;

  /**
   * Generates PDFBox signature options that includes the visible signature.
   * <p>
   * Invokes {@link #getVisibleSignatureOptions(PDDocument, Date, int)} with {@code signatureSize} set to 0.
   * </p>
   *
   * @param doc the PDF document where the visible signature will be added
   * @param signTime the time when this signature is claimed to be created
   * @return a signature options object with visible signature
   * @throws IOException for errors creating the signature options
   */
  public SignatureOptions getVisibleSignatureOptions(final PDDocument doc, final Date signTime) throws IOException {
    return this.getVisibleSignatureOptions(doc, signTime, 0);
  }

  /**
   * Generates PDFBox signature options that includes the visible signature.
   *
   * @param doc the PDF document where the visible signature will be added
   * @param signTime the time when this signature is claimed to be created
   * @param signatureSize the preferred size of the signature data content (0 will use default size)
   * @return a signature options object with visible signature
   * @throws IOException for errors creating the signature options
   */
  public SignatureOptions getVisibleSignatureOptions(final PDDocument doc, final Date signTime, final int signatureSize)
      throws IOException {

    final SignatureOptions sigOptons = new SignatureOptions();
    sigOptons.setPreferredSignatureSize(signatureSize);

    // If page is less than 1, set to last page.
    this.page = this.page < 1 ? doc.getNumberOfPages() : this.page;

    try (final InputStream imageStream = this.createImageFromSVG(
        this.getPersonalizedSvgImage(this.svgImage, signTime))) {
      final PDVisibleSignDesigner visibleSignDesigner = new PDVisibleSignDesigner(doc, imageStream, this.page);
      visibleSignDesigner.xAxis(this.xOffset).yAxis(this.yOffset).zoom(this.zoomPercent).adjustForRotation();

      final PDVisibleSigProperties visibleSignatureProperties = new PDVisibleSigProperties();
      // visibleSignatureProperties.signerName(name).signerLocation(location).signatureReason(reason).
      visibleSignatureProperties.page(this.page).visualSignEnabled(true).setPdVisibleSignature(visibleSignDesigner)
          .buildSignature();

      // Set signature in signature options
      sigOptons.setVisualSignature(visibleSignatureProperties.getVisibleSignature());
      sigOptons.setPage(this.page - 1);
      return sigOptons;
    }
    catch (final TranscoderException e) {
      final String msg = String.format("Failed to create visible signature options - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new IOException(msg, e);
    }
  }

  private InputStream createImageFromSVG(final String svg) throws TranscoderException {
    final Reader reader = new BufferedReader(new StringReader(svg));
    final TranscoderInput svgImage = new TranscoderInput(reader);

    final ByteArrayOutputStream bos = new ByteArrayOutputStream();
    final TranscoderOutput tcOut = new TranscoderOutput(bos);

    final PNGTranscoder pngTranscoder = new PNGTranscoder();
    pngTranscoder.addTranscodingHint(SVGAbstractTranscoder.KEY_WIDTH,
        Float.valueOf(String.valueOf(this.pixelImageWidth)));
    pngTranscoder.addTranscodingHint(SVGAbstractTranscoder.KEY_HEIGHT,
        Float.valueOf(String.valueOf(this.pixelImageHeight)));
    pngTranscoder.transcode(svgImage, tcOut);
    return new ByteArrayInputStream(bos.toByteArray());
  }

  private String getPersonalizedSvgImage(final String svg, final Date signingTime) {

    String personalizedJson = svg;
    final Set<String> keySet = this.personalizationParams.keySet();
    for (final String parameterId : keySet) {
      personalizedJson = personalizedJson.replaceAll("##" + parameterId.toUpperCase() + "##",
          this.personalizationParams.get(parameterId));
    }

    if (this.includeDate) {
      personalizedJson = personalizedJson.replaceAll("##SIGNTIME##", this.createDateFormatter().format(signingTime));
    }
    return personalizedJson;
  }

  private SimpleDateFormat createDateFormatter() {
    return this.dateFormat != null ? new SimpleDateFormat(this.dateFormat) : new SimpleDateFormat(DEFAULT_DATE_FORMAT);
  }

}
