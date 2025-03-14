/*
 * Copyright 2019-2025 IDsec Solutions AB
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
import lombok.NoArgsConstructor;
import lombok.Setter;
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
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;

/**
 * Data object holding the parameters necessary to provide a signature image to a PDF document.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
public class VisibleSignatureImage {

  /** Default date format. */
  public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd HH:mm z";

  public static final TimeZone DEFAULT_TIMEZONE = TimeZone.getDefault();

  /** Constant representing "first page" (1). */
  public static final int FIRST_PAGE = 1;

  /** Contants representing "last page" (0). */
  public static final int LAST_PAGE = 0;

  /** The page number where the image should be inserted. 0 means last page. */
  @Setter
  private int page;

  /** The x-axis offset in pixels where the image should be inserted. */
  @Setter
  private int xOffset;

  /** The y-axis offset in pixels where the image should be inserted. */
  @Setter
  private int yOffset;

  /** The zoom percentagy of the image, where 0 means original size. */
  @Setter
  private int zoomPercent;

  /** A map of name value pairs that will be included in the image (if it supports it). */
  @Setter
  private Map<String, String> personalizationParams;

  /** The width of the image in pixels. */
  @Setter
  private int pixelImageWidth;

  /** The height of the image in pixels. */
  @Setter
  private int pixelImageHeight;

  /** Tells whether the sign date should be included in the image. */
  @Setter
  private boolean includeDate;

  /** Date format for signing time. The default is {@link #DEFAULT_DATE_FORMAT}. */
  private String dateFormat;

  /** The contents of the SVG image. */
  @Setter
  private String svgImage;

  /** The time zone for signing time. The default is {@link #DEFAULT_TIMEZONE}. */
  private String timeZoneId;

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
   * Assigns the date format to use.
   *
   * @param dateFormat the date format
   * @throws IllegalArgumentException for invalid input
   */
  public void setDateFormat(final String dateFormat) throws IllegalArgumentException {
    checkDateFormat(dateFormat);
    this.dateFormat = dateFormat;
  }

  private static void checkDateFormat(final String dateFormat) throws IllegalArgumentException {
    try {
      if (dateFormat != null) {
        new SimpleDateFormat(dateFormat);
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("invalid date format: " + dateFormat, e);
    }
  }

  /**
   * Assigns the time zone ID.
   *
   * @param timeZoneId the time zone ID, for example "Europe/Stockholm"
   * @throws IllegalArgumentException for invalid input
   */
  public void setTimeZoneId(final String timeZoneId) throws IllegalArgumentException {
    checkTimeZoneId(timeZoneId);
    this.timeZoneId = timeZoneId;
  }

  private static void checkTimeZoneId(final String timeZoneId) throws IllegalArgumentException {
    try {
      if (timeZoneId != null) {
        ZoneId.of(timeZoneId);
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Invalid time zone id: " + timeZoneId, e);
    }
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

  /**
   * Creates a date formatter given the settings of the bean
   *
   * @return a {@link SimpleDateFormat}
   */
  public SimpleDateFormat createDateFormatter() {
    final SimpleDateFormat createdDateFormat = Optional.ofNullable(this.dateFormat)
        .map(SimpleDateFormat::new)
        .orElseGet(() -> new SimpleDateFormat(DEFAULT_DATE_FORMAT));
    final TimeZone usedTimeZone = Optional.ofNullable(this.timeZoneId)
        .map(TimeZone::getTimeZone)
        .orElse(DEFAULT_TIMEZONE);
    createdDateFormat.setTimeZone(usedTimeZone);
    return createdDateFormat;
  }

  // Lombok builder template
  public static class VisibleSignatureImageBuilder {

    public VisibleSignatureImageBuilder dateFormat(final String dateFormat) {
      checkDateFormat(dateFormat);
      this.dateFormat = dateFormat;
      return this;
    }

    public VisibleSignatureImageBuilder timeZoneId(final String timeZoneId) {
      checkTimeZoneId(timeZoneId);
      this.timeZoneId = timeZoneId;
      return this;
    }

  }

}
