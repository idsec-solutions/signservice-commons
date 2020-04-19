/*
 * Copyright 2019-2020 IDsec Solutions AB
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
import lombok.Data;
import lombok.NoArgsConstructor;
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
import java.util.Set;
import java.util.logging.Logger;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VisibleSigImage {
  public static final Logger LOG = Logger.getLogger(VisibleSigImage.class.getName());
  public static final SimpleDateFormat BASIC_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm");
  public static final int FIRST_PAGE = 1;
  public static final int LAST_PAGE = 0;

  private int page;
  private int xOffset;
  private int yOffset;
  private int zoomPercent;
  private Map<String, String> personalizationParams;
  private int pixelImageWidth;
  private int pixelImageHeight;
  private boolean includeDate;
  private String svgImage;

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
      InputStream imageStream = createImageFromSVG(getPersonalizedSvgImage(svgImage, signTime));
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


  private InputStream createImageFromSVG(String svg) throws TranscoderException {
    Reader reader = new BufferedReader(new StringReader(svg));
    TranscoderInput svgImage = new TranscoderInput(reader);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    TranscoderOutput tcOut = new TranscoderOutput(bos);

    PNGTranscoder pngTranscoder = new PNGTranscoder();
    pngTranscoder.addTranscodingHint(PNGTranscoder.KEY_WIDTH, Float.valueOf(String.valueOf(pixelImageWidth)));
    pngTranscoder.addTranscodingHint(PNGTranscoder.KEY_HEIGHT, Float.valueOf(String.valueOf(pixelImageHeight)));
    pngTranscoder.transcode(svgImage, tcOut);
    return new ByteArrayInputStream(bos.toByteArray());
  }

  private String getPersonalizedSvgImage(String svg, Date signingTime) {

    String personalizedJson = svg;
    Set<String> keySet = personalizationParams.keySet();
    for (String parameterId: keySet){
      personalizedJson = personalizedJson.replaceAll("##" + parameterId.toUpperCase() + "##" , personalizationParams.get(parameterId));
    }

    if (includeDate){
      personalizedJson = personalizedJson.replaceAll("##SIGNTIME##", BASIC_DATE_FORMAT.format(signingTime));
    }
    return personalizedJson;
  }


}
