package se.idsec.signservice.pdf.sign;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * Implements a Sweden Connect test image as PDF visible signature.
 */
public class ConfigurableSignImage extends VisibleSigImage {

  private int pixelImageWidth;
  private int pixelImageHeight;
  private boolean includeDate;
  private String imageTemplateLocation;

  /**
   * Creates a visible image object which has the capability to generate a personalized PDF visible signature image
   * @param page page where the signature object is to be placed where first page is represented by 1. Any value below 1 indicates the last page.
   * @param xOffset x coordinate where the signature image will be placed
   * @param yOffset y coordinate where the signature image will be placed
   * @param zoomPercent zoom percentage. From -100 to any positive integer. 0 indicates no zoom effect
   * @param pixelImageWidth width of the final pixel image
   * @param pixelImageHeight height of the final pixel image
   * @param includeDate true if the image can take date input
   * @param imageTemplateLocation true if the image can take date input
   * @param personalizationParams Personalization parameters
   */
  public ConfigurableSignImage(String imageTemplateLocation, int pixelImageWidth, int pixelImageHeight, boolean includeDate,
    int page, int xOffset, int yOffset, int zoomPercent, Map<String, String> personalizationParams) {
    super(page, xOffset, yOffset, zoomPercent, personalizationParams);
    this.imageTemplateLocation = imageTemplateLocation;
    this.pixelImageWidth = pixelImageWidth;
    this.pixelImageHeight = pixelImageHeight;
    this.includeDate = includeDate;
  }

  @Override protected String getImageLocation() {
    return imageTemplateLocation;
  }

  @Override protected int getImageWidth() {
    return pixelImageWidth;
  }

  @Override protected int getImageHeight() {
    return pixelImageHeight;
  }

  @Override protected String getPersonalizedSvgImage(String svg, Date signingTime) {

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
