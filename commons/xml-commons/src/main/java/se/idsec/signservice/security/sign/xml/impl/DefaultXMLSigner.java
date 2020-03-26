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
package se.idsec.signservice.security.sign.xml.impl;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmRegistry;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.logic.Constraint;
import se.idsec.signservice.security.sign.SigningCredential;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSigner;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;

/**
 * Default implementation of the {@link XMLSigner} interface.
 * <p>
 * If the signature algorithm is not explicitly set the OpenSAML {@link SignatureSigningConfiguration} system
 * configuration will be used to obtain a default.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultXMLSigner implements XMLSigner {

  /** The default canonicalization method - required Exclusive Canonicalization (omits comments). */
  public static final String DEFAULT_CANONICALIZATION_TRANSFORM = Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;

  /** The default XPath transform (don't include Signature elements). */
  public static final String DEFAULT_XPATH_TRANSFORM = "not(ancestor-or-self::ds:Signature)";

  /** The signing credential. */
  private final SigningCredential signingCredential;

  /**
   * An indicator that tells where in the document the resulting Signature element should be inserted. If not set, the
   * default "insert as the last child of the document root element" will be used.
   */
  private XMLSignatureLocation signatureLocation = new XMLSignatureLocation();

  /** The digest algorithm. */
  private String digestAlgorithm;

  /** The signature algorithm. */
  private String signatureAlgorithm;

  /** The URI for that canonicalization method. Default is {@value #DEFAULT_CANONICALIZATION_TRANSFORM}. */
  private String canonicalizationTransform = DEFAULT_CANONICALIZATION_TRANSFORM;

  /**
   * If set, includes the given XPath expression in an XPath transform. The default is
   * {@value #DEFAULT_XPATH_TRANSFORM}.
   */
  private String xPathTransform = DEFAULT_XPATH_TRANSFORM;

  /**
   * Should the certificate chain/path be included in the signature (if available from
   * {@link SigningCredential#getCertificateChain()}). The default is {@code false} (only the entity certificate is
   * included).
   */
  private boolean includeCertificateChain = false;

  /**
   * Should an ID attribute be written to the resulting ds:Signature element. Default is {@code false}.
   */
  private boolean includeSignatureId = false;

  /** For generating ID:s. */
  private static SecureRandom random =
      new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes(Charset.forName("UTF-8")));

  /**
   * Constructor.
   * 
   * @param signingCredential
   *          the signing credential to use
   */
  public DefaultXMLSigner(final SigningCredential signingCredential) {
    this.signingCredential = Constraint.isNotNull(signingCredential, "signingCredential must not be null");
  }

  /**
   * Creates a builder for {@code DefaultXMLSigner} objects.
   * 
   * @param signingCredential
   *          the signing credential to use
   * @return a builder instance
   */
  public static DefaultXMLSignerBuilder builder(final SigningCredential signingCredential) {
    return new DefaultXMLSignerBuilder(signingCredential);
  }

  /** {@inheritDoc} */
  @Override
  public XMLSignerResult sign(final Document document) throws SignatureException {

    try {
      // Create Signature ...
      //
      XMLSignature signature = new XMLSignature(document, "", this.getSignatureAlgorithm(), this.canonicalizationTransform);

      // Insert the Signature element into the document.
      //
      this.signatureLocation.insertSignature(signature.getElement(), document);

      // Setup transforms
      //
      Transforms transforms = new Transforms(document);
      transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
      transforms.addTransform(this.canonicalizationTransform);
      if (StringUtils.hasText(this.xPathTransform)) {
        XPathContainer xpath = new XPathContainer(document);
        xpath.setXPathNamespaceContext(XMLSignature.getDefaultPrefix(Constants.SignatureSpecNS), Constants.SignatureSpecNS);
        xpath.setXPath(this.xPathTransform);
        transforms.addTransform(Transforms.TRANSFORM_XPATH, xpath.getElementPlusReturns());
      }

      // Get the ID reference.
      //
      final String signatureUriReference = registerIdAttributes(document); 

      // Add the document to sign to the signature
      //
      signature.addDocument(signatureUriReference, transforms, this.getDigestAlgorithm());

      // Add signature ID.
      //
      if (this.includeSignatureId) {
        signature.setId("id-" + (new BigInteger(128, random)).toString(16));
      }

      // Set KeyInfo
      //
      if (this.includeCertificateChain
          && this.signingCredential.getCertificateChain().size() > 1) {

        X509Data x509data = new X509Data(document);
        for (X509Certificate c : this.signingCredential.getCertificateChain()) {
          x509data.addCertificate(c);
        }
        signature.getKeyInfo().add(x509data);
      }
      else if (this.signingCredential.getSigningCertificate() != null) {
        signature.addKeyInfo(this.signingCredential.getSigningCertificate());
      }
      else if (this.signingCredential.getPublicKey() != null) {
        signature.addKeyInfo(this.signingCredential.getPublicKey());
      }

      // Finally, sign the document.
      //
      signature.sign(this.signingCredential.getPrivateKey());

      return new DefaultXMLSignerResult(signature);
    }
    catch (XMLSecurityException e) {
      final String msg = String.format("Error while creating Signature - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new SignatureException(msg, e);
    }
    catch (XPathExpressionException e) {
      final String msg = String.format("Failed to find location where to insert Signature - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new SignatureException(msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public SigningCredential getSigningCredential() {
    return this.signingCredential;
  }

  /**
   * Sets the indicator that tells where in the document the resulting Signature element should be inserted. If not set,
   * the default "insert as the last child of the document root element" will be used.
   * 
   * @param signatureLocation
   *          location indicator
   */
  public void setSignatureLocation(final XMLSignatureLocation signatureLocation) {
    if (signatureLocation != null) {
      this.signatureLocation = signatureLocation;
    }
  }

  /**
   * Assigns the URI for the signature algorithm to be used.
   * 
   * @param signatureAlgorithm
   *          the signature algorithm URI
   * @throws NoSuchAlgorithmException
   *           if the algorithm is not supported (or blacklisted)
   * @throws SignatureException
   *           if the signature algorithm can not be used by the current signature credential
   */
  public void setSignatureAlgorithm(final String signatureAlgorithm) throws NoSuchAlgorithmException, SignatureException {

    // Assert that the signature algorithm is supported.
    //
    AlgorithmDescriptor descriptor = AlgorithmSupport.getGlobalAlgorithmRegistry().get(signatureAlgorithm);
    if (descriptor == null) {
      final String msg = String.format("Algorithm '%s' is not supported as a signing algorithm", signatureAlgorithm);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }
    if (AlgorithmDescriptor.AlgorithmType.Signature != descriptor.getType()) {
      final String msg = String.format("Algorithm '%s' is not a valid signature algorithm", signatureAlgorithm);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }

    // Make sure that it isn't blacklisted (we use OpenSAML's system configuration).
    //
    final SignatureSigningConfiguration signingConfig = ConfigurationService.get(SignatureSigningConfiguration.class);
    if (!AlgorithmSupport.validateAlgorithmURI(signatureAlgorithm, signingConfig.getWhitelistedAlgorithms(),
      signingConfig.getBlacklistedAlgorithms())) {
      final String msg =
          String.format("Signature algorithm '%s' is black listed according to the system configuration", signatureAlgorithm);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }

    // Check that the supplied credential is consistent with the supplied algorithm's specified key algorithm and key
    // length,
    // where applicable.
    //
    if (!AlgorithmSupport.checkKeyAlgorithmAndLength(this.signingCredential.getPrivateKey(), descriptor)) {
      final String msg = String.format(
        "Signature algorithm '%s' can not be used together with configured signing credential", signatureAlgorithm);
      log.error("{}", msg);
      throw new SignatureException(msg);
    }

    this.signatureAlgorithm = signatureAlgorithm;
    this.digestAlgorithm = this.getDigestAlgorithmFromSignatureAlgorithm(signatureAlgorithm);
  }

  /**
   * Gets the signature algorithm to use.
   * <p>
   * If the digest algorithm is not explicitly set the OpenSAML {@link SignatureSigningConfiguration} system
   * configuration will be used to obtain a default.
   * </p>
   * 
   * @return the signature algorithm URI
   */
  public String getSignatureAlgorithm() {
    if (this.signatureAlgorithm != null) {
      return this.signatureAlgorithm;
    }

    final SignatureSigningConfiguration signingConfig = ConfigurationService.get(SignatureSigningConfiguration.class);
    for (String algo : signingConfig.getSignatureAlgorithms()) {
      if (AlgorithmSupport.checkKeyAlgorithmAndLength(this.signingCredential.getPrivateKey(),
        AlgorithmSupport.getGlobalAlgorithmRegistry().get(algo))) {

        this.signatureAlgorithm = algo;
        log.info("Using digest algorithm '{}' as the default", this.signatureAlgorithm);
        return this.signatureAlgorithm;
      }
    }
    // Should never happen
    throw new SecurityException("No default signature algorithm found");
  }

  /**
   * Gets the digest algorithm to use.
   * 
   * @return the digest algorithm URI
   */
  public String getDigestAlgorithm() {
    if (this.digestAlgorithm != null) {
      return this.digestAlgorithm;
    }
    this.digestAlgorithm = this.getDigestAlgorithmFromSignatureAlgorithm(this.getSignatureAlgorithm());
    return this.digestAlgorithm;
  }

  /**
   * Given a signature algorithm URI, the method sets the digest algorithm corresponding to this
   * 
   * @param signatureAlgorithm
   *          the signature algorithm URI
   * @return the digest algorithm
   */
  private String getDigestAlgorithmFromSignatureAlgorithm(final String signatureAlgorithm) {
    final AlgorithmRegistry registry = AlgorithmSupport.getGlobalAlgorithmRegistry();
    final AlgorithmDescriptor signDescriptor = registry.get(signatureAlgorithm);
    return registry.getDigestAlgorithm(((SignatureAlgorithm) signDescriptor).getDigest()).getURI();
  }

  /**
   * Assigns the canonicalization method to use. Default is {@value #DEFAULT_CANONICALIZATION_TRANSFORM}.
   * 
   * @param canonicalizationTransform
   *          canonicalization method URI
   */
  public void setCanonicalizationTransform(final String canonicalizationTransform) {
    if (StringUtils.hasText(canonicalizationTransform)) {
      this.canonicalizationTransform = canonicalizationTransform;
    }
  }

  /**
   * Sets the XPath expression to be used in an XPath transform. The default is {@value #DEFAULT_XPATH_TRANSFORM}. If
   * {@code null}, no XPath transform is used.
   * 
   * @param xPathTransform
   *          XPath expression
   */
  public void setXPathTransform(final String xPathTransform) {
    this.xPathTransform = xPathTransform;
  }

  /**
   * Sets whether the certificate chain/path be included in the signature (if available from
   * {@link SigningCredential#getCertificateChain()}). The default is {@code false} (only the entity certificate is
   * included).
   * 
   * @param includeCertificateChain
   *          whether the certificate chain should be included
   */
  public void setIncludeCertificateChain(boolean includeCertificateChain) {
    this.includeCertificateChain = includeCertificateChain;
  }

  /**
   * Should an ID attribute be written to the resulting ds:Signature element. Default is {@code true}.
   * 
   * @param includeSignatureId
   *          whether an ID attribute should be written to the Signature element
   */
  public void setIncludeSignatureId(final boolean includeSignatureId) {
    this.includeSignatureId = includeSignatureId;
  }
  
  /**
   * Looks for an ID reference in the root element, and if found, registers it using the
   * {@link Element#setIdAttribute(String, boolean)} method.
   * 
   * @param document
   *          the document
   * @return the signature URI reference ("" if no ID is found)
   */
  public static String registerIdAttributes(final Document document) {
    final Element rootElement = document.getDocumentElement();
    String signatureUriReference = XMLUtils.getAttributeValue(rootElement, "ID");
    if (StringUtils.hasText(signatureUriReference)) {
      rootElement.setIdAttribute("ID", true);
    }
    else {
      signatureUriReference = XMLUtils.getAttributeValue(rootElement, "Id");
      if (StringUtils.hasText(signatureUriReference)) {
        rootElement.setIdAttribute("Id", true);
      }
    }
    return !StringUtils.hasText(signatureUriReference)
        ? ""
        : (signatureUriReference.trim().startsWith("#") ? signatureUriReference.trim() : "#" + signatureUriReference.trim());
  }
  

  /**
   * Builder for {@link DefaultXMLSigner} objects.
   */
  public static class DefaultXMLSignerBuilder {

    /** The object being built. */
    private DefaultXMLSigner signer;

    /**
     * Constructor.
     * 
     * @param signingCredential
     *          the signing credential to use
     */
    public DefaultXMLSignerBuilder(final SigningCredential signingCredential) {
      this.signer = new DefaultXMLSigner(signingCredential);
    }

    /**
     * Builds the signer object.
     * 
     * @return the DefaultXMLSigner object
     */
    public DefaultXMLSigner build() {
      return this.signer;
    }

    /**
     * See {@link DefaultXMLSigner#setSignatureLocation(XMLSignatureLocation)}.
     * 
     * @param signatureLocation
     *          location indicator
     * @return the builder
     */
    public DefaultXMLSignerBuilder signatureLocation(final XMLSignatureLocation signatureLocation) {
      this.signer.setSignatureLocation(signatureLocation);
      return this;
    }

    /**
     * See {@link DefaultXMLSigner#setSignatureAlgorithm(String)}.
     * 
     * @param signatureAlgorithm
     *          the signature algorithm URI
     * @return the builder
     * @throws NoSuchAlgorithmException
     *           if the algorithm is not supported (or blacklisted)
     * @throws SignatureException
     *           if the signature algorithm can not be used by the current signature credential
     */
    public DefaultXMLSignerBuilder signatureAlgorithm(final String signatureAlgorithm)
        throws NoSuchAlgorithmException, SignatureException {
      this.signer.setSignatureAlgorithm(signatureAlgorithm);
      return this;
    }

    /**
     * See {@link DefaultXMLSigner#setCanonicalizationTransform(String)}.
     * 
     * @param canonicalizationTransform
     *          canonicalization method URI
     * @return the builder
     */
    public DefaultXMLSignerBuilder setCanonicalizationTransform(final String canonicalizationTransform) {
      this.signer.setCanonicalizationTransform(canonicalizationTransform);
      return this;
    }

    /**
     * See {@link DefaultXMLSigner#setXPathTransform(String)}.
     * 
     * @param xPathTransform
     *          XPath expression
     * @return the builder
     */
    public DefaultXMLSignerBuilder xPathTransform(final String xPathTransform) {
      this.signer.setXPathTransform(xPathTransform);
      return this;
    }

    /**
     * See {@link DefaultXMLSigner#setIncludeCertificateChain(boolean)}.
     * 
     * @param includeCertificateChain
     *          whether the certificate chain should be included
     * @return the builder
     */
    public DefaultXMLSignerBuilder includeCertificateChain(final boolean includeCertificateChain) {
      this.signer.setIncludeCertificateChain(includeCertificateChain);
      return this;
    }

    /**
     * See {@link DefaultXMLSigner#setIncludeSignatureId(boolean)}.
     * 
     * @param includeSignatureId
     *          whether an ID attribute should be written to the Signature element
     * @return the builder
     */
    public DefaultXMLSignerBuilder setIncludeSignatureId(final boolean includeSignatureId) {
      this.signer.setIncludeSignatureId(includeSignatureId);
      return this;
    }

  }

}
