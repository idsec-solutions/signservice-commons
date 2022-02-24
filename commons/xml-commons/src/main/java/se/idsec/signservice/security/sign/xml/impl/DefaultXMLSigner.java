/*
 * Copyright 2019-2022 IDsec Solutions AB
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
import java.util.Objects;
import java.util.Optional;

import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSigner;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.swedenconnect.security.algorithms.AlgorithmPredicates;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;

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
  public static final String DEFAULT_XPATH_TRANSFORM =
      "not(ancestor-or-self::*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#'])";

  /** The signing credential. */
  private final PkiCredential signingCredential;

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
   * {@link PkiCredential#getCertificateChain()}. The default is {@code false} (only the entity certificate is
   * included).
   */
  private boolean includeCertificateChain = false;

  /**
   * Should an ID attribute be written to the resulting ds:Signature element. Default is {@code false}.
   */
  private boolean includeSignatureId = false;

  /** The algorithm registry. */
  private AlgorithmRegistry algorithmRegistry;

  /** For generating ID:s. */
  private static SecureRandom random =
      new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes(Charset.forName("UTF-8")));

  /**
   * Constructor.
   *
   * @param signingCredential
   *          the signing credential to use
   */
  public DefaultXMLSigner(final PkiCredential signingCredential) {
    this.signingCredential = Objects.requireNonNull(signingCredential, "signingCredential must not be null");
  }

  /**
   * Creates a builder for {@code DefaultXMLSigner} objects.
   *
   * @param signingCredential
   *          the signing credential to use
   * @return a builder instance
   */
  public static DefaultXMLSignerBuilder builder(final PkiCredential signingCredential) {
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
      if (StringUtils.isNotEmpty(this.xPathTransform)) {
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
      else if (this.signingCredential.getCertificate() != null) {
        signature.addKeyInfo(this.signingCredential.getCertificate());
      }
      else if (this.signingCredential.getPublicKey() != null) {
        signature.addKeyInfo(this.signingCredential.getPublicKey());
      }

      // Finally, sign the document.
      //
      signature.sign(this.signingCredential.getPrivateKey());

      final DefaultXMLSignerResult result = new DefaultXMLSignerResult(signature);
      result.setSignerCertificate(this.signingCredential.getCertificate());
      if (this.includeCertificateChain) {
        result.setSignerCertificateChain(this.signingCredential.getCertificateChain());
      }
      return result;
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
  public PkiCredential getSigningCredential() {
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
    final SignatureAlgorithm algorithm = this.getAlgorithmRegistry().getAlgorithm(signatureAlgorithm, SignatureAlgorithm.class);
    if (algorithm == null) {
      final String msg = String.format("Algorithm '%s' is not supported as a signing algorithm", signatureAlgorithm);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }
    if (algorithm.getUri().equals(XMLSignature.ALGO_ID_SIGNATURE_RSA_PSS)) {
      final String msg = String.format("Incomplete algorithm '%s' - missing parameters", signatureAlgorithm);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }

    // Make sure that it isn't blacklisted.
    //
    if (algorithm.isBlacklisted()) {
      final String msg =
          String.format("Signature algorithm '%s' is black listed according to the system configuration", signatureAlgorithm);
      log.error("{}", msg);
      throw new NoSuchAlgorithmException(msg);
    }

    // Check that the supplied credential is consistent with the supplied algorithm's specified key algorithm.
    //
    if (!algorithm.getKeyType().equals(this.signingCredential.getPrivateKey().getAlgorithm())) {
      final String msg = String.format(
        "Signature algorithm '%s' can not be used together with configured signing credential", signatureAlgorithm);
      log.error("{}", msg);
      throw new SignatureException(msg);
    }

    this.signatureAlgorithm = signatureAlgorithm;
    this.digestAlgorithm = algorithm.getMessageDigestAlgorithm().getUri();
  }

  /**
   * Gets the signature algorithm to use.
   * <p>
   * If the digest algorithm is not explicitly set, the default signature algorithm given by the
   * {@link AlgorithmRegistry} will be used.
   * </p>
   *
   * @return the signature algorithm URI
   */
  public String getSignatureAlgorithm() {
    if (this.signatureAlgorithm != null) {
      return this.signatureAlgorithm;
    }

    final SignatureAlgorithm alg = this.getAlgorithmRegistry().getAlgorithm(
      AlgorithmPredicates.fromKeyType(this.signingCredential.getPrivateKey().getAlgorithm()), SignatureAlgorithm.class);
    if (alg != null) {
      this.signatureAlgorithm = alg.getUri();
      this.digestAlgorithm = alg.getMessageDigestAlgorithm().getUri();
      log.info("Using signature algorithm '{}' as the default", this.signatureAlgorithm);
      return this.signatureAlgorithm;
    }
    else {
      // Should never happen
      throw new SecurityException("No default signature algorithm found");
    }
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
    // Will set the digest algorithm as well ...
    this.getSignatureAlgorithm();
    return this.digestAlgorithm;
  }

  /**
   * Assigns the canonicalization method to use. Default is {@value #DEFAULT_CANONICALIZATION_TRANSFORM}.
   *
   * @param canonicalizationTransform
   *          canonicalization method URI
   */
  public void setCanonicalizationTransform(final String canonicalizationTransform) {
    if (StringUtils.isNotEmpty(canonicalizationTransform)) {
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
   * {@link PkiCredential#getCertificateChain()}). The default is {@code false} (only the entity certificate is
   * included).
   *
   * @param includeCertificateChain
   *          whether the certificate chain should be included
   */
  public void setIncludeCertificateChain(final boolean includeCertificateChain) {
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
   * Assigns the {@link AlgorithmRegistry} to use. If not assigned, the registry configured for
   * {@link AlgorithmRegistrySingleton} will be used.
   *
   * @param algorithmRegistry
   *          the registry to use
   */
  public void setAlgorithmRegistry(final AlgorithmRegistry algorithmRegistry) {
    this.algorithmRegistry = algorithmRegistry;
  }

  /**
   * Gets the {@link AlgorithmRegistry} to use.
   *
   * @return the AlgorithmRegistry
   */
  private AlgorithmRegistry getAlgorithmRegistry() {
    if (this.algorithmRegistry == null) {
      this.algorithmRegistry = AlgorithmRegistrySingleton.getInstance();
    }
    return this.algorithmRegistry;
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
    String signatureUriReference = Optional.ofNullable(rootElement.getAttributeNodeNS(null, "ID"))
      .map(Attr::getValue)
      .orElse(null);
    if (StringUtils.isNotEmpty(signatureUriReference)) {
      rootElement.setIdAttribute("ID", true);
    }
    else {
      signatureUriReference = Optional.ofNullable(rootElement.getAttributeNodeNS(null, "Id"))
        .map(Attr::getValue)
        .orElse(null);
      if (StringUtils.isNotEmpty(signatureUriReference)) {
        rootElement.setIdAttribute("Id", true);
      }
    }
    return StringUtils.isEmpty(signatureUriReference)
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
    public DefaultXMLSignerBuilder(final PkiCredential signingCredential) {
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
    public DefaultXMLSignerBuilder canonicalizationTransform(final String canonicalizationTransform) {
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
    public DefaultXMLSignerBuilder includeSignatureId(final boolean includeSignatureId) {
      this.signer.setIncludeSignatureId(includeSignatureId);
      return this;
    }

  }

}
