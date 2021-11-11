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

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult.Status;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSignatureValidator;

/**
 * Default implementation of the {@link XMLSignatureValidator} interface.
 * <p>
 * Note that this implementation only supports validation of signatures that covers the supplied document.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultXMLSignatureValidator implements XMLSignatureValidator {

  /** XAdES namespace URI. */
  private static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

  /** A (possibly empty) list of required signer certificates. */
  private final List<X509Certificate> requiredSignerCertificates;

  /** Optional certificate validator. */
  private final CertificateValidator certificateValidator;

  /** Flag that tells if the validator should handle XAdES signatures. */
  protected boolean xadesProcessing = true;

  /**
   * Constructor setting up the validator so that no required certificates are configured and no certificate path
   * validation is performed. This means that no control of the signer certificate will be performed.
   */
  public DefaultXMLSignatureValidator() {
    this.requiredSignerCertificates = Collections.emptyList();
    this.certificateValidator = null;
  }

  /**
   * Constructor setting up the validator to require that the signature is signed using the supplied certificate.
   * 
   * @param acceptedSignerCertificate
   *          required signer certificate
   */
  public DefaultXMLSignatureValidator(final X509Certificate acceptedSignerCertificate) {
    this(Collections.singletonList(acceptedSignerCertificate));
  }

  /**
   * Constructor setting up the validator to require that the signature is signed using any of the supplied
   * certificates.
   * 
   * @param acceptedSignerCertificates
   *          required signer certificates
   */
  public DefaultXMLSignatureValidator(final List<X509Certificate> acceptedSignerCertificates) {
    this.requiredSignerCertificates = acceptedSignerCertificates;
    this.certificateValidator = null;
  }

  /**
   * Constructor setting up the validator to perform a certificate validation of the signer certificate using the
   * supplied certificate validator instance.
   * 
   * @param certificateValidator
   *          certificate validator instance
   */
  public DefaultXMLSignatureValidator(final CertificateValidator certificateValidator) {
    this.requiredSignerCertificates = Collections.emptyList();
    this.certificateValidator = certificateValidator;
  }

  /** {@inheritDoc} */
  @Override
  public List<SignatureValidationResult> validate(final Document document) throws SignatureException {

    // First locate all signature elements ...
    //
    NodeList signatureElements = document.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
    if (signatureElements.getLength() == 0) {
      throw new SignatureException("Supplied document is not signed");
    }
    List<Element> signatures = new ArrayList<>();
    for (int i = 0; i < signatureElements.getLength(); i++) {
      signatures.add((Element) signatureElements.item(i));
    }
    return this.validate(document, signatures);
  }

  /** {@inheritDoc} */
  @Override
  public List<SignatureValidationResult> validate(final Document document, final XMLSignatureLocation signatureLocation)
      throws SignatureException {
    if (signatureLocation == null) {
      return this.validate(document);
    }
    try {
      final Element signature = signatureLocation.getSignature(document);
      if (signature == null) {
        throw new SignatureException("Could not find Signature element");
      }
      return this.validate(document, Collections.singletonList(signature));
    }
    catch (XPathExpressionException e) {
      throw new SignatureException(e.getMessage(), e);
    }
  }

  /**
   * Validates the supplied signatures.
   * 
   * @param document
   *          the document containing the signatures
   * @param signatures
   *          the signatures
   * @return a list of result objects
   */
  protected List<SignatureValidationResult> validate(final Document document, final List<Element> signatures) {

    // Get the document ID attribute (and register the ID attributes).
    //
    final String signatureUriReference = DefaultXMLSigner.registerIdAttributes(document);

    // Register ID nodes for XAdES ...
    //
    if (this.xadesProcessing) {
      this.registerXadesIdNodes(document);
    }

    // Verify all signatures ...
    //
    List<SignatureValidationResult> results = new ArrayList<>();
    for (Element signature : signatures) {
      DefaultXMLSignatureValidationResult result = this.validateSignature(signature, signatureUriReference);

      // If we have a cert path validator installed, perform path validation...
      //
      if (result.isSuccess() && this.certificateValidator != null) {
        try {
          CertificateValidationResult validatorResult = this.certificateValidator.validate(
            result.getSignerCertificate(), result.getAdditionalCertificates(), null);
          result.setCertificateValidationResult(validatorResult);
        }
        catch (CertPathBuilderException e) {
          final String msg = String.format("Failed to build a path to a trusted root for signer certificate - %s", e.getMessage());
          log.error("{}", e.getMessage(), e);
          result.setError(Status.ERROR_NOT_TRUSTED, msg, e);
        }
        catch (GeneralSecurityException e) {
          final String msg = String.format("Certificate path validation failure for signer certificate - %s", e.getMessage());
          log.error("{}", e.getMessage(), e);
          result.setError(Status.ERROR_SIGNER_INVALID, msg, e);
        }
      }
      results.add(result);
    }

    return results;
  }

  /**
   * Validates the signature value and checks that the signer certificate is accepted.
   * 
   * @param signature
   *          the signature element
   * @param signatureUriReference
   *          the signature URI reference
   * @return a validation result
   */
  protected DefaultXMLSignatureValidationResult validateSignature(final Element signature, final String signatureUriReference) {

    DefaultXMLSignatureValidationResult result = new DefaultXMLSignatureValidationResult();
    result.setSignatureElement(signature);
        
    try {
      // Parse the signature element.
      XMLSignature xmlSignature = new XMLSignature(signature, "");

      // Set the signature algorithm
      result.setSignatureAlgorithm(xmlSignature.getSignedInfo().getSignatureMethodURI());

      // Make sure the signature covers the entire document.
      //
      final List<String> uris = this.getSignedInfoReferenceURIs(xmlSignature.getSignedInfo().getElement());
      if (!uris.contains(signatureUriReference) && !uris.contains("") ) {
        final String msg = String.format("The Signature contained the reference(s) %s - none of these covers the entire document", uris);
        log.error(msg);
        result.setError(Status.ERROR_BAD_FORMAT, msg);
        return result;
      }

      // Locate the certificate that was used to sign ...
      //
      PublicKey validationKey = null;

      if (xmlSignature.getKeyInfo() != null) {
        final X509Certificate validationCertificate = xmlSignature.getKeyInfo().getX509Certificate();
        if (validationCertificate != null) {
          result.setSignerCertificate(validationCertificate);

          // Get hold of any other certs (intermediate and roots)
          result.setAdditionalCertificates(this.getAdditionalCertificates(xmlSignature.getKeyInfo(), validationCertificate));

          validationKey = validationCertificate.getPublicKey();
        }
        else {
          log.info("No certificate found in signature's KeyInfo ...");
          validationKey = xmlSignature.getKeyInfo().getPublicKey();
        }
      }
      else {
        log.warn("No KeyInfo element found in Signature ...");
      }

      // Check signature ...
      //
      if (validationKey == null) {
        // If we did not find a validation key (or cert) in the key info, we can try using any of the
        // supplied required signer certificates. But if no certs have been supplied we have to fail.
        //
        final String msg = "No certificate or public key found in signature's KeyInfo";
        if (this.requiredSignerCertificates.isEmpty()) {
          log.info("{} - and no required signer certificates available", msg);
          result.setError(Status.ERROR_BAD_FORMAT, msg);
          return result;
        }
        // Otherwise, lets try to check the signature using the required signer certificates ...
        //
        log.debug("{} - using required signer certificates to check signature ...", msg);
        for (X509Certificate rc : this.requiredSignerCertificates) {
          try {
            if (xmlSignature.checkSignatureValue(rc)) {
              log.debug("Certificate [{}] verified signature successfully", CertificateUtils.toLogString(rc));
              result.setSignerCertificate(rc);
              result.setStatus(Status.SUCCESS);
              return result;
            }
          }
          catch (XMLSignatureException e) {
            log.error("Certificate [{}] could not be used to validate signature value", CertificateUtils.toLogString(rc), e);
          }
          log.debug("Certificate [{}] could not be used to validate signature value", CertificateUtils.toLogString(rc));
        }
        log.info("{} - And none of supplied required signer certificates verified signature", msg);
        result.setError(Status.ERROR_BAD_FORMAT,
          msg + " - And none of supplied required signer certificates verified signature");
        return result;
      }
      else {
        // The KeyInfo contained cert/key. First verify signature bytes...
        //
        try {
          if (!xmlSignature.checkSignatureValue(validationKey)) {
            final String msg = "Signature is invalid - signature value did not validate correctly or reference digest comparison failed";
            log.info("{}", msg);
            result.setError(Status.ERROR_INVALID_SIGNATURE, msg);
            return result;
          }
        }
        catch (XMLSignatureException e) {
          final String msg = "Signature is invalid - " + e.getMessage();
          log.info("{}", msg, e);
          result.setError(Status.ERROR_INVALID_SIGNATURE, msg, e);
          return result;
        }
        log.debug("Signature value was successfully validated");

        // Next, make sure that the signer is one of the required ...
        //
        if (result.getSignerCertificate() == null) {
          // If the KeyInfo did not contain a signer certificate, but only a key, we check if
          // we can find a certificate among our required signer certificates that has a matching
          // key ...
          //
          if (this.requiredSignerCertificates.isEmpty()) {
            // We won't be able to find the signer certificate. If we have a certificate validator
            // installed, we may fail right now since it requires a subject certificate as input.
            // Otherwise, this validator is set up to not perform certificate checking ...
            //
            if (this.certificateValidator != null) {
              result.setError(Status.ERROR_SIGNER_INVALID, "Could not find a signer certificate");
              return result;
            }
            log.info("No certificate checking performed - signature is regarded as valid");
            result.setStatus(Status.SUCCESS);
          }
          for (X509Certificate rc : this.requiredSignerCertificates) {
            if (rc.getPublicKey().equals(validationKey)) {
              log.debug("Required certificate [{}] matched key found in KeyInfo", CertificateUtils.toLogString(rc));
              result.setStatus(Status.SUCCESS);
              result.setSignerCertificate(rc);
              return result;
            }
          }
          // If we get here none of the supplied required signer certificates had a public key
          // that matched the public key that verified the signature. We must fail ...
          //
          final String msg = "None of the supplied required certificates matched signing key";
          log.info("Signature validation failed - {}", msg);
          result.setError(Status.ERROR_SIGNER_NOT_ACCEPTED, msg);
          return result;
        }
        else {
          // OK, this is the most common case. The KeyInfo contained and certificate and
          // now we just want to make sure that this certificate is listed among the required
          // certificates.
          //
          if (this.requiredSignerCertificates.isEmpty()) {
            // If we don't have any required signer certificates, we return success for now
            // and possibly perform a path validation later on.
            //
            result.setStatus(Status.SUCCESS);
            return result;
          }
          else {
            // Find a matching certificate ...
            for (X509Certificate rc : this.requiredSignerCertificates) {
              if (result.getSignerCertificate().equals(rc)) {
                log.debug("Required certificate [{}] matched certificate found in KeyInfo", CertificateUtils.toLogString(rc));
                result.setStatus(Status.SUCCESS);
                return result;
              }
            }
            // None of the required signer certificate matched the certificate used to sign - fail.
            //
            final String msg = "None of the supplied required certificates matched signing certificate";
            log.info("Signature validation failed - {}", msg);
            result.setError(Status.ERROR_SIGNER_NOT_ACCEPTED, msg);
            return result;
          }
        }
      }
    }
    catch (XMLSecurityException | SignatureException e) {
      result.setError(Status.ERROR_BAD_FORMAT, e.getMessage(), e);
      return result;
    }
  }

  /**
   * Extracts all certificates from the supplied KeyInfo except for the actual signer certificate.
   * 
   * @param keyInfo
   *          the KeyInfo
   * @param signerCertificate
   *          the signer certificate
   * @return a list of certificates
   */
  protected List<X509Certificate> getAdditionalCertificates(final KeyInfo keyInfo, final X509Certificate signerCertificate) {
    List<X509Certificate> additional = new ArrayList<>();
    for (int i = 0; i < keyInfo.lengthX509Data(); i++) {
      try {
        final X509Data x509data = keyInfo.itemX509Data(i);
        if (x509data == null) {
          continue;
        }
        for (int j = 0; j < x509data.lengthCertificate(); j++) {
          final XMLX509Certificate xmlCert = x509data.itemCertificate(j);
          if (xmlCert != null) {
            final X509Certificate cert = CertificateUtils.decodeCertificate(xmlCert.getCertificateBytes());
            if (!cert.equals(signerCertificate)) {
              additional.add(cert);
            }
          }
        }
      }
      catch (XMLSecurityException | CertificateException e) {
        log.error("Failed to extract X509Certificate from KeyInfo", e);
        continue;
      }
    }
    return additional;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSigned(final Document document) throws IllegalArgumentException {
    try {
      NodeList signatureElements = document.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
      return signatureElements.getLength() > 0;
    }
    catch (Exception e) {
      throw new IllegalArgumentException("Invalid document", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getRequiredSignerCertificates() {
    return this.requiredSignerCertificates;
  }

  /** {@inheritDoc} */
  @Override
  public CertificateValidator getCertificateValidator() {
    return this.certificateValidator;
  }

  /**
   * Sets flag that tells whether this validator should handle XAdES processing. The default is {@code true}
   * 
   * @param xadesProcessing
   *          whether to process XAdES
   */
  public void setXadesProcessing(boolean xadesProcessing) {
    this.xadesProcessing = xadesProcessing;
  }

  /**
   * Looks for any {@code xades:SignedProperties} elements and registers an Id attribute for the elements that are
   * found.
   * 
   * @param document
   *          the document to manipulate
   */
  protected void registerXadesIdNodes(Document document) {
    final NodeList xadesSignedProperties = document.getElementsByTagNameNS(XADES_NAMESPACE, "SignedProperties");
    for (int i = 0; i < xadesSignedProperties.getLength(); i++) {
      final Element sp = (Element) xadesSignedProperties.item(i);
      sp.setIdAttribute("Id", true);
    }
  }

  /**
   * Utility method for getting hold of the reference URI:s of a {@code SignedInfo} element.
   * 
   * @param signedInfo
   *          the signed info element
   * @return a list of one or more reference URI:s
   * @throws SignatureException
   *           for unmarshalling errors
   */
  private List<String> getSignedInfoReferenceURIs(final Element signedInfo) throws SignatureException {
    final NodeList references = signedInfo.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Reference");
    if (references.getLength() == 0) {
      throw new SignatureException("No Reference element found in SignedInfo of signature");
    }
    List<String> uris = new ArrayList<>();
    for (int i = 0; i < references.getLength(); i++) {
      final Element reference = (Element) references.item(i);
      uris.add(reference.getAttribute("URI"));
    }
    return uris;
  }

}
