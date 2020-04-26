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
package se.idsec.signservice.security.sign.pdf;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import se.idsec.signservice.security.sign.SignatureValidationResult;

/**
 * Signature validation result for validating PDF signatures.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PDFSignatureValidationResult extends SignatureValidationResult {

  /**
   * Gets the PDF signature object (that was validated).
   * 
   * @return the PDF signature object
   */
  PDSignature getPdfSignature();

  /**
   * Gets the claimed signing time.
   * <p>
   * This is primarily obtained from the signed attributes, and if not present there, read from the PDF signature
   * dictionary.
   * </p>
   * 
   * @return the signing time (as millis since epoch)
   */
  Long getClaimedSigningTime();

  /**
   * Gets the URI identifier of the signature algorithm.
   * 
   * @return signature algorithm URI identifier
   */
  String getSignatureAlgorithm();

  /**
   * Predicate that tells if the signature has the CMS algorithm protection signed attribute set.
   * 
   * @return true if the CMS algorithm protection signed attribute is set and false otherwise
   */
  boolean isCmsAlgorithmProtection();

  /**
   * Predicate that tells if the signature that was validated is a PAdES signature (and this was correctly validated).
   * 
   * @return true if PAdES, and false otherwise
   */
  boolean isPades();

}
