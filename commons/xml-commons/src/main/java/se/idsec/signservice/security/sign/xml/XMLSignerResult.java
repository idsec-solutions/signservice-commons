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
package se.idsec.signservice.security.sign.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import se.idsec.signservice.security.sign.SignerResult;

/**
 * Represents the result from an XML signature operation.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 * @see XMLSigner
 */
public interface XMLSignerResult extends SignerResult<Document> {

  /**
   * Gets the {@code ds:Signature} element of the signed document ({@link #getSignedDocument()}).
   * 
   * @return the Signature element
   */
  Element getSignatureElement();

  /**
   * Gets the {@code ds:SignedInfo} element from the {@code ds:Signature} element of the signed document
   * ({@link #getSignedDocument()}).
   * 
   * @return the SignedInfo element
   */
  Element getSignedInfo();

  /**
   * Gets the canonicalized bytes of the {@code ds:SignedInfo} element from the {@code ds:Signature} element of the
   * signed document ({@link #getSignedDocument()}).
   * 
   * @return a byte array
   */
  byte[] getCanonicalizedSignedInfo();

}
