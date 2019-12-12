/*
 * Copyright 2019 IDsec Solutions AB
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

import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import se.idsec.signservice.security.sign.xml.XMLSignerResult;

/**
 * Default implementation of the {@link XMLSignerResult}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultXMLSignerResult implements XMLSignerResult {

  /** The signature object. */
  private XMLSignature signature;

  /** The time of signing. */
  private long signingTime;

  /**
   * Constructor.
   * 
   * @param signature
   *          the signature object
   */
  public DefaultXMLSignerResult(final XMLSignature signature) {
    this.signature = signature;
    this.signingTime = System.currentTimeMillis();
  }

  /** {@inheritDoc} */
  @Override
  public Document getSignedDocument() {
    return this.signature.getDocument();
  }

  /** {@inheritDoc} */
  @Override
  public long getSigningTime() {
    return this.signingTime;
  }

  /** {@inheritDoc} */
  @Override
  public Element getSignatureElement() {
    return this.signature.getElement();
  }

  /** {@inheritDoc} */
  @Override
  public Element getSignedInfo() {
    return this.signature.getSignedInfo().getElement();
  }

}
