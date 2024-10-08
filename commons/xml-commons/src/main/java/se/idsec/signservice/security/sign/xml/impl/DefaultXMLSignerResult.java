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
package se.idsec.signservice.security.sign.xml.impl;

import java.io.IOException;
import java.io.UncheckedIOException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import se.idsec.signservice.security.sign.impl.AbstractSignerResult;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;

/**
 * Default implementation of the {@link XMLSignerResult}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultXMLSignerResult extends AbstractSignerResult<Document> implements XMLSignerResult {

  /** The signature object. */
  private final XMLSignature signature;

  /**
   * Constructor.
   *
   * @param signature the signature object
   */
  public DefaultXMLSignerResult(final XMLSignature signature) {
    this.signature = signature;
    this.setSignedDocument(this.signature.getDocument());
    this.setSigningTime(System.currentTimeMillis());
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

  /** {@inheritDoc} */
  @Override
  public byte[] getCanonicalizedSignedInfo() {
    try {
      return this.signature.getSignedInfo().getCanonicalizedOctetStream();
    }
    catch (final XMLSecurityException e) {
      throw new SecurityException("Failed to canonicalize SignedInfo", e);
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Failed to canonicalize SignedInfo", e);
    }

  }

}
