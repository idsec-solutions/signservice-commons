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
package se.idsec.signservice.security.sign.pdf.impl;

import se.idsec.signservice.security.sign.impl.AbstractSignerResult;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;

/**
 * Default implementation of the signature result interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPDFSignerResult extends AbstractSignerResult<byte[]> implements PDFSignerResult {

  /** Signed attribute bytes. */
  private byte[] signedAttributes;

  /** CMS signed data bytes. */
  private byte[] signedData;

  /** {@inheritDoc} */
  @Override
  public byte[] getSignedAttributes() {
    return signedAttributes;
  }

  /**
   * Assigns the signed attributes bytes.
   * 
   * @param signedAttributes
   *          CMS signed attributes
   */
  public void setSignedAttributes(final byte[] signedAttributes) {
    this.signedAttributes = signedAttributes;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getSignedData() {
    return this.signedData;
  }

  /**
   * Assigns the CMS signed data.
   * 
   * @param signedData
   *          the signed data bytes
   */
  public void setSignedData(final byte[] signedData) {
    this.signedData = signedData;
  }

}
