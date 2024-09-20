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
package se.idsec.signservice.security.sign.pdf.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

/**
 * Wraps an {@link InputStream} into a CMSProcessable object for Bouncy Castle. It's an alternative to the
 * CMSProcessableByteArray.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMSProcessableInputStream implements CMSTypedData {

  private final InputStream in;
  private final ASN1ObjectIdentifier contentType;

  /**
   * Constructor that defaults to use the 1.2.840.113549.1.7.1 OID (PKCS#7 data).
   *
   * @param is
   *          the input stream
   */
  public CMSProcessableInputStream(final InputStream is) {
    this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
  }

  /**
   * Constructor.
   *
   * @param type
   *          the OID of the object
   * @param is
   *          the input stream
   */
  public CMSProcessableInputStream(final ASN1ObjectIdentifier type, final InputStream is) {
    this.contentType = type;
    this.in = is;
  }

  /** {@inheritDoc} */
  @Override
  public Object getContent() {
    return this.in;
  }

  /** {@inheritDoc} */
  @Override
  public void write(final OutputStream out) throws IOException, CMSException {
    // read the content only one time
    final byte[] buffer = new byte[8 * 1024];
    int read;
    while ((read = this.in.read(buffer)) != -1) {
      out.write(buffer, 0, read);
    }
    this.in.close();
  }

  /** {@inheritDoc} */
  @Override
  public ASN1ObjectIdentifier getContentType() {
    return this.contentType;
  }
}