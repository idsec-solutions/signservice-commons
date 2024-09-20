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
package se.idsec.signservice.security.sign.impl;

import se.idsec.signservice.security.sign.SignerResult;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Abstract base class for {@link SignerResult} implementations.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractSignerResult<T> implements SignerResult<T> {

  /** The signed document. */
  private T signedDocument;

  /** The signing time. */
  private long signingTime;

  /** The signer certificate. */
  private X509Certificate signerCertificate;

  /** The signer certificate chain. */
  private List<X509Certificate> signerCertificateChain;

  /** {@inheritDoc} */
  @Override
  public T getSignedDocument() {
    return this.signedDocument;
  }

  /**
   * Assigns the signed document.
   *
   * @param signedDocument the signed document
   */
  public void setSignedDocument(final T signedDocument) {
    this.signedDocument = signedDocument;
  }

  /** {@inheritDoc} */
  @Override
  public long getSigningTime() {
    return this.signingTime;
  }

  /**
   * Assigns the signing time.
   *
   * @param signingTime the siging time (in millis since epoch)
   */
  public void setSigningTime(final long signingTime) {
    this.signingTime = signingTime;
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getSignerCertificate() {
    return this.signerCertificate;
  }

  /**
   * Assigns the signer certificate.
   *
   * @param signerCertificate the signer certificate
   */
  public void setSignerCertificate(final X509Certificate signerCertificate) {
    this.signerCertificate = signerCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getSignerCertificateChain() {
    return signerCertificateChain != null
        ? this.signerCertificateChain
        : this.signerCertificate != null ? Collections.singletonList(this.signerCertificate) : Collections.emptyList();
  }

  /**
   * Assigns the signer certificate chain.
   *
   * @param signerCertificateChain the signer certificate chain
   */
  public void setSignerCertificateChain(final List<X509Certificate> signerCertificateChain) {
    this.signerCertificateChain = signerCertificateChain;
  }

}
