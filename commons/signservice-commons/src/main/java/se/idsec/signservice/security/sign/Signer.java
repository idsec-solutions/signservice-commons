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
package se.idsec.signservice.security.sign;

import java.security.SignatureException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Interface that represents a signer, i.e. an instance that given a set of signature properties signs documents.
 * 
 * @param <T>
 *          the type for the document that is signed
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface Signer<T, R extends SignerResult<T>> {

  /**
   * Signs the document using the installed signing credential ({@link #getSigningCredential()}).
   * 
   * @param document
   *          the document to sign
   * @return a signature result (including the signed document)
   * @throws SignatureException
   *           for signature errors
   */
  R sign(@Nonnull final T document) throws SignatureException;

  /**
   * Signs the document using the installed signing credential ({@link #getSigningCredential()}).
   * 
   * @param document
   *          the document to sign
   * @param adesRequirement
   *          optional AdES requirements
   * @return a signature result (including the signed document)
   * @throws SignatureException
   *           for signature errors
   */
  R sign(@Nonnull final T document, @Nullable final EtsiAdesRequirement adesRequirement) throws SignatureException;

  /**
   * Gets the signing credential that is used for the signing operation.
   * 
   * @return the signing credential
   */
  @Nonnull
  SigningCredential getSigningCredential();

}
