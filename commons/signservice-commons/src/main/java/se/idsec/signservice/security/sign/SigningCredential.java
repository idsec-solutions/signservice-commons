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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Interface representing a signing credential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SigningCredential {

  /**
   * Gets the signing certificate.
   * 
   * @return the signing certificate
   */  
  @Nullable
  X509Certificate getSigningCertificate();
  
  /**
   * Gets the public key.
   * 
   * @return the public key
   * @see X509Certificate#getPublicKey()
   */
  @Nonnull
  PublicKey getPublicKey();

  /**
   * Gets the private key.
   * 
   * @return the private key
   */
  @Nonnull
  PrivateKey getPrivateKey();

  /**
   * Gets the certificate chain for the signing certificate. The signing certificate is included.
   * <p>
   * If no signing certificate is available and empty list is returned.
   * </p>
   * 
   * @return the certificate chain
   */
  @Nonnull
  List<X509Certificate> getCertificateChain();

  /**
   * Gets the name for the credential (for logging purposes)
   * 
   * @return the credential name
   */
  String getName();

}
