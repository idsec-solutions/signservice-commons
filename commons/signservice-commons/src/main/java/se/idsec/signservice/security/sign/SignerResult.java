/*
 * Copyright 2019-2022 IDsec Solutions AB
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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Representation of the result to an {@link Signer#sign(Object)} invocation. 
 * 
 * @param <T> the type of document signed 
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignerResult<T> {
  
  /**
   * Gets the signed document.
   * @return the signed document
   */
  T getSignedDocument();
  
  /**
   * Gets the time of signing
   * @return the time of signing (milliseconds since 1970-01-01)
   */
  long getSigningTime();
  
  /**
   * Gets the signer certificate.
   * 
   * @return the signer certificate
   */
  X509Certificate getSignerCertificate();

  /**
   * Gets the signer certificate chain. The chain starts with the signer certificate. 
   * 
   * @return signer certificate chain (holding at least one certificate)
   */
  List<X509Certificate> getSignerCertificateChain();  

}
