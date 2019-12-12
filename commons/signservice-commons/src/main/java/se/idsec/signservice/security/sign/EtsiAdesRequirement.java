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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Representation of a ETSI AdES requirement for signing.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface EtsiAdesRequirement {

  /**
   * The type of AdES signature.
   */
  public enum AdesType {
    /** ETSI Basic Electronic Signature format */
    BES,
    /** ETSI Extended Policy Electronic Signature format */
    EPES;
  }

  /**
   * Gets the type of requested AdES signature.
   * 
   * @return AdES type
   */
  @Nonnull
  AdesType getAdesType();

  /**
   * Gets the optional AdES object.
   * 
   * @return the AdES object or null
   */
  @Nullable
  byte[] getAdesObject();

  /**
   * Gets the signature policy needed if EPES is used.
   * 
   * @return the signature policy or null
   */
  @Nullable
  String getSignaturePolicy();

}
