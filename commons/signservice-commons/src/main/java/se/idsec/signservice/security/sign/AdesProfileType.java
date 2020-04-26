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
package se.idsec.signservice.security.sign;

import org.apache.commons.lang.StringUtils;

/**
 * An enumeration representing the different ETSI AdES types.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum AdesProfileType {

  /** No AdES */
  None("None"),

  /** ETSI Basic Electronic Signature format */
  BES("BES"),

  /** ETSI Extended Policy Electronic Signature format */
  EPES("EPES");

  /**
   * Gets the string representation of the enum.
   * 
   * @return the string representation
   */
  public String getStringValue() {
    return this.stringValue;
  }

  /**
   * Given a string representation, the method returns the corresponing enum.
   * <p>
   * If provided with {@code null} or an empty string {@link #None} is returned.
   * </p>
   * 
   * @param stringValue
   *          string representation
   * @return the enum
   * @throws IllegalArgumentException
   *           if an invalid string is provided
   */
  public static AdesProfileType fromStringValue(final String stringValue) throws IllegalArgumentException {
    if (StringUtils.isBlank(stringValue)) {
      return AdesProfileType.None;
    }
    for (AdesProfileType a : AdesProfileType.values()) {
      if (a.getStringValue().equalsIgnoreCase(stringValue)) {
        return a;
      }
    }
    throw new IllegalArgumentException(stringValue + " is not a valid AdesProfileType");
  }

  /**
   * Constructor.
   * 
   * @param stringValue
   *          the string representation of the enum.
   */
  private AdesProfileType(final String stringValue) {
    this.stringValue = stringValue;
  }

  /** The string representation of the enum. */
  private final String stringValue;

}
