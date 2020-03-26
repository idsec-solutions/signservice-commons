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
package se.idsec.signservice.xml;

/**
 * Exception class for internal XML related exceptions such as configuration exceptions.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InternalXMLException extends RuntimeException {

  /** For serializing. */
  private static final long serialVersionUID = -5756277379887046375L;

  /**
   * Constructor.
   * 
   * @param message
   *          the error message
   */
  public InternalXMLException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   *
   * @param message
   *          the error message
   * @param cause
   *          the cause of the error
   */
  public InternalXMLException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
