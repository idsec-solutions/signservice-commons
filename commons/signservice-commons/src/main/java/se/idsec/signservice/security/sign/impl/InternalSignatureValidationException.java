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

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.SignatureValidator;

import java.io.Serial;

/**
 * Exception that may be used internally by implementations of the {@link SignatureValidator} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InternalSignatureValidationException extends Exception {

  /** For serialization. */
  @Serial
  private static final long serialVersionUID = -7516393774554663769L;

  /** The validation status. */
  private final SignatureValidationResult.Status status;

  /**
   * Constructor assigning the validation status and the error message.
   *
   * @param status the validation status
   * @param message the error message
   */
  public InternalSignatureValidationException(final SignatureValidationResult.Status status, final String message) {
    this(status, message, null);
  }

  /**
   * Constructor assigning the validation status, the error message and the cause of the error.
   *
   * @param status the validatin status
   * @param message the error message
   * @param cause the cause of the error
   */
  public InternalSignatureValidationException(final SignatureValidationResult.Status status, final String message,
      final Throwable cause) {
    super(message, cause);
    this.status = status;
    if (this.status == null) {
      throw new IllegalArgumentException("Status can not be null");
    }
    if (this.status == SignatureValidationResult.Status.SUCCESS) {
      throw new IllegalArgumentException("Status can not be SUCCESS");
    }
  }

  /**
   * Gets the validation status.
   *
   * @return the validation status
   */
  public SignatureValidationResult.Status getStatus() {
    return this.status;
  }

}
