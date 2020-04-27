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
package se.idsec.signservice.security.sign.xml;

import java.security.SignatureException;

import org.w3c.dom.Document;

import se.idsec.signservice.security.sign.Signer;
import se.idsec.signservice.security.sign.VoidSignerParameters;

/**
 * Interface for XML signatures.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface XMLSigner extends Signer<Document, XMLSignerResult, VoidSignerParameters> {
  
  /**
   * This implementation does not support any type of parameters. Will invoke {@code sign(Document)}.
   */
  default XMLSignerResult sign(final Document document, final VoidSignerParameters parameters) throws SignatureException {
    return this.sign(document);
  }
  
}
