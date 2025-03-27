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
package se.idsec.signservice.security.sign.xml.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import se.idsec.signservice.security.sign.xml.XMLTestBase;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreBuilder;

import java.security.KeyStore;

/**
 * Test cases for {@link DefaultXMLSigner}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultXMLSignerTest extends XMLTestBase {

  @Test
  public void testDefaultSignature() {
    Assertions.assertDoesNotThrow(() -> {
      final Document document = getDocument("xml/simple.xml");
      final PkiCredential credential = this.getSigningCredential();

      final DefaultXMLSigner operation = new DefaultXMLSigner(credential);

      operation.sign(document);
    });
  }

  private PkiCredential getSigningCredential() throws Exception {
    final KeyStore keyStore = KeyStoreBuilder.builder()
        .location("classpath:test-credentials.jks")
        .type("JKS")
        .password("secret")
        .build();

    return new KeyStoreCredential(keyStore, "test", "secret".toCharArray());
  }

}
