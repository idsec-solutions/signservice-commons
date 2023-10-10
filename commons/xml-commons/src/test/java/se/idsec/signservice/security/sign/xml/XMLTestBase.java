/*
 * Copyright 2019-2023 IDsec Solutions AB
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

import java.io.InputStream;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;

import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * Abstract base class for XML tests.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class XMLTestBase {

  @BeforeAll
  public static void init() {
    org.apache.xml.security.Init.init();
  }

  protected static Document getDocument(final String path) throws Exception {
    final Resource resource = new ClassPathResource(path);
    try (final InputStream is = resource.getInputStream()) {
      return DOMUtils.createDocumentBuilder().parse(is);
    }
  }

  protected X509Certificate getCertificate(final String path) throws Exception {
    return X509Utils.decodeCertificate(new ClassPathResource(path));
  }

}
