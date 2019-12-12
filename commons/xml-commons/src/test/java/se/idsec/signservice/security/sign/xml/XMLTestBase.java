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
package se.idsec.signservice.security.sign.xml;

import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.BeforeClass;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;

/**
 * Abstract base class for XML tests. 
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class XMLTestBase {

  @BeforeClass
  public static void initializeOpenSAML() throws Exception {
    OpenSAMLInitializer.getInstance().initialize(
      new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
      new OpenSAMLSecurityExtensionConfig());
  }

  protected static Document getDocument(String path) throws Exception {
    Resource resource = new ClassPathResource(path);
    InputStream is = resource.getInputStream();
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setIgnoringComments(false);
      DocumentBuilder builder = dbf.newDocumentBuilder();
      return builder.parse(is);
    }
    finally {
      is.close();
    }
  }

  
}
