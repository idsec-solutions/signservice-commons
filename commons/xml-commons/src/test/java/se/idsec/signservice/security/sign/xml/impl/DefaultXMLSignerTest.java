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
package se.idsec.signservice.security.sign.xml.impl;

import java.security.KeyStoreException;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Document;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.idsec.signservice.security.sign.SigningCredential;
import se.idsec.signservice.security.sign.impl.KeyStoreSigningCredential;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.XMLTestBase;

/**
 * Test cases for {@link DefaultXMLSigner}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultXMLSignerTest extends XMLTestBase {
  
  @Test
  public void testDefaultSignature() throws Exception {
    Document document = getDocument("xml/simple.xml");
    SigningCredential credential = getSigningCredential();

    DefaultXMLSigner operation = new DefaultXMLSigner(credential);
    
    XMLSignerResult result = operation.sign(document); 
    System.out.println(SerializeSupport.prettyPrintXML(result.getSignedDocument()));
    
    System.out.println(SerializeSupport.prettyPrintXML(result.getSignedInfo()));    
  }
  
  private SigningCredential getSigningCredential() throws KeyStoreException {
    return new KeyStoreSigningCredential(
      new ClassPathResource("test-credentials.jks"), "secret".toCharArray(), "test");
  }

}
