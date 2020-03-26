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

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;

import se.swedenconnect.schemas.csig.dssext_1_1.SignMessage;
import se.swedenconnect.schemas.saml_2_0.assertion.EncryptedElementType;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;

/**
 * Test cases for JAXBMarshaller.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JAXBMarshallerTest {

  @Test
  public void testMarshallRootElement() throws Exception {
    se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory f = new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();
    SignMessage sm = f.createSignMessage();
    sm.setDisplayEntity("abc");
    
    Document doc = JAXBMarshaller.marshall(sm);
    Assert.assertEquals("SignMessage", doc.getDocumentElement().getLocalName());
    Assert.assertEquals("csig", doc.getDocumentElement().getPrefix());
    
    // A non-root element should not work ...
    EncryptedElementType ee = new EncryptedElementType();
    try {
      JAXBMarshaller.marshall(ee);
      Assert.fail("Expected JAXBException");
    }
    catch (JAXBException e) {      
    }
  }
  
  @Test
  public void testMarshallNonRootElement() throws Exception {
    se.swedenconnect.schemas.saml_2_0.assertion.ObjectFactory f = new se.swedenconnect.schemas.saml_2_0.assertion.ObjectFactory();
    
    NameIDType type = new NameIDType();
    type.setFormat("test");
    
    JAXBElement<NameIDType> e = f.createNameID(type);
    Document doc = JAXBMarshaller.marshallNonRootElement(e);    
    Assert.assertNotNull(doc.getDocumentElement());
  }

}
