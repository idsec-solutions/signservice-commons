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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;

/**
 * Test cases for DOMUtils.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DOMUtilsTest {

  private Resource resource = new ClassPathResource("signResponse.xml");

  @Test
  public void testCreateDocumentBuilder() throws Exception {
    DocumentBuilder b = DOMUtils.createDocumentBuilder();
    Assert.assertNotNull(b);
  }

  @Test
  public void testPrettyPrint() throws Exception {

    Document doc = DOMUtils.inputStreamToDocument(resource.getInputStream());

    String s = DOMUtils.prettyPrint(doc);
    Assert.assertTrue(StringUtils.hasText(s));
    Assert.assertTrue(s.contains("<dss:SignResponse"));

    s = DOMUtils.prettyPrint(doc.getDocumentElement());
    Assert.assertTrue(StringUtils.hasText(s));
    
    s = DOMUtils.prettyPrint(null);
    Assert.assertTrue(s.isEmpty());
  }

  @Test
  public void testNodeToBytes() throws Exception {
    Document doc = DOMUtils.inputStreamToDocument(resource.getInputStream());

    byte[] bytes = DOMUtils.nodeToBytes(doc.getDocumentElement());
    Assert.assertNotNull(bytes);
    Assert.assertTrue(bytes.length > 0);

    Document doc2 = DOMUtils.bytesToDocument(bytes);
    Assert.assertEquals("SignResponse", doc2.getDocumentElement().getLocalName());
  }

  @Test
  public void testNodeToBase64() throws Exception {
    Document doc = DOMUtils.inputStreamToDocument(resource.getInputStream());

    String base64 = DOMUtils.nodeToBase64(doc.getDocumentElement());
    Assert.assertTrue(StringUtils.hasText(base64));

    byte[] bytes = Base64.getDecoder().decode(base64);
    Assert.assertArrayEquals(DOMUtils.nodeToBytes(doc.getDocumentElement()), bytes);
  }
  
  @Test
  public void testInputStreamToDocument() throws Exception {
    Document doc = DOMUtils.inputStreamToDocument(resource.getInputStream());
    Assert.assertEquals("SignResponse", doc.getDocumentElement().getLocalName());
    
    InputStream notXml = new ByteArrayInputStream("<not-valid-xml>".getBytes());
    try {
      DOMUtils.inputStreamToDocument(notXml);
      Assert.fail("Expected InternalXMLException");
    }
    catch (InternalXMLException e) {      
    }
  }
  
  @Test
  public void testBytesToDocument() throws Exception {
    String xml = "<Sample>Hej</Sample>";
    Document doc = DOMUtils.bytesToDocument(xml.getBytes());
    Assert.assertEquals("Sample", doc.getDocumentElement().getLocalName());
    Assert.assertEquals("Hej", doc.getDocumentElement().getTextContent());
    
    try {
      DOMUtils.bytesToDocument("bbashjhiahdua".getBytes());
      Assert.fail("Expected InternalXMLException");
    }
    catch (InternalXMLException e) {      
    }
  }
  
  @Test
  public void testBase64ToDocument() throws Exception {
    String xml = "<Sample>Hej</Sample>";
    String b64 = Base64.getEncoder().encodeToString(xml.getBytes());
    
    Document doc = DOMUtils.base64ToDocument(b64);
    Assert.assertEquals("Sample", doc.getDocumentElement().getLocalName());
    Assert.assertEquals("Hej", doc.getDocumentElement().getTextContent());
    
    try {
      DOMUtils.base64ToDocument(
        Base64.getEncoder().encodeToString("bbashjhiahdua".getBytes()));
      Assert.fail("Expected InternalXMLException");
    }
    catch (InternalXMLException e) {      
    }
    
    try {
      DOMUtils.base64ToDocument("NOT-BASE-64");
      Assert.fail("Expected InternalXMLException");
    }
    catch (InternalXMLException e) {      
    }
  }

}
