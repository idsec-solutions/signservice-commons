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
package se.idsec.signservice.xml;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;

/**
 * Test cases for DOMUtils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DOMUtilsTest {

  @Test
  public void testCreateDocumentBuilder() throws Exception {
    final DocumentBuilder b = DOMUtils.createDocumentBuilder();
    Assertions.assertNotNull(b);
  }

  @Test
  public void testPrettyPrint() throws Exception {

    final Document doc = DOMUtils.inputStreamToDocument(
        ClassLoaderUtils.getResourceAsStream("/signResponse.xml", DOMUtilsTest.class));

    String s = DOMUtils.prettyPrint(doc);
    Assertions.assertFalse(StringUtils.isBlank(s));
    Assertions.assertTrue(s.contains("<dss:SignResponse"));

    s = DOMUtils.prettyPrint(doc.getDocumentElement());
    Assertions.assertFalse(StringUtils.isBlank(s));

    s = DOMUtils.prettyPrint(null);
    Assertions.assertTrue(s.isEmpty());
  }

  @Test
  public void testNodeToBytes() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(
        ClassLoaderUtils.getResourceAsStream("/signResponse.xml", DOMUtilsTest.class));

    final byte[] bytes = DOMUtils.nodeToBytes(doc.getDocumentElement());
    Assertions.assertNotNull(bytes);
    Assertions.assertTrue(bytes.length > 0);

    final Document doc2 = DOMUtils.bytesToDocument(bytes);
    Assertions.assertEquals("SignResponse", doc2.getDocumentElement().getLocalName());
  }

  @Test
  public void testNodeToBase64() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(
        ClassLoaderUtils.getResourceAsStream("/signResponse.xml", DOMUtilsTest.class));

    final String base64 = DOMUtils.nodeToBase64(doc.getDocumentElement());
    Assertions.assertFalse(StringUtils.isBlank(base64));

    final byte[] bytes = Base64.getDecoder().decode(base64);
    Assertions.assertArrayEquals(DOMUtils.nodeToBytes(doc.getDocumentElement()), bytes);
  }

  @Test
  public void testInputStreamToDocument() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(
        ClassLoaderUtils.getResourceAsStream("/signResponse.xml", DOMUtilsTest.class));

    Assertions.assertEquals("SignResponse", doc.getDocumentElement().getLocalName());

    final InputStream notXml = new ByteArrayInputStream("<not-valid-xml>".getBytes());

    Assertions.assertThrows(DOMException.class, () -> {
      DOMUtils.inputStreamToDocument(notXml);
    });
  }

  @Test
  public void testBytesToDocument() throws Exception {
    final String xml = "<Sample>Hej</Sample>";
    final Document doc = DOMUtils.bytesToDocument(xml.getBytes());
    Assertions.assertEquals("Sample", doc.getDocumentElement().getLocalName());
    Assertions.assertEquals("Hej", doc.getDocumentElement().getTextContent());

    Assertions.assertThrows(DOMException.class, () -> {
      DOMUtils.bytesToDocument("bbashjhiahdua".getBytes());
    });
  }

  @Test
  public void testBase64ToDocument() throws Exception {
    final String xml = "<Sample>Hej</Sample>";
    final String b64 = Base64.getEncoder().encodeToString(xml.getBytes());

    final Document doc = DOMUtils.base64ToDocument(b64);
    Assertions.assertEquals("Sample", doc.getDocumentElement().getLocalName());
    Assertions.assertEquals("Hej", doc.getDocumentElement().getTextContent());

    Assertions.assertThrows(DOMException.class, () -> {
      DOMUtils.base64ToDocument(
          Base64.getEncoder().encodeToString("bbashjhiahdua".getBytes()));
    });

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      DOMUtils.base64ToDocument("NOT-BASE-64");
    });
  }

}
