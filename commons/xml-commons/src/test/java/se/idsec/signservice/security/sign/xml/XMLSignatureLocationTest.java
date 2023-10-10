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

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.xpath.XPathExpressionException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition;
import se.idsec.signservice.xml.DOMUtils;

/**
 * Tests for {@code XMLSignatureLocation}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class XMLSignatureLocationTest extends XMLTestBase {

  @Test
  public void testDefault() throws Exception {

    final XMLSignatureLocation location = new XMLSignatureLocation();

    final Document empty = getDocument("xml/empty.xml");
    location.insertSignature(createSignatureElement(), empty);
    Assertions.assertEquals("Signature", getLastElement(empty));
    Assertions.assertTrue(location.getSignature(empty) != null);
    location.testInsert(empty);

    final Document simple = getDocument("xml/simple.xml");
    location.insertSignature(createSignatureElement(), simple);
    Assertions.assertEquals("Signature", getLastElement(simple));
    Assertions.assertTrue(location.getSignature(simple) != null);
    location.testInsert(simple);

    // Make sure it works even if signature has the same document owner
    final Document simple2 = getDocument("xml/simple.xml");
    location.insertSignature((Element) simple2.importNode(createSignatureElement(), true), simple2);
    Assertions.assertEquals("Signature", getLastElement(simple2));
    Assertions.assertTrue(location.getSignature(simple2) != null);

    final Document signRequest = getDocument("xml/signRequest.xml");
    location.insertSignature(createSignatureElement(), signRequest);
    Assertions.assertEquals("Signature", getLastElement(signRequest));
    Assertions.assertTrue(location.getSignature(signRequest) != null);
  }

  @Test
  public void testFirst() throws Exception {
    final XMLSignatureLocation location = new XMLSignatureLocation(ChildPosition.FIRST);

    final Document empty = getDocument("xml/empty.xml");
    location.insertSignature(createSignatureElement(), empty);
    Assertions.assertEquals("Signature", getFirstElement(empty));
    Assertions.assertTrue(location.getSignature(empty) != null);

    final Document simple = getDocument("xml/simple.xml");
    location.insertSignature(createSignatureElement(), simple);
    Assertions.assertEquals("Signature", getFirstElement(simple));
    Assertions.assertTrue(location.getSignature(simple) != null);

    final Document signRequest = getDocument("xml/signRequest.xml");
    location.insertSignature(createSignatureElement(), signRequest);
    Assertions.assertEquals("Signature", getFirstElement(signRequest));
    Assertions.assertTrue(location.getSignature(signRequest) != null);
  }

  @Test
  public void testXPathBasic() throws Exception {

    String[] xpaths = new String[] { "/", "/Root" };
    for (final String xpath : xpaths) {
      final XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

      final Document doc = getDocument("xml/empty.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assertions.assertEquals(
          "Signature", getLastElement(doc), String.format("Document: empty.xml, xPath: %s", xpath));
      Assertions.assertTrue(location.getSignature(doc) != null);
    }
    for (final String xpath : xpaths) {
      final XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.FIRST);

      final Document doc = getDocument("xml/empty.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assertions.assertEquals(
          "Signature", getFirstElement(doc), String.format("Document: empty.xml, xPath: %s", xpath));
      Assertions.assertTrue(location.getSignature(doc) != null);
    }

    XMLSignatureLocation location = new XMLSignatureLocation("/NotElement", ChildPosition.LAST);
    Document doc = getDocument("xml/empty.xml");
    try {
      location.insertSignature(createSignatureElement(), doc);
      Assertions.fail("Expected XPathExpressionException");
    }
    catch (final XPathExpressionException e) {
    }
    try {
      location.testInsert(doc);
      Assertions.fail("Expected XPathExpressionException");
    }
    catch (final XPathExpressionException e) {
    }

    xpaths = new String[] { "/TheRoot/ElementOne", "/*/ElementOne" };
    for (final String xpath : xpaths) {
      location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

      doc = getDocument("xml/simple.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assertions.assertEquals(
          "Signature", getLastElement(doc, "ElementOne"), String.format("Document: simple.xml, xPath: %s", xpath));
      Assertions.assertTrue(location.getSignature(doc) != null);
    }
    for (final String xpath : xpaths) {
      location = new XMLSignatureLocation(xpath, ChildPosition.FIRST);

      doc = getDocument("xml/simple.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assertions.assertEquals(
          "Signature", getFirstElement(doc, "ElementOne"), String.format("Document: simple.xml, xPath: %s", xpath));
      Assertions.assertTrue(location.getSignature(doc) != null);
    }
  }

  @Test
  public void testXPathMultiple() throws Exception {
    final String[] xpaths = new String[] { "/TheRoot/Element", "/*/Element", "//Element[1]" };
    for (final String xpath : xpaths) {
      final XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

      final Document doc = getDocument("xml/multipleElements.xml");
      location.insertSignature(createSignatureElement(), doc);

      Assertions.assertEquals(
          "Signature", getLastElement(doc, "Element"),
          String.format("Document: multipleElements.xml, xPath: %s", xpath));
      Assertions.assertTrue(location.getSignature(doc) != null);
    }
    // Select the second Element.
    //
    String xpath = "/TheRoot/Element[2]";
    XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

    Document doc = getDocument("xml/multipleElements.xml");
    location.insertSignature(createSignatureElement(), doc);

    Assertions.assertEquals(
        "Signature",
        doc.getDocumentElement().getElementsByTagName("Element").item(1).getChildNodes()
            .item(doc.getDocumentElement().getElementsByTagName("Element").item(1).getChildNodes().getLength() - 1)
            .getLocalName(),
        String.format("Document: multipleElements.xml, xPath: %s", xpath));
    Assertions.assertTrue(location.getSignature(doc) != null);

    // Select fails
    //
    xpath = "/TheRoot/Element[3]";
    location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

    doc = getDocument("xml/multipleElements.xml");
    try {
      location.insertSignature(createSignatureElement(), doc);
      Assertions.fail("Expected XPathExpressionException");
    }
    catch (final XPathExpressionException e) {
    }
    try {
      location.testInsert(doc);
      Assertions.fail("Expected XPathExpressionException");
    }
    catch (final XPathExpressionException e) {
    }
  }

  @Test
  public void testXPathSignRequest() throws Exception {
    final XMLSignatureLocation location =
        new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);

    final Document signRequest = getDocument("xml/signRequest.xml");
    location.insertSignature(createSignatureElement(), signRequest);

    final Node node = signRequest.getDocumentElement().getElementsByTagName("dss:OptionalInputs").item(0);
    Assertions.assertEquals("Signature",
        node.getChildNodes().item(node.getChildNodes().getLength() - 1).getLocalName());
    Assertions.assertTrue(location.getSignature(signRequest) != null);
  }

  @Test
  public void testXPathSignRequestSameOwner() throws Exception {
    final XMLSignatureLocation location =
        new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);

    final Document signRequest = getDocument("xml/signRequest2.xml");
    final Element signatureElement = (Element) signRequest.importNode(createSignatureElement(), true);

    location.insertSignature(signatureElement, signRequest);

    final Node node = signRequest.getDocumentElement().getElementsByTagName("OptionalInputs").item(0);
    Assertions.assertEquals("Signature",
        node.getChildNodes().item(node.getChildNodes().getLength() - 1).getLocalName());
  }

  @Test
  public void testIgnoreBlanks() throws Exception {
    final XMLSignatureLocation location =
        new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);
    final Document signRequest = getDocument("xml/signRequest3.xml");

    // Assert that the last child is a text node (empty), and that this will be ignored
    final NodeList childs =
        signRequest.getDocumentElement().getElementsByTagName("dss:OptionalInputs").item(0).getChildNodes();
    Assertions.assertTrue(childs.item(childs.getLength() - 1).getNodeType() == Node.TEXT_NODE);

    Assertions.assertNotNull(location.getSignature(signRequest));

  }

  private static String getFirstElement(final Document doc) {
    return doc.getDocumentElement().getChildNodes().item(0).getLocalName();
  }

  private static String getFirstElement(final Document doc, final String parent) {
    return doc.getDocumentElement().getElementsByTagName(parent).item(0).getChildNodes().item(0).getLocalName();
  }

  private static String getLastElement(final Document doc) {
    return doc.getDocumentElement().getChildNodes().item(doc.getDocumentElement().getChildNodes().getLength() - 1)
        .getLocalName();
  }

  private static String getLastElement(final Document doc, final String parent) {
    final Node node = doc.getDocumentElement().getElementsByTagName(parent).item(0);
    return node.getChildNodes().item(node.getChildNodes().getLength() - 1).getLocalName();
  }

  private static Element createSignatureElement() throws Exception {
    final Document doc = DOMUtils.createDocumentBuilder().newDocument();

    final Element element = doc.createElementNS(XMLSignature.XMLNS, "ds:Signature");
    doc.appendChild(element);

    element.setTextContent("Test");

    return element;
  }

}
