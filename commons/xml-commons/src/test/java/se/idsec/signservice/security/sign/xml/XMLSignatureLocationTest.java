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

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.xpath.XPathExpressionException;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

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

    XMLSignatureLocation location = new XMLSignatureLocation();

    Document empty = getDocument("xml/empty.xml");
    location.insertSignature(createSignatureElement(), empty);
    Assert.assertEquals("Signature", getLastElement(empty));
    Assert.assertTrue(location.getSignature(empty) != null);    
    location.testInsert(empty);

    Document simple = getDocument("xml/simple.xml");
    location.insertSignature(createSignatureElement(), simple);
    Assert.assertEquals("Signature", getLastElement(simple));
    Assert.assertTrue(location.getSignature(simple) != null);
    location.testInsert(simple);

    // Make sure it works even if signature has the same document owner
    Document simple2 = getDocument("xml/simple.xml");
    location.insertSignature((Element) simple2.importNode(createSignatureElement(), true), simple2);
    Assert.assertEquals("Signature", getLastElement(simple2));
    Assert.assertTrue(location.getSignature(simple2) != null);

    Document signRequest = getDocument("xml/signRequest.xml");
    location.insertSignature(createSignatureElement(), signRequest);
    Assert.assertEquals("Signature", getLastElement(signRequest));
    Assert.assertTrue(location.getSignature(signRequest) != null);
  }

  @Test
  public void testFirst() throws Exception {
    XMLSignatureLocation location = new XMLSignatureLocation(ChildPosition.FIRST);

    Document empty = getDocument("xml/empty.xml");
    location.insertSignature(createSignatureElement(), empty);
    Assert.assertEquals("Signature", getFirstElement(empty));
    Assert.assertTrue(location.getSignature(empty) != null);

    Document simple = getDocument("xml/simple.xml");
    location.insertSignature(createSignatureElement(), simple);
    Assert.assertEquals("Signature", getFirstElement(simple));
    Assert.assertTrue(location.getSignature(simple) != null);

    Document signRequest = getDocument("xml/signRequest.xml");
    location.insertSignature(createSignatureElement(), signRequest);
    Assert.assertEquals("Signature", getFirstElement(signRequest));
    Assert.assertTrue(location.getSignature(signRequest) != null);
  }

  @Test
  public void testXPathBasic() throws Exception {

    String[] xpaths = new String[] { "/", "/Root" };
    for (String xpath : xpaths) {
      XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

      Document doc = getDocument("xml/empty.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assert.assertEquals(
        String.format("Document: empty.xml, xPath: %s", xpath),
        "Signature", getLastElement(doc));
      Assert.assertTrue(location.getSignature(doc) != null);
    }
    for (String xpath : xpaths) {
      XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.FIRST);

      Document doc = getDocument("xml/empty.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assert.assertEquals(
        String.format("Document: empty.xml, xPath: %s", xpath),
        "Signature", getFirstElement(doc));
      Assert.assertTrue(location.getSignature(doc) != null);
    }

    XMLSignatureLocation location = new XMLSignatureLocation("/NotElement", ChildPosition.LAST);
    Document doc = getDocument("xml/empty.xml");
    try {
      location.insertSignature(createSignatureElement(), doc);
      Assert.fail("Expected XPathExpressionException");
    }
    catch (XPathExpressionException e) {
    }
    try {
      location.testInsert(doc);
      Assert.fail("Expected XPathExpressionException");
    }
    catch (XPathExpressionException e) {
    }

    xpaths = new String[] { "/TheRoot/ElementOne", "/*/ElementOne" };
    for (String xpath : xpaths) {
      location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

      doc = getDocument("xml/simple.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assert.assertEquals(
        String.format("Document: simple.xml, xPath: %s", xpath),
        "Signature", getLastElement(doc, "ElementOne"));
      Assert.assertTrue(location.getSignature(doc) != null);
    }
    for (String xpath : xpaths) {
      location = new XMLSignatureLocation(xpath, ChildPosition.FIRST);

      doc = getDocument("xml/simple.xml");
      location.insertSignature(createSignatureElement(), doc);
      Assert.assertEquals(
        String.format("Document: simple.xml, xPath: %s", xpath),
        "Signature", getFirstElement(doc, "ElementOne"));
      Assert.assertTrue(location.getSignature(doc) != null);
    }
  }

  @Test
  public void testXPathMultiple() throws Exception {
    String[] xpaths = new String[] { "/TheRoot/Element", "/*/Element", "//Element[1]" };
    for (String xpath : xpaths) {
      XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

      Document doc = getDocument("xml/multipleElements.xml");
      location.insertSignature(createSignatureElement(), doc);

      Assert.assertEquals(
        String.format("Document: multipleElements.xml, xPath: %s", xpath),
        "Signature", getLastElement(doc, "Element"));
      Assert.assertTrue(location.getSignature(doc) != null);
    }
    // Select the second Element.
    //
    String xpath = "/TheRoot/Element[2]";
    XMLSignatureLocation location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

    Document doc = getDocument("xml/multipleElements.xml");
    location.insertSignature(createSignatureElement(), doc);
    
    Assert.assertEquals(
      String.format("Document: multipleElements.xml, xPath: %s", xpath),
      "Signature",
      doc.getDocumentElement().getElementsByTagName("Element").item(1).getChildNodes()
        .item(doc.getDocumentElement().getElementsByTagName("Element").item(1).getChildNodes().getLength() - 1).getLocalName());
    Assert.assertTrue(location.getSignature(doc) != null);

    // Select fails
    //
    xpath = "/TheRoot/Element[3]";
    location = new XMLSignatureLocation(xpath, ChildPosition.LAST);

    doc = getDocument("xml/multipleElements.xml");
    try {
      location.insertSignature(createSignatureElement(), doc);
      Assert.fail("Expected XPathExpressionException");
    }
    catch (XPathExpressionException e) {
    }
    try {
      location.testInsert(doc);
      Assert.fail("Expected XPathExpressionException");
    }
    catch (XPathExpressionException e) {
    }
  }

  @Test
  public void testXPathSignRequest() throws Exception {
    XMLSignatureLocation location = new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);
        
    Document signRequest = getDocument("xml/signRequest.xml");
    location.insertSignature(createSignatureElement(), signRequest);
    
    Node node = signRequest.getDocumentElement().getElementsByTagName("dss:OptionalInputs").item(0);    
    Assert.assertEquals("Signature", node.getChildNodes().item(node.getChildNodes().getLength() - 1).getLocalName());
    Assert.assertTrue(location.getSignature(signRequest) != null);
  }
  
  @Test
  public void testXPathSignRequestSameOwner() throws Exception {
    XMLSignatureLocation location = new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST); 
        
    Document signRequest = getDocument("xml/signRequest2.xml");
    Element signatureElement = (Element) signRequest.importNode(createSignatureElement(), true); 
    
    location.insertSignature(signatureElement, signRequest);
    
    Node node = signRequest.getDocumentElement().getElementsByTagName("OptionalInputs").item(0);    
    Assert.assertEquals("Signature", node.getChildNodes().item(node.getChildNodes().getLength() - 1).getLocalName()); 
  }
    
  private static String getFirstElement(Document doc) {
    return doc.getDocumentElement().getChildNodes().item(0).getLocalName();
  }

  private static String getFirstElement(Document doc, String parent) {
    return doc.getDocumentElement().getElementsByTagName(parent).item(0).getChildNodes().item(0).getLocalName();
  }

  private static String getLastElement(Document doc) {
    return doc.getDocumentElement().getChildNodes().item(doc.getDocumentElement().getChildNodes().getLength() - 1).getLocalName();
  }

  private static String getLastElement(Document doc, String parent) {
    Node node = doc.getDocumentElement().getElementsByTagName(parent).item(0);
    return node.getChildNodes().item(node.getChildNodes().getLength() - 1).getLocalName();
  }

  private static Element createSignatureElement() throws Exception {
    Document doc = DOMUtils.createDocumentBuilder().newDocument();

    Element element = doc.createElementNS(XMLSignature.XMLNS, "ds:Signature");
    doc.appendChild(element);

    element.setTextContent("Test");

    return element;
  }

}
