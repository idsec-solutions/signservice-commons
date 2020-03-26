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

import java.util.ArrayList;
import java.util.List;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import lombok.extern.slf4j.Slf4j;

/**
 * Tells where in an XML document the signature should be inserted or found.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLSignatureLocation {

  /**
   * Enum for indicating the point within a selected parent node.
   */
  public enum ChildPosition {
    FIRST, LAST
  };

  /** Indicator for first or last child of a selected parent node. */
  private ChildPosition childPosition;

  /**
   * The XPath expression for selecting the parent node (or {@code null} which means the the parent node is the document
   * root element).
   */
  private XPathExpression xPathExpression;

  /** The textual representation of the XPath expression (for logging). */
  private String xPath;

  /**
   * Constructor setting up the signature location to "the last child of the document root element".
   */
  public XMLSignatureLocation() {
    this(ChildPosition.LAST);
  }

  /**
   * Constructor setting of the signature location to "the first child of the document root element"
   * ({@code childPosition} == {@link ChildPosition#FIRST} or "the last child of the document root element"
   * ({@code childPosition} == {@link ChildPosition#LAST}.
   * 
   * @param childPosition
   *          first of last child of the document root element
   */
  public XMLSignatureLocation(final ChildPosition childPosition) {
    this.childPosition = childPosition;
  }

  /**
   * Constructor accepting an XPath expression for finding the parent element of where we should insert/find the
   * signature element. Note that the result of evaluating the XPath expression <b>MUST</b> be one single node.
   * <p>
   * <b>Note</b>: Beware of that the document supplied to {@link #insertSignature(Element, Document)} or
   * {@link #getSignature(Document)} may be created using a namespace aware parser and you may want to use the
   * {@code local-name()} XPath construct.
   * </p>
   * 
   * @param parentXPath
   *          XPath expression for locating the parent node of the signature element
   * @param childPosition
   *          whether to insert/find the signature as the first or last child of the given parent node
   * @throws XPathExpressionException
   *           for illegal XPath expressions
   */
  public XMLSignatureLocation(final String parentXPath, final ChildPosition childPosition) throws XPathExpressionException {
    this.childPosition = childPosition;
    this.xPath = parentXPath;
    this.xPathExpression = XPathFactory.newInstance().newXPath().compile(parentXPath);
  }

  /**
   * Inserts the given {@code Signature} element into the document according to this object's configuration.
   * <p>
   * Note: If the owner document of the given {@code Signature} element is not the same as the {@code document}
   * paramater, the element is imported into this document.
   * </p>
   * 
   * @param signature
   *          the element to insert
   * @param document
   *          the document to which the signature element should be inserted
   * @throws XPathExpressionException
   *           for XPath selection errors
   */
  public void insertSignature(final Element signature, final Document document) throws XPathExpressionException {

    // If the signature element comes from a different document, import it.
    final boolean sameOwner = XMLUtils.getOwnerDocument(signature) == document;
    Node signatureNode = sameOwner ? signature : document.importNode(signature, true);

    Node parentNode = this.xPathExpression != null
        ? (Node) this.xPathExpression.evaluate(document, XPathConstants.NODE)
        : document.getDocumentElement();

    if (parentNode == null) {
      // Node was not found
      final String msg = String.format("Could not find XML node for insertion of Signature - XPath: %s", xPath);
      log.error(msg);
      throw new XPathExpressionException(msg);
    }

    // If the XPath "/" was given we help a bit ...
    if (parentNode.getNodeType() == Node.DOCUMENT_NODE) {
      parentNode = ((Document) parentNode).getDocumentElement();
    }

    if (ChildPosition.LAST == this.childPosition) {
      parentNode.appendChild(signatureNode);
    }
    else {
      parentNode.insertBefore(signatureNode, parentNode.getFirstChild());
    }
  }

  /**
   * Finds a signature element based on this object's settings.
   * 
   * @param document
   *          the document to locate the signature element
   * @return the signature element or null if no Signature element is found
   * @throws XPathExpressionException
   *           for XPath selection errors
   */
  public Element getSignature(final Document document) throws XPathExpressionException {
    List<Node> nodes = new ArrayList<>();
    if (this.xPathExpression != null) {
      NodeList _nodes = (NodeList) this.xPathExpression.evaluate(document, XPathConstants.NODESET);
      if (_nodes.getLength() == 0) {
        return null;
      }
      for (int i = 0; i < _nodes.getLength(); i++) {
        nodes.add(_nodes.item(i));
      }
    }
    else {
      nodes.add(document.getDocumentElement());
    }

    // If we get more than one hit for the parent node, we fail if more than one holds a signature element.
    //
    Element signatureElement = null;
    for (Node parentNode : nodes) {
      if (parentNode.getNodeType() == Node.DOCUMENT_NODE) {
        parentNode = ((Document) parentNode).getDocumentElement();
      }
      final NodeList childs = parentNode.getChildNodes();
      if (childs.getLength() == 0) {
        continue;
      }
      // Skip comments
      int pos = ChildPosition.LAST == this.childPosition ? childs.getLength() - 1 : 0;
      Node signatureNode = null;
      while (signatureNode == null && pos >= 0 && pos < childs.getLength()) {
        if (childs.item(pos).getNodeType() == Node.COMMENT_NODE) {
          if (ChildPosition.LAST == this.childPosition) {
            pos--;
          }
          else {
            pos++;
          }
        }
        else {
          signatureNode = childs.item(pos);
        }
      }
      if (signatureNode != null && signatureNode.getNodeType() == Node.ELEMENT_NODE) {
        if (javax.xml.crypto.dsig.XMLSignature.XMLNS.equals(signatureNode.getNamespaceURI())
            && "Signature".equals(signatureNode.getLocalName())) {
          if (signatureElement != null) {
            throw new XPathExpressionException("XPath expression found more than one Signature element");
          }
          signatureElement = (Element) signatureNode;
        }
      }
    }

    return signatureElement;
  }

  /**
   * Method that can be used to verify that the supplied XPath expression can be used for the supplied document.
   * 
   * @param document
   *          the document to evaluate the XPath expression against
   * @throws XPathExpressionException
   *           if the XPath expression is incorrect (does not find a node)
   */
  public void testInsert(final Document document) throws XPathExpressionException {
    if (this.xPathExpression != null) {
      Node parentNode = (Node) this.xPathExpression.evaluate(document, XPathConstants.NODE);
      if (parentNode == null) {
        throw new XPathExpressionException(String.format("Could not find XML node for insertion of Signature - XPath: %s", xPath));
      }
      log.debug("XPath expression '{}' evaluated to node '{}'", this.xPath, parentNode.getLocalName());
    }
  }

}
