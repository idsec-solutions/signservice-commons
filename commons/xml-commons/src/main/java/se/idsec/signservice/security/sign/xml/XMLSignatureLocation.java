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

import javax.annotation.Nonnull;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import lombok.extern.slf4j.Slf4j;

/**
 * Tells where in an XML document the signature should be inserted.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLSignatureLocation {

  /**
   * Enum for indicating the insertion point within a selected parent node.
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
  public XMLSignatureLocation(@Nonnull final ChildPosition childPosition) {
    this.childPosition = childPosition;
  }

  /**
   * Constructor accepting an XPath expression for finding the parent element of where we should insert the signature
   * element. Note that the result of evaluating the XPath expression <b>MUST</b> be one single node.
   * <p>
   * <b>Note</b>: Beware of that the document supplied to {@link #insertSignature(Element, Document)} may be created
   * using a namespace aware parser and you may want to use the {@code local-name()} XPath construct.
   * </p>
   * 
   * @param parentXPath
   *          XPath expression for locating the parent node of the signature element
   * @param childPosition
   *          whether to insert the signature as the first or last child of the given parent node
   * @throws XPathExpressionException
   *           for illegal XPath expressions
   */
  public XMLSignatureLocation(@Nonnull final String parentXPath, @Nonnull final ChildPosition childPosition)
      throws XPathExpressionException {
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
  public void insertSignature(@Nonnull final Element signature, @Nonnull final Document document) throws XPathExpressionException {

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
   * Method that can be used to verify that the supplied XPath expression can be used for the supplied document.
   * 
   * @param document
   *          the document to evaluate the XPath expression against
   * @throws XPathExpressionException
   *           if the XPath expression is incorrect (does not find a node)
   */
  public void test(@Nonnull final Document document) throws XPathExpressionException {
    if (this.xPathExpression != null) {
      Node parentNode = (Node) this.xPathExpression.evaluate(document, XPathConstants.NODE);
      log.debug("XPath expression '{}' evaluated to node '{}'", this.xPath, parentNode.getLocalName());
    }
  }

}
