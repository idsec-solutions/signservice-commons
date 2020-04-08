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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Utilities for processing DOM documents.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DOMUtils {

  /** The document builder factory. */
  private static DocumentBuilderFactory documentBuilderFactory;

  /** DOM transformer for pretty printing of XML nodes. */
  private static Transformer prettyPrintTransformer;

  /** DOM transformer. */
  private static Transformer transformer;

  static {
    try {
      documentBuilderFactory = DocumentBuilderFactory.newInstance();
      documentBuilderFactory.setNamespaceAware(true);
      documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
      documentBuilderFactory.setXIncludeAware(false);
      documentBuilderFactory.setExpandEntityReferences(false);
    }
    catch (ParserConfigurationException e) {
      throw new InternalXMLException("Failed to setup document builder factory", e);
    }

    try {
      TransformerFactory transformerFactory = TransformerFactory.newInstance();
      prettyPrintTransformer = transformerFactory.newTransformer();
      prettyPrintTransformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
      prettyPrintTransformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
      prettyPrintTransformer.setOutputProperty(OutputKeys.METHOD, "xml");
      prettyPrintTransformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      prettyPrintTransformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
      prettyPrintTransformer.setOutputProperty(OutputKeys.INDENT, "yes");

      transformer = transformerFactory.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
    }
    catch (TransformerConfigurationException e) {
      throw new InternalXMLException("Failed to setup transformer", e);
    }
  }

  /**
   * Creates a new {link DocumentBuilder} instance.
   * <p>
   * The document builder factory used is created according to the <a href=
   * "https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J">
   * OWASP recommendations</a> for XML External Entity Prevention.
   * </p>
   * 
   * @return a "safe" DocumentBuilder instance
   */
  public static DocumentBuilder createDocumentBuilder() {
    try {
      return documentBuilderFactory.newDocumentBuilder();
    }
    catch (ParserConfigurationException e) {
      throw new InternalXMLException("Failed to create document builder", e);
    }
  }

  /**
   * Pretty prints the supplied XML node to a string.
   * 
   * @param node
   *          the XML node to pretty print
   * @return a formatted string
   */
  public static String prettyPrint(final Node node) {
    if (node == null) {
      return "";
    }
    try {
      final StringWriter writer = new StringWriter();
      prettyPrintTransformer.transform(new DOMSource(node), new StreamResult(writer));
      return writer.toString();
    }
    catch (Exception e) {
      return "";
    }
  }

  /**
   * Transforms the supplied XML node into its canonical byte representation.
   * 
   * @param node
   *          the XML node to transform
   * @return a byte array holding the XML document bytes
   */
  public static byte[] nodeToBytes(final Node node) {
    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      transformer.transform(new DOMSource(node), new StreamResult(output));
      return output.toByteArray();
    }
    catch (TransformerException e) {
      throw new InternalXMLException("Failed to transform XML node to bytes", e);
    }
  }

  /**
   * Transforms the supplied XML node into its canonical byte representation and Base64-encoded these bytes.
   * 
   * @param node
   *          the XML node to transform
   * @return the Base64-encoding of the XML node
   */
  public static String nodeToBase64(final Node node) {
    return Base64.getEncoder().encodeToString(nodeToBytes(node));
  }

  /**
   * Parses an input stream into a DOM document.
   * 
   * @param stream
   *          the stream
   * @return a DOM document
   */
  public static Document inputStreamToDocument(final InputStream stream) {
    try {
      return createDocumentBuilder().parse(stream);
    }
    catch (SAXException | IOException e) {
      throw new InternalXMLException("Failed to decode bytes into DOM document", e);
    }
  }

  /**
   * Parses a byte array into a DOM document.
   * 
   * @param bytes
   *          the bytes to parse
   * @return a DOM document
   */
  public static Document bytesToDocument(final byte[] bytes) {
    return inputStreamToDocument(new ByteArrayInputStream(bytes));
  }

  /**
   * Decodes a Base64 string and parses it into a DOM document.
   * 
   * @param base64
   *          the Base64-encoded string
   * @return a DOM document
   */
  public static Document base64ToDocument(final String base64) {
    try {
      return bytesToDocument(Base64.getDecoder().decode(base64));
    }
    catch (IllegalArgumentException e) {
      throw new InternalXMLException("Invalid Base64");
    }
  }
  
  // Hidden constructor
  private DOMUtils() {
  }

}
