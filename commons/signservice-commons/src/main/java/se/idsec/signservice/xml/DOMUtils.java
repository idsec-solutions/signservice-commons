/*
 * Copyright 2019-2022 IDsec Solutions AB
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
import java.util.Collections;
import java.util.Map;
import java.util.Queue;
import java.util.WeakHashMap;
import java.util.concurrent.ArrayBlockingQueue;

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

import org.w3c.dom.DOMException;
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

  /** We lovingly borrow from Apache's xmlsec ... States the parser pool size. */
  private static int parserPoolSize = Integer.getInteger("org.apache.xml.security.parser.pool-size", 20);

  /** Map of classloaders and queues of document builders. */
  private static final Map<ClassLoader, Queue<DocumentBuilder>> documentBuilders = Collections.synchronizedMap(
      new WeakHashMap<>());

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
    catch (final ParserConfigurationException e) {
      throw new RuntimeException("Failed to setup document builder factory", e);
    }

    try {
      final TransformerFactory transformerFactory = TransformerFactory.newInstance();
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
    catch (final TransformerConfigurationException e) {
      throw new RuntimeException("Failed to setup transformer", e);
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
    catch (final ParserConfigurationException e) {
      throw new DOMException(DOMException.NOT_SUPPORTED_ERR, "Failed to create document builder");
    }
  }

  /**
   * Pretty prints the supplied XML node to a string.
   *
   * @param node the XML node to pretty print
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
    catch (final Exception e) {
      return "";
    }
  }

  /**
   * Transforms the supplied XML node into its canonical byte representation.
   *
   * @param node the XML node to transform
   * @return a byte array holding the XML document bytes
   */
  public static byte[] nodeToBytes(final Node node) {
    try {
      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      transformer.transform(new DOMSource(node), new StreamResult(output));
      return output.toByteArray();
    }
    catch (final TransformerException e) {
      throw new DOMException(DOMException.NOT_SUPPORTED_ERR, "Failed to transform XML node to bytes");
    }
  }

  /**
   * Transforms the supplied XML node into its canonical byte representation and Base64-encoded these bytes.
   *
   * @param node the XML node to transform
   * @return the Base64-encoding of the XML node
   */
  public static String nodeToBase64(final Node node) {
    return Base64.getEncoder().encodeToString(nodeToBytes(node));
  }

  /**
   * Parses an input stream into a DOM document.
   *
   * @param stream the stream
   * @return a DOM document
   */
  public static Document inputStreamToDocument(final InputStream stream) {

    ClassLoader loader = Thread.currentThread().getContextClassLoader();
    if (loader == null) {
      loader = DOMUtils.class.getClassLoader();
    }
    if (loader == null) {
      try {
        return createDocumentBuilder().parse(stream);
      }
      catch (SAXException | IOException e) {
        throw new DOMException(DOMException.SYNTAX_ERR, "Failed to decode bytes into DOM document");
      }
    }
    final Queue<DocumentBuilder> queue = getDocumentBuilderPool(loader);
    final DocumentBuilder documentBuilder = getDocumentBuilder(queue);
    try {
      return documentBuilder.parse(stream);
    }
    catch (SAXException | IOException e) {
      throw new DOMException(DOMException.SYNTAX_ERR, "Failed to decode bytes into DOM document");
    }
    finally {
      returnToPool(documentBuilder, queue);
    }
  }

  /**
   * Parses a byte array into a DOM document.
   *
   * @param bytes the bytes to parse
   * @return a DOM document
   */
  public static Document bytesToDocument(final byte[] bytes) {
    return inputStreamToDocument(new ByteArrayInputStream(bytes));
  }

  /**
   * Decodes a Base64 string and parses it into a DOM document.
   *
   * @param base64 the Base64-encoded string
   * @return a DOM document
   */
  public static Document base64ToDocument(final String base64) {
    return bytesToDocument(Base64.getDecoder().decode(base64));
  }

  /**
   * Gets a document builder pool (queue) for the given class loader.
   *
   * @param loader the class loader
   * @return a queue of document builders
   */
  private static Queue<DocumentBuilder> getDocumentBuilderPool(final ClassLoader loader) {
    Queue<DocumentBuilder> queue = documentBuilders.get(loader);
    if (queue == null) {
      queue = new ArrayBlockingQueue<>(parserPoolSize);
      documentBuilders.put(loader, queue);
    }
    return queue;
  }

  /**
   * Gets a document builder from the given queue. If no document builder is available a new one is created.
   *
   * @param queue the queue
   * @return a document builder
   */
  private static DocumentBuilder getDocumentBuilder(final Queue<DocumentBuilder> queue) {
    DocumentBuilder documentBuilder = queue.poll();
    if (documentBuilder == null) {
      documentBuilder = createDocumentBuilder();
    }
    return documentBuilder;
  }

  /**
   * Returns the given document builder to the pool (queue).
   *
   * @param documentBuilder the document builder
   * @param queue the pool
   */
  private static void returnToPool(final DocumentBuilder documentBuilder, final Queue<DocumentBuilder> queue) {
    if (queue != null) {
      documentBuilder.reset();
      queue.offer(documentBuilder);
    }
  }

  // Hidden constructor
  private DOMUtils() {
  }

}
