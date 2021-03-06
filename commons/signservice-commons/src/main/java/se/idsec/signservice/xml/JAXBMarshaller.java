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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.w3c.dom.Document;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * Utility class for marshalling of JAXB objects.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JAXBMarshaller {

  /** Namespace prefix mapper. */
  private static NamespacePrefixMapper namespacePrefixMapper = new CustomNamespaceMapper();

  /**
   * Marshalls the supplied JAXB object into a DOM document.
   * <p>
   * Note: elements not having the {@code XmlRootElement} annotation will not be possible to marshall using this method.
   * Instead use the {@link #marshallNonRootElement(JAXBElement)}.
   * </p>
   * 
   * @param jaxbObject
   *          the object to marshall
   * @return the DOM document
   * @throws JAXBException
   *           for marshalling errors
   */
  public static Document marshall(final Object jaxbObject) throws JAXBException {
    Document document = DOMUtils.createDocumentBuilder().newDocument();
    JAXBContext context = JAXBContextUtils.createJAXBContext(jaxbObject.getClass());
    Marshaller marshaller = context.createMarshaller();
    marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper", namespacePrefixMapper);
    marshaller.marshal(jaxbObject, document);
    return document;
  }

  /**
   * Marshalls a JAXB object that is not an XML root element (i.e. it is not annotated with {@code XmlRootElement}). In
   * order to get a {@code JAXBElement} for the object use the {@code ObjectFactory}'s create method.
   * 
   * @param jaxbElement
   *          the element to marshall
   * @return the DOM document
   * @throws JAXBException
   *           for marshalling errors
   */
  public static Document marshallNonRootElement(final JAXBElement<?> jaxbElement) throws JAXBException {
    Document document = DOMUtils.createDocumentBuilder().newDocument();
    JAXBContext context = JAXBContextUtils.createJAXBContext(jaxbElement.getDeclaredType());
    Marshaller marshaller = context.createMarshaller();
    marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper", namespacePrefixMapper);
    marshaller.marshal(jaxbElement, document);
    return document;
  }
  
  // Hidden constructor
  private JAXBMarshaller() {    
  }

}
