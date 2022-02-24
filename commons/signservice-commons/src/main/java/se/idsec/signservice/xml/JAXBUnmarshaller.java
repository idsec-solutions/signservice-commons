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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.w3c.dom.Node;

/**
 * Utility class for JAXB unmarshalling.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JAXBUnmarshaller {

  /**
   * Utility method for unmarshalling a DOM node into a JAXB object.
   * 
   * @param node
   *          the DOM node
   * @param clazz
   *          the type of the resulting JAXB object
   * @return a JAXB object of type T
   * @throws JAXBException
   *           for unmarshalling errors
   */
  public static <T> T unmarshall(final Node node, Class<T> clazz) throws JAXBException {
    JAXBContext context = JAXBContextUtils.createJAXBContext(clazz);
    Unmarshaller unmarshaller = context.createUnmarshaller();
    Object jaxbObject = unmarshaller.unmarshal(node);
    if (JAXBElement.class.isInstance(jaxbObject)) {
      JAXBElement<?> jaxbElm = JAXBElement.class.cast(jaxbObject);
      return clazz.cast(jaxbElm.getValue());
    }
    else {
      return clazz.cast(jaxbObject);
    }
  }
  
  // Hidden constructor
  private JAXBUnmarshaller() {    
  }
 
}
