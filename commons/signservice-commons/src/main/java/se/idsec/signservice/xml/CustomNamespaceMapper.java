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

import java.util.HashMap;
import java.util.Map;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * A customized namespace mapper that helps us getting the namespace prefixes when performing JAXB marshalling.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CustomNamespaceMapper extends NamespacePrefixMapper {

  /** Namespace to prefix map. */
  private Map<String, String> prefixMap;

  /** Mapping of namespaces to prefix strings. */
  private static String[][] namespaceToPrefixMapping = {
      { "http://www.w3.org/XML/1998/namespace", "xml" },
      { "http://www.w3.org/2001/XMLSchema", "xs" },
      { "http://www.w3.org/2001/XMLSchema-instance", "xsi" },
      { "http://www.w3.org/2000/09/xmldsig#", "ds" },
      { "http://www.w3.org/2001/04/xmlenc#", "xenc" },
      { "urn:oasis:names:tc:SAML:1.0:assertion", "saml" },
      { "urn:oasis:names:tc:SAML:2.0:assertion", "saml2" },
      { "urn:oasis:names:tc:dss:1.0:core:schema", "dss" },
      { "http://id.elegnamnden.se/csig/1.1/dss-ext/ns", "csig" },
      { "http://id.elegnamnden.se/csig/1.1/sap/ns", "sap" },
      { "http://uri.etsi.org/01903/v1.3.2#", "xades" },
      { "http://uri.etsi.org/01903/v1.4.1#", "xadesext" },
      { "http://id.elegnamnden.se/auth-cont/1.0/saci", "saci" },
      { "http://id.swedenconnect.se/auth-cont/1.0/ext-auth-info", "sacex" },
      { "http://www.w3.org/2009/xmldsig11#", "dsig11" },
      { "http://www.w3.org/2009/xmlenc11#", "xenc11" },
      { "http://www.w3.org/2001/10/xml-exc-c14n#", "ec" }
  };

  /**
   * Constructor.
   */
  public CustomNamespaceMapper() {
    this.prefixMap = new HashMap<>();
    for (String[] mapping : namespaceToPrefixMapping) {
      this.prefixMap.put(mapping[0], mapping[1]);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getPreferredPrefix(final String namespaceUri, final String suggestion, final boolean requirePrefix) {
    return this.prefixMap.getOrDefault(namespaceUri, suggestion);
  }

}
