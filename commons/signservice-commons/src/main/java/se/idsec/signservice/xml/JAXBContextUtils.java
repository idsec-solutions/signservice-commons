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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

/**
 * Utilities for creating {@code JAXBContext} objects.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JAXBContextUtils {

  /** Cache of queried package dependencies. */
  private static ConcurrentMap<String, String> packageCache = new ConcurrentHashMap<>();
  
  static {
    // Fill the package cache with Apache xmlsec settings ...
    packageCache.put("org.apache.xml.security.binding.excc14n", "");
    packageCache.put("org.apache.xml.security.binding.xmldsig", "");
    packageCache.put("org.apache.xml.security.binding.xmldsig.pss", "org.apache.xml.security.binding.xmldsig");      
    packageCache.put("org.apache.xml.security.binding.xmldsig11", "org.apache.xml.security.binding.xmldsig");
    packageCache.put("org.apache.xml.security.binding.xmlenc", "org.apache.xml.security.binding.xmldsig");
    packageCache.put("org.apache.xml.security.binding.xmlenc11", 
      "org.apache.xml.security.binding.xmldsig:org.apache.xml.security.binding.xmlenc");
    packageCache.put("org.apache.xml.security.binding.xop", "");
  }

  /**
   * Returns a string holding the comma-separated package names that are required to create a {@link JAXBContext} that
   * can marshall and unmarshall the given class.
   * 
   * @param clazz
   *          JAXB class
   * @return a string of package names (never empty)
   */
  public static String getPackageNames(final Class<?> clazz) {
    //
    // For the Sweden Connect JAXB libraries we always have a JAXBContextFactory class that knows about
    // which packages that implement the classes that corresponds to schema includes for the schema that
    // holds the given class.
    // For Apache xmlsec classes we handle it by our static configuration. 
    //
    final String packageName = clazz.getPackage().getName();
    String dependentPackages = packageCache.get(packageName);
    if (dependentPackages == null) {
      try {
        Class<?> jaxbFactory = Class.forName(packageName + ".JAXBContextFactory");
        Method method = jaxbFactory.getMethod("getDependentPackages");
        final String[] packagesArray = (String[]) method.invoke(null);
        StringBuffer sb = new StringBuffer();
        for (String p : packagesArray) {
          if (sb.length() > 0) {
            sb.append(':');
          }
          sb.append(p);
        }
        dependentPackages = sb.toString();
      }
      catch (ClassNotFoundException | NoSuchMethodException | SecurityException
          | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
        dependentPackages = "";
      }
      packageCache.put(packageName, dependentPackages);
    }
    return dependentPackages.isEmpty() ? packageName : packageName + ":" + dependentPackages;
  }

  /**
   * Creates a {@link JAXBContext} instance that can be used to marshall/unmarshall the given JAXB class.
   * 
   * @param clazz the class
   * @return a JAXBContext instance
   * @throws JAXBException for JAXB errors
   */
  public static JAXBContext createJAXBContext(Class<?> clazz) throws JAXBException {
    return JAXBContext.newInstance(getPackageNames(clazz));
  }

  // Hidden constructor.
  private JAXBContextUtils() {
  }

}
