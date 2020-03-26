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
import javax.xml.bind.JAXBException;

import org.junit.Assert;
import org.junit.Test;

/**
 * Test cases for {@code JAXBContextUtils}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JAXBContextUtilsTest {

  @Test
  public void testGetPackageNames() throws Exception {
    Assert.assertEquals(buildPackageString("org.apache.xml.security.binding.xmlenc11",
      org.apache.xml.security.binding.xmlenc11.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(org.apache.xml.security.binding.xmlenc11.ConcatKDFParamsType.class));
    
    Assert.assertEquals(buildPackageString("org.apache.xml.security.binding.xmlenc",
      org.apache.xml.security.binding.xmlenc.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(org.apache.xml.security.binding.xmlenc.EncryptionMethodType.class));
    
    Assert.assertEquals(buildPackageString("org.apache.xml.security.binding.xmldsig11",
      org.apache.xml.security.binding.xmldsig11.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(org.apache.xml.security.binding.xmldsig11.ECValidationDataType.class));
    
    Assert.assertEquals(buildPackageString("org.apache.xml.security.binding.xmldsig", 
      org.apache.xml.security.binding.xmldsig.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(org.apache.xml.security.binding.xmldsig.SignatureType.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.cert.authcont.saci_1_0", 
      se.swedenconnect.schemas.cert.authcont.saci_1_0.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.csig.dssext_1_1", 
      se.swedenconnect.schemas.csig.dssext_1_1.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.csig.dssext_1_1.CertRequestProperties.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.etsi.xades_1_4_1",
      se.swedenconnect.schemas.etsi.xades_1_4_1.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.etsi.xades_1_4_1.RecomputedDigestValue.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.etsi.xades_1_3_2",
      se.swedenconnect.schemas.etsi.xades_1_3_2.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.etsi.xades_1_3_2.CounterSignature.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.cert.authcont.ext_auth_info_1_0",
      se.swedenconnect.schemas.cert.authcont.ext_auth_info_1_0.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.cert.authcont.ext_auth_info_1_0.ExtAuthInfo.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.dss_1_0",
      se.swedenconnect.schemas.dss_1_0.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.dss_1_0.AttachmentReference.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.saml_1_1.assertion",
      se.swedenconnect.schemas.saml_1_1.assertion.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.saml_1_1.assertion.Attribute.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.saml_2_0.assertion",
      se.swedenconnect.schemas.saml_2_0.assertion.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement.class));
    
    Assert.assertEquals(buildPackageString("se.swedenconnect.schemas.csig.sap_1_1",
      se.swedenconnect.schemas.csig.sap_1_1.JAXBContextFactory.getDependentPackages()),
      JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.csig.sap_1_1.SADRequest.class));
    
    // Verify that caching works
    String d1 = JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.csig.sap_1_1.SADRequest.class);
    String d2 = JAXBContextUtils.getPackageNames(se.swedenconnect.schemas.csig.sap_1_1.SADRequest.class);
    Assert.assertTrue(d1 == d2);
    
    // No registered dependent package names ...
    String e = JAXBContextUtils.getPackageNames(java.lang.Integer.class);
    Assert.assertEquals("java.lang", e);
  }
  
  @Test
  public void testCreateJAXBContext() throws Exception {
    JAXBContext c = JAXBContextUtils.createJAXBContext(se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement.class);
    Assert.assertNotNull(c);
    Assert.assertNotNull(c.createMarshaller());
    Assert.assertNotNull(c.createUnmarshaller());
    
    try {
      JAXBContextUtils.createJAXBContext(Integer.class);
      Assert.fail("Expected JAXBException");
    }
    catch (JAXBException e) {      
    }
  }

  private static String buildPackageString(final String pkg, final String[] dependencies) {
    StringBuffer sb = new StringBuffer(pkg);
    if (dependencies != null) {
      for (String p : dependencies) {
        sb.append(':').append(p);
      }
    }
    return sb.toString();
  }

}
