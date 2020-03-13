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
package se.idsec.signservice.security.sign.xml.impl;

import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.xml.XMLTestBase;

/**
 * Test cases for {@code DefaultXMLSignatureValidator}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultXMLSignatureValidatorTest extends XMLTestBase {

  @Test
  public void testValidate1() throws Exception {
    final Document document = getDocument("signResponse1.xml");
    
    DefaultXMLSignatureValidator validator = new DefaultXMLSignatureValidator(Arrays.asList(getCertificate("konki-sign.crt")));
    validator.setXadesProcessing(false);
    
    List<SignatureValidationResult> result = validator.validate(document);
    Assert.assertEquals(1, result.size());
    Assert.assertTrue(result.get(0).isSuccess());
  }


}
