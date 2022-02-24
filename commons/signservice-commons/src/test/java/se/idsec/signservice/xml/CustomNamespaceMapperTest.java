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

import org.junit.Assert;
import org.junit.Test;

/**
 * Test cases for CustomNamespaceMapper.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CustomNamespaceMapperTest {

  @Test
  public void testMapper() throws Exception {
    CustomNamespaceMapper mapper = new CustomNamespaceMapper();
    
    String prefix = mapper.getPreferredPrefix("http://www.w3.org/2000/09/xmldsig#", null, true);
    Assert.assertEquals("ds", prefix);
    
    // Not registered
    prefix = mapper.getPreferredPrefix("http://www.w3.org/2000/09/custom#", "custom", true);
    Assert.assertEquals("custom", prefix);
    
    prefix = mapper.getPreferredPrefix("http://www.w3.org/2000/09/custom#", "custom", false);
    Assert.assertEquals("custom", prefix);
    
    prefix = mapper.getPreferredPrefix("http://www.w3.org/2000/09/custom#", null, true);
    Assert.assertNull(prefix);
  }

}
