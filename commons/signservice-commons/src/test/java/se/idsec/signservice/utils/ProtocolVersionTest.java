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
package se.idsec.signservice.utils;

import org.junit.Assert;
import org.junit.Test;

/**
 * Testing the ProtocolVersion.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProtocolVersionTest {

  @Test
  public void testVersionComparator() {

    Assert.assertEquals(0, compare("1", "1"));
    Assert.assertEquals(0, compare("1", "1."));
    Assert.assertEquals(0, compare("1.2", "1.2"));
    Assert.assertEquals(0, compare("1.13.2", "1.13.2"));
    Assert.assertEquals(0, compare("1.2.3.4.5.6.7.8", "1.2.3.4.5.6.7.8"));
    Assert.assertEquals(0, compare("1.2.0", "1.2"));
    Assert.assertEquals(0, compare("1.0.0", "1"));
    Assert.assertTrue(compare("1.15", "1.5") > 0);
    Assert.assertTrue(compare("1.5.1.11", "1.5.1.9") > 0);
    Assert.assertTrue(compare("1.5.1", "1.5") > 0);
    Assert.assertTrue(compare("2.5", "1.15") > 0);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalVersionString1() {
    ProtocolVersion.valueOf("1.sdfsdfsdf");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalVersionString2() {
    ProtocolVersion.valueOf("not a number");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalVersionString3() {
    ProtocolVersion.valueOf("");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalVersionString4() {
    ProtocolVersion.valueOf(".");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalVersionString5() {
    ProtocolVersion.valueOf("1..6");
  }

  private int compare(final String version, final String otherVersion) {
    return ProtocolVersion.valueOf(version).compareTo(ProtocolVersion.valueOf(otherVersion));
  }

}
