/*
 * Copyright 2019-2024 IDsec Solutions AB
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Testing the ProtocolVersion.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProtocolVersionTest {

  @Test
  public void testVersionComparator() {

    Assertions.assertEquals(0, this.compare("1", "1"));
    Assertions.assertEquals(0, this.compare("1", "1."));
    Assertions.assertEquals(0, this.compare("1.2", "1.2"));
    Assertions.assertEquals(0, this.compare("1.13.2", "1.13.2"));
    Assertions.assertEquals(0, this.compare("1.2.3.4.5.6.7.8", "1.2.3.4.5.6.7.8"));
    Assertions.assertEquals(0, this.compare("1.2.0", "1.2"));
    Assertions.assertEquals(0, this.compare("1.0.0", "1"));
    Assertions.assertTrue(this.compare("1.15", "1.5") > 0);
    Assertions.assertTrue(this.compare("1.5", "1.15") < 0);
    Assertions.assertTrue(this.compare("1.5.1.11", "1.5.1.9") > 0);
    Assertions.assertTrue(this.compare("1.5.1.9", "1.5.1.11") < 0);
    Assertions.assertTrue(this.compare("1.5.1", "1.5") > 0);
    Assertions.assertTrue(this.compare("1.5", "1.5.1") < 0);
    Assertions.assertTrue(this.compare("2.5", "1.15") > 0);
    Assertions.assertTrue(this.compare("1.15", "2.5") < 0);
  }

  @Test
  public void testIllegalVersionString1() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      ProtocolVersion.valueOf("1.sdfsdfsdf");
    });
  }

  @Test
  public void testIllegalVersionString2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      ProtocolVersion.valueOf("not a number");
    });
  }

  @Test
  public void testIllegalVersionString3() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      ProtocolVersion.valueOf("");
    });
  }

  @Test
  public void testIllegalVersionString4() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      ProtocolVersion.valueOf(".");
    });
  }

  @Test
  public void testIllegalVersionString5() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      ProtocolVersion.valueOf("1..6");
    });
  }

  private int compare(final String version, final String otherVersion) {
    return ProtocolVersion.valueOf(version).compareTo(ProtocolVersion.valueOf(otherVersion));
  }

}
