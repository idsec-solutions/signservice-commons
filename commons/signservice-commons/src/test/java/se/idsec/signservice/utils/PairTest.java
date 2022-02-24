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

import java.util.HashMap;

import org.junit.Assert;
import org.junit.Test;


/**
 * Test cases for Pair.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PairTest {

  @SuppressWarnings("unlikely-arg-type")
  @Test
  public void testPair() throws Exception {
    
    // Not much to test, but it is nice with 100% code coverage.
    
    Pair<String, String> p1 = new Pair<>("a1", "b1");
    Assert.assertEquals("a1", p1.getFirst());
    Assert.assertEquals("b1", p1.getSecond());
    Pair<String, String> p11 = new Pair<>("a1", "b1");
    
    Pair<String, String> p2 = new Pair<>("c", "d");
    Pair<String, String> p3 = new Pair<>("c", null);
    
    Assert.assertTrue(p1.equals(p1));
    Assert.assertTrue(p1.equals(p11));
    Assert.assertFalse(p1.equals(p2));
    Assert.assertFalse(p1.equals(null));
    Assert.assertFalse(p1.equals(new HashMap<>()));
    Assert.assertFalse(p2.equals(p3));
    
    String s1 = p1.toString();
    Assert.assertTrue(s1.contains("a1") && s1.contains("b1"));
    String s3 = p3.toString();
    Assert.assertTrue(s3.contains("c") && s3.contains("null"));
    
    Assert.assertEquals(p1.hashCode(), p11.hashCode());
  }
  
}
