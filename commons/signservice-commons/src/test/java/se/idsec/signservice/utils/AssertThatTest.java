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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * Test cases for {@code AssertThat}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AssertThatTest {

  @Test
  public void testIsTrue1() throws Exception {
    AssertThat.isTrue(true, "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsTrue2() throws Exception {
    AssertThat.isTrue(1 == 5, "Msg");
  }
  
  @Test
  public void testIsFalse1() throws Exception {
    AssertThat.isFalse(false, "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsFalse2() throws Exception {
    AssertThat.isFalse(true, "Msg");
  }
  
  @Test
  public void testIsNotNull1() throws Exception {
    AssertThat.isNotNull(new String(), "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotNull2() throws Exception {
    AssertThat.isNotNull(null, "Msg");
  }
  
  @Test
  public void testIsNull1() throws Exception {
    AssertThat.isNull(null, "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsNull2() throws Exception {
    AssertThat.isNull(new String(), "Msg");
  }
  
  @Test
  public void testHasText1() throws Exception {
    AssertThat.hasText("This is text", "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testHasText2() throws Exception {
    AssertThat.hasText(null, "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testHasText3() throws Exception {
    AssertThat.hasText(new String(), "Msg");
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testHasText4() throws Exception {
    AssertThat.hasText(new String("   "), "Msg");
  }
  
  @Test
  public void testIsNotEmpty_Array1() throws Exception {
    AssertThat.isNotEmpty(new Integer[] { 1 }, "Msg");
  }
    
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotEmpty_Array2() throws Exception {
    AssertThat.isNotEmpty((Integer[]) null, "Msg");
  }  
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotEmpty_Array3() throws Exception {
    AssertThat.isNotEmpty(new Integer[] { }, "Msg");
  }
  
  @Test
  public void testIsNotEmpty_Collection1() throws Exception {
    AssertThat.isNotEmpty(Collections.singleton(Integer.valueOf(1)), "Msg");
    AssertThat.isNotEmpty(Collections.singletonList(Integer.valueOf(1)), "Msg");
  }
    
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotEmpty_Collection2() throws Exception {
    AssertThat.isNotEmpty((Collection<?>) null, "Msg");
  }  
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotEmpty_Collection3() throws Exception {
    AssertThat.isNotEmpty(Collections.emptyList(), "Msg");
  }
  
  @Test
  public void testIsNotEmpty_Map1() throws Exception {
    Map<String, String> m = new HashMap<>();
    m.put("1", "2");
    AssertThat.isNotEmpty(m, "Msg");
  }
    
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotEmpty_Map2() throws Exception {
    AssertThat.isNotEmpty((Map<?,?>) null, "Msg");
  }  
  
  @Test(expected = IllegalArgumentException.class)
  public void testIsNotEmpty_Map3() throws Exception {
    AssertThat.isNotEmpty(new HashMap<>(), "Msg");
  }

}
