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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test cases for {@code AssertThat}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AssertThatTest {

  @Test
  public void testIsTrue1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.isTrue(true, "Msg"));
  }

  @Test
  public void testIsTrue2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isTrue(1 == 5, "Msg"));
  }

  @Test
  public void testIsFalse1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.isFalse(false, "Msg"));
  }

  @Test
  public void testIsFalse2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isFalse(true, "Msg"));
  }

  @Test
  public void testIsNotNull1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.isNotNull("", "Msg"));
  }

  @Test
  public void testIsNotNull2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNotNull(null, "Msg"));
  }

  @Test
  public void testIsNull1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.isNull(null, "Msg"));
  }

  @Test
  public void testIsNull2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNull("", "Msg"));
  }

  @Test
  public void testHasText1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.hasText("This is text", "Msg"));
  }

  @Test
  public void testHasText2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.hasText(null, "Msg"));
  }

  @Test
  public void testHasText3() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.hasText("", "Msg"));
  }

  @Test
  public void testHasText4() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.hasText("   ", "Msg"));
  }

  @Test
  public void testIsNotEmpty_Array1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.isNotEmpty(new Integer[] { 1 }, "Msg"));
  }

  @Test
  public void testIsNotEmpty_Array2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNotEmpty((Integer[]) null, "Msg"));
  }

  @Test
  public void testIsNotEmpty_Array3() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNotEmpty(new Integer[] {}, "Msg"));
  }

  @Test
  public void testIsNotEmpty_Collection1() {
    Assertions.assertDoesNotThrow(() -> AssertThat.isNotEmpty(Collections.singleton(1), "Msg"));
    Assertions.assertDoesNotThrow(() -> AssertThat.isNotEmpty(List.of(1), "Msg"));
  }

  @Test
  public void testIsNotEmpty_Collection2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNotEmpty((Collection<?>) null, "Msg"));
  }

  @Test
  public void testIsNotEmpty_Collection3() {
    Assertions.assertThrows(IllegalArgumentException.class,
        () -> AssertThat.isNotEmpty(Collections.emptyList(), "Msg"));
  }

  @Test
  public void testIsNotEmpty_Map1() {
    Assertions.assertDoesNotThrow(() -> {
      final Map<String, String> m = new HashMap<>();
      m.put("1", "2");
      AssertThat.isNotEmpty(m, "Msg");
    });
  }

  @Test
  public void testIsNotEmpty_Map2() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNotEmpty((Map<?, ?>) null, "Msg"));
  }

  @Test
  public void testIsNotEmpty_Map3() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> AssertThat.isNotEmpty(new HashMap<>(), "Msg"));
  }

}
