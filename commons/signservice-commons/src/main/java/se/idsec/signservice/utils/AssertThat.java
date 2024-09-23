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

import org.apache.commons.lang3.StringUtils;

import java.util.Collection;
import java.util.Map;

/**
 * Utility class that helps us make assertions, for example when checking that all required properties have been
 * assigned.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AssertThat {

  /**
   * Asserts that a boolean expression evaluates to {@code true}.
   *
   * @param expression the boolean expression
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the expression is false
   */
  public static void isTrue(final boolean expression, final String message) {
    if (!expression) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that a boolean expression evaluates to {@code false}.
   *
   * @param expression the boolean expression
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the expression is true
   */
  public static void isFalse(final boolean expression, final String message) {
    if (expression) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that an object is not {@code null}.
   *
   * @param object the object to check
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the object is null
   */
  public static void isNotNull(final Object object, final String message) {
    if (object == null) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that an object is {@code null}.
   *
   * @param object the object to check
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the object is not null
   */
  public static void isNull(final Object object, final String message) {
    if (object != null) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that the given string contains text content, i.e., it must not be {@code null} and must contain at least
   * one non-whitespace character.
   *
   * @param text the string to check
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the text does not contain valid text content
   */
  public static void hasText(final String text, final String message) {
    if (StringUtils.isBlank(text)) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that an array contains elements, meaning it must not be {@code null} and must contain at least one
   * element.
   *
   * @param array the array to check
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the object array is null or contains no elements
   */
  public static void isNotEmpty(final Object[] array, final String message) {
    if (array == null || array.length == 0) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that a collection contains elements, meaning it must not be {@code null} and must contain at least one
   * element.
   *
   * @param collection the collection to check
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the collection is null or contains no elements
   */
  public static void isNotEmpty(final Collection<?> collection, final String message) {
    if (collection == null || collection.isEmpty()) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Asserts that a map contains entries, meaning it must not be {@code null} and must contain at least one entry.
   *
   * @param map the map to check
   * @param message the exception message to use if the assertion fails
   * @throws IllegalArgumentException if the map is null or contains no entries
   */
  public static void isNotEmpty(final Map<?, ?> map, final String message) {
    if (map == null || map.isEmpty()) {
      throw new IllegalArgumentException(message);
    }
  }

  // Hidden
  private AssertThat() {
  }

}
