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

import java.util.Objects;

/**
 * Representation of a Pair.
 * 
 * @param <T1>
 *          type of the first element
 * @param <T2>
 *          type of the second element
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pair<T1, T2> {

  /** The first element. */
  private final T1 first;

  /** The second element. */
  private final T2 second;

  /**
   * Constructor.
   * 
   * @param first
   *          the first element
   * @param second
   *          the second element
   */
  public Pair(final T1 first, final T2 second) {
    this.first = first;
    this.second = second;
  }

  /**
   * Get the first element.
   * 
   * @return the first element
   */
  public T1 getFirst() {
    return this.first;
  }

  /**
   * Gets the second element.
   * 
   * @return the second element
   */
  public T2 getSecond() {
    return this.second;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.first, this.second);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (!(obj instanceof Pair)) {
      return false;
    }
    Pair<?, ?> other = (Pair<?, ?>) obj;
    return Objects.equals(this.first, other.first) && Objects.equals(this.second, other.second);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "Pair [first=" + this.first + ", second=" + this.second + "]";
  }

}
