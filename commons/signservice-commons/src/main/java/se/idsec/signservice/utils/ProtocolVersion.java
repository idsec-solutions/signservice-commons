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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A representation of a protocol version.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProtocolVersion implements Comparable<ProtocolVersion> {

  /** The version in string format. */
  private final String versionString;

  /** The components of the version. */
  private final List<Integer> versionComponents;

  /**
   * Constructor
   *
   * @param version
   *          the version as a string of integer values separated by "."
   */
  public ProtocolVersion(final String version) {
    this.versionString = Optional.ofNullable(version)
      .map(String::trim)
      .orElseThrow(() -> new IllegalArgumentException("version must not be null"));

    try {
      this.versionComponents = new ArrayList<>();
      final String[] components = version.split("\\.");
      for (final String s : components) {
        final Integer i = Integer.valueOf(s);
        if (i < 0) {
          throw new IllegalArgumentException("Negative version components are not allowed");
        }
        this.versionComponents.add(i);
      }
      if (this.versionComponents.isEmpty()) {
        throw new IllegalArgumentException("Invalid version string");
      }
    }
    catch (final NumberFormatException e) {
      throw new IllegalArgumentException("Invalid version string");
    }
  }

  /**
   * Creates a {@code ProtocolVersion} object given a version in string format.
   *
   * @param version
   *          the version string
   * @return a ProtocolVersion object
   */
  public static ProtocolVersion valueOf(final String version) {
    return new ProtocolVersion(version);
  }

  /** {@inheritDoc} */
  @Override
  public int compareTo(final ProtocolVersion o) {
    final int maxCount = Math.max(this.versionComponents.size(), o.versionComponents.size());

    for (int i = 0; i < maxCount; i++) {
      final Integer thisValue = i < this.versionComponents.size() ? this.versionComponents.get(i) : 0;
      final Integer compareValue = i < o.versionComponents.size() ? o.versionComponents.get(i) : 0;
      if (thisValue != compareValue) {
        return thisValue - compareValue;
      }
    }
    return 0;
  }

  /**
   * Compares the given version string with this object. See {@link #compareTo(ProtocolVersion)}.
   *
   * @param o
   *          the version string to compare with this object
   * @return a negative value if this object is less than the specified version, 0 if they are equal, and a positive
   *         value if this object is greater than the supplied version
   */
  public int compareTo(final String o) {
    return this.compareTo(ProtocolVersion.valueOf(o));
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.versionComponents);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj instanceof String) {
      try {
        return this.compareTo((String) obj) == 0;
      }
      catch (final Exception e) {
        return false;
      }
    }
    else if (!(obj instanceof ProtocolVersion)) {
      return false;
    }
    return this.compareTo((ProtocolVersion) obj) == 0;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.versionString;
  }

}
