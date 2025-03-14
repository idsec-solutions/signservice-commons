/*
 * Copyright 2019-2025 IDsec Solutions AB
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
package se.idsec.signservice.security.sign.pdf.document;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

class VisibleSignatureImageTest {

  @Test
  void testCreateDateFormatterWithNullValues() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    final SimpleDateFormat formatter = visibleSignatureImage.createDateFormatter();
    Assertions.assertEquals(VisibleSignatureImage.DEFAULT_DATE_FORMAT, formatter.toPattern());
    Assertions.assertEquals(VisibleSignatureImage.DEFAULT_TIMEZONE, formatter.getTimeZone());
  }

  @Test
  void testCreateDateFormatterWithCustomValues() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    visibleSignatureImage.setDateFormat("yyyy-MM-dd HH:mm z");
    visibleSignatureImage.setTimeZoneId("UTC");
    final SimpleDateFormat formatter = visibleSignatureImage.createDateFormatter();
    Assertions.assertEquals("yyyy-MM-dd HH:mm z", formatter.toPattern());
    Assertions.assertEquals(TimeZone.getTimeZone("UTC"), formatter.getTimeZone());
  }

  @Test
  void testCreateDateFormatterSweden() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    visibleSignatureImage.setDateFormat("yyyy-MM-dd HH:mm:ss z");
    visibleSignatureImage.setTimeZoneId("Europe/Stockholm");
    final SimpleDateFormat formatter = visibleSignatureImage.createDateFormatter();

    Assertions.assertEquals("1970-01-01 01:00:00 CET", formatter.format(new Date(0)));
  }

  @Test
  void setTimeZoneId_Should_ThrowException_When_ZoneIdIsInvalid() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    Assertions.assertThrows(IllegalArgumentException.class,
        () -> visibleSignatureImage.setTimeZoneId("invalid/zoneid"));
    Assertions.assertThrows(IllegalArgumentException.class,
        () -> VisibleSignatureImage.builder().timeZoneId("invalid/zoneid").build());
  }

  @Test
  void setTimeZoneId_Should_NotThrowException_When_ZoneIdIsValid() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    Assertions.assertDoesNotThrow(() -> visibleSignatureImage.setTimeZoneId("Europe/Stockholm"));
    Assertions.assertDoesNotThrow(() -> VisibleSignatureImage.builder().timeZoneId("Europe/Stockholm").build());
  }

  @Test
  void setDateFormat_Should_ThrowException_When_FormatIsInvalid() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    Assertions.assertThrows(IllegalArgumentException.class,
        () -> visibleSignatureImage.setDateFormat("invalid/format"));

    Assertions.assertThrows(IllegalArgumentException.class,
        () -> VisibleSignatureImage.builder().dateFormat("invalid/format").build());
  }

  @Test
  void setDateFormat_Should_NotThrowException_When_FormatIsValid() {
    final VisibleSignatureImage visibleSignatureImage = new VisibleSignatureImage();
    Assertions.assertDoesNotThrow(() -> visibleSignatureImage.setDateFormat("yyyy-MM-dd HH:mm z"));
    Assertions.assertDoesNotThrow(() -> VisibleSignatureImage.builder().dateFormat("yyyy-MM-dd HH:mm z").build());
  }
}
