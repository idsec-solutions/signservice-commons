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
package se.idsec.signservice.security.certificate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 * Utilities for handling X.509 certificates.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CertificateUtils {

  /** Factory for creating certificates. */
  private static final CertificateFactory factory;

  static {
    try {
      factory = CertificateFactory.getInstance("X.509");
    }
    catch (final CertificateException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Decodes a {@link X509Certificate} from its encoding.
   *
   * @param encoding the certificate encoding
   * @return a X509Certificate object
   * @throws CertificateException for decoding errors
   */
  public static X509Certificate decodeCertificate(final byte[] encoding) throws CertificateException {
    return decodeCertificate(new ByteArrayInputStream(encoding));
  }

  /**
   * Decodes a {@link X509Certificate} from an input stream.
   *
   * @param stream the stream to read
   * @return a X509Certificate object
   * @throws CertificateException for decoding errors
   */
  public static X509Certificate decodeCertificate(final InputStream stream) throws CertificateException {
    return (X509Certificate) factory.generateCertificate(stream);
  }

  /**
   * Decodes a {@link X509CRL} from its encoding.
   *
   * @param encoding the CRL encoding
   * @return a X509CRL object
   * @throws CRLException for decoding errors
   */
  public static X509CRL decodeCrl(final byte[] encoding) throws CRLException {
    return decodeCrl(new ByteArrayInputStream(encoding));
  }

  /**
   * Decodes a {@link X509CRL} from an input stream.
   *
   * @param stream the stream to read
   * @return a X509CRL object
   * @throws CRLException for decoding errors
   */
  public static X509CRL decodeCrl(final InputStream stream) throws CRLException {
    return (X509CRL) factory.generateCRL(stream);
  }

  /**
   * The {@link X509Certificate#toString()} prints way too much for a normal log entry. This method displays the
   * subject, issuer and serial number.
   *
   * @param certificate the certificate to log
   * @return a log string
   */
  public static String toLogString(final X509Certificate certificate) {
    if (certificate == null) {
      return "null";
    }
    return "subject='%s', issuer='%s', serial-number='%s'".formatted(certificate.getSubjectX500Principal().getName(),
        certificate.getIssuerX500Principal().getName(), certificate.getSerialNumber());
  }

  // Hidden
  private CertificateUtils() {
  }

}
