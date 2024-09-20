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
package se.idsec.signservice.security.sign.pdf.configuration;

/**
 * Object Identifiers useful for PDF signature handling.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFObjectIdentifiers {

  /** Object identifier for PKCS#7 data. */
  public static final String ID_PKCS7_DATA = "1.2.840.113549.1.7.1";

  /** Object identifier for PKCS#7 signed data. */
  public static final String ID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";

  /** Object identifier for the RSA algorithm. */
  public static final String ID_RSA = "1.2.840.113549.1.1.1";

  /** Object identifier for the DSA algorithm. */
  public static final String ID_DSA = "1.2.840.10040.4.1";

  /** Object identifier for the ECDSA algorithm. */
  public static final String ID_ECDSA = "1.2.840.10045.2.1";

  /** Object identifier for the ContentType object. */
  public static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";

  /** Object identifier for MessageDigest. */
  public static final String ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

  /** Object identifier for SigningTime attribute. */
  public static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";

  /** Object identifier for the Revocation information archival attribute. */
  public static final String ID_ADBE_REVOCATION = "1.2.840.113583.1.1.8";

  /** Object identifier for the Adobe Time Stamp. */
  public static final String ID_TSA = "1.2.840.113583.1.1.9.1";

  /** Object identifier for time stamp token. */
  public static final String ID_TIMESTAMP_ATTRIBUTE = "1.2.840.113549.1.9.16.2.14";

  /** Object identifier for Online Certificate Status Protocol (OCSP). */
  public static final String ID_OCSP = "1.3.6.1.5.5.7.48.1";

  /** Object identifier for S/MIME Signing certificate (id-aa-signingCertificate). */
  public static final String ID_AA_SIGNING_CERTIFICATE_V1 = "1.2.840.113549.1.9.16.2.12";

  /** Object identifier for Signing certificate V2 . */
  public static final String ID_AA_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";

  /** Object identifier for the CMS algorithm protection attribute. */
  public static final String ID_AA_CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52";

  /** Object identifier for 256-bit Elliptic Curve Cryptography (ECC). */
  public static final String ID_EC_P256 = "1.2.840.10045.3.1.7";

}
