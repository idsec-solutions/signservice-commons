/*
 * Copyright 2019-2020 IDsec Solutions AB
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
 * Object Identifiers useful for PDF signature handling
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfObjectIds {

    public static final String ID_PKCS7_DATA = "1.2.840.113549.1.7.1";
    public static final String ID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";
    public static final String ID_RSA = "1.2.840.113549.1.1.1";
    public static final String ID_DSA = "1.2.840.10040.4.1";
    public static final String ID_ECDSA = "1.2.840.10045.2.1";
    public static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    public static final String ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    public static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";
    public static final String ID_ADBE_REVOCATION = "1.2.840.113583.1.1.8";
    public static final String ID_TSA = "1.2.840.113583.1.1.9.1";
    public static final String ID_TIMESTAMP_ATTRIBUTE = "1.2.840.113549.1.9.16.2.14";
    public static final String ID_OCSP = "1.3.6.1.5.5.7.48.1";
    public static final String ID_AA_SIGNING_CERTIFICATE_V1 = "1.2.840.113549.1.9.16.2.12";
    public static final String ID_AA_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
    public static final String ID_AA_CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52";
    
    //Eliptic curves
    public static final String ID_EC_P256 = "1.2.840.10045.3.1.7";
}
