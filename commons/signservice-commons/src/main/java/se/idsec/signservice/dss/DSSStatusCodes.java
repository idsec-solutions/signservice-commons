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
package se.idsec.signservice.dss;

/**
 * Contains the DSS status codes along with the Sweden Connect extensions.
 * <p>
 * The status codes for validation are not listed.
 * </p>
 * <p>
 * See section 2.6 of <a href="http://docs.oasis-open.org/dss/v1.0/oasis-dss-core-spec-v1.0-os.html">Digital Signature
 * Service Core Protocols, Elements, and Bindings Version 1.0</a> and section 3.1.7 of <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html#sign-response-status-codes">Swedish
 * eID Framework - Registry for identifiers</a>.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DSSStatusCodes {

  /** The protocol executed successfully. */
  public static final String DSS_SUCCESS = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";

  /** The end user cancelled the signature operation. */
  public static final String DSS_MINOR_USER_CANCEL = "http://id.elegnamnden.se/sig-status/1.0/user-cancel";

  /** The request could not be satisfied due to an error on the part of the requester. */
  public static final String DSS_REQUESTER_ERROR = "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError";

  /** Sweden Connect extension. The time window for the signature request has expired. */
  public static final String DSS_MINOR_REQUESTER_ERROR_REQUEST_EXPIRED =
      "http://id.elegnamnden.se/sig-status/1.0/req-expired";

  /** Sweden Connect extension. The authenticated user does not match the signer identity attributes in the request. */
  public static final String DSS_MINOR_REQUESTER_ERROR_USER_MISMATCH =
      "http://id.elegnamnden.se/sig-status/1.0/user-mismatch";

  /** Sweden Connect extension. The requested level of assurance for user authentication is not supported. */
  public static final String DSS_MINOR_REQUESTER_ERROR_UNSUPPORTED_LOA =
      "http://id.elegnamnden.se/sig-status/1.0/unsupported-loa";

  /** Sweden Connect extension. The authentication during the signature operation failed. */
  public static final String DSS_MINOR_AUTHN_FAILED = "http://id.swedenconnect.se/sig-status/1.1/authn-failed";

  /**
   * Sweden Connect extension. The Signature Service, or Identity Provider authenticating the end user, has detected a
   * security violation (such as a possible fraud).
   */
  public static final String DSS_MINOR_SECURITY_VIOLATION =
      "http://id.swedenconnect.se/sig-status/1.1/security-violation";

  /**
   * A ds:Reference element is present in the ds:Signature containing a full URI, but the corresponding input document
   * is not present in the request.
   */
  public static final String DSS_MINOR_REQUESTER_ERROR_REFERENCED_DOCUMENT_NOT_PRESENT =
      "urn:oasis:names:tc:dss:1.0:resultminor:ReferencedDocumentNotPresent";

  /** The required key information was not supplied by the client, but the server expected it to do so. */
  public static final String DSS_MINOR_REQUESTER_ERROR_KEY_INFO_NOT_PROVIDED =
      "urn:oasis:names:tc:dss:1.0:resultminor:KeyInfoNotProvided";

  /** The server was not able to create a signature because more than one RefUri was omitted. */
  public static final String DSS_MINOR_REQUESTER_MORE_THAN_ONE_REFURI_OMITTED =
      "urn:oasis:names:tc:dss:1.0:resultminor:MoreThanOneRefUriOmitted";

  /** The value of the RefURI attribute included in an input document is not valid. */
  public static final String DSS_MINOR_REQUESTER_INVALID_REFURI =
      "urn:oasis:names:tc:dss:1.0:resultminor:InvalidRefURI";

  /** The server was not able to parse a Document. */
  public static final String DSS_MINOR_REQUESTER_NOT_PARSEABLE_XML_DOCUMENT =
      "urn:oasis:names:tc:dss:1.0:resultminor:NotParseableXMLDocument";

  /** The server doesn't recognize or can't handle any optional input. */
  public static final String DSS_MINOR_REQUESTER_NOT_SUPPORTED = "urn:oasis:names:tc:dss:1.0:resultminor:NotSupported";

  /**
   * The signature or its contents are not appropriate in the current context. For example, the signature may be
   * associated with a signature policy and semantics which the DSS server considers unsatisfactory.
   */
  public static final String DSS_MINOR_REQUESTER_INAPPROPRIATE_SIGNATURE =
      "urn:oasis:names:tc:dss:1.0:resultminor:Inappropriate:signature";

  /** The request could not be satisfied due to an error on the part of the responder. */
  public static final String DSS_RESPONDER_ERROR = "urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError";

  /**
   * Sweden Connect extension. A requirement to display sign message was included in the sign request, but the sign
   * service could not establish that the sign message was displayed to the user.
   */
  public static final String DSS_MINOR_RESPONDER_ERROR_SIGMESSAGE_ERROR =
      "http://id.elegnamnden.se/sig-status/1.0/sigmessage-error";

  /**
   * The processing of the request failed due to an error not covered by the existing error codes. Further details
   * should be given in the result message for the user which may be passed on to the relevant administrator.
   */
  public static final String DSS_MINOR_RESPONDER_ERROR_GENERAL_ERROR =
      "urn:oasis:names:tc:dss:1.0:resultminor:GeneralError";

  /** Locating the identified key failed (e.g. look up failed in directory or in local key file). */
  public static final String DSS_MINOR_RESPONDER_ERROR_KEY_LOOKUP_FAILED =
      "urn:oasis:names:tc:dss:1.0:resultminor:invalid:KeyLookupFailed";

  /** The request could not be satisfied due to insufficient information. */
  public static final String DSS_INSUFFICIENT_INFORMATION =
      "urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation";

  // Hidden
  private DSSStatusCodes() {
  }

}
