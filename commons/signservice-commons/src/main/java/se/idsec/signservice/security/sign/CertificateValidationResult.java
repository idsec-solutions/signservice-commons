package se.idsec.signservice.security.sign;

import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface representing the successful result of a signature validation operation.
 *
 * Failed certificate validation returns an Exception with suitable information.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateValidationResult {

  /**
   * Gets the certificate path that was used to validate the target certificate.
   * <p>
   * The certificate path starts with the target certificate and ends with the trust anchor.
   * Every certificate except the target certificate must validate the certificate preceding it in the list.
   * </p>
   *
   * @return the target certificate chain
   */
  List<X509Certificate> getValidatedCertificatePath();

  /**
   * Gets optional path validation result
   * <p>
   *   This result object is only relevant if the certificate validation function
   *   performed PKIX path validation from the target certificate to a trusted trust anchor
   *   certificate. This method returning {@code null} does not mean that certificate validation failed.
   * </p>
   * @return {@link PKIXCertPathValidatorResult} or {@code null} if no path validation result is available
   */
  PKIXCertPathValidatorResult getPKIXCertPathValidatorResult();

}
