package se.idsec.signservice.security.sign.impl;

import se.idsec.signservice.security.sign.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;

import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Default implementation of the {@link SignatureValidationResult} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCertificateValidationResult implements CertificateValidationResult {

  /** Certificates used to validate the target certificate, including the target certificate and trust anchor */
  private List<X509Certificate> validatedCertificatePath;

  /** Optional PKIX path validation result */
  private PKIXCertPathValidatorResult pkixCertPathValidatorResult;

  /**
   * Default constructor.
   */
  public DefaultCertificateValidationResult() {
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getValidatedCertificatePath() {
    return null;
  }

  /**
   * Assigns the validated certificate path
   * @param validatedCertificatePath validated certificate path
   */
  public void setValidatedCertificatePath(List<X509Certificate> validatedCertificatePath) {
    this.validatedCertificatePath = validatedCertificatePath;
  }

  /** {@inheritDoc} */
  @Override
  public PKIXCertPathValidatorResult getPKIXCertPathValidatorResult() {
    return null;
  }

  /**
   * Assigns the PKIX path validation result
   * @param pkixCertPathValidatorResult PKIX path validation result
   */
  public void setPkixCertPathValidatorResult(PKIXCertPathValidatorResult pkixCertPathValidatorResult) {
    this.pkixCertPathValidatorResult = pkixCertPathValidatorResult;
  }


}
