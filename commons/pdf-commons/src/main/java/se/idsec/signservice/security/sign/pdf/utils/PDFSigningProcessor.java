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
package se.idsec.signservice.security.sign.pdf.utils;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import se.idsec.signservice.security.sign.pdf.PDFBoxSignatureInterface;
import se.idsec.signservice.security.sign.pdf.document.VisibleSignatureImage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;

/**
 * This class provides a PDF signing processor that provides the basic functionality to use a
 * {@link org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface} implementation to generate PDF
 * signature data.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Setter
@AllArgsConstructor
@Builder
@Slf4j
public class PDFSigningProcessor {

  /**
   * Signs the supplied PDF document. The document is closed by this method (in all cases).
   *
   * @param pdfDocument the document to sign
   * @param pdfSignatureProvider the PDFBox signature provider
   * @param signTimeAndID the signing time (and ID)
   * @param visibleSignatureImage optional signature image
   * @return a result
   * @throws SignatureException for signature errors
   */
  public static Result signPdfDocument(
      final PDDocument pdfDocument,
      final PDFBoxSignatureInterface pdfSignatureProvider,
      final long signTimeAndID,
      final VisibleSignatureImage visibleSignatureImage) throws SignatureException {

    try (pdfDocument) {
      // Create signature dictionary
      //
      final PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);

      if (pdfSignatureProvider.isPades()) {
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
      }
      else {
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      }

      // Sets signing time and document ID to the signing time value set during pre-signing.
      //
      final Calendar signingTime = Calendar.getInstance();
      signingTime.setTime(new Date(signTimeAndID));
      signature.setSignDate(signingTime);
      pdfDocument.setDocumentId(signTimeAndID);

      // Register signature dictionary and sign interface
      //
      if (visibleSignatureImage != null) {
        final SignatureOptions visibleSignatureOptions =
            visibleSignatureImage.getVisibleSignatureOptions(pdfDocument, signingTime.getTime());
        pdfDocument.addSignature(signature, pdfSignatureProvider, visibleSignatureOptions);
      }
      else {
        pdfDocument.addSignature(signature, pdfSignatureProvider);
      }

      // Execute signing operation and get resulting PDF document.
      //
      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      // This is where the signing process is invoked
      pdfDocument.saveIncremental(output);
      pdfDocument.close();

      return Result.builder()
          .document(output.toByteArray())
          .cmsSignedData(pdfSignatureProvider.getCmsSignedData())
          .cmsSignedAttributes(pdfSignatureProvider.getCmsSignedAttributes())
          .build();
    }
    catch (final IOException e) {
      final String msg = String.format("Failed to sign PDF document - %s", e.getMessage());
      log.error("{}", msg);
      throw new SignatureException(msg, e);
    }
  }

  /**
   * Result object for
   * {@link PDFSigningProcessor#signPdfDocument(PDDocument, PDFBoxSignatureInterface, long, VisibleSignatureImage)}.
   */
  @Getter
  @Builder
  public static class Result {

    /** The signed document. */
    private final byte[] document;

    /** The CMS SignedData. */
    private final byte[] cmsSignedData;

    /** The signed attributes. */
    private final byte[] cmsSignedAttributes;
  }

}
