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
package se.idsec.signservice.security.sign.pdf.signprocess;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Setter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import se.idsec.signservice.security.sign.pdf.SignserviceSignatureInterface;
import se.idsec.signservice.security.sign.pdf.document.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.pdf.impl.DefaultPDFSignerResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * This class provides a PDF signing processor that provides the basic functionality to use a
 * {@link org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface} implementation to
 * generate PDF signature data
 */
@Setter
@AllArgsConstructor
@Builder
public class PDFSigningProcessor {

  private final SignserviceSignatureInterface signatureInterface;
  private final PDFSignTaskDocument document;
  private final PDDocument pdfDocument;
  private final List<X509Certificate> chain;
  private final long signTimeAndID;

  public DefaultPDFSignerResult signPdf() throws IOException {
    try {
      boolean pades = false;
      String adesRequirement = document.getAdesType();
      if (adesRequirement != null) {
        pades =
          adesRequirement.equals(PDFSignTaskDocument.ADES_PROFILE_BES) || adesRequirement.equals(PDFSignTaskDocument.ADES_PROFILE_EPES);
      }
      signatureInterface.setPades(pades);

      // create signature dictionary
      PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      if (pades) {
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
      }
      else {
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      }

      // Sets signing time and document ID to the signing time value set during pr-signing
      // These values must match for the signature to match the signed document
      Calendar signingTime = Calendar.getInstance();
      signingTime.setTime(new Date(signTimeAndID));
      signature.setSignDate(signingTime);
      pdfDocument.setDocumentId(signTimeAndID);

      // register signature dictionary and sign interface
      if (document.getVisibleSigImage() != null) {
        SignatureOptions visibleSignatureOptions = document.getVisibleSigImage()
          .getVisibleSignatureOptions(pdfDocument, signingTime.getTime());
        pdfDocument.addSignature(signature, signatureInterface, visibleSignatureOptions);
      }
      else {
        pdfDocument.addSignature(signature, signatureInterface);
      }

      // Execute signing operation and get resulting PDF document
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      // This is where the signing process is invoked
      pdfDocument.saveIncremental(output);
      output.close();
      pdfDocument.close();

      byte[] pdfDocumentBytes = output.toByteArray();

      //Set results
      DefaultPDFSignerResult result = new DefaultPDFSignerResult();
      result.setSuccess(true);
      result.setPdfSignTaskDocument(PDFSignTaskDocument.builder()
        .pdfDocument(pdfDocumentBytes)
        .adesType(document.getAdesType())
        .signTimeAndId(signTimeAndID)
        .cmsSignedData(signatureInterface.getCmsSignedData())
        .build());
      result.setSignerCertificate(chain.get(0));
      result.setSignerCertificateChain(chain);
      result.setSignedAttributes(signatureInterface.getCmsSignedAttributes());
      return result;
    }
    catch (Exception ex) {

      throw new IOException(ex);
    }
  }

}
