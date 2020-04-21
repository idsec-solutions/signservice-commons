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
package se.idsec.signservice.security.sign.pdf.impl;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import se.idsec.signservice.security.sign.pdf.signprocess.PdfBoxSigUtil;
import se.idsec.signservice.security.sign.pdf.SignserviceSignatureInterface;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Implementation of the SignatureInterface where the signature is constructed by replacing signature data in an existing signature
 * with data obtains from a remote signing service.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ReplaceSignatureInterfaceImpl implements SignserviceSignatureInterface {

    /** The original ContentInfo bytes holding SignedInfo from the original pre-signing process */
    private byte[] originalSignedData;

    /** The modified signed attributes provided from the signature service */
    private byte[] newSignedAttributesData;

    /** The signature value provided by the signature service */
    private byte[] newSignatureValue;

    /** The signer certificate chain provided by the signature service */
    private List<X509Certificate> signerCertchain;

    /** The updated Content Info holding SignedData */
    private byte[] updatedCmsSignedData;

    /** The CMS Signed attributes */
    private byte[] cmsSignedAttributes;


    /**
     * Constructor for the replace signature interface implementation
     * @param originalSignedData the original ContentInfo bytes holding SignedInfo from the original pre-signing process
     * @param newSignedAttributesData the modified signed attributes provided from the signature service
     * @param newSignatureValue the signature value provided by the signature service
     * @param signerCertchain the signer certificate chain provided by the signature service
     */
    public ReplaceSignatureInterfaceImpl(byte[] originalSignedData, byte[] newSignedAttributesData, byte[] newSignatureValue,
      List<X509Certificate> signerCertchain) {
        this.originalSignedData = originalSignedData;
        this.newSignedAttributesData = newSignedAttributesData;
        this.newSignatureValue = newSignatureValue;
        this.signerCertchain = signerCertchain;
    }


    /** {@inheritDoc} */
    @Override public byte[] getCmsSignedData() {
        return updatedCmsSignedData;
    }

    /** {@inheritDoc} */
    @Override public byte[] getCmsSignedAttributes() {
        return cmsSignedAttributes;
    }

    /** This value is not set as it has no function in this implementation of the interface */
    @Override public void setPades(boolean pades) {
    }

    /**
     * SignatureInterface implementation.
     * <p>
     * This method will be called from inside of the pdfbox and create the PKCS
     * #7 signature (CMS ContentInfo). The given InputStream contains the bytes that are given by
     * the byte range.
     * </p>
     * <p>
     * In this implementation of the signature interface no new signature is created. Instead a previous pre-sign signature is updated
     * with signature value, signed attributes and certificates from a remote signature process
     * </p>
     * @param content the message bytes being signed (specified by ByteRange in the signature dictionary)
     * @return CMS ContentInfo bytes holding the complete PKCS#7 signature structure
     * @throws IOException error during signature creation
     */
    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            updatedCmsSignedData = PdfBoxSigUtil.updatePdfPKCS7(originalSignedData, newSignedAttributesData, newSignatureValue, signerCertchain);
            cmsSignedAttributes = PdfBoxSigUtil.getCmsSignedAttributes(updatedCmsSignedData);
            return updatedCmsSignedData;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

}
