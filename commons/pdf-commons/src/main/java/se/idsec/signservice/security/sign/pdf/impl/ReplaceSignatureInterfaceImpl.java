/*
 * Copyright 2015 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.security.sign.pdf.impl;

import lombok.Getter;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import se.idsec.signservice.pdf.utils.PdfBoxSigUtil;
import se.idsec.signservice.security.sign.pdf.SignserviceSignatureInterface;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Implementation of the SignatureInterface where the
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
     * Does nothing. Override this if needed.
     *
     * @param signedData Generated CMS signed data
     * @return CMSSignedData Extended CMS signed data
     */
    protected CMSSignedData signTimeStamps(CMSSignedData signedData) throws IOException, TSPException {
        return signedData;
    }

    /**
     * SignatureInterface implementation.
     *
     * This method will be called from inside of the pdfbox and create the PKCS
     * #7 signature. The given InputStream contains the bytes that are given by
     * the byte range.
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
