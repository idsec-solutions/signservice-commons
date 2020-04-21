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
package se.idsec.signservice.security.sign.pdf.verify;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Holding signature verification result for a single CMS signature within a PDF document
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CMSSigVerifyResult {

    /**  */
    private X509Certificate cert = null;
    /**  */
    private List<X509Certificate> certList = new ArrayList<>();
    /** The chain */
    private boolean valid = false;
    /** true if this signature is a PAdES signature */
    private boolean pades;
    /** true is this signature has verified the signing certificate reference in PAdES signature */
    private boolean padesVerified;
    /** claimed signing time from signed attributes if present or else from the signature dictionary */
    private Date claimedSigningTime;
    /** Public key type */
    private String pkType;
    /** Signature algorithm URI identifier */
    private String sigAlgo;
    /** Signing key length */
    private int keyLength;
    /** true if ths signature has the CMS algorithm protection signed attribute */
    private boolean cmsAlgoProtection;
    /** Signature algorithm claimed by the CMS algorithm protection signed attribute */
    private AlgorithmIdentifier cmsAlgoProtSigAlgo;
    /** Hash algorithm claimed by the CMS algorithm protection signed attribute */
    private AlgorithmIdentifier cmsAlgoProtHashAlgo;
    /** PDF signature object */
    private PDSignature signature;

}
