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

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CMSSigVerifyResult {

    private X509Certificate cert = null;
    private List<X509Certificate> certList = new ArrayList<>();
    private boolean valid = false;
    private boolean pades;
    private boolean padesVerified;
    private Date claimedSigningTime;
    private String pkType;
    private EcCurve ecCurve;
    private String sigAlgo;
    private int keyLength;
    private boolean cmsAlgoProtection;
    private AlgorithmIdentifier cmsAlgoProtSigAlgo;
    private AlgorithmIdentifier cmsAlgoProtHashAlgo;
    private PDSignature signature;

}
