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
