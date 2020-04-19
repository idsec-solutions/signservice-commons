package se.idsec.signservice.security.sign.pdf.verify;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PdfSigVerifyResult {

    private boolean lastSigValid;
    private boolean allSigsValid;
    private List<CMSSigVerifyResult> resultList = new ArrayList<>();
    private int sigCnt;
    private int validSignatures;
}