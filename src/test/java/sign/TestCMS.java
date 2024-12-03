package sign;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.tomaszewski.VerifierCMS;
import org.tomaszewski.SignerCMS;
import org.tomaszewski.utils.Report;
import org.tomaszewski.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class TestCMS {
    String SIG_ALG = Utils.env.get("SIG_ALG");
    String MESSAGE = Utils.env.get("MESSAGE");

    @Test
    void signAndVerify() {
        try {
            String p12Path = Utils.env.get("CERT_1_PATH", "https://raw.githubusercontent.com/Seis/icp/master/END_USER.p12");
            String pemPath = Utils.env.get("CERT_1_PEM", "https://raw.githubusercontent.com/Seis/icp/master/END_USER.pem");

            Utils.save(p12Path);
            String localPemPath = Utils.save(pemPath);

            byte[] messageBytes = MESSAGE.getBytes();

            byte[] signed = new SignerCMS().withURL(
                    messageBytes,
                    Utils.getFromURI(p12Path),
                    new ArrayList<>(
                            Arrays.asList(
                                    "thisisaninvalidurlfortest",
                                    pemPath,
                                    localPemPath
                            )),
                    Utils.env.get("CERT_1_PASS", "1234"),
                    SIG_ALG
            );

            Utils.write("signed.p7s", signed);

            List<Report> verificationResult = VerifierCMS.verify(signed);
            verificationResult.stream().map(Report::isValid).forEach(Assertions::assertTrue);

            System.out.println("Signature count: " + verificationResult.size());

            verificationResult.forEach(result ->
                    System.out.println(result.toString())
            );
            System.out.println("========================================");
            System.out.println("Resigning " + Utils.env.get("RESIGN_COUNT","0") + " times");
            System.out.println("========================================");



            p12Path = Utils.env.get("CERT_N_PATH", "https://raw.githubusercontent.com/Seis/icp/master/END_USER_PJ.p12");
            pemPath = Utils.env.get("CERT_N_PEM", "https://raw.githubusercontent.com/Seis/icp/master/END_USER_PJ.pem");

            Utils.save(p12Path);
            localPemPath = Utils.save(pemPath);

            byte[] multiSign = signed;
            for (int i = 0; i < Integer.parseInt(Utils.env.get("RESIGN_COUNT","0")); i++) {
                multiSign = new SignerCMS().withURL(
                        multiSign,
                        Utils.getFromURI(Utils.env.get("CERT_N_PATH")),

                        new ArrayList<>(
                                Arrays.asList(
                                        "thisisaninvalidurlfortest",
                                        pemPath,
                                        localPemPath
                                )),
                        Utils.env.get("CERT_N_PASS","1234"),
                        SIG_ALG
                );
                Utils.write("signed_(" + (i+2) + ").p7s", multiSign);

                List<Report> verificationResult2 = VerifierCMS.verify(multiSign);
                System.out.println("Signature count: " + verificationResult2.size());

                verificationResult2.forEach(result ->
                        System.out.println(result.toString())
                );

                verificationResult2.stream().map(Report::isValid).forEach(Assertions::assertTrue);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
