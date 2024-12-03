package sign;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.tomaszewski.utils.Report;
import org.tomaszewski.utils.Utils;
import org.tomaszewski.SignerXML;
import org.tomaszewski.VerifierXML;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

class TestXML {
    String SIG_ALG = Utils.env.get("SIG_ALG");

    @Test
    void signAndVerify() {
        try {
            String p12Path = Utils.env.get("CERT_1_PATH", "https://raw.githubusercontent.com/Seis/icp/master/END_USER.p12");
            String pemPath = Utils.env.get("CERT_1_PEM", "https://raw.githubusercontent.com/Seis/icp/master/END_USER.pem");

            Utils.save(p12Path);
            String localPemPath = Utils.save(pemPath);

            String xmlFileToSign = Utils.save(Utils.env.get("XML"));

            byte[] signed;
            try (FileInputStream is = new FileInputStream(xmlFileToSign)) {
                signed = new SignerXML().withURL(
                        is,
                        Utils.getFromURI(p12Path),
                        new ArrayList<>(
                                Arrays.asList(
                                        pemPath,
                                        localPemPath,
                                        "https://aaaaaaaaaaa.org"
                                )),
                        Utils.env.get("CERT_1_PASS", "1234"),
                        SIG_ALG
                );

                Utils.write("signed.xml", signed);
            }

            System.out.println("Signed one time");
            List<Report> verificationResult = VerifierXML.verifyAll(signed);
            verificationResult.forEach(result ->
                    System.out.println(result.toString())
            );

            // todo commented to development only
            verificationResult.stream().map(Report::isValid).forEach(Assertions::assertTrue);

            //multiple signs

            byte[] multiSign = signed;
            for (int i = 0; i < Integer.parseInt(Objects.requireNonNull(Utils.env.get("RESIGN_COUNT"))); i++) {

                signed = new SignerXML().withURL(
                        new ByteArrayInputStream(multiSign),
                        Utils.getFromURI(Utils.env.get("CERT_N_PATH", Utils.env.get("CERT_N_PATH"))),
                        new ArrayList<>(
                                Arrays.asList(
                                        Utils.env.get("CERT_N_PEM", Utils.env.get("CERT_N_PEM")),
                                        "https://aaaaaaaaaaa.org"
                                )),
                        Utils.env.get("CERT_1_PASS", "1234"),
                        SIG_ALG
                );

                Utils.write("signature_" + i + "_signed.xml", signed);
                System.out.println("signed " + i + " extra times");
                multiSign = signed;
            }


            List<Report> verificationResult2 = VerifierXML.verifyAll(signed);
            verificationResult2.forEach(result ->
                    System.out.println(result.toString())
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
