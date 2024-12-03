package org.tomaszewski;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.cms.CMSException;
import org.tomaszewski.utils.MyCertificate;
import org.tomaszewski.utils.Report;
import org.tomaszewski.utils.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class VerifierXML {

    public static List<Report> verifyAll(byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CMSException, IOException {
        List<Report> verifyResult = new ArrayList<>();
        System.out.println("this file has a total of signatures: " + getSignatureCount(signatureBytes));
        verifyResult.addAll(verify(signatureBytes, true));
        verifyResult.addAll(verify(signatureBytes, false));

        return verifyResult;
    }

    public static int getSignatureCount(byte[] sigBytes){
        var xmlIS = new ByteArrayInputStream(sigBytes);

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(xmlIS);

            return doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").getLength();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static List<Report> verify(byte[] sigBytes, boolean remote) {
        var xmlIS = new ByteArrayInputStream(sigBytes);

        ArrayList<Report> reports = new ArrayList<>();

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(xmlIS);

            NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("No XML Digital Signature found, document is discarded");
            }

            for (int i = 0; i < nl.getLength(); i++){

                Element sigElement = (Element) nl.item(i);
                XMLSignature signature = new XMLSignature(sigElement, null);

                List<MyCertificate> certificateList = remote ?
                        Utils.getMyCertList(signature.getKeyInfo()) :
                        new ArrayList<>();

                X509Certificate cert = remote ?
                        certificateList.get(0).cert :
                        signature.getKeyInfo().getX509Certificate();

                PublicKey publicKey = cert.getPublicKey();


                boolean valid = signature.checkSignatureValue(publicKey);

                if (!valid) {
                    reports.add(
                            new Report(
                                    Integer.MIN_VALUE,
                                    signature.checkSignatureValue(publicKey),
                                    "signature integrity",
                                    remote ?
                                            Report.Method.REMOTE :
                                            Report.Method.EMBEDDED,
                                    remote ?
                                            certificateList.get(0).uri :
                                            cert.getSubjectDN().getName(),
                                    Report.SignatureType.XML));
                    continue;
                }

                reports.add(
                        new Report(
                                Integer.MIN_VALUE,
                                !Utils.isPathInvalid(cert, Integer.MIN_VALUE),
                                "path validation",
                                remote ?
                                        Report.Method.REMOTE :
                                        Report.Method.EMBEDDED,
                                remote ?
                                        certificateList.get(0).uri :
                                        cert.getSubjectDN().getName(),
                                Report.SignatureType.XML));

            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return reports;
    }
}
