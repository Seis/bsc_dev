package org.tomaszewski;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.tomaszewski.utils.*;
import org.tomaszewski.utils.Logger.Logger;
import org.tomaszewski.utils.Logger.MyLevel;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;

public class VerifierCMS {

    public static List<Report> verify(byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CMSException, IOException {
        List<Report> verifyResult = new ArrayList<>();

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(signature)) {
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            ContentInfo contentInfo = ContentInfo.getInstance(asn1Primitive);
            SignedData signedData = SignedData.getInstance(contentInfo.getContent());

            verifyResult.addAll(verifyFromRemote(signature, signedData));
            verifyResult.addAll(verifyFromEmbedded(signature, signedData));

            return verifyResult;
        }
    }

    private static Collection<? extends Report> verifyFromRemote(byte[] signature, SignedData signedData) throws CMSException, NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
        String signatureDigestAlgorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(AlgorithmIdentifier.getInstance(signerInfo.getDigestEncryptionAlgorithm()));
        ASN1ObjectIdentifier signatureDigestAlgorithmIdentifier = AlgorithmIdentifier.getInstance(signerInfo.getDigestEncryptionAlgorithm()).getAlgorithm();
        CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signatureDigestAlgorithmIdentifier, signature), signature);

        List<Report> result = new ArrayList<>();
        ASN1Set sigInfos = signedData.getSignerInfos();
        List<MyCertificate> uriCertList = Utils.getMyCertList(sigInfos);

        Signature sig;
        // validate signatures with the public keys
        for (int i = 0; i < uriCertList.size(); i++) {
            MyCertificate cert = uriCertList.get(i);

            SignerInformation si = (SignerInformation) cms.getSignerInfos().getSigners().toArray()[i];
            sig = Signature.getInstance(signatureDigestAlgorithmName);
            sig.initVerify(cert.cert);


            // builds and checks the certificate chain for all certs
            if (Utils.isPathInvalid(cert.cert, i)) {
                result.add(new Report(
                        i,
                        false,
                        "Certification path validation",
                        Report.Method.REMOTE,
                        cert.uri,
                        Report.SignatureType.CMS
                ));
                continue;
            }

            sig.update(si.getEncodedSignedAttributes());
            boolean verification2 = false;
            try {
                verification2 = sig.verify(si.getSignature());
            } catch (Exception e) {
                Logger.log(Level.WARNING, "ERROR_VERIFYING", e);
            }
            result.add(new Report(
                    i,
                    verification2,
                    "Signature integrity verification",
                    Report.Method.REMOTE,
                    cert.uri,
                    Report.SignatureType.CMS
            ));
            break;
        }
        return result;
    }

    private static List<Report> verifyFromEmbedded(byte[] signature, SignedData signedData) throws NoSuchAlgorithmException, CMSException, InvalidKeyException, IOException, SignatureException {
        List<Report> result = new ArrayList<>();
        ASN1Encodable[] signerInfoArray = signedData.getSignerInfos().toArray();
        for (int sigIndex = 0; sigIndex < signerInfoArray.length; sigIndex++) {
            SignerInfo signerInfo = SignerInfo.getInstance(signerInfoArray[sigIndex]);
            ASN1ObjectIdentifier digestAlg = AlgorithmIdentifier.getInstance(signerInfo.getDigestEncryptionAlgorithm()).getAlgorithm();
            CMSSignedData cmsSingle = new CMSSignedData(new CMSProcessableByteArray(digestAlg, signature), signature);
            String sigDigestAlgName = new DefaultAlgorithmNameFinder().getAlgorithmName(AlgorithmIdentifier.getInstance(signerInfo.getDigestEncryptionAlgorithm()));
            Signature sigVer = Signature.getInstance(sigDigestAlgName);
            SignerInformation signerInformation = (SignerInformation) cmsSingle.getSignerInfos().getSigners().toArray()[sigIndex];

            List<Certificate> signersCertList = new ArrayList<>();
            cmsSingle.getCertificates().getMatches(null).forEach(certificateHolder -> {
                try {
                    byte[] cert = certificateHolder.getEncoded();
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    Certificate c = cf.generateCertificate(new ByteArrayInputStream(cert));
                    signersCertList.add(c);
                } catch (IOException | CertificateException e) {
                    throw new RuntimeException(e);
                }
            });

            if (cmsSingle.getSignerInfos().getSigners().size() > signersCertList.size()) {
                if(!signersCertList.isEmpty()){
                    Logger.log(MyLevel.PLS_DONT, "Not enough certificates to verify all signatures, results may vary.");
                }
            }

            boolean sigRes = false;
            for (Certificate certificate : signersCertList) {

                sigVer.initVerify(certificate.getPublicKey());
                sigVer.update(signerInformation.getEncodedSignedAttributes());
                try {
                    sigRes = sigVer.verify(signerInformation.getSignature());
                    if (sigRes){
                        if (Utils.isPathInvalid((X509Certificate) certificate, sigIndex)) {
                            sigRes = false;
                        }
                        break;
                    }
                } catch (SignatureException e){
                    Logger.log(Level.WARNING, "SIG_" + sigIndex + "_INVALID", e);
                }

            }
            result.add(
                    new Report(
                            sigIndex,
                            sigRes,
                            "Certification path validation",
                            Report.Method.EMBEDDED,
                            Utils.getAliasFromUnsigned(signerInformation.getUnsignedAttributes()),
                            Report.SignatureType.CMS
                    )
            );
        }
        return result;
    }

}
