package org.tomaszewski;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.tomaszewski.utils.Logger.Logger;
import org.tomaszewski.utils.MyRemoteKeyStore;
import org.tomaszewski.utils.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class SignerCMS {

    public byte[] withURL(byte[] dataTBS, InputStream certIS, List<String> remoteCertList, String certPass, String sigAlg) {
        try {
            MyRemoteKeyStore rk = new MyRemoteKeyStore(certIS, certPass.toCharArray(), "PKCS12", remoteCertList);

            return sign(dataTBS, rk, sigAlg);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | IOException |
                 OperatorCreationException | CMSException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sign(byte[] data, MyRemoteKeyStore ks, String sigAlg) throws KeyStoreException, OperatorCreationException, CertificateEncodingException, CMSException, IOException {
        List<SignerInfoGenerator> sigs = new ArrayList<>();
        Security.addProvider(new BouncyCastleProvider());
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        X509Certificate signingCertificate = (X509Certificate) ks.getKeyStore().getCertificate(ks.getKeyStore().aliases().nextElement());
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).build(ks.getPrivateKey());
            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(dcp);

            ASN1EncodableVector signedAttrVector = new ASN1EncodableVector();
            signedAttrVector.add(Utils.getRemoteCertAttribute(ks.getCertUrlList()));
            AttributeTable table = new AttributeTable(signedAttrVector);
            builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(table));

            if (Logger.DEBUG) {
                Utils.addAliasUnsignedAttribute(ks, builder);
            }

            SignerInfoGenerator siGen = builder.build(contentSigner, signingCertificate);
            sigs.add(siGen);
        } catch (KeyStoreException | OperatorCreationException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }


        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        CMSTypedData cmsData;

        try {
            // were adding sigs
            CMSSignedData originalSignedData = new CMSSignedData(data);
            cmsData = new CMSProcessableByteArray(data);
            SignerInformationStore signers = originalSignedData.getSignerInfos();
            cmsGenerator.addSigners(signers);

            if (Logger.DEBUG) {

                List<X509CertificateHolder> embeddedCerts = originalSignedData.getCertificates().getMatches(null).stream().map(X509CertificateHolder.class::cast).toList();
                List<X509Certificate> signersList = new ArrayList<>(embeddedCerts.stream().map(x -> {
                    try {
                        return Utils.getX509(x.getEncoded());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }).toList());
                signersList.add(signingCertificate);
                cmsGenerator.addCertificates(new JcaCertStore(signersList));
            }
        } catch (CMSException e) {
//            first sig
            if (Logger.DEBUG) {
                List<X509Certificate> signersList = new ArrayList<>();
                signersList.add(signingCertificate);
                cmsGenerator.addCertificates(new JcaCertStore(signersList));
            }
            cmsData = new CMSProcessableByteArray(data);
        }

        sigs.forEach(cmsGenerator::addSignerInfoGenerator);


        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        return cms.getEncoded();
    }
}
