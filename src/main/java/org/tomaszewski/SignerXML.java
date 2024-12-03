package org.tomaszewski;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyInfoReference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.tomaszewski.utils.MyRemoteKeyStore;
import org.tomaszewski.utils.Utils;
import org.tomaszewski.utils.XMLAlgEnum;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class SignerXML {

    static {
        Init.init();
    }

    public byte[] withURL(InputStream xmlIS, InputStream certIS, List<String> remoteCertList, String certPass, String sigAlg) {
        try {
            MyRemoteKeyStore rk = new MyRemoteKeyStore(certIS, certPass.toCharArray(), "PKCS12", remoteCertList);
            return sign(xmlIS, rk, sigAlg);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sign(InputStream xmlIS, MyRemoteKeyStore ks, String sigAlg) throws Exception {
        Pair<Document, NodeList> preparedXML = prepareXML(xmlIS);
        NodeList nodes = preparedXML.getRight();
        Document newDoc = preparedXML.getLeft();

        XMLSignature sig = new XMLSignature(newDoc, null, XMLAlgEnum.fromString(sigAlg).getAlgoId(), new BouncyCastleProvider());

        Node root = nodes.item(0);
        root.appendChild(sig.getElement());

        // Add the transforms
        Transforms transforms = new Transforms(newDoc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        // add the certificate
        X509Certificate cert = (X509Certificate) ks.getKeyStore().getCertificate(ks.getKeyStore().aliases().nextElement());
        sig.addKeyInfo(cert);
        sig.addKeyInfo(cert.getPublicKey());

        // Add the remote certificates
        KeyInfo keyInfo = sig.getKeyInfo();
        ks.getCertUrlList().forEach(url -> {
            KeyInfoReference keyInfoReference = new KeyInfoReference(newDoc, url);
            keyInfo.add(keyInfoReference);
        });
        // Sign the document
        PrivateKey privateKey = ks.getPrivateKey();
        sig.sign(privateKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        XMLUtils.outputDOM(newDoc, outputStream);

        // Convert the document to byte array
        return outputStream.toByteArray();
    }

    @NotNull
    private static Pair<Document, NodeList> prepareXML(InputStream xmlIS) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(xmlIS);
        Document newDoc = Utils.generateDocToSign(doc);

        boolean alreadySigned = doc.getElementsByTagName("internallyDetached").getLength() != 0;

        NodeList nodes = (alreadySigned ? doc : newDoc).getElementsByTagName("internallyDetached");

        if (nodes.getLength() == 0) throw new RuntimeException("No root element found in the XML document");

        return Pair.of(
                alreadySigned ?
                        doc :
                        newDoc,
                nodes
        );
    }
}