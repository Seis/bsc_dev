package org.tomaszewski.utils;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;

import io.github.cdimascio.dotenv.Dotenv;
import org.tomaszewski.utils.Logger.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.logging.Level;

public class Utils {
    public static final Dotenv env = Dotenv.configure().directory("").load();

    public static void addAliasUnsignedAttribute(MyRemoteKeyStore ks, JcaSignerInfoGeneratorBuilder builder) throws KeyStoreException {
        String alias = ks.getKeyStore().aliases().nextElement();
        ASN1Set k = new DERSet(new BEROctetString(alias.getBytes()));
        Attribute d = new Attribute(OID.ALIAS_UNSIGNED_ATTRIBUTE, k);
        builder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(d)));
    }

    /**
     * Tries to get the InputStream from a string as url or file on fail.
     * @param certUri String of the resource
     * @return InputStream of the resource
     */
    public static InputStream getFromURI(String certUri) {
        try {
            // remote
            return new URL(certUri).openStream();

        } catch (IOException e) {
            try {
                //local
                return new BufferedInputStream(new FileInputStream(certUri));
            } catch (FileNotFoundException ex) {
                return null;
            } catch (NullPointerException ex) {
                System.out.println("URI is null");
                throw new RuntimeException();
            }
        }
    }

    public static void write(String filename, byte[] data) throws IOException {
        Files.write(Paths.get(filename), data);
    }

    public static String save(String path) throws IOException {
        byte[] data = Utils.getFromURI(path).readAllBytes();
        String[] nameSplit = path.split("/");
        String fileName = nameSplit[nameSplit.length - 1];
        write("/tmp/" + fileName, data);
        return "/tmp/" + fileName;
    }

    public static String getAliasFromUnsigned(AttributeTable unsignedAttributes) {
        try {
            Attribute b = unsignedAttributes.get(OID.ALIAS_UNSIGNED_ATTRIBUTE);
            ASN1Set cert_set = b.getAttrValues();
            return new String(cert_set.getObjectAt(0).toASN1Primitive().getEncoded());
        } catch (NullPointerException | IOException ignored) {
        }
        return null;
    }

    //(DERSet)  SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    //              Attribute ::= SEQUENCE {
    //                  attrType OBJECT IDENTIFIER,
    //                      attrValues (DERSequence) SET OF AttributeValue }
    //                          AttributeValue ::= ANY (GeneralNames)
    //                                GeneralName ::= CHOICE {
    //                                    otherName                 [0]  AnotherName,
    //                                    rfc822Name                [1]  IA5String,
    //                                    dNSName                   [2]  IA5String,
    //                                    x400Address               [3]  ORAddress,
    //                                    directoryName             [4]  Name,
    //                                    ediPartyName              [5]  EDIPartyName,
    //                                    uniformResourceIdentifier [6]  IA5String,
    //                                    iPAddress                 [7]  OCTET STRING,
    //                                    registeredID              [8]  OBJECT IDENTIFIER }

    /**
     * Converts the list of string of certificate paths to an Attribute as the aforementioned structure
     * @param certPathList list of certificate paths
     * @return Attribute with the structure
     */
    public static Attribute getRemoteCertAttribute(List<String> certPathList) {
        GeneralNamesBuilder gnb = new GeneralNamesBuilder();
        for (String certPath : certPathList) {
            gnb.addName(new GeneralName(6, certPath));
        }

        return new Attribute(
                OID.REMOTE_CERT, new DERSet(gnb.build())
        );
    }

    /**\
     * Gets the certificates from the Attribute of the signed data as generated by the getRemoteCertAttribute
     * @param sigInfos Signatures that contain the signed attributes with the remote certificates
     * @return List of MyCertificate with the certificate and the uri used to get it
     */
    public static List<MyCertificate> getMyCertList(ASN1Set sigInfos) {
        List<List<String>> certUriList = new ArrayList<>();
        sigInfos.iterator().forEachRemaining(sigInfoSet -> {
            SignerInfo sigInfo = SignerInfo.getInstance(sigInfoSet);
            AttributeTable attributeTable = new AttributeTable(sigInfo.getAuthenticatedAttributes());
            Attribute remoteCertAttr = attributeTable.get(OID.REMOTE_CERT);
            ASN1Set cert_set = remoteCertAttr.getAttrValues();
            ASN1Sequence cert_seq = ASN1Sequence.getInstance(cert_set.getObjectAt(0));
            List<String> certUris = new ArrayList<>();
            for (int i = 0; i < cert_seq.size(); i++) {
                GeneralName url = GeneralName.getInstance(cert_seq.getObjectAt(i));
                certUris.add(url.getName().toString());
            }
            certUriList.add(certUris);
        });

        return getCertsFromURI(certUriList);
    }

    /**
     * @param certUriList list with the lists of the possible uri's for the certificate
     * @return list with pairs of <Certificate, uri used to get the certificate>
     */

    private static List<MyCertificate> getCertsFromURI(List<List<String>> certUriList) {
        List<MyCertificate> uriCertList = new ArrayList<>();
        certUriList.forEach(uriList -> {
            for (String uriString : uriList) {
                X509Certificate cert = getX509(uriString);
                if (cert == null) continue;
                uriCertList.add(new MyCertificate(cert, uriString));
            }
        });
        return uriCertList;
    }

    public static X509Certificate getX509(InputStream is) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(is);
    }

    public static X509Certificate getX509(byte[] x){
        InputStream is = new ByteArrayInputStream(x);
        try {
            return getX509(is);
        } catch (CertificateException ignored) {
            return null;
        }
    }

    public static X509Certificate getX509(String x){
        InputStream is = getFromURI(x);
        try {
            return getX509(is);
        } catch (CertificateException ignored) {
            return null;
        }
    }

    /**
     * Attempts to get the certificates from the AIA extension on cert
     * @param cert Target certificate for aia extraction
     * @return List of certificates that are present on the AIA of cert
     * @throws CertPathBuilderException If AIA extension are not found on certificate or inaccessible
     */
    public static Collection<? extends Certificate> getTree(X509Certificate cert) throws CertPathBuilderException {
        try {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
                    JcaX509ExtensionUtils.parseExtensionValue(
                            cert.getExtensionValue(OID.AIA.getId())
                    )
            );
            String aiaLocation = "";
            for (AccessDescription accessDescription : aia.getAccessDescriptions()) {
                if (accessDescription.getAccessMethod().getId().equals(OID.CA_ISSUER.getId())) {
                    aiaLocation = accessDescription.getAccessLocation().getName().toString();
                    break;
                }
            }

            if (aiaLocation.isEmpty()){
                throw new CertPathBuilderException("AIA_NOT_FOUND_" + cert.getIssuerX500Principal());
            }

            InputStream is = new URL(aiaLocation).openStream();

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificates(is);

        } catch (IOException | CertificateException e) {
            throw new CertPathBuilderException("CERT_TREE_ERROR_" + cert.getIssuerX500Principal(), e);
        }
    }
    public static Stack<X509Certificate> assemblePath(X509Certificate cert) throws CertPathBuilderException {
        int MAXIMUM_LENGTH = 5;
        return assemblePath(cert, MAXIMUM_LENGTH);
    }

    /**
     * Receives a certificate and attempts to build a path with it issuers
     * @param cert Final certificate to build path
     * @param maximumLength Maximum number of certificates on the path
     * @return Stack with cert at bottom and the root certification authority at top
     * @throws CertPathBuilderException when the path is bigger than maximumLength,
     *                                  when there are inconsistencies with the issuers
     *                                  or a problem accessing the authority info access.
     */
    public static Stack<X509Certificate> assemblePath(X509Certificate cert, int maximumLength) throws CertPathBuilderException {
        Stack<X509Certificate> certStack = new Stack<>();
        certStack.add(cert);

        // get all certs from the certification path from cert
        List<X509Certificate> relatedCerts = Utils.getTree(cert).stream().map(X509Certificate.class::cast).toList();

        // while the issuer of the current cert is not the subject of the previous cert
        while (!cert.getIssuerX500Principal().equals(certStack.peek().getSubjectX500Principal())) {
            if (certStack.size() > maximumLength) {
                throw new CertPathBuilderException("CERTIFICATION_PATH_REACH_THE_MAXIMUM_SIZE");
            }

            int sizeBeforeLoop = certStack.size();
            // search in the related certs the issuer of the current cert
            for (X509Certificate x: relatedCerts){
                if (x.getSubjectX500Principal().equals(certStack.peek().getIssuerX500Principal())){
                    certStack.push(x);
                    cert = x;
                    break;
                }
            }
            if (sizeBeforeLoop == certStack.size()){
                throw new CertPathBuilderException("ISSUER_OF_CERT_NOT_FOUND" + certStack.peek().getIssuerX500Principal());
            }
        }
        return certStack;
    }

    /**
     * Checks if the path is valid
     * @param cert Certificate to check the path
     * @return true if the path is invalid, false otherwise
    **/
    public static boolean isPathInvalid(X509Certificate cert, int sigIndex) {
        try {
            Stack<X509Certificate> certificateStack;
            try {
                certificateStack = assemblePath(cert);
            } catch (CertPathBuilderException e) {
                Logger.log(Level.SEVERE, e.getMessage());
                return true;
            }
            CertPath certPath = CertificateFactory.getInstance("X509").generateCertPath(certificateStack);
            TrustAnchor rootCA = new TrustAnchor(certificateStack.pop(), null);

            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
            revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS, PKIXRevocationChecker.Option.SOFT_FAIL));

            PKIXParameters validationParameters = new PKIXParameters(Collections.singleton(rootCA));
            validationParameters.addCertPathChecker(revocationChecker);
            validationParameters.setDate(cert.getNotBefore());
            validationParameters.setRevocationEnabled(false);

            certPathValidator.validate(certPath, validationParameters);

            return false;

        } catch (CertificateException e) {
            Logger.log(Level.SEVERE, "ERROR_WHILE_MAKING_CERT_PATH_ON_" + sigIndex, e);
        } catch (InvalidAlgorithmParameterException e) {
            Logger.log(Level.SEVERE, "ROOT_CERTIFICATE_NOT_FOUND_ON_" + sigIndex);
        } catch (NoSuchAlgorithmException e) {
            Logger.log(Level.SEVERE, "NOT_INSTANCE_OF_PKIX_ON_" + sigIndex);
        } catch (CertPathValidatorException e) {
            Logger.log(Level.SEVERE, "CERTIFICATION_PATH_EXCEPTION_ON_" + sigIndex, e);
        }
        return true;
    }



    /**\
     * Gets the certificates from the Attribute of the signed data as generated by the getRemoteCertAttribute
     * @param keyInfo KeyInfo from signatures that contain the KeyInfoReference with the remote certificates
     * @return List of MyCertificate with the certificate and the uri used to get it
     */
    public static List<MyCertificate> getMyCertList(KeyInfo keyInfo) throws XMLSecurityException {

        ArrayList<String> certUriList = new ArrayList<>();
        for (int i = 0; i < keyInfo.lengthKeyInfoReference(); i++) {
            certUriList.add(keyInfo.itemKeyInfoReference(i).getURI());
        }

        return getCertsFromURI(List.of(certUriList));
    }

    /**
     * Gets the root node to sign from the document
     * @param documentToSign Document to get the root node
     * @return Node to sign
     * @throws XPathExpressionException If the xpath is invalid
     */
    public static Node getRootNodeToSign(Document documentToSign) throws XPathExpressionException {
        String nodeToSignXPath =  "/*[1]";
        String[] split = nodeToSignXPath.split("/");
        StringBuilder newPath = new StringBuilder();
        if (split[0].isEmpty() && split[1].isEmpty()) {
            newPath.append("/");
        }
        for (String s : split) {
            if (s.isEmpty()) continue;
            if (s.startsWith("*")) {
                newPath.append("/")
                        .append(s);
                continue;
            }
            String name = s;
            if (s.contains(":")) {
                String[] split2 = s.split(":");
                name = split2[1];
            }
            String position = "";
            if (name.contains("[")) {
                String[] split2 = name.split("\\[");
                name = split2[0];
                position = "[" + split2[1];
            }
            newPath.append("/")
                    .append("*[local-name()='").append(name).append("']")
                    .append(position);

        }
        nodeToSignXPath = newPath.toString();
        Node root = documentToSign.getDocumentElement();


        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath1 = xPathFactory.newXPath();
        XPathExpression expression = xpath1.compile(nodeToSignXPath);
        Node nodeToSign = (Node) expression.evaluate(root, XPathConstants.NODE);
        return nodeToSign;
    }

    public static Document generateDocToSign(Document oldDoc) throws ParserConfigurationException, XPathExpressionException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        //create empty xml document
        Document newDoc = db.newDocument();
        //create tag internally detached as root of doc2
        Element newRoot = newDoc.createElement("internallyDetached");
        newDoc.appendChild(newRoot);
        //append the root of doc to newRoot of doc2
        Node newNodeToSign = newDoc.importNode(Utils.getRootNodeToSign(oldDoc), true);
        newRoot.appendChild(newNodeToSign);
        return newDoc;
    }
}