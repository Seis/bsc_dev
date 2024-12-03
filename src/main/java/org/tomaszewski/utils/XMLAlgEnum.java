package org.tomaszewski.utils;

import org.apache.xml.security.signature.XMLSignature;

public enum XMLAlgEnum {
    SHA256withRSA(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256),
    SHA384withRSA(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384),
    SHA512withRSA(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512),
    SHA256withECDSA(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256),
    SHA384withECDSA(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384),
    SHA512withECDSA(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512),
    Ed25519(XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED25519),
    Ed448(XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED448);

    private final String algoId;

    XMLAlgEnum(String algoId) {
        this.algoId = algoId;
    }

    public String getAlgoId() {
        return algoId;
    }

    public static XMLAlgEnum fromString(String text) {
        for (XMLAlgEnum b : XMLAlgEnum.values()) {
            if (String.valueOf(b).equalsIgnoreCase(text)) {
                return b;
            }
        }
        return null;
    }
}
