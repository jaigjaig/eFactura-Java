/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package efactura;
import java.awt.RenderingHints.Key;
import java.io.File;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.crypto.KeyGenerator;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.xml.security.encryption.EncryptedData;






/**
 *
 * @author jaime
 */
public class XMLEncryptionSample {
    static {
        org.apache.xml.security.Init.init();
    }
    private static Document parseFile(String fileName) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(fileName);
    }
    private static SecretKey generateSymmetricKey() throws Exception {
        String jceAlgorithmName = "DESede";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        return keyGenerator.generateKey();
    }
    private static void writeDocToFile(Document doc, String fileName)    throws Exception {
        FileOutputStream outStream = new FileOutputStream(new File(fileName));
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        DOMSource source = new DOMSource(doc);
        transformer.transform(source, new StreamResult(outStream));
        outStream.close();
    }
    public static void encrypt(String source, String target, String ns, String element,Key publicKey, String keyName) throws Exception {
            // Lee XML desde archivo
            Document document = parseFile(source);
            // Genera clave simétrica para TripleDes
            Key symmetricKey = (Key) generateSymmetricKey();
            // Inicializa cifrador para cifrar la clave simétrica
            XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            keyCipher.init(XMLCipher.WRAP_MODE, (java.security.Key) publicKey);
            // Cifra la clave simetrica
            EncryptedKey encryptedKey = keyCipher
            .encryptKey(document, (java.security.Key) symmetricKey);
            // Especifica el elemento del documento XML a cifrar
            Element rootElement = document.getDocumentElement();
            Element elementToEncrypt = rootElement;
            if (element != null) {
                elementToEncrypt = (Element) rootElement.getElementsByTagNameNS(ns, element).item(0);
                if (elementToEncrypt == null) {   
                System.err.println("No se encuentra el elemento: " + element);
                }
            }
        // Inicializa cifrador para cifrar el Elemento XML
        XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, (java.security.Key) symmetricKey);
        // Agrega informacion de la clave de cifrado
        EncryptedData encryptedDataElement = xmlCipher.getEncryptedData();
        KeyInfo innerKeyInfo = new KeyInfo(document);
        innerKeyInfo.addKeyName(keyName);
        encryptedKey.setKeyInfo(innerKeyInfo);
        KeyInfo keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedDataElement.setKeyInfo(keyInfo);
        // Cifra
        xmlCipher.doFinal(document, elementToEncrypt);
        // Escribe el resultado en el archivo destino
        writeDocToFile(document, target);
    }
    public static void decrypt(String source, String target, Key privateKey)throws Exception {
        // Lee XML desde archivo
        Document document = parseFile(source);
        // Obtiene el Elemento XML con datos cifrados
        String namespaceURI = EncryptionConstants.EncryptionSpecNS;
        String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;
        Element encryptedDataElement = (Element) document
        .getElementsByTagNameNS(namespaceURI, localName).item(0);
        // Se desencripta la clave simétrica
        XMLCipher xmlCipher = XMLCipher.getInstance();
        xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        xmlCipher.setKEK((java.security.Key) privateKey);
        // Se reemplaza el nodo encriptado con la información desencriptada
        xmlCipher.doFinal(document, encryptedDataElement);
        // Escribe el resultado en el archivo destino
        writeDocToFile(document, target);
    }

}

