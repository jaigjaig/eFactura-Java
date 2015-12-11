/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package efactura;
import efactura.XMLEncryptionSample;
import java.awt.RenderingHints;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
/**
 *
 * @author jaime
 */
public class EFactura {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, Exception {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        String p12Password = "16923509j";
        keystore.load(new FileInputStream("./clientclient.p12"), p12Password.toCharArray());
        privateKey = (PrivateKey) keystore.getKey("client", p12Password.toCharArray());
        publicKey = keystore.getCertificate("client").getPublicKey();
        /*Finalmente, para efectuar una prueba, se pueden utilizar los métodos encrypt/decrypt de la
        siguiente manera:*/
        
        XMLEncryptionSample.encrypt("SinEncriptar.xml", "Encriptado.xml", "http://cfe.dgi.gub.uy", "Compl_Fiscal_Data", (RenderingHints.Key) publicKey, "CERT_DGI_EFACTURA");
        XMLEncryptionSample.decrypt("Encriptado.xml", "Desencriptado.xml", (RenderingHints.Key) privateKey);
    }
    
}
