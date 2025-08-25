package es.gob.jmulticard.connection.ca;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.connection.ApduConnection;

/** Conexi&oacute;n tras realizar el ChipAuthentication para establecimiento de canal seguro por NFC.
 * @author Logalty
*/
public abstract class ChipAuthentication {
    ApduConnection connection;
    CryptoHelper cryptoHlpr;

    public void setConnection(ApduConnection connection) {
        this.connection = connection;
    }

    public void setCryptoHlpr(CryptoHelper cryptoHlpr) {
        this.cryptoHlpr = cryptoHlpr;
    }

    public ApduConnection getConnection() {
        return connection;
    }

    public CryptoHelper getCryptoHlpr() {
        return cryptoHlpr;
    }
}

