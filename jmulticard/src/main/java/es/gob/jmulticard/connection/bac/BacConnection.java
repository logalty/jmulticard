package es.gob.jmulticard.connection.bac;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection;

/** Conexi&oacute;n BAC para establecimiento de canal seguro por NFC.
 * @author Logalty
*/
public class BacConnection extends Cwa14890OneV2Connection {
    public BacConnection(ApduConnection connection, CryptoHelper cryptoHlpr) {
        super(connection, cryptoHlpr);
    }
}
