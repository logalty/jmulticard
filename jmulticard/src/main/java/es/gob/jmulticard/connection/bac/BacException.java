package es.gob.jmulticard.connection.bac;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.card.icao.IcaoException;

/** Error relacionado con el protocolo BAC.
 * @author Logalty. */
public class BacException extends IcaoException {

    /** Identificador de versi&oacute;n para la serializaci&oacute;n. */
    private static final long serialVersionUID = 0;

    /** Constructor.
     * @param retCode Palabra de estado obtenida como c&oacute;digo
     *                de retorno.
     * @param origin APDU que origin&oacute; el error.
     * @param description Descripci&oacute;n de la excepci&oacute;n. */
    public BacException(final StatusWord retCode,
                         final Apdu origin,
                         final String description) {
        super(retCode, origin, description);
    }

    /** Crea la excepci&oacute;n de error relacionado con el protocolo BAC.
     * @param description Detalle de la excepci&oacute;n.
     * @param e Excepci&oacute;n de origen. */
    public BacException(final String description, final Throwable e) {
        super(description, e);
    }

    /** Crea la excepci&oacute;n de error relacionado con el protocolo BAC.
     * @param description Detalle de la excepci&oacute;n. */
    public BacException(final String description) {
        super(description);
    }

}
