package es.gob.jmulticard.connection;

import java.util.Arrays;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;

/** Conexi&oacute;n seg&uacute;n ISO 7816 con una tarjeta inteligente
 * insertada en un lector.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class AbstractApduConnectionIso7816 implements ApduConnection {

    /** Etiqueta que identifica que es necesario recuperar el
     * resultado del comando anterior. */
    private static final byte TAG_RESPONSE_PENDING = 0x61;

    /** Etiqueta que identifica que la longitud de respuesta
     * indicada no es correcta. */
    private static final byte TAG_RESPONSE_INVALID_LENGTH = 0x6C;

	/** Obtiene el tama&ntilde;o m&aacute;ximo de APDU que se puede
	 * enviar sin necesidad de hacer una envoltura.
	 * @return Tama&ntilde;o m&aacute;ximo (en octetos) de APDU que se
	 *         puede enviar sin necesidad de hacer una envoltura. */
	public abstract int getMaxApduSize();

	/** Tama&ntilde;o de chunk preferido para READ BINARY (en bytes de texto claro por APDU).
	 * <p>El valor por defecto (220) es seguro para el canal BAC (3DES-CBC SM) dentro de
	 * una APDU est&aacute;ndar ISO 7816-4 de 256 bytes: el overhead SM ocupa ~35&nbsp;bytes
	 * (DO87 header + padding + DO99 + DO8E), dejando 220 bytes de payload &uacute;til.</p>
	 * <p>Las subclases que tengan acceso a informaci&oacute;n del transporte (p.ej.
	 * {@code IsoDep.getMaxTransceiveLength()}) pueden sobreescribir este m&eacute;todo
	 * para devolver un valor mayor cuando el chip y el transporte lo soporten.</p>
	 * @return N&uacute;mero m&aacute;ximo de bytes de texto claro por comando READ BINARY. */
	public int getPreferredReadChunkSize() {
		return 220;
	}

	/** Transmite una APDU.
	 * @param apdu Comando APDU a transmitir.
	 * @return APDU de respuesta.
	 * @throws ApduConnectionException Si hay cualquier problema durante el env&iacute;o. */
	protected abstract ResponseApdu internalTransmit(byte[] apdu) throws ApduConnectionException;

	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
        if (command == null) {
            throw new IllegalArgumentException(
        		"No se puede transmitir una APDU nula" //$NON-NLS-1$
            );
        }

		final byte[] sendApdu;
		// Si la APDU es mayor que el tamano maximo la troceamos y la envolvemos
		if (command.getBytes().length > getMaxApduSize()) {

			int sentLength = 0;
			final int totalLength = command.getBytes().length;
			final int contentSizeEnvelope = getMaxApduSize() - 5; // La cabecera de la APDU son 5 octetos

			while (totalLength - sentLength > contentSizeEnvelope) {
				final byte[] apduChunk = Arrays.copyOfRange(
					command.getBytes(),
					sentLength,
					sentLength + contentSizeEnvelope
				);

				final ResponseApdu response = internalTransmit(
					HexUtils.concatenateByteArrays(
						new byte[] {
							(byte) 0x90,
							(byte) 0xC2,
							(byte) 0x00,
							(byte) 0x00,
							(byte) apduChunk.length
						},
						apduChunk
					)
				);
				if(!response.isOk()) {
					return response;
				}
				sentLength += contentSizeEnvelope;
			}

			// La ultima APDU se envia fuera del bucle
			final byte[] apduChunk = Arrays.copyOfRange(
				command.getBytes(),
				sentLength,
				totalLength
			);
			sendApdu = HexUtils.concatenateByteArrays(
				new byte[] {
					(byte) 0x90,
					(byte) 0xC2,
					(byte) 0x00,
					(byte) 0x00,
					(byte) apduChunk.length
				},
				apduChunk
			);
		}
		// Si es pequena, se envia directamente
		else {
			sendApdu = command.getBytes();
		}
    	final ResponseApdu response = internalTransmit(sendApdu);

        // Solicitamos el resultado de la operacion si es necesario
        if (response.getStatusWord().getMsb() == TAG_RESPONSE_PENDING) {
            // Si ya se ha devuelto parte de los datos, los concatenamos al resultado
            if (response.getData().length > 0) {
                final byte[] data = response.getData();
                final byte[] additionalData = transmit(
                    new GetResponseApduCommand(
                		(byte) 0x00, response.getStatusWord().getLsb()
            		)
                ).getBytes();

                final byte[] fullResponse = new byte[data.length + additionalData.length];
                System.arraycopy(data, 0, fullResponse, 0, data.length);
                System.arraycopy(additionalData, 0, fullResponse, data.length, additionalData.length);

                return new ResponseApdu(fullResponse);
            }
            return transmit(new GetResponseApduCommand((byte) 0x00, response.getStatusWord().getLsb()));
        }

        // En caso de longitud esperada incorrecta, reenviamos la APDU con la longitud esperada recibida.
        // Incluimos la condicion del CLA igual 0x00 para que no afecte a las APDUs cifradas
        // (de eso se encargara la clase de conexion con canal seguro)
		if (response.getStatusWord().getMsb() == TAG_RESPONSE_INVALID_LENGTH && command.getCla() == (byte) 0x00) {
            command.setLe(response.getStatusWord().getLsb());
            return transmit(command);
        }

        return response;
	}

}
