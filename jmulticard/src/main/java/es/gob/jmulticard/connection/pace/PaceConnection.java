package es.gob.jmulticard.connection.pace;

import java.util.logging.Logger;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.card.AbstractSmartCard;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.connection.cwa14890.InvalidCryptographicChecksumException;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessagingException;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessagingType;

/** Conexi&oacute;n PACE para establecimiento de canal seguro por NFC.
 * @author Sergio Mart&iacute;nez Rico
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class PaceConnection extends Cwa14890OneV2Connection {

	private static final StatusWord INVALID_CRYPTO_CHECKSUM = new StatusWord((byte)0x66, (byte)0x88);

	/** Octeto de valor m&aacute;s significativo que indica un <i>Le</i> incorrecto en la petici&oacute;n. */
	private static final byte MSB_INCORRECT_LE = (byte) 0x6C;

	/** Octeto de valor m&aacute;s significativo que indica un <i>Le</i> incorrecto en la petici&oacute;n. */
	private transient SecureMessaging sm;

	/** Conexi&oacute;n PACE para establecimiento de canal seguro por NFC.
	 * @param connection Conexi&oacute;n base sobre la que crear el nuevo canal.
	 * @param cryptoHlpr Clase para el cifrado de datos.
	 * @param secMsg Clase contenedora de las variables para establecer el canal PACE (Kenc, Kmac, Ssc). */
	public PaceConnection(final ApduConnection connection,
			              final CryptoHelper cryptoHlpr,
			              final SecureMessaging secMsg) {
		super(connection, cryptoHlpr);
		sm = secMsg;
		subConnection = connection;
	}

	@Override
	public String toString() {
    	return "Conexion de tipo PACE " + //$NON-NLS-1$
			(isOpen()
				? "abierta sobre " + getSubConnection() //$NON-NLS-1$
					: "cerrada"); //$NON-NLS-1$
    }

	/** Abre el canal seguro con la tarjeta.
	 * La conexi&oacute;n se reiniciar&aacute; previamente a la apertura del canal. */
	@Override
	public void open() {
		openState = true;
	}

	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		// Si es el comando para verificar el PIN se creara una instancia nueva de la clase
		// CommandApdu ya que la clase StcmVerifyApduCommand no incluye la contrasena como parte
		// la APDU, sino en un attributo aparte
		final CommandApdu finalCommand = new CommandApdu(
			command.getCla(),
			command.getIns(),
			command.getP1(),
			command.getP2(),
			command.getData(),
			command.getLe()
		);

		final boolean isChv = finalCommand.getIns() == VerifyApduCommand.INS_VERIFY;

		if (AbstractSmartCard.DEBUG) {
			Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
				"APDU de comando en claro: " + //$NON-NLS-1$
					(isChv ? "Verificacion de PIN" : HexUtils.hexify(finalCommand.getBytes(), true)) //$NON-NLS-1$
			);
		}

		// Encriptacion de la APDU para su envio por el canal seguro
		final CommandApdu protectedApdu;
		try {
			protectedApdu = sm.wrap(finalCommand);
		}
		catch (final SecureMessagingException e) {
			throw new ApduConnectionException(
				"No ha sido posible cifrar un mensaje seguro con el canal PACE", e //$NON-NLS-1$
			);
		}

		ResponseApdu responseApdu = subConnection.transmit(protectedApdu);

		// Manejar GET RESPONSE (SW1=0x61): el chip indica que hay más datos disponibles
    responseApdu = handleGetResponse(responseApdu);

    // SIEMPRE intentar descifrar para mantener SSC sincronizado
    final ResponseApdu decipherApdu;
    try {
        decipherApdu = sm.unwrap(responseApdu);  // ← SSC se incrementa siempre
    } catch (final SecureMessagingException e1) {
        // Si unwrap falla, la respuesta no es SM → comprobar SW externo
        if (!responseApdu.getStatusWord().isOk()
            && !new StatusWord((byte)0x62,(byte)0x82).equals(responseApdu.getStatusWord())) {
            throw new ApduConnectionException(
                "Error transmitiendo la APDU cifrada:\n" +
                "Error: " + responseApdu.getStatusWord() + "\n" +
                "Respuesta:\n" + responseApdu
            );
        }
        throw new ApduConnectionException(
            "No ha sido posible descifrar un mensaje seguro con el canal PACE", e1
        );
    }

    if (INVALID_CRYPTO_CHECKSUM.equals(decipherApdu.getStatusWord())) {
        throw new InvalidCryptographicChecksumException();
    }

    // Comprobar el SW INTERNO (descifrado) en vez del externo
    if (!decipherApdu.getStatusWord().isOk()
        && !new StatusWord((byte)0x62,(byte)0x82).equals(decipherApdu.getStatusWord())) {
        throw new ApduConnectionException(
            "Error transmitiendo la APDU cifrada:\n" +
            "Error: " + decipherApdu.getStatusWord()
        );
    }

    // Manejo de Le incorrecto
    if (decipherApdu.getStatusWord().getMsb() == MSB_INCORRECT_LE) {
        command.setLe(decipherApdu.getStatusWord().getLsb());
        return transmit(command);
    }
		return decipherApdu;
	}

		public void restartSecureMessaging(SecureMessaging sm) {
		if (sm == null) {
			throw new IllegalArgumentException("El objeto SecureMessaging no puede ser nulo"); //$NON-NLS-1$
		}
		this.sm = sm;
	}

	public SecureMessagingType getType() {
		return sm.getType();
	}

		/**
	 * Maneja respuestas SW1=0x61 (más datos disponibles) enviando GET RESPONSE
	 * repetidamente hasta obtener todos los datos. El GET RESPONSE se envía SIN
	 * secure messaging ya que opera a nivel de transporte (ICAO 9303 / ISO 7816-4).
	 *
	 * @param initialResponse La respuesta inicial que puede contener SW 61xx
	 * @return La respuesta completa con todos los datos acumulados
	 */
	private ResponseApdu handleGetResponse(ResponseApdu initialResponse) throws ApduConnectionException {
			ResponseApdu currentResponse = initialResponse;
			java.io.ByteArrayOutputStream accumulatedData = new java.io.ByteArrayOutputStream();

			// Acumular datos de la respuesta inicial (si los hay)
			if (currentResponse.getData() != null && currentResponse.getData().length > 0) {
					try {
							accumulatedData.write(currentResponse.getData());
					} catch (java.io.IOException e) {
							throw new ApduConnectionException("Error acumulando datos GET RESPONSE", e);
					}
			}

			// Mientras el chip indique que hay más datos (SW1=0x61)
			int maxIterations = 50; // Límite de seguridad
			while (currentResponse.getStatusWord().getMsb() == (byte) 0x61 && maxIterations-- > 0) {
					int remaining = currentResponse.getStatusWord().getLsb() & 0xFF;
					if (remaining == 0) remaining = 256; // 0x00 = 256 bytes

					Logger.getLogger("es.gob.jmulticard").info("GET RESPONSE: " + remaining + " bytes más disponibles");

					// GET RESPONSE se envía SIN secure messaging (nivel transporte)
					CommandApdu getResponseCmd = new CommandApdu(
							(byte) 0x00, // CLA
							(byte) 0xC0, // INS = GET RESPONSE
							(byte) 0x00, // P1
							(byte) 0x00, // P2
							null,        // Sin datos
							remaining    // Le = bytes esperados
					);

					currentResponse = subConnection.transmit(getResponseCmd);

					if (currentResponse.getData() != null && currentResponse.getData().length > 0) {
							try {
									accumulatedData.write(currentResponse.getData());
							} catch (java.io.IOException e) {
									throw new ApduConnectionException("Error acumulando datos GET RESPONSE", e);
							}
					}
			}

			// Si no hubo GET RESPONSE, devolver la respuesta original
			if (accumulatedData.size() == 0 ||
					initialResponse.getStatusWord().getMsb() != (byte) 0x61) {
					return initialResponse;
			}

			// Reconstruir ResponseApdu con todos los datos acumulados + SW final
			byte[] allData = accumulatedData.toByteArray();
			byte[] fullResponse = new byte[allData.length + 2];
			System.arraycopy(allData, 0, fullResponse, 0, allData.length);
			fullResponse[allData.length] = currentResponse.getStatusWord().getMsb();
			fullResponse[allData.length + 1] = currentResponse.getStatusWord().getLsb();

			Logger.getLogger("es.gob.jmulticard").info("GET RESPONSE completado: " + allData.length + " bytes totales");
			return new ResponseApdu(fullResponse);
	}

}
