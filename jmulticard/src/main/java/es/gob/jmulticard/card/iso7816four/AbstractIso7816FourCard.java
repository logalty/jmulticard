/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard.card.iso7816four;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.iso7816four.GetChallengeApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ReadBinaryApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ReadRecordApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectDfByNameApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse;
import es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.card.AbstractSmartCard;
import es.gob.jmulticard.card.CardSecurityException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.icao.TlvHeaderInfo;
import es.gob.jmulticard.connection.AbstractApduConnectionIso7816;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.connection.cwa14890.SecureChannelException;

/** Tarjeta compatible ISO-7816-4.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 * @author Alberto Mart&iacute;nez. */
public abstract class AbstractIso7816FourCard extends AbstractSmartCard {

	/** Condici&oacute;n de seguridad no satisfecha. */
    private static final StatusWord SW_UNSATISFIED_SECURITY_STATE = new StatusWord((byte) 0x69, (byte) 0x82);

    /** EF o DF no encontrado. */
    private static final StatusWord SW_FILE_NOT_FOUND = new StatusWord((byte) 0x6A, (byte) 0x82);

    /** Se ha alcanzado prematuramente el final de fichero. */
    private static final StatusWord SW_EOF_REACHED = new StatusWord((byte) 0x62, (byte) 0x82);

    /** El <i>offset</i> sobrepasa el l&iacute;mite de tama&ntilde;o del EF. */
    private static final StatusWord SW_OFFSET_OUTSIDE_EF = new StatusWord((byte) 0x6B, (byte) 0x00);

    /** Tama&ntilde;o m&aacute;ximo de datos que se puede leer en una &uacute;nica APDU. */
    private static final int MAX_READ_CHUNK = 0xFF;

    /** <code>Logger</code> por defecto. */
    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    /**
     * Tama&ntilde;o de chunk por defecto para READ BINARY (bytes de texto claro por APDU).
     * Seguro para BAC 3DES-SM en APDU est&aacute;ndar: 256B respuesta - ~35B overhead SM = 220B &uacute;tiles.
     */
    private static final int DEFAULT_READ_CHUNK_SIZE = 220;

    /** Construye una tarjeta compatible ISO 7816-4.
     * @param c Octeto de clase (CLA) de las APDU.
     * @param conn Connexi&oacute;n con la tarjeta. */
    public AbstractIso7816FourCard(final byte c, final ApduConnection conn) {
        super(c, conn);
    }

    /**
     * Obtiene el tama&ntilde;o de chunk inicial preferido para READ BINARY consultando
     * la conexi&oacute;n de transporte subyacente.
     *
     * <p>Recorre la cadena de conexiones (canal SM &rarr; transporte raw) para llegar
     * a {@link AbstractApduConnectionIso7816} y delegar en su
     * {@link AbstractApduConnectionIso7816#getPreferredReadChunkSize()}. Esto permite
     * que cada sabor de hardware (Android IsoDep, Sunmi, PAX) aporte su valor &oacute;ptimo
     * sin que esta clase conozca los detalles del transporte.</p>
     *
     * @return N&uacute;mero de bytes de texto claro para el primer READ BINARY de la sesi&oacute;n.
     */
    protected int getPreferredInitialReadChunkSize() {
        ApduConnection conn = getConnection();
        int maxWalk = 8; // Tope de seguridad ante cadenas circulares
        while (conn instanceof Cwa14890Connection && maxWalk-- > 0) {
            final ApduConnection sub = ((Cwa14890Connection) conn).getSubConnection();
            if (sub == null) break;
            conn = sub;
        }
        if (conn instanceof AbstractApduConnectionIso7816) {
            final int chunk = ((AbstractApduConnectionIso7816) conn).getPreferredReadChunkSize();
            LOGGER.info("getPreferredInitialReadChunkSize: transport=" + conn.getClass().getSimpleName()
                    + " chunk=" + chunk);
            return chunk;
        }
        LOGGER.warning("getPreferredInitialReadChunkSize: no AbstractApduConnectionIso7816 found (conn="
                + (conn != null ? conn.getClass().getSimpleName() : "null") + "), default=" + DEFAULT_READ_CHUNK_SIZE);
        return DEFAULT_READ_CHUNK_SIZE;
    }

    /**
     * Lee un archivo usando Short File Identifier (SFI) sin necesidad de SELECT previo.
     * Esto es compatible con pasaportes que no soportan SELECT en modo BAC secure messaging.
     *
     * @param sfi Short File Identifier del archivo (byte bajo del FID)
     * @param offset Offset desde el inicio del archivo
     * @param length Número de bytes a leer
     * @return Datos leídos del archivo
     * @throws ApduConnectionException Si hay error en la comunicación
     */
    protected byte[] readBinaryBySFI(int sfi, int offset, int length) throws ApduConnectionException {
        // P1 = 0x80 | SFI (bit 7 activado para indicar que usamos SFI)
        byte p1 = (byte) (0x80 | (sfi & 0x1F));  // Solo los 5 bits bajos del SFI
        byte p2 = (byte) offset;  // Offset en el archivo

        CommandApdu commandApdu = new CommandApdu(
            (byte) 0x00,  // CLA
            (byte) 0xB0,  // INS (READ BINARY)
            p1,           // P1 = 0x80 | SFI
            p2,           // P2 = Offset
            null,         // No data
            length // Le (bytes esperados)
        );

        ResponseApdu response = getConnection().transmit(commandApdu);

        if (!response.getStatusWord().isOk()) {
            throw new ApduConnectionException(
                "Error leyendo archivo con SFI " + Integer.toHexString(sfi) +
                ": " + response.getStatusWord()
            );
        }

        return response.getData();
    }
    /** Lee un contenido binario del fichero actualmente seleccionado.
     * @param msbOffset Octeto m&aacute;s significativo del desplazamiento
     *                  (<i>offset</i>) hasta el punto de inicio de la lectura desde
     *        			el comienzo del fichero.
     * @param lsbOffset Octeto menos significativo del desplazamiento (<i>offset</i>)
     *                  hasta el punto de inicio de la lectura desde el comienzo del
     *                  fichero.
     * @param readLength Longitud de los datos a leer (en octetos).
     * @return APDU de respuesta.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws RequiredSecurityStateNotSatisfiedException Si la lectura requiere el cumplimiento
     *                        de una condici&oacute;n de seguridad y esta no se ha satisfecho.
     * @throws OffsetOutsideEfException Si el desplazamiento indicado o el tama&ntilde;o indicados
     *                                  para la lectura caen fuera de los l&iacute;mites del fichero. */
    private ResponseApdu readBinary(final byte msbOffset,
    		                        final byte lsbOffset,
    		                        final int readLength) throws ApduConnectionException,
                                                                  RequiredSecurityStateNotSatisfiedException,
                                                                  OffsetOutsideEfException {
    	final CommandApdu apdu = new ReadBinaryApduCommand(
			getCla(), msbOffset, lsbOffset, readLength
		);
    	final ResponseApdu res = getConnection().transmit(
			apdu
		);
        if (res.isOk()) {
        	return res;
        }
        if (SW_OFFSET_OUTSIDE_EF.equals(res.getStatusWord())) {
        	throw new OffsetOutsideEfException(SW_OFFSET_OUTSIDE_EF, apdu);
        }
        if (SW_UNSATISFIED_SECURITY_STATE.equals(res.getStatusWord())) {
        	throw new RequiredSecurityStateNotSatisfiedException(res.getStatusWord());
        }
        if (SW_EOF_REACHED.equals(res.getStatusWord())) {
        	LOGGER.warning("Se ha alcanzado el final de fichero antes de poder leer los octetos indicados"); //$NON-NLS-1$
        	return res;
        }
        LOGGER.warning("Respuesta invalida en la lectura de binario con el codigo: " + res.getStatusWord()); //$NON-NLS-1$
        throw new ApduConnectionException("Respuesta invalida en la lectura de binario con el codigo: " + res.getStatusWord()); //$NON-NLS-1$
    }

    /** Lee todos los registros del binario actualmente seleccionado.
     * @return Lista de registros leidos del binario actualmente seleccionado.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws Iso7816FourCardException SI ocurren problemas durante la lectura de los registros. */
    public List<byte[]> readAllRecords() throws ApduConnectionException, Iso7816FourCardException {
    	final List<byte[]> ret = new ArrayList<>();
    	StatusWord readedResponseSw;
    	final CommandApdu readRecordApduCommand = new ReadRecordApduCommand(getCla());
    	do {
    		final ResponseApdu readedResponse = sendArbitraryApdu(readRecordApduCommand);
    		readedResponseSw = readedResponse.getStatusWord();
    		if (!readedResponse.isOk() && !ReadRecordApduCommand.RECORD_NOT_FOUND.equals(readedResponseSw)) {
    			throw new Iso7816FourCardException(
					"Error en la lectura de registro", readedResponseSw //$NON-NLS-1$
    			);
    		}
    		ret.add(readedResponse.getData());
    	} while (!ReadRecordApduCommand.RECORD_NOT_FOUND.equals(readedResponseSw));

    	return ret;
    }

    /** Lee por completo el contenido binario del fichero actualmente seleccionado.
     * @param len Longitud del fichero a leer.
     * @return APDU de respuesta.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws IOException Si hay problemas en el <i>buffer</i> de lectura. */
    public byte[] readBinaryComplete(int len) throws IOException {
        int off = 0;
        if (len == 0) {
            try {
                TlvHeaderInfo headerInfo = parseFileHeader((byte) 4);
                if (headerInfo == null) {
                    LOGGER.warning("No se pudo parsear cabecera TLV, usando lectura incremental");
                    return readBinaryIncremental();
                }
                len = headerInfo.valueLength + headerInfo.headerLength;
                LOGGER.info("Tamaño total calculado desde cabecera TLV: " + len +
                        " (header=" + headerInfo.headerLength + " + value=" + headerInfo.valueLength + ")");
            } catch (final RequiredSecurityStateNotSatisfiedException e) {
                throw new IOException("Condicion de seguridad no satisfecha al leer el fichero", e);
            } catch (final OffsetOutsideEfException e) {
                throw new IOException("Se ha intentado una lectura fuera de los limites del fichero", e);
            } catch (final ApduConnectionException e) {
                throw new IOException("Error de conexion al leer el fichero", e);
            } catch (final Iso7816FourCardException e) {
                throw new IOException("Error leyendo fichero", e);
            }
        }

        ResponseApdu readedResponse;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Chunk inicial: valor preferido de la conexion de transporte subyacente.
        // AndroidNfcConnection devuelve 220B (techo seguro para 3DES-SM en APDU estandar).
        // SunmiNfcConnection y PaxNfcConnection devuelven 164B (conservador para SDKs OEM).
        // La logica de back-off reduce el chunk si el chip responde con error.
        int readChunkSize = getPreferredInitialReadChunkSize();
        int apduCount = 0;
        LOGGER.info("READ_BINARY_START fileLen=" + len + " initialChunk=" + readChunkSize);

        while (off < len) {
            // ICAO 9303 Part 11 §9.9.1: READ BINARY with P1 bit7=0 limits offset to 15 bits (max 0x7FFF = 32767).
            // When off > 0x7FFF, P1 bit7 would be set, which the chip interprets as SFI addressing.
            // TODO: implement READ BINARY with offset data object (INS=0xB1) for files > 32 KB per ICAO 9303 §9.9.
            if (off > 0x7FFF) {
                LOGGER.severe("READ_BINARY offset=" + off + " excede el limite de 15 bits (0x7FFF=32767). "
                        + "Los datos por encima de 32 KB no pueden leerse con READ BINARY estandar. "
                        + "Devolviendo datos parciales.");
                break;
            }
            final byte msbOffset = (byte)(off >> 8);
            final byte lsbOffset = (byte)(off & 0xFF);
            final int left = len - off;
            final int requestedBytes = Math.min(left, readChunkSize);

            try {
                apduCount++;
                readedResponse = readBinary(msbOffset, lsbOffset, requestedBytes);
            } catch (final OffsetOutsideEfException e) {
                LOGGER.warning("Lectura fuera de limites en offset=" + off + ", devolviendo lo leido");
                break;
            } catch (final RequiredSecurityStateNotSatisfiedException e) {
                throw new IOException("Condicion de seguridad no satisfecha", e);
            } catch (final ApduConnectionException e) {
                LOGGER.warning("Error de conexion en offset=" + off + ": " + e.getMessage());
                final String errMsg = e.getMessage() != null ? e.getMessage() : "";
                final boolean smCorrupted = errMsg.contains("SecureMessaging")
                        || errMsg.contains("checksum")
                        || errMsg.contains("cifrar")
                        || errMsg.contains("descifrar");
                if (smCorrupted) {
                    LOGGER.severe("Error de Secure Messaging en offset=" + off
                            + ". SSC posiblemente desincronizado. Devolviendo datos parciales.");
                    break;
                }
                if (readChunkSize > 96 && off < len) {
                    readChunkSize = readChunkSize / 4;
                    LOGGER.warning("Error de conexion en offset=" + off
                            + " (" + errMsg + "), reduciendo chunk a " + readChunkSize);
                    continue;
                }
                LOGGER.warning("Error de conexion irrecuperable en offset=" + off
                        + ", devolviendo lo leido: " + errMsg);
                break;
            }

            LOGGER.finest("READ_BINARY apduCalls=" + apduCount
                    + " offset=" + off
                    + " requested=" + requestedBytes
                    + " readed=" + (readedResponse.getData() != null ? readedResponse.getData().length : 0)
                    + " status=" + readedResponse.getStatusWord());
            final boolean eofReached = SW_EOF_REACHED.equals(readedResponse.getStatusWord());

            if (!readedResponse.isOk() && !eofReached) {
                throw new IOException("Error leyendo binario (" + readedResponse.getStatusWord() + ")");
            }

            final byte[] data = readedResponse.getData();

            if (data != null && data.length > 0) {
                final int bytesToWrite = Math.min(data.length, len - off);
                out.write(data, 0, bytesToWrite);
                off += bytesToWrite;
            }

            if (eofReached && (data == null || data.length == 0) && off < len) {
                if (readChunkSize > 96) {
                    readChunkSize = readChunkSize / 4;
                    LOGGER.finest("EOF sin datos en offset=" + off + ", reduciendo chunk a " + readChunkSize + " bytes");
                    continue;
                }
                LOGGER.warning("EOF sin datos en offset=" + off + " con chunk minimo, deteniendo lectura");
                break;
            }

            if (eofReached) {
                break;
            }

            if (data == null || data.length == 0) {
                break;
            }
        }

        final byte[] result = out.toByteArray();
        LOGGER.info("READ_BINARY_DONE apduCalls=" + apduCount
                + " bytesRead=" + result.length
                + " fileLen=" + len
                + " finalChunk=" + readChunkSize);
        if (result.length < len) {
            LOGGER.warning("readBinaryComplete: leidos " + result.length
                    + " de " + len + " bytes esperados");
            throw new IOException("No se pudo leer el fichero completo, leidos " + result.length + " de " + len + " bytes esperados");
        }
        return result;
    }

    /**
     * Lee un archivo binario en bloques incrementales hasta encontrar EOF.
     * Útil cuando SELECT FILE no devuelve el tamaño correcto.
     * @return Contenido completo del archivo.
     * @throws IOException Si hay problemas leyendo.
     * @throws Iso7816FourCardException Si hay errores APDU.
     */
    public byte[] readBinaryIncremental() throws IOException, Iso7816FourCardException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int offset = 0;
        final int blockSize = 250; // Leer en bloques de 250 bytes (seguro para secure messaging)

        while (true) {
            try {
                final byte msbOffset = (byte) ((offset >> 8) & 0xFF);
                final byte lsbOffset = (byte) (offset & 0xFF);

                final ResponseApdu response = readBinary(msbOffset, lsbOffset, (byte) blockSize);

                final byte[] data = response.getData();
                if (data == null || data.length == 0) {
                    break; // EOF alcanzado
                }

                baos.write(data);

                // Si recibimos menos bytes de los solicitados, hemos llegado al final
                if (data.length < blockSize) {
                    break;
                }

                offset += data.length;

            } catch (final OffsetOutsideEfException e) {
                // Fin del archivo alcanzado
                LOGGER.info("EOF alcanzado en offset: " + offset);
                break;
            } catch (final ApduConnectionException e) {
                throw new CryptoCardException("Error en comunicación durante lectura incremental", e);
            }
        }

        return baos.toByteArray();
}
    /**
     * Lee un archivo binario en bloques incrementales hasta encontrar EOF.
     * No falla si el tamaño reportado por SELECT es incorrecto.
     * @return Contenido completo del archivo sin padding.
     * @throws IOException Si hay problemas leyendo.
     * @throws Iso7816FourCardException Si hay errores APDU.
     */
    public byte[] readBinaryIncrementalWithPadding() throws IOException, Iso7816FourCardException {
        final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        int offset = 0;
        final int blockSize = 164; // 164 bytes máximo en BAC para evitar problemas con padding

        while (true) {
            try {
                final byte msbOffset = (byte) ((offset >> 8) & 0xFF);
                final byte lsbOffset = (byte) (offset & 0xFF);

                // readBinary es el método privado de AbstractIso7816FourCard
                final ResponseApdu response = readBinary(msbOffset, lsbOffset, (byte) blockSize);

                final byte[] data = response.getData();
                if (data == null || data.length == 0) {
                    LOGGER.info("EOF alcanzado en offset " + offset + " (sin datos)");
                    break;
                }

                baos.write(data);
                LOGGER.fine("Leídos " + data.length + " bytes en offset " + offset);

                // Si recibimos menos bytes de los solicitados, hemos llegado al final
                if (data.length < blockSize) {
                    LOGGER.info("EOF alcanzado en offset " + offset + " (" + data.length + " < " + blockSize + ")");
                    break;
                }

                offset += data.length;

                // Protección contra loops infinitos
                if (offset > 65536) { // 64KB máximo por DG
                    LOGGER.warning("Límite de 64KB alcanzado, deteniendo lectura");
                    break;
                }

            } catch (final OffsetOutsideEfException e) {
                LOGGER.info("EOF alcanzado en offset " + offset + " (OffsetOutsideEfException)");
                break;
            } catch (final RequiredSecurityStateNotSatisfiedException e) {
                throw new CardSecurityException("No se tienen permisos para leer", e);
            } catch (final ApduConnectionException e) {
                LOGGER.info("EOF alcanzado (ApduConnectionException) en offset " + offset + ": " + e.getMessage());
                break;
            }
        }

        final byte[] result = baos.toByteArray();

        // CRÍTICO: Eliminar padding ISO 9797-1 (0x80 seguido de 0x00s) al final
        return removePadding(result);
    }

    /**
     * Elimina el padding ISO 9797-1 (0x80 seguido de 0x00s) del final de los datos.
     * Este padding es añadido por el secure messaging en BAC.
     * @param data Datos con posible padding.
     * @return Datos sin padding.
     */
    private byte[] removePadding(final byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        // Buscar el último 0x80 que marca el inicio del padding
        int paddingStart = data.length;
        for (int i = data.length - 1; i >= 0; i--) {
            if (data[i] == (byte) 0x80) {
                // Verificar que después solo hay 0x00s
                boolean isPadding = true;
                for (int j = i + 1; j < data.length; j++) {
                    if (data[j] != (byte) 0x00) {
                        isPadding = false;
                        break;
                    }
                }
                if (isPadding) {
                    paddingStart = i;
                    break;
                }
            } else if (data[i] != (byte) 0x00) {
                // Si encontramos un byte que no es 0x00 ni 0x80, no hay padding
                break;
            }
        }

        if (paddingStart < data.length) {
            LOGGER.fine("Eliminando " + (data.length - paddingStart) + " bytes de padding ISO 9797-1");
            final byte[] result = new byte[paddingStart];
            System.arraycopy(data, 0, result, 0, paddingStart);
            return result;
        }

        return data;
    }
	/** Selecciona un fichero por nombre.
	 * @param name Nombre del fichero
	 * @return Tama&ntilde;o del fichero seleccionado.
	 * @throws ApduConnectionException Si ocurre alg&uacute;n problema durante la selecci&oacute;n
	 * @throws Iso7816FourCardException Si el fichero no se puede seleccionar por cualquier otra causa */
    public int selectFileByName(final String name) throws ApduConnectionException,
                                                          Iso7816FourCardException {
    	return selectFileByName(name.getBytes());
    }

	/** Selecciona un fichero por nombre.
	 * @param name Nombre del fichero en hexadecimal
	 * @return Tama&ntilde;o del fichero seleccionado.
	 * @throws FileNotFoundException Si el fichero no existe
     * @throws ApduConnectionException Si ocurre alg&uacute;n problema durante la selecci&oacute;n
	 * @throws Iso7816FourCardException Si el fichero no se puede seleccionar por cualquier otra causa */
    public int selectFileByName(final byte[] name) throws ApduConnectionException,
                                                          FileNotFoundException,
                                                          Iso7816FourCardException {
    	final CommandApdu selectCommand = new SelectDfByNameApduCommand(getCla(), name);
    	final ResponseApdu response = sendArbitraryApdu(selectCommand);
    	if (response.isOk()) {
    		return new SelectFileApduResponse(response).getFileLength();
    	}
        final StatusWord sw = response.getStatusWord();
        if (SW_FILE_NOT_FOUND.equals(sw)) {
            throw new FileNotFoundException(name);
        }
        throw new Iso7816FourCardException(sw, selectCommand);
    }

    /** Selecciona un fichero (DF o EF).
     * @param id Identificador del fichero a seleccionar.
     * @return Tama&ntilde;o del fichero seleccionado.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero. */
    public int selectFileById(final byte[] id) throws ApduConnectionException,
                                                      Iso7816FourCardException {
    	final CommandApdu selectCommand = new SelectFileByIdApduCommand(getCla(), id);
		final ResponseApdu res = getConnection().transmit(selectCommand);
		if (SW_FILE_NOT_FOUND.equals(res.getStatusWord())) {
    		throw new FileNotFoundException(id);
    	}
        final SelectFileApduResponse response = new SelectFileApduResponse(res);
        if (response.isOk()) {
            return response.getFileLength();
        }
        final StatusWord sw = response.getStatusWord();
        if (SW_FILE_NOT_FOUND.equals(sw)) {
            throw new FileNotFoundException(id);
        }
        if (SW_UNSATISFIED_SECURITY_STATE.equals(sw)) {
        	throw new RequiredSecurityStateNotSatisfiedException(response.getStatusWord());
        }
        throw new Iso7816FourCardException(sw, selectCommand);
    }

    /** Selecciona un fichero y lo lee por completo.
     * @param id Identificador del fichero a leer.
     * @return Contenido del fichero apuntado por la direcci&oacute;n <code>id</code>.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero.
     * @throws IOException Si hay problemas en el <i>buffer</i> de lectura. */
    public byte[] selectFileByIdAndRead(final byte[] id) throws Iso7816FourCardException,
                                                                IOException {
        final int fileLength = selectFileById(id);
        return readBinaryComplete(fileLength);
    }

    /** Selecciona un fichero (DF o EF).
     * @param location La ruta absoluta donde se encuentra el fichero a leer
     * @return Tama&ntilde;o del fichero seleccionado
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero */
    public int selectFileByLocation(final Location location) throws ApduConnectionException,
    Iso7816FourCardException {
        return selectFileByLocation(location, null);
    }

    /** Selecciona un fichero (DF o EF).
     * @param location La ruta absoluta donde se encuentra el fichero a leer
     * @param fileSize tamaño del fichero si ha sido calculado previamente
     * @return Tama&ntilde;o del fichero seleccionado
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero */
    public int selectFileByLocation(final Location location, final Integer fileSize) throws ApduConnectionException,
            Iso7816FourCardException {
        int fileLength = 0;
        Location loc = location;
        selectFileById(new byte[] { (byte)0x3F, (byte)0x00 });
        // selectMasterFile();
        while (loc != null) {
            final byte[] id = loc.getFile();
            fileLength = selectFileById(id);
            loc = loc.getChild();
        }
        if (fileSize != null) {
            return fileSize;
        }
        return fileLength;
    }

    /** Selecciona un fichero y lo lee por completo.
     * @param location Ruta absoluta del fichero a leer.
     * @return Contenido del fichero apuntado por la ruta <code>location</code>.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero.
     * @throws IOException Si hay problemas en el <i>buffer</i> de lectura. */
    public byte[] selectFileByLocationAndRead(final Location location) throws IOException,
    Iso7816FourCardException {
        return selectFileByLocationAndRead(location, null);
    }

    /** Selecciona un fichero y lo lee por completo.
     * @param location Ruta absoluta del fichero a leer.
     * @param fileSize tamaño del fichero si ha sido calculado previamente
     * @return Contenido del fichero apuntado por la ruta <code>location</code>.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero.
     * @throws IOException Si hay problemas en el <i>buffer</i> de lectura. */
    public byte[] selectFileByLocationAndRead(final Location location, final Integer fileSize) throws IOException,
            Iso7816FourCardException {
        final int fileLength = selectFileByLocation(location, fileSize);
        LOGGER.info(
        	"Tamaño del grupo: " + fileLength //$NON-NLS-1$
            );

        return readBinaryComplete(fileLength);
    }

    /** Selecciona el fichero maestro (directorio ra&iacute;z de la tarjeta).
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws FileNotFoundException Si no se encuentra el MF.
     * @throws Iso7816FourCardException Si no se puede seleccionar el fichero maestro por cualquier otra causa. */
    protected abstract void selectMasterFile() throws ApduConnectionException,
                                                      FileNotFoundException,
                                                      Iso7816FourCardException;

    /** Establece una clave p&uacute;blica para la la verificaci&oacute;n posterior de
     * un certificado emitido por otro al que pertenece esta clave.
     * @param refPublicKey Referencia a la clave p&uacute;blica para su carga.
     * @throws SecureChannelException Cuando ocurre un error durante la selecci&oacute;n de la clave.
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con la tarjeta. */
    public void setPublicKeyToVerification(final byte[] refPublicKey) throws SecureChannelException,
                                                                             ApduConnectionException {
    	final ResponseApdu res = sendArbitraryApdu(
			new CommandApdu(
				(byte)0x00, // CLA
				(byte)0x22, // INS = MSE
				(byte)0x81, // P1  = EXTERNAL AUTHENTICATION
				(byte)0xB6, // P2  = SET
				new Tlv((byte)0x83, refPublicKey).getBytes(),
				null
			)
		);
    	if (!res.isOk()) {
    		throw new SecureChannelException(
				"Error estableciendo la clave publica para verificacion, con respuesta: " + //$NON-NLS-1$
					res.getStatusWord()
			);
    	}
    }

    /** Lanza un desaf&iacute;o a la tarjeta para obtener un array de 8 bytes aleatorios.
     * @return Array de 8 bytes aleatorios.
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con la tarjeta. */
    public byte[] getChallenge() throws ApduConnectionException {
        final ResponseApdu res = getConnection().transmit(new GetChallengeApduCommand((byte) 0x00));
        if (res.isOk()) {
        	return res.getData();
        }
        throw new ApduConnectionException(
    		"Respuesta invalida en la obtencion de desafio con el codigo: " + res.getStatusWord() //$NON-NLS-1$
		);
    }

    /** Verifica el PIN de la tarjeta. El m&eacute;todo reintenta hasta que se introduce el PIN correctamente,
     * se bloquea la tarjeta por exceso de intentos de introducci&oacute;n de PIN o se recibe una excepci&oacute;n
     * (derivada de <code>RuntimeException</code> o una <code>ApduConnectionException</code>.
     * @param pinPc PIN de la tarjeta.
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con la tarjeta.
     * @throws PinException Si el PIN proporcionado en la <i>PasswordCallback</i>
     *                      es incorrecto y no estaba habilitado el reintento autom&aacute;tico
     * @throws es.gob.jmulticard.card.AuthenticationModeLockedException Si est&aacute; bloqueada la verificaci&oacute;n
     *         de PIN (por ejemplo, por superar el n&uacute;mero m&aacute;ximo de intentos). */
    public abstract void verifyPin(PasswordCallback pinPc) throws ApduConnectionException, PinException;

    /**
     * Lee y parsea la cabecera TLV del fichero actualmente seleccionado.
     * Equivalente al código Swift de iOS que funciona correctamente.
     *
     * @param initialReadLength Cuántos bytes leer inicialmente para la cabecera.
     * @return TlvHeaderInfo con la información parseada, o null si hay error.
     */
    private TlvHeaderInfo parseFileHeader(byte initialReadLength) throws ApduConnectionException, RequiredSecurityStateNotSatisfiedException, OffsetOutsideEfException {
        // Leer al menos 4 bytes como en Swift: <tag><length><data...>
        if (initialReadLength < 4) {
            initialReadLength = 4;
        }

        ResponseApdu resp = readBinary((byte)0x00, (byte)0x00, initialReadLength);

        // Aceptar respuestas OK o EOF Warning (6282)
        if (!resp.isOk() && !SW_EOF_REACHED.equals(resp.getStatusWord())) {
            LOGGER.warning("parseFileHeader: respuesta no OK: " + resp.getStatusWord());
            return null;
        }

        byte[] headerBytes = resp.getData();
        if (headerBytes == null || headerBytes.length < 2) {
            LOGGER.warning("parseFileHeader: datos insuficientes");
            return null;
        }

        // Tag en el primer byte
        int tag = headerBytes[0] & 0xFF;

        // Parsear longitud ASN.1 (equivalente a asn1Length en Swift)
        int valueLength;
        int headerTotalLength;  // Equivalente a "amountRead" en Swift

        byte lengthByte = headerBytes[1];

        if ((lengthByte & 0xFF) < 0x80) {
            // Forma corta: el byte directamente es la longitud
            valueLength = lengthByte & 0x7F;
            headerTotalLength = 2; // Tag (1) + Length (1)

        } else if ((lengthByte & 0xFF) == 0x81) {
            // Forma larga: 1 byte adicional para la longitud
            if (headerBytes.length < 3) {
                LOGGER.warning("parseFileHeader: cabecera incompleta para 0x81");
                return null;
            }
            valueLength = headerBytes[2] & 0xFF;
            headerTotalLength = 3; // Tag (1) + 0x81 (1) + Length (1)

        } else if ((lengthByte & 0xFF) == 0x82) {
            // Forma larga: 2 bytes adicionales para la longitud
            if (headerBytes.length < 4) {
                LOGGER.warning("parseFileHeader: cabecera incompleta para 0x82");
                return null;
            }
            // Leer 2 bytes en big-endian
            valueLength = ((headerBytes[2] & 0xFF) << 8) | (headerBytes[3] & 0xFF);
            headerTotalLength = 4; // Tag (1) + 0x82 (1) + Length (2)

        } else {
            // 0x83 o superior (3+ bytes de longitud) o longitud indefinida (0x80)
            LOGGER.warning("parseFileHeader: formato de longitud no soportado: 0x" +
                        Integer.toHexString(lengthByte & 0xFF));
            return null;
        }

        LOGGER.info("parseFileHeader: Tag=0x" + Integer.toHexString(tag) +
                    ", headerLength=" + headerTotalLength +
                    ", valueLength=" + valueLength +
                    ", totalLength=" + (headerTotalLength + valueLength));

        return new TlvHeaderInfo(tag, valueLength, headerTotalLength,
                                Arrays.copyOf(headerBytes, Math.min(headerBytes.length, headerTotalLength)));
    }
}