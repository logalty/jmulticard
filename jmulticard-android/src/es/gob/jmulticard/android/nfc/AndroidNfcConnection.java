package es.gob.jmulticard.android.nfc;

import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.connection.AbstractApduConnectionIso7816;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.ApduConnectionProtocol;
import es.gob.jmulticard.connection.CardConnectionListener;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre NFC para Android.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class AndroidNfcConnection extends AbstractApduConnectionIso7816 {

    private static final boolean DEBUG = false;
    private static final String TAG = AndroidNfcConnection.class.getSimpleName();

    private static final int ISODEP_TIMEOUT = 15000;

    /** Version code de Android P. */
    private static final int ANDROID_P = 28;

    /**
     * Overhead m&aacute;ximo de Secure Messaging BAC (3DES-CBC) en la respuesta:
     * DO87 header (3B) + padding block (8B) + DO99 (4B) + DO8E (10B) = 25B.
     * Se usa un margen conservador de 35B para absorber variaciones de longitud.
     */
    private static final int SM_RESPONSE_OVERHEAD = 35;

    /**
     * L&iacute;mite seguro absoluto de bytes de payload por APDU en modo est&aacute;ndar
     * (Le=0x00 = 256 bytes de respuesta m&aacute;xima, menos el overhead SM).
     */
    private static final int MAX_CHUNK_STANDARD_APDU = 220;

    /** M&aacute;ximo de bytes de payload cuando el transporte soporta APDUs extendidas.
     * El chip ICAO devuelve como mucho ~699 bytes por APDU con extended Le,
     * independientemente del Le solicitado. Usamos 1800 como techo seguro. */
    private static final int MAX_CHUNK_EXTENDED_APDU = 1800;

    private final IsoDep mIsoDep;

    /** Tama&ntilde;o de transceive m&aacute;ximo reportado por el controlador NFC del dispositivo. */
    private int mMaxTransceiveLength = 261; // ISO 7816 standard minimum

    /** Constructor de la clase para la gesti&oacute;n de la conexi&oacute;n por NFC.
     * @param tag <code>Tag</code> para obtener el objeto <code>IsoDep</code> y establecer la
     *            conexi&oacute;n.
     * @throws IOException Si falla el establecimiento de la conexi&oacute;n. */
    public AndroidNfcConnection(final Tag tag) throws IOException {
        if (tag == null) {
            throw new IllegalArgumentException("El tag NFC no puede ser nulo");
        }
        this.mIsoDep = IsoDep.get(tag);
        this.mIsoDep.connect();
        this.mIsoDep.setTimeout(ISODEP_TIMEOUT);

        // Capturamos la capacidad real de transceive del controlador NFC del dispositivo.
        // Este valor se usa para calibrar el chunk size de READ BINARY y reducir round trips.
        this.mMaxTransceiveLength = this.mIsoDep.getMaxTransceiveLength();
        Log.d(TAG, "IsoDep maxTransceiveLength=" + this.mMaxTransceiveLength
                + (this.mMaxTransceiveLength > 261 ? " (extended APDU capable)" : " (standard only)"));

        // Retenemos la conexion hasta nuestro siguiente envio
        // Solo en la versiones de Android afectadas por el error https://issuetracker.google.com/issues/36977343
        if (
        		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
        		android.os.Build.VERSION.SDK_INT <  ANDROID_P
        ) {
            NFCWatchdogRefresher.holdConnection(this.mIsoDep);
        }
    }

    @Override
    public ResponseApdu internalTransmit(final byte[] apdu) throws ApduConnectionException {
        if (this.mIsoDep == null) {
            throw new ApduConnectionException(
                "No se puede transmitir sobre una conexion NFC cerrada"
            );
        }

	  final boolean isChv = apdu[1] == VerifyApduCommand.INS_VERIFY;

        if (DEBUG) {
            Log.d(TAG, "Se va a enviar la APDU:\n" + (isChv ? "Verificacion de PIN" : HexUtils.hexify(apdu, apdu.length > 32)));
        }

        // Liberamos la conexion para transmitir.
	  // Solo en la versiones de Android afectadas por el error https://issuetracker.google.com/issues/36977343
        if (
        		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
        		android.os.Build.VERSION.SDK_INT <  ANDROID_P
        ) {
            NFCWatchdogRefresher.stopHoldingConnection();
        }

        final byte[] bResp;
        try {
            bResp = this.mIsoDep.transceive(apdu);
        }
        catch (final IOException e) {
            // Evitamos que salga el PIN en la traza de excepcion
            throw new ApduConnectionException(
			"Error tratando de transmitir la APDU\n" + (isChv ? "Verificacion de PIN" : HexUtils.hexify(apdu, apdu.length > 32)),
                    	e
            );
        }
        finally {
            // Retenemos la conexion hasta nuestro siguiente envio
        	// Solo en la versiones de Android afectadas por el error https://issuetracker.google.com/issues/36977343
            if (
            		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
            		android.os.Build.VERSION.SDK_INT <  ANDROID_P
            ) {
                NFCWatchdogRefresher.holdConnection(this.mIsoDep);
            }
        }

        final ResponseApdu response = new ResponseApdu(bResp);

        if (DEBUG) {
            Log.d(TAG, "Respuesta:\n" + HexUtils.hexify(response.getBytes(), bResp.length > 32));
        }

        return response;
    }

    @Override
    public void open() throws ApduConnectionException {
        try {
            if (!this.mIsoDep.isConnected()) {
                this.mIsoDep.connect();
            }
        }
        catch (final Exception e) {
            throw new ApduConnectionException(
                "Error intentando abrir la comunicacion NFC contra la tarjeta", e
            );
        }
    }

    @Override
    public void close() throws ApduConnectionException {
        // Liberamos la conexion
        if (
        		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
        		android.os.Build.VERSION.SDK_INT <  ANDROID_P
        ) {
            NFCWatchdogRefresher.stopHoldingConnection();
        }
        try {
        	this.mIsoDep.close();
        }
	  catch(final IOException ioe) {
        	throw new ApduConnectionException(
                "Error indefinido cerrando la conexion con la tarjeta", ioe
            );
        }
    }

    @Override
    public byte[] reset() throws ApduConnectionException {
    	  // No se cierran las conexiones por NFC
        if (this.mIsoDep != null) {
        	if (this.mIsoDep.getHistoricalBytes() != null) {
        		return this.mIsoDep.getHistoricalBytes();
        	}
		return this.mIsoDep.getHiLayerResponse();
        }
        throw new ApduConnectionException(
            "Error indefinido reiniciando la conexion con la tarjeta"
        );
    }

	@Override
	public void addCardConnectionListener(final CardConnectionListener ccl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeCardConnectionListener(final CardConnectionListener ccl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long[] getTerminals(final boolean onlyWithCardPresent) {
		return new long[] { 0 };
	}

	@Override
	public String getTerminalInfo(final int terminal) {
		return "Interfaz ISO-DEP NFC de Android";
	}

	@Override
	public void setTerminal(final int t) {
		// Vacio, solo hay un terminal NFC por terminal
	}

	@Override
	public boolean isOpen() {
		return this.mIsoDep.isConnected();
	}

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		// No hace nada, siempre es T=CL
	}

    @Override
    public ApduConnection getSubConnection() {
        return null; // Esta es la conexion de mas bajo nivel
    }

    @Override
    public int getMaxApduSize() {
        return 0xff;
    }

    /**
     * Devuelve el tama&ntilde;o de chunk preferido para READ BINARY en bytes de texto claro.
     *
     * <p><b>Modo est&aacute;ndar (maxTransceiveLength &le; 261)</b>: se usa {@code MAX_CHUNK_STANDARD_APDU}
     * (220 bytes). El canal SM ({@code SecureMessaging.wrap}) siempre pone {@code Le=0x00}
     * en la APDU protegida, lo que limita la respuesta a 256 bytes; el overhead SM (~35B)
     * deja 220 bytes de payload &uacute;til por APDU.</p>
     *
     * <p><b>Modo extendido (maxTransceiveLength &gt; 261)</b>: aunque el transporte NFC puede
     * manejar APDUs m&aacute;s grandes, el canal SM necesita usar Le extendida en la APDU protegida
     * (pendiente de implementar en {@code SecureMessaging.wrap}). Por ahora se devuelve el
     * mismo valor seguro para evitar errores de protocolo.</p>
     *
     * @return N&uacute;mero de bytes de texto claro por READ BINARY.
     */
    @Override
    public int getPreferredReadChunkSize() {
        // El comando SM READ BINARY (sin cuerpo de datos) ocupa ~24 bytes:
        //   [CLA INS P1 P2] + [00 Lc_hi Lc_lo] + [DO97(4B)] + [DO8E(10B)] + [00 Le_hi Le_lo]
        // Siempre cabe en 261 bytes, independientemente del Le que pidamos.
        //
        // mMaxTransceiveLength limita el COMANDO enviado, no la RESPUESTA recibida.
        // Android IsoDep ensambla automaticamente respuestas multi-frame ISO 14443-4,
        // por lo que podemos recibir 700-1800 bytes en un unico transceive().
        //
        // Usamos extended Le siempre. El back-off de readBinaryComplete() reducira
        // el chunk si el chip devuelve 6700 (Le incorrecto) o error de transporte.
        Log.d(TAG, "getPreferredReadChunkSize: maxTransceive=" + mMaxTransceiveLength
                + " -> usando chunk extendido=" + MAX_CHUNK_EXTENDED_APDU);
        return MAX_CHUNK_EXTENDED_APDU;
    }

    /** @return Longitud m&aacute;xima de transceive reportada por el controlador NFC. */
    public int getMaxTransceiveLength() {
        return mMaxTransceiveLength;
    }
}
