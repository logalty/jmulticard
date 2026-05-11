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
package es.gob.jmulticard.card.dnie;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.SignatureValidationPolicy;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.DataGroupHash;
import es.gob.jmulticard.asn1.icao.LdsSecurityObject;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.asn1.icao.SubjectFacePhoto;
import es.gob.jmulticard.asn1.icao.SubjectSignaturePhoto;
import es.gob.jmulticard.card.CardSecurityException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.CryptoCardSecurityException;
import es.gob.jmulticard.card.PasswordCallbackNotFoundException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.icao.InvalidSecurityObjectException;
import es.gob.jmulticard.card.icao.MrtdLds1;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.card.iso7816four.RequiredSecurityStateNotSatisfiedException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.bac.BacConnection;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection;

/** DNI Electr&oacute;nico versi&oacute;n 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class Dnie3 extends Dnie implements MrtdLds1 {

    private transient String idesp = null;

		private transient Mrz cachedDg1 = null;

		private transient Com cachedCom = null;

		private transient byte[] cachedDG14 = null;

    /** Construye una clase que representa un DNIe 3&#46;0.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad que pueden
     *                   variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @param loadCertsAndKeys Si se indica <code>true</code>, se cargan las referencias a
     *                         las claves privadas y a los certificados mientras que, si se
     *                         indica <code>false</code>, no se cargan, permitiendo la
     *                         instanciaci&oacute;n de un DNIe sin capacidades de firma o
     *                         autenticaci&oacute;n con certificados.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.*/
    protected Dnie3(final ApduConnection conn,
    	            final PasswordCallback pwc,
    	            final CryptoHelper cryptoHlpr,
    	            final CallbackHandler ch,
    	            final boolean loadCertsAndKeys) throws ApduConnectionException {
		  super(conn, pwc, cryptoHlpr, ch, loadCertsAndKeys);
      this.rawConnection = conn;
    }

    /** Construye una clase que representa un DNIe 3&#46;0.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad que pueden
     *                   variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.*/
    Dnie3(final ApduConnection conn,
    	  final PasswordCallback pwc,
    	  final CryptoHelper cryptoHlpr,
    	  final CallbackHandler ch) throws ApduConnectionException {
        this(conn, pwc, cryptoHlpr, ch, true);
    }

	//*************************************************************************
	//******************* METODOS SOBRECARGADOS DE CLASES PADRE ***************

	@Override
    public String getCardName() {
        return "DNIe 3.0/4.0"; //$NON-NLS-1$
    }

    /** Si no se hab&iacute;a hecho anteriormente, establece y abre el canal seguro de PIN CWA-14890,
     * solicita y comprueba el PIN e inmediatamente despu&eacute;s y, si la verificaci&oacute;n es correcta,
     * establece el canal de <b>usuario</b> CWA-14890.
     * Si falla alg&uacute;n punto del proceso, vuelve al modo inicial de conexi&oacute;n (sin canal seguro).
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido. */
	@Override
	public void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, PinException {
		openSecureChannelIfNotAlreadyOpened(true);
	}

	@Override
	public void openSecureChannelIfNotAlreadyOpened(final boolean doChv) throws CryptoCardException,
	                                                                            PinException {

        // Si el canal seguro esta ya abierto salimos sin hacer nada
        if (isSecurityChannelOpen()) {
        	return;
        }

        if (DEBUG) {
        	LOGGER.info("Conexion actual: " + getConnection()); //$NON-NLS-1$
        	LOGGER.info("Conexion subyacente: " + this.rawConnection); //$NON-NLS-1$
        }

        // Si la conexion esta cerrada, la reestablecemos
        if (!getConnection().isOpen()) {
	        try {
				setConnection(this.rawConnection);
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException(
	        		"Error en el establecimiento del canal inicial previo al seguro de PIN", e //$NON-NLS-1$
	    		);
			}
        }

        if (doChv) {
	        // Establecemos el canal PIN y lo verificamos
	        final ApduConnection pinSecureConnection = new Cwa14890OneV2Connection(
	    		this,
	    		getConnection(),
	    		getCryptoHelper(),
	    		DnieFactory.getDnie3PinCwa14890Constants(this.idesp),
	    		DnieFactory.getDnie3PinCwa14890Constants(this.idesp)
			);

	        try {
						selectFileById(new byte[] { (byte)0x3F, (byte)0x00 });
//	        	selectMasterFile();
	        }
	        catch (final Exception e) {
	        	LOGGER.warning(
	    			"Error seleccionando el MF tras el establecimiento del canal seguro de PIN: " + e //$NON-NLS-1$
				);
	        }

	        try {
	        	setConnection(pinSecureConnection);
	        }
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException(
	    			"Error en el establecimiento del canal seguro de PIN", e //$NON-NLS-1$
				);
	        }

	        LOGGER.info("Canal seguro de PIN para DNIe establecido"); //$NON-NLS-1$

	        try {
	        	verifyPin(getInternalPasswordCallback());
	        }
	        catch (final PasswordCallbackNotFoundException e) {
	        	// Si no se indico un medio para obtener el PIN, ignoramos el establecimiento del canal
	        	// de PIN, pero continuamos para establecer el canal de usuario
	        	LOGGER.info("No se proporcionaron medios para verificar el canal de PIN: " + e); //$NON-NLS-1$
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException(
	    			"Error en la verificacion de PIN", e //$NON-NLS-1$
				);
	        }
        }

		try {
			selectFileById(new byte[] { (byte)0x3F, (byte)0x00 });
			// selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionado el MF antes del establecimiento del canal seguro de usuario", e //$NON-NLS-1$
    		);
		}

        // Establecemos ahora el canal de usuario
        final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		getConnection(),
    		getCryptoHelper(),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp)
		);

        try {
            setConnection(usrSecureConnection);
        }
        catch (final ApduConnectionException e) {
            throw new CryptoCardException(
        		"Error en el establecimiento del canal seguro de usuario", e //$NON-NLS-1$
    		);
        }

        LOGGER.info("Canal seguro de Usuario para DNIe establecido"); //$NON-NLS-1$
    }

	@Override
	protected byte[] signInternal(final byte[] data,
                                  final String signAlgorithm,
                                  final PrivateKeyReference privateKeyReference) throws CryptoCardException,
                                                                                        PinException {
		if (!(privateKeyReference instanceof DniePrivateKeyReference)) {
            throw new IllegalArgumentException(
        		"La referencia a la clave privada tiene que ser de tipo DniePrivateKeyReference" //$NON-NLS-1$
    		);
        }
        return signOperation(data, signAlgorithm, privateKeyReference);
	}

	//*************************************************************************
	//******************* METODOS DE EXCLUSIVOS DE ESTA CLASE *****************

    /** Abre el canal seguro de usuario.
     * @return Nueva conexi&oacute;n establecida.
     * @throws CryptoCardException Si hay problemas en la apertura de canal. */
    public ApduConnection openUserChannel() throws CryptoCardException {

    	final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		getConnection(),
    		getCryptoHelper(),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp)
		);

		try {
			selectFileById(new byte[] { (byte)0x3F, (byte)0x00 });
			//selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionando el MF tras el establecimiento del canal seguro de usuario", e //$NON-NLS-1$
    		);
		}

        try {
            setConnection(usrSecureConnection);
        }
        catch (final ApduConnectionException e) {
            throw new CryptoCardException(
        		"Error en el establecimiento del canal seguro de usuario", e //$NON-NLS-1$
    		);
        }
    	return getConnection();
    }

	@Override
	protected boolean needsPinForLoadingCerts() {
		// "true" en DNIe 1.0, "false" en cualquier otro.
		return false;
	}


	//*************************************************************************
	//*************** METODOS HEREDADOS DE ICAO MRTD LDS1 *********************

	@Override
	public X509Certificate[] checkSecurityObjects(SignatureValidationPolicy policy) throws IOException,
	                                                       InvalidSecurityObjectException,
	                                                       TlvException,
	                                                       Asn1Exception,
	                                                       SignatureException,
	                                                       CertificateException {
		openSecureChannelIfNotAlreadyOpened(false);
		final Sod sod = getSod();
		sod.validateSignature(policy);
		final LdsSecurityObject ldsSecurityObject = sod.getLdsSecurityObject(policy);

		openSecureChannelIfNotAlreadyOpened(false);

		for (final DataGroupHash dgh : ldsSecurityObject.getDataGroupHashes()) {

			final byte[] dgBytes;
			switch(dgh.getDataGroupNumber()) {
				case 1:
					dgBytes = getDg1().getBytes();
					break;
				case 2:
					dgBytes = getDg2().getBytes();
					break;
				case 3:
					// El DG3 necesita canal administrativo, le damos un tratamiento especial
					// para permitir verificar solo con canal de usuario
					try {
						dgBytes = getDg3();
					}
					catch(final CardSecurityException e) {
						LOGGER.warning(
							"Se omite la comprobacion del DG3 con el SOD por no poder leerse: " + e //$NON-NLS-1$
						);
						continue;
					}
					break;
				case 4:
					dgBytes = getDg4();
					break;
				case 5:
					dgBytes = getDg5();
					break;
				case 6:
					dgBytes = getDg6();
					break;
				case 7:
					dgBytes = getDg7().getBytes();
					break;
				case 8:
					dgBytes = getDg8();
					break;
				case 9:
					dgBytes = getDg9();
					break;
				case 10:
					dgBytes = getDg10();
					break;
				case 11:
					dgBytes = getDg11();
					break;
				case 12:
					dgBytes = getDg12();
					break;
				case 13:
					dgBytes = getDg13().getBytes();
					break;
				case 14:
					dgBytes = getDg14();
					break;
				case 15:
					dgBytes = getDg15();
					break;
				case 16:
					dgBytes = getDg16();
					break;
				default:
					throw new InvalidSecurityObjectException(
						"El SOD define huella para un DG inexistente: " + dgh.getDataGroupNumber() //$NON-NLS-1$
					);
			}
			final byte[] actualHash = this.cryptoHelper.digest(
				CryptoHelper.DigestAlgorithm.getDigestAlgorithm(ldsSecurityObject.getDigestAlgorithm()),
				dgBytes
			);

			if (!Arrays.equals(actualHash, dgh.getDataGroupHashValue())) {
				throw new InvalidSecurityObjectException(
					"El DG" + dgh.getDataGroupNumber() + " no concuerda con la huella del SOD, " + //$NON-NLS-1$ //$NON-NLS-2$
						"se esperaba " + HexUtils.hexify(actualHash, false) + //$NON-NLS-1$
							" y se ha encontrado " + HexUtils.hexify(dgh.getDataGroupHashValue(), false) //$NON-NLS-1$
				);
			}
		}

		// Llegados aqui, todas las huellas coinciden
		return sod.getCertificateChain(policy);
	}

    @Override
	public byte[] getCardAccess() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_CARD_ACCESS_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("CardAcess no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el CardAccess", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getAtrInfo() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_ATR_INFO_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("ATR/INFO no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el ATR/INFO", e); //$NON-NLS-1$
		}
    }

    @Override
	public Mrz getDg1() throws IOException {
//		try {
			if (cachedDg1 == null) {
//				if (rawConnection instanceof BacConnection){
					cachedDg1 = getDg1ByFileId();
				// 	byte[] dg1Data = readBinaryBySFI(0x01, 0, 256);
				// 	return new Dnie3Dg01Mrz(dg1Data);
//				}
//				cachedDg1 = new Dnie3Dg01Mrz(
//						selectFileByLocationAndRead(FILE_DG01_LOCATION)
//				);
			}
			return cachedDg1;
//		}
/* 		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG1 no encontrado: " + e); //$NON-NLS-1$
    }
			catch (final Iso7816FourCardException e) {
				throw new CryptoCardException("Error leyendo el DG1", e); //$NON-NLS-1$
		}
				*/
	}

	@Override
	public Mrz getDg1ByFileId() throws IOException {
		try {
			byte[] dg1File = DG01_FILE_ID_TAG;

			int fileLength = selectFileById(dg1File);
			LOGGER.info("DG1 - Tamaño reportado por SELECT: " + fileLength);

			// if (fileLength <= 0) {
			// 	LOGGER.warning("SELECT FILE reportó tamaño inválido, intentando lectura incremental");
      //   // Leer en bloques hasta encontrar EOF
      //   return new Dnie3Dg01Mrz(readBinaryIncrementalWithPadding());
			// }

			byte[] dg1Bytes = readBinaryComplete(fileLength);
      return new Dnie3Dg01Mrz(dg1Bytes);

			// byte[] dg1Bytes = selectFileByIdAndRead(dg1File);
			// return new Dnie3Dg01Mrz(dg1Bytes);
		} catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG1", e); //$NON-NLS-1$
		}
	}

    @Override
	public SubjectFacePhoto getDg2() throws IOException {
/*     final SubjectFacePhoto ret = new SubjectFacePhoto();
		try {
			if (rawConnection instanceof BacConnection){
			*/
				return getDg2ByFileId();
    	// 	byte[] dg2Data = readBinaryBySFI(0x02, 0, 4096); // DG2 suele ser más grande
			/*
    	ret.setDerValue(dg2Data);
			 	return ret;
			 }
			}
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG02_LOCATION));
			return ret;

		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG2 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG2", e); //$NON-NLS-1$
		}*/
	}

	@Override
	public SubjectFacePhoto getDg2ByFileId() throws IOException {
		final SubjectFacePhoto ret = new SubjectFacePhoto();
		try {
			byte[] dg2File = DG02_FILE_ID_TAG;
      int fileLength = selectFileById(dg2File);
      LOGGER.info("DG2 - Tamaño reportado por SELECT: " + fileLength);
			byte[] dg2Bytes;
			// if (fileLength <= 0) {
			// 		LOGGER.warning("SELECT FILE reportó tamaño inválido para DG2, intentando lectura incremental");
			// 		dg2Bytes = readBinaryIncrementalWithPadding();
			// } else {
			dg2Bytes = readBinaryComplete(fileLength);
			// }
			// byte[] dg2Bytes = selectFileByIdAndRead(dg2File);
			ret.setDerValue(dg2Bytes);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw new FileNotFoundException("DG2 no encontrado: " + e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG2", e); //$NON-NLS-1$
		}
		return ret;
	}

    @Override
	public byte[] getDg3() throws IOException {
		try {
			// if (rawConnection instanceof BacConnection){
			// 	return getDg3ByFileId();
			// }
			return selectFileByLocationAndRead(FILE_DG03_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG3 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		// El DG3 necesita canal administrativo, le damos un tratamiento especial
		catch(final RequiredSecurityStateNotSatisfiedException e) {
			throw new CardSecurityException(
				"No se tienen permisos para leer el DG3", e //$NON-NLS-1$
			);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG3", e); //$NON-NLS-1$
		}
	}

	@Override
	public byte[] getDg3ByFileId() throws IOException {
		try {
			byte[] dg3File = DG03_FILE_ID_TAG;
			return selectFileByIdAndRead(dg3File);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG3 no encontrado").initCause(e); //$NON-NLS-1$
		}
		// El DG3 necesita canal administrativo, le damos un tratamiento especial
		catch(final RequiredSecurityStateNotSatisfiedException e) {
			throw new CardSecurityException(
					"No se tienen permisos para leer el DG3", e //$NON-NLS-1$
			);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG3", e); //$NON-NLS-1$
		}
	}

    @Override
	public SubjectSignaturePhoto getDg7() throws IOException {
		/*
    final SubjectSignaturePhoto ret = new SubjectSignaturePhoto();
		try {
			if (rawConnection instanceof BacConnection) {
				*/
				return getDg7ByFileId();
				/*
			}
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG07_LOCATION));
			return ret;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG7 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG7", e); //$NON-NLS-1$
		}
			*/
	}

	@Override
	public SubjectSignaturePhoto getDg7ByFileId() throws IOException {
		final SubjectSignaturePhoto ret = new SubjectSignaturePhoto();
		try {
			byte[] dg7File = DG07_FILE_ID_TAG;
			int fileLength = selectFileById(dg7File);
      LOGGER.info("DG7 - Tamaño reportado por SELECT: " + fileLength);

			byte[] dg7Bytes;
			// if (fileLength <= 0) {
			// 		LOGGER.warning("SELECT FILE reportó tamaño inválido para DG7, intentando lectura incremental");
			// 		dg7Bytes = readBinaryIncrementalWithPadding();
			// } else {
			dg7Bytes = readBinaryComplete(fileLength);
			// }
			ret.setDerValue(dg7Bytes);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG7 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG7", e); //$NON-NLS-1$
		}
		return ret;
	}

	@Override
	public byte[] getDg11() throws IOException {
/*
		try {
			if (rawConnection instanceof BacConnection) {
			*/
				return getDg11ByFileId();
				/*
			}
			return selectFileByLocationAndRead(FILE_DG11_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG11 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11", e); //$NON-NLS-1$
		}*/
	}
	@Override
	public byte[] getDg11ByFileId() throws IOException {
		try {
			byte[] dg11File = DG11_FILE_ID_TAG;
			int fileLength = selectFileById(dg11File);
      LOGGER.info("DG11 - Tamaño reportado por SELECT: " + fileLength);

			byte[] dg11Bytes;
			// if (fileLength <= 0) {
			// 		LOGGER.warning("SELECT FILE reportó tamaño inválido para DG11, intentando lectura incremental");
			// 		dg11Bytes = readBinaryIncrementalWithPadding();
			// } else {
			dg11Bytes = readBinaryComplete(fileLength);
			// }

			return dg11Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG11 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg12() throws IOException {
		try {
			// if (rawConnection instanceof BacConnection) {
			// 	return getDg12ByFileId();
			// }
			return selectFileByLocationAndRead(FILE_DG12_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG12 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG12", e); //$NON-NLS-1$
		}
	}

	@Override
	public byte[] getDg12ByFileId() throws IOException {
		try {
			byte[] dg12File = DG12_FILE_ID_TAG;
			return selectFileByIdAndRead(dg12File);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG12 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG12", e); //$NON-NLS-1$
		}
	}

  @Override
	public OptionalDetails getDg13() throws IOException {
/* 		try {
			if (rawConnection instanceof BacConnection) {
			*/
				return getDg13ByFileId();
/* 			}
			final OptionalDetails ret = new OptionalDetailsDnie3();
			ret.setDerValue(
				selectFileByLocationAndRead(FILE_DG13_LOCATION)
			);
			return ret;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG13 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG13", e); //$NON-NLS-1$
		}
			*/
	}

	@Override
	public OptionalDetails getDg13ByFileId() throws IOException {
		try {
			final OptionalDetails ret = new OptionalDetailsDnie3();
				byte[] dg13File = DG13_FILE_ID_TAG;
        int fileLength = selectFileById(dg13File);
        LOGGER.info("DG13 - Tamaño reportado por SELECT: " + fileLength);

        byte[] dg13Bytes;
        // if (fileLength <= 0) {
        //     LOGGER.warning("SELECT FILE reportó tamaño inválido para DG13, intentando lectura incremental");
        //     dg13Bytes = readBinaryIncrementalWithPadding();
        // } else {
				dg13Bytes = readBinaryComplete(fileLength);
        // }

        ret.setDerValue(dg13Bytes);
				return ret;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG13 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG13", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg14() throws IOException {
/*
		try {
			if (rawConnection instanceof BacConnection) {
			*/
			if (cachedDG14 == null) {
				cachedDG14 = getDg14ByFileId();
			}
			return cachedDG14;
/* 			}
			return selectFileByLocationAndRead(FILE_DG14_LOCATION);
		}
    catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    	throw (IOException) new FileNotFoundException("DG14 no encontrado").initCause(e); //$NON-NLS-1$
    }
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG14", e); //$NON-NLS-1$
		}
		*/
	}

	@Override
	public byte[] getDg14ByFileId() throws IOException {
		try {
			byte[] dg14File = DG14_FILE_ID_TAG;

			// SELECT FILE y obtener tamaño
			int fileLength = selectFileById(dg14File);
			LOGGER.info("DG14 - Tamaño reportado por SELECT: " + fileLength);

			byte[] dg14Bytes;
			// if (fileLength <= 0) {
			// 		LOGGER.warning("SELECT FILE reportó tamaño inválido para DG14, intentando lectura incremental");
			// 		dg14Bytes = readBinaryIncrementalWithPadding();
			// } else {
			dg14Bytes = readBinaryComplete(fileLength);
			// }

			return dg14Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG14 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG14", e); //$NON-NLS-1$
		}
	}

  @Override
	public Sod getSod() throws IOException {
/*
		final Sod sod = new Sod(this.getCryptoHelper());
    try {
			if (rawConnection instanceof BacConnection) {
			*/
				return getSodByFileId();
/*
			}
			sod.setDerValue(
					selectFileByLocationAndRead(FILE_SOD_LOCATION)
			);
			return sod;
		}
		catch (final Asn1Exception | TlvException | Iso7816FourCardException e) {
			throw new IOException(
				"No se puede crear un SOD a partir del contenido del fichero", e //$NON-NLS-1$
			);
		}
			*/
	}

	@Override
	public Sod getSodByFileId() throws IOException {
		final Sod sod = new Sod(this.getCryptoHelper());
		try {
			byte[] sodFile = SOD_FILE_ID_TAG;
						// SELECT FILE y obtener tamaño
			int fileLength = selectFileById(sodFile);
			LOGGER.info("SOD - Tamaño reportado por SELECT: " + fileLength);

			byte[] sodBytes;
			// if (fileLength <= 0) {
			// 		LOGGER.warning("SELECT FILE reportó tamaño inválido para SOD, intentando lectura incremental");
			// 		sodBytes = readBinaryIncrementalWithPadding();
			// } else {
			sodBytes = readBinaryComplete(fileLength);
			// }
			sod.setDerValue(sodBytes);
		}
		catch (final Asn1Exception | TlvException | Iso7816FourCardException e) {
			throw new IOException(
					"No se puede crear un SOD a partir del contenido del fichero", e //$NON-NLS-1$
			);
		}
		return sod;
	}

  @Override
	public Com getCom() throws IOException {
//		try {
//			if (rawConnection instanceof BacConnection) {
			if (cachedCom == null) {
//				if (rawConnection instanceof BacConnection){
					cachedCom = getComByFileId();
				// 	byte[] dg1Data = readBinaryBySFI(0x01, 0, 256);
				// 	return new Dnie3Dg01Mrz(dg1Data);
//				}
//				cachedDg1 = new Dnie3Dg01Mrz(
//						selectFileByLocationAndRead(FILE_DG01_LOCATION)
//				);
			}
			return cachedCom;
// 			}
// 		final Com com = new Com();
//			com.setDerValue(
//					selectFileByLocationAndRead(FILE_COM_LOCATION)
//			);
//			return com;
//		}
//     catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
//    		throw (IOException) new FileNotFoundException("COM no encontrado").initCause(e); //$NON-NLS-1$
//    }
//		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
//			throw new CryptoCardException("Error leyendo el 'Common Data' (COM)", e); //$NON-NLS-1$
//		}

	}

	@Override
	public Com getComByFileId() throws IOException {
		try {
			LOGGER.info("Leyendo COM del chip por ID de fichero");
			final Com com = new Com();
			byte[] comFile = COM_FILE_ID_TAG;

			// SELECT FILE y obtener tamaño
			int fileLength = selectFileById(comFile);
//			LOGGER.info("COM - Tamaño reportado por SELECT: " + fileLength);
			LOGGER.info("COM - Tamaño reportado por SELECT");

			byte[] comBytes;
			// if (fileLength <= 0) {
			// 		LOGGER.warning("SELECT FILE reportó tamaño inválido para COM, intentando lectura incremental");
			// 		comBytes = readBinaryIncrementalWithPadding();
			// } else {
			LOGGER.info("COM - Leyendo binario completo");
			comBytes = readBinaryComplete(fileLength);
			// }

			LOGGER.info("COM - Asignando valor DER");

			com.setDerValue(comBytes);
			return com;

			// byte[] comBytes = selectFileByIdAndRead(comFile);
			// com.setDerValue(comBytes);
			// return com;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			LOGGER.warning("COM no encontrado por ID de fichero, intentando por ubicación"); //$NON-NLS-1$
			throw (IOException) new FileNotFoundException("COM no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			LOGGER.severe("Error leyendo el 'Common Data' (COM)"); //$NON-NLS-1$
			throw new CryptoCardException("Error leyendo el 'Common Data' (COM)", e); //$NON-NLS-1$
		}
	}

	//*************************************************************************
	//********** METODOS DE ICAO MRTD LDS1 NO SOPORTADOS **********************

    @Override
	public byte[] getCardSecurity() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene CardSecurity" //$NON-NLS-1$
		);
  }

  @Override
	public byte[] getDg4() throws IOException {
    throw new CryptoCardSecurityException(
			"Hace falta canal de administrador para leer el DG4" //$NON-NLS-1$
		);
	}

	@Override
	public byte[] getDg4ByFileId() throws IOException {
		throw new CryptoCardSecurityException(
				"Hace falta canal de administrador para leer el DG4" //$NON-NLS-1$
		);
	}

	@Override
	public byte[] getDg5() throws IOException {
    	/*throw new UnsupportedOperationException(
			"Este MRTD no tiene DG5" //$NON-NLS-1$
		);*/

		try {
			if (rawConnection instanceof BacConnection) {
				return getDg5ByFileId();
			}
			return selectFileByLocationAndRead(FILE_DG05_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG5 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG5", e); //$NON-NLS-1$
		}
  }

	@Override
	public byte[] getDg5ByFileId() throws IOException {
		/*throw new UnsupportedOperationException(
				"Este MRTD no tiene DG5" //$NON-NLS-1$
		);*/

		try {
			byte[] dg5File = DG05_FILE_ID_TAG;
			byte[] dg5Bytes = selectFileByIdAndRead(dg5File);
			return dg5Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG5 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG5", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg6() throws IOException {
    	/* throw new UnsupportedOperationException(
			"Este MRTD no tiene DG6" //$NON-NLS-1$
		);*/

		try {
			if (rawConnection instanceof BacConnection) {
				return getDg6ByFileId();
			}
			return selectFileByLocationAndRead(FILE_DG06_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG6 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG6", e); //$NON-NLS-1$
		}
  }

	@Override
	public byte[] getDg6ByFileId() throws IOException {
		/*throw new UnsupportedOperationException(
				"Este MRTD no tiene DG6" //$NON-NLS-1$
		);*/

		try {
			byte[] dg6File = DG06_FILE_ID_TAG;
			byte[] dg6Bytes = selectFileByIdAndRead(dg6File);
			return dg6Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG6 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG6", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg8() throws IOException {
    	/*throw new UnsupportedOperationException(
			"Este MRTD no tiene DG8" //$NON-NLS-1$
		);*/

		try {
			if (rawConnection instanceof BacConnection) {
				return getDg8ByFileId();
			}
			return selectFileByLocationAndRead(FILE_DG08_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG8 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG8", e); //$NON-NLS-1$
		}
  }

	@Override
	public byte[] getDg8ByFileId() throws IOException {
		/*throw new UnsupportedOperationException(
				"Este MRTD no tiene DG8" //$NON-NLS-1$
		);*/

		try {
			byte[] dg8File = DG08_FILE_ID_TAG;
			byte[] dg8Bytes = selectFileByIdAndRead(dg8File);
			return dg8Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG8 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG8", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg9() throws IOException {
    	/*throw new UnsupportedOperationException(
			"Este MRTD no tiene DG9" //$NON-NLS-1$
		);*/

		try {
			if (rawConnection instanceof BacConnection) {
				return getDg9ByFileId();
			}
			return selectFileByLocationAndRead(FILE_DG09_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG9 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG9", e); //$NON-NLS-1$
		}
  }

	@Override
	public byte[] getDg9ByFileId() throws IOException {
		/*throw new UnsupportedOperationException(
				"Este MRTD no tiene DG9" //$NON-NLS-1$
		);*/

		try {
			byte[] dg9File = DG09_FILE_ID_TAG;
			byte[] dg9Bytes = selectFileByIdAndRead(dg9File);
			return dg9Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG9 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG9", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg10() throws IOException {
    	/*throw new UnsupportedOperationException(
			"Este MRTD no tiene DG10" //$NON-NLS-1$
		);*/

		try {
			if (rawConnection instanceof BacConnection) {
				return getDg10ByFileId();
			}
			return selectFileByLocationAndRead(FILE_DG10_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG10 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG9", e); //$NON-NLS-1$
		}
  }

	@Override
	public byte[] getDg10ByFileId() throws IOException {
		/*throw new UnsupportedOperationException(
				"Este MRTD no tiene DG10" //$NON-NLS-1$
		);*/

		try {
			byte[] dg10File = DG10_FILE_ID_TAG;
			byte[] dg10Bytes = selectFileByIdAndRead(dg10File);
			return dg10Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG10 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG10", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg15() throws IOException {
    	/*throw new UnsupportedOperationException(
			"Este MRTD no tiene DG15" //$NON-NLS-1$
		);*/

//		try {
//			if (rawConnection instanceof BacConnection) {
				return getDg15ByFileId();
//			}
//			return selectFileByLocationAndRead(FILE_DG15_LOCATION);
//		}
//		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
//			throw (IOException) new FileNotFoundException("DG15 no encontrado").initCause(e); //$NON-NLS-1$
//		}
//		catch (final Iso7816FourCardException e) {
//			throw new CryptoCardException("Error leyendo el DG15", e); //$NON-NLS-1$
//		}
  }

	@Override
	public byte[] getDg15ByFileId() throws IOException {
		try {
			byte[] dg15File = DG15_FILE_ID_TAG;
			int fileLength = selectFileById(dg15File);
			LOGGER.info("DG15 - Tamaño reportado por SELECT: " + fileLength);

			byte[] dg15Bytes;
			dg15Bytes = readBinaryComplete(fileLength);
			return dg15Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG15 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG15", e); //$NON-NLS-1$
		}
	}

  @Override
	public byte[] getDg16() throws IOException {
    	/*throw new UnsupportedOperationException(
			"Este MRTD no tiene DG16" //$NON-NLS-1$
		);*/

		try {
			if (rawConnection instanceof BacConnection) {
				return getDg16ByFileId();
			}
			return selectFileByLocationAndRead(FILE_DG16_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG16 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG16", e); //$NON-NLS-1$
		}
  }

	@Override
	public byte[] getDg16ByFileId() throws IOException {
		/*throw new UnsupportedOperationException(
				"Este MRTD no tiene DG16" //$NON-NLS-1$
		);*/

		try {
			byte[] dg16File = DG16_FILE_ID_TAG;
			byte[] dg16Bytes = selectFileByIdAndRead(dg16File);
			return dg16Bytes;
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
			throw (IOException) new FileNotFoundException("DG16 no encontrado").initCause(e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG16", e); //$NON-NLS-1$
		}
	}
}