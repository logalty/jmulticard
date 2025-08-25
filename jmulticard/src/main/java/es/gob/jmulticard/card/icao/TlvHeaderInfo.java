package es.gob.jmulticard.card.icao;

/*
  Clase auxiliar para devolver la información parseada
*/
public class TlvHeaderInfo {
    public final int tag;            // El byte del Tag (asumiendo 1 byte para DGs)
    public final int valueLength;    // Longitud del campo Valor (V)
    public final int headerLength;   // Longitud total de la cabecera (T+L), es decir, el offset al valor.
    public final byte[] rawHeaderBytes; // Los bytes leídos para la cabecera

    public TlvHeaderInfo(int tag, int valueLength, int headerLength, byte[] rawHeaderBytes) {
        this.tag = tag;
        this.valueLength = valueLength;
        this.headerLength = headerLength;
        this.rawHeaderBytes = rawHeaderBytes;
    }
}
