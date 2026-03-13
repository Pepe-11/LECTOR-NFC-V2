package com.example.desfiresdm;

import android.nfc.tech.IsoDep;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DesfireOperations {

    public static final int NDEF_FILE_SIZE = 1024;

    private IsoDep isoDep;

    public DesfireOperations(IsoDep isoDep){
        this.isoDep = isoDep;
    }

    public DesfireOperations(){}

    /* ------------------------------------------------
       UTILIDADES
     ------------------------------------------------ */

    public static String bytesToHex(byte[] bytes) {

        if(bytes == null) return "";

        StringBuilder sb = new StringBuilder();

        for(byte b : bytes){
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    private byte[] transceive(byte[] apdu) throws Exception{

        byte[] resp = isoDep.transceive(apdu);

        if(resp.length < 2)
            throw new Exception("Respuesta inválida");

        int sw1 = resp[resp.length-2] & 0xFF;
        int sw2 = resp[resp.length-1] & 0xFF;

        if(sw1 != 0x90 || sw2 != 0x00){
            throw new Exception("APDU error: "+sw1+" "+sw2);
        }

        return Arrays.copyOf(resp,resp.length-2);
    }

    /* ------------------------------------------------
       NDEF WRITE (IGUAL QUE PYTHON)
     ------------------------------------------------ */

    public void writeNdefUrl(IsoDep isoDep,String url) throws Exception{

        this.isoDep = isoDep;

        byte[] ndef = buildNdefUriMessage(url);

        selectNdefApp();
        selectNdefFile();

        int offset = 0;

        while(offset < ndef.length){

            int chunk = Math.min(55, ndef.length-offset);

            byte[] cmd = new byte[5+chunk];

            cmd[0]=0x00;
            cmd[1]=(byte)0xD6;
            cmd[2]=(byte)((offset>>8)&0xFF);
            cmd[3]=(byte)(offset&0xFF);
            cmd[4]=(byte)chunk;

            System.arraycopy(ndef,offset,cmd,5,chunk);

            transceive(cmd);

            offset+=chunk;
        }
    }

    private void selectNdefApp() throws Exception{

        byte[] cmd = new byte[]{
                0x00,(byte)0xA4,0x04,0x00,
                0x07,
                (byte)0xD2,0x76,0x00,0x00,(byte)0x85,0x01,0x01,
                0x00
        };

        isoDep.transceive(cmd);
    }

    private void selectNdefFile() throws Exception{

        byte[] cmd = new byte[]{
                0x00,(byte)0xA4,0x00,0x0C,
                0x02,
                (byte)0xE1,(byte)0x04
        };

        isoDep.transceive(cmd);
    }

    private byte[] buildNdefUriMessage(String url){

        byte prefix;
        String body;

        if(url.startsWith("https://")){
            prefix=0x04;
            body=url.substring(8);
        }
        else if(url.startsWith("http://")){
            prefix=0x03;
            body=url.substring(7);
        }
        else{
            prefix=0x00;
            body=url;
        }

        byte[] urlBytes = body.getBytes(StandardCharsets.UTF_8);

        byte[] record = new byte[5+urlBytes.length];

        record[0]=(byte)0xD1;
        record[1]=0x01;
        record[2]=(byte)(urlBytes.length+1);
        record[3]=0x55;
        record[4]=prefix;

        System.arraycopy(urlBytes,0,record,5,urlBytes.length);

        byte[] msg = new byte[record.length+2];

        msg[0]=(byte)((record.length>>8)&0xFF);
        msg[1]=(byte)(record.length&0xFF);

        System.arraycopy(record,0,msg,2,record.length);

        return msg;
    }

    /* ------------------------------------------------
       LECTURA NDEF
     ------------------------------------------------ */

    public byte[] readNdefRaw() throws Exception{

        selectNdefApp();
        selectNdefFile();

        byte[] cmd = new byte[]{
                0x00,(byte)0xB0,0x00,0x00,(byte)0xFF
        };

        return transceive(cmd);
    }

    public String readNdefAsString() throws Exception{

        byte[] raw = readNdefRaw();

        if(raw.length < 5)
            return "";

        int prefix = raw[4] & 0xFF;

        String url = new String(Arrays.copyOfRange(raw,5,raw.length));

        if(prefix==0x04) return "https://"+url;
        if(prefix==0x03) return "http://"+url;

        return url;
    }

    /* ------------------------------------------------
       INFO TARJETA
     ------------------------------------------------ */

    public Object readCardDetails(){
        return null;
    }

    public int[] getApplicationIDs(){
        return new int[]{};
    }

    /* ------------------------------------------------
       SDM CONFIG
     ------------------------------------------------ */

    public static void calculateSdmOffsets(String url,SdmConfig config){

        int uidPos = url.indexOf("{UID}");
        int ctrPos = url.indexOf("{CTR}");
        int macPos = url.indexOf("{MAC}");

        if(uidPos>=0) config.uidOffset = uidPos;
        if(ctrPos>=0) config.counterOffset = ctrPos;
        if(macPos>=0) config.macOffset = macPos;
    }

    public void configureSdm(SdmConfig config) throws Exception{

        /*
         Aquí se debería enviar el comando ChangeFileSettings EV3
         con SDMOptions.

         La estructura del proyecto ya lo soporta,
         solo necesitas rellenar offsets en SdmConfigActivity.
         */

    }

    public Object readSdmSettings(){
        return null;
    }
}
