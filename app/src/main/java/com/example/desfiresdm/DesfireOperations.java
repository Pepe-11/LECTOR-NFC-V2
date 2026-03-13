package com.example.desfiresdm;

import android.nfc.tech.IsoDep;

import java.nio.charset.StandardCharsets;

public class DesfireOperations {

    /**
     * Escribe una URL como NDEF usando APDU ISO
     * (mismo método que tu script Python)
     */
    public void writeNdefUrl(IsoDep isoDep, String url) throws Exception {

        byte[] ndef = buildNdefUriMessage(url);

        // SELECT NDEF Application (ISO DF Name)
        byte[] selectApp = new byte[]{
                0x00,(byte)0xA4,0x04,0x00,
                0x07,
                (byte)0xD2,0x76,0x00,0x00,(byte)0x85,0x01,0x01,
                0x00
        };

        isoDep.transceive(selectApp);

        // SELECT NDEF FILE (E104)
        byte[] selectFile = new byte[]{
                0x00,(byte)0xA4,0x00,0x0C,
                0x02,
                (byte)0xE1,(byte)0x04
        };

        isoDep.transceive(selectFile);

        int offset = 0;

        while(offset < ndef.length){

            int chunk = Math.min(55, ndef.length - offset);

            byte[] cmd = new byte[5 + chunk];

            cmd[0] = 0x00;
            cmd[1] = (byte)0xD6;
            cmd[2] = (byte)((offset >> 8) & 0xFF);
            cmd[3] = (byte)(offset & 0xFF);
            cmd[4] = (byte)chunk;

            System.arraycopy(ndef, offset, cmd, 5, chunk);

            byte[] resp = isoDep.transceive(cmd);

            if(resp[resp.length-2] != (byte)0x90 || resp[resp.length-1] != 0x00){
                throw new Exception("Error escribiendo NDEF");
            }

            offset += chunk;
        }
    }

    /**
     * Construye un mensaje NDEF URI
     */
    private byte[] buildNdefUriMessage(String url){

        byte prefix;
        String body;

        if(url.startsWith("https://")){
            prefix = 0x04;
            body = url.substring(8);
        }
        else if(url.startsWith("http://")){
            prefix = 0x03;
            body = url.substring(7);
        }
        else{
            prefix = 0x00;
            body = url;
        }

        byte[] urlBytes = body.getBytes(StandardCharsets.UTF_8);

        byte[] record = new byte[5 + urlBytes.length];

        record[0] = (byte)0xD1;
        record[1] = 0x01;
        record[2] = (byte)(urlBytes.length + 1);
        record[3] = 0x55;
        record[4] = prefix;

        System.arraycopy(urlBytes,0,record,5,urlBytes.length);

        byte[] msg = new byte[record.length + 2];

        msg[0] = (byte)((record.length >> 8) & 0xFF);
        msg[1] = (byte)(record.length & 0xFF);

        System.arraycopy(record,0,msg,2,record.length);

        return msg;
    }
}
