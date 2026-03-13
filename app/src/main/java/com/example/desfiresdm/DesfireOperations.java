package com.example.desfiresdm;

import android.nfc.tech.IsoDep;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DesfireOperations {

    private IsoDep isoDep;

    public static final byte[] NDEF_AID =
            {(byte)0xD2,0x76,0x00,0x00,(byte)0x85,0x01,0x01};

    public static final byte[] NDEF_FILE =
            {(byte)0xE1,(byte)0x04};

    public DesfireOperations(IsoDep isoDep){
        this.isoDep = isoDep;
    }

    /* ------------------------------------------------ */
    /* APDU HELPER                                       */
    /* ------------------------------------------------ */

    private byte[] transceive(byte[] apdu) throws Exception{

        byte[] resp = isoDep.transceive(apdu);

        if(resp.length < 2)
            throw new Exception("Invalid response");

        int sw1 = resp[resp.length-2] & 0xFF;
        int sw2 = resp[resp.length-1] & 0xFF;

        if(sw1 != 0x90 || sw2 != 0x00)
            throw new Exception("APDU error "+sw1+" "+sw2);

        return Arrays.copyOf(resp,resp.length-2);
    }

    /* ------------------------------------------------ */
    /* SELECT NDEF APP                                   */
    /* ------------------------------------------------ */

    public void selectNdefApplication() throws Exception{

        byte[] cmd = new byte[]{
                0x00,(byte)0xA4,0x04,0x00,
                0x07,
                (byte)0xD2,0x76,0x00,0x00,(byte)0x85,0x01,0x01,
                0x00
        };

        isoDep.transceive(cmd);
    }

    public void selectNdefFile() throws Exception{

        byte[] cmd = new byte[]{
                0x00,(byte)0xA4,0x00,0x0C,
                0x02,
                (byte)0xE1,(byte)0x04
        };

        isoDep.transceive(cmd);
    }

    /* ------------------------------------------------ */
    /* CREATE NDEF STRUCTURE                             */
    /* ------------------------------------------------ */

    public void createNdefApplication() throws Exception{

        byte[] apdu = new byte[]{
                (byte)0x90,0xCA,0x00,0x00,
                0x05,
                0x01,0x00,0x00,
                0x0F,0x01,
                0x00
        };

        isoDep.transceive(apdu);
    }

    public void createNdefFile() throws Exception{

        byte[] apdu = new byte[]{
                (byte)0x90,(byte)0xCD,0x00,0x00,
                0x07,
                0x02,
                0x00,0x00,
                (byte)0xEE,
                0x00,0x00,
                (byte)0xFF,
                0x00
        };

        isoDep.transceive(apdu);
    }

    /* ------------------------------------------------ */
    /* BUILD NDEF URL                                    */
    /* ------------------------------------------------ */

    private byte[] buildNdefUri(String url){

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

    /* ------------------------------------------------ */
    /* WRITE NDEF                                        */
    /* ------------------------------------------------ */

    public void writeNdefUrl(String url) throws Exception{

        selectNdefApplication();
        selectNdefFile();

        byte[] ndef = buildNdefUri(url);

        int offset = 0;

        while(offset < ndef.length){

            int chunk = Math.min(50,ndef.length-offset);

            byte[] cmd = new byte[5 + chunk];

            cmd[0] = 0x00;
            cmd[1] = (byte)0xD6;
            cmd[2] = (byte)((offset >> 8) & 0xFF);
            cmd[3] = (byte)(offset & 0xFF);
            cmd[4] = (byte)chunk;

            System.arraycopy(ndef,offset,cmd,5,chunk);

            transceive(cmd);

            offset += chunk;
        }
    }

    /* ------------------------------------------------ */
    /* CONFIGURE SDM                                     */
    /* ------------------------------------------------ */

    public void configureSdm(SdmConfig cfg) throws Exception{

        byte sdmOptions = 0x01;
        byte sdmAccess = 0x0F;

        byte[] cmd = new byte[]{
                (byte)0x90,0x5F,0x00,0x00,
                0x0B,
                0x02,
                sdmOptions,
                sdmAccess,
                (byte)cfg.uidOffset,
                (byte)cfg.counterOffset,
                (byte)cfg.macOffset,
                0x00,0x00,0x00,
                0x00
        };

        isoDep.transceive(cmd);
    }

    /* ------------------------------------------------ */
    /* READ NDEF                                         */
    /* ------------------------------------------------ */

    public String readNdef() throws Exception{

        selectNdefApplication();
        selectNdefFile();

        byte[] cmd = new byte[]{
                0x00,(byte)0xB0,0x00,0x00,(byte)0xFF
        };

        byte[] data = transceive(cmd);

        if(data.length < 5)
            return "";

        int prefix = data[4] & 0xFF;

        String body = new String(Arrays.copyOfRange(data,5,data.length));

        if(prefix==0x04) return "https://"+body;
        if(prefix==0x03) return "http://"+body;

        return body;
    }
}
