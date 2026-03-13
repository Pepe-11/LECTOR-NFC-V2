package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.DESFireEV1File;
import com.nxp.nfclib.interfaces.IKeyData;
import com.nxp.nfclib.KeyType;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    public static final byte[] NDEF_AID = new byte[]{
            (byte)0xD2,0x76,0x00,0x00,(byte)0x85,0x01,0x01
    };

    public static final byte CC_FILE_ID   = 0x01;
    public static final byte NDEF_FILE_ID = 0x02;

    public static final int NDEF_FILE_SIZE = 256;

    private final IDESFireEV1 card;

    public DesfireOperations(IDESFireEV1 card){
        this.card = card;
    }

    // constructor vacío para pantallas que solo calculan offsets
    public DesfireOperations(){}

    //────────────────────────────
    // UTIL
    //────────────────────────────

    public static String bytesToHex(byte[] data){
        if(data==null) return "";
        StringBuilder sb=new StringBuilder();
        for(byte b:data) sb.append(String.format("%02X",b));
        return sb.toString();
    }

    //────────────────────────────
    // CREAR APP NDEF
    //────────────────────────────

    public void createNdefApp() throws Exception {

        card.selectApplication(0);

        byte keySettings = 0x0F;
        byte numberOfKeys = 0x01;

        card.createApplication(0x010000,keySettings,numberOfKeys);

        card.selectApplication(0x010000);

        createCapabilityContainer();
        createNdefFile();

        Log.d(TAG,"NDEF app creada");
    }

    private void createCapabilityContainer() throws Exception {

        DESFireEV1File.StdDataFileSettings settings =
                new DESFireEV1File.StdDataFileSettings(
                        IDESFireEV1.CommunicationType.Plain,
                        (byte)0xEE,(byte)0xEE,(byte)0x00,(byte)0xEE,
                        15
                );

        card.createFile(CC_FILE_ID,settings);

        byte[] cc=new byte[]{
                0x00,0x0F,
                0x20,
                0x00,0xFF,
                0x00,0xFF,
                0x04,0x06,
                0x00,NDEF_FILE_ID,
                0x00,(byte)0xFF,
                0x00,
                (byte)0xFF
        };

        card.writeData(CC_FILE_ID,0,cc.length,cc);
    }

    private void createNdefFile() throws Exception {

        DESFireEV1File.StdDataFileSettings settings =
                new DESFireEV1File.StdDataFileSettings(
                        IDESFireEV1.CommunicationType.Plain,
                        (byte)0xEE,(byte)0xEE,(byte)0x00,(byte)0xEE,
                        NDEF_FILE_SIZE
                );

        card.createFile(NDEF_FILE_ID,settings);
    }

    //────────────────────────────
    // ESCRIBIR NDEF URL
    //────────────────────────────

    public void writeNdefUrl(String url) throws Exception {

        byte[] ndef = buildUriRecord(url);

        card.writeData(
                NDEF_FILE_ID,
                0,
                ndef.length,
                ndef
        );

        Log.d(TAG,"URL escrita: "+url);
    }

    //────────────────────────────
    // CONSTRUIR URI NDEF
    //────────────────────────────

    private byte[] buildUriRecord(String url){

        byte prefix;
        String payload;

        if(url.startsWith("https://")){
            prefix=0x04;
            payload=url.substring(8);
        }else if(url.startsWith("http://")){
            prefix=0x03;
            payload=url.substring(7);
        }else{
            prefix=0x00;
            payload=url;
        }

        byte[] urlBytes=payload.getBytes(StandardCharsets.UTF_8);

        byte[] record=new byte[5+urlBytes.length];

        record[0]=(byte)0xD1;
        record[1]=0x01;
        record[2]=(byte)(urlBytes.length+1);
        record[3]=0x55;
        record[4]=prefix;

        System.arraycopy(urlBytes,0,record,5,urlBytes.length);

        byte[] msg=new byte[record.length+2];

        msg[0]=(byte)((record.length>>8)&0xFF);
        msg[1]=(byte)(record.length&0xFF);

        System.arraycopy(record,0,msg,2,record.length);

        return msg;
    }

    //────────────────────────────
    // LECTURA NDEF
    //────────────────────────────

    public byte[] readNdefRaw() throws Exception {

        return card.readData(
                NDEF_FILE_ID,
                0,
                NDEF_FILE_SIZE
        );
    }

    public String readNdefAsString() throws Exception {

        byte[] raw = readNdefRaw();

        if(raw.length<5) return "";

        int len=((raw[0]&0xFF)<<8)|(raw[1]&0xFF);

        byte[] rec= Arrays.copyOfRange(raw,2,2+len);

        return new String(rec,StandardCharsets.UTF_8);
    }

    //────────────────────────────
    // INFO TARJETA
    //────────────────────────────

    public IDESFireEV1.CardDetails readCardDetails() throws Exception{
        return card.getCardDetails();
    }

    public int[] getApplicationIDs() throws Exception{
        return card.getApplicationIDs();
    }

}
