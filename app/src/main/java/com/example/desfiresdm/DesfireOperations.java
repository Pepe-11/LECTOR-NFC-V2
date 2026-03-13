package com.example.desfiresdm;

import android.util.Log;

import com.nxp.nfclib.desfire.DESFireEV3;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.interfaces.IKeyData;
import com.nxp.nfclib.KeyType;

import java.nio.charset.StandardCharsets;

public class DesfireOperations {

    private static final String TAG = "DesfireOps";

    public static final byte[] NDEF_AID = new byte[]{
            (byte)0xD2,0x76,0x00,0x00,(byte)0x85,0x01,0x01
    };

    public static final byte NDEF_CC_FILE_ID = 0x01;
    public static final byte NDEF_DATA_FILE_ID = 0x02;

    public static final int NDEF_FILE_SIZE = 256;

    public static final byte[] DEFAULT_KEY = new byte[16];

    private final DESFireEV3 card;

    public DesfireOperations(DESFireEV3 card){
        this.card = card;
    }

    //────────────────────────────────────────
    // AUTENTICACIÓN
    //────────────────────────────────────────

    public void authenticatePicc(byte[] key) throws Exception {

        byte[] k = key != null ? key : DEFAULT_KEY;

        IKeyData keyData = card.getKeyData(KeyType.AES128);
        keyData.setKey(k);

        card.authenticate(keyData,0,false, IDESFireEV1.AuthType.Native);

        Log.d(TAG,"Autenticado en PICC");
    }

    private void authenticateApp(byte[] key,int keyNo) throws Exception {

        byte[] k = key != null ? key : DEFAULT_KEY;

        IKeyData keyData = card.getKeyData(KeyType.AES128);
        keyData.setKey(k);

        card.authenticate(keyData,keyNo,false,IDESFireEV1.AuthType.Native);
    }

    //────────────────────────────────────────
    // CREAR APP NDEF
    //────────────────────────────────────────

    public void createNdefApp(byte[] appMasterKey) throws Exception {

        card.selectApplication(new byte[]{0x00,0x00,0x00});

        authenticatePicc(null);

        byte keySettings = 0x0F;
        byte numberOfKeys = (byte)0x82;

        card.createApplication(NDEF_AID,keySettings,numberOfKeys);

        card.selectApplication(NDEF_AID);

        authenticateApp(null,0);

        createCapabilityContainerFile();

        createNdefDataFile();

        Log.d(TAG,"Aplicación NDEF creada");
    }

    //────────────────────────────────────────
    // CREAR CC FILE
    //────────────────────────────────────────

    private void createCapabilityContainerFile() throws Exception {

        byte readAccess = (byte)0xEE;
        byte writeAccess = (byte)0x00;

        DESFireEV3File.StdEV3DataFileSettings ccSettings =
                new DESFireEV3File.StdEV3DataFileSettings(
                        IDESFireEV1.CommunicationType.Plain,
                        readAccess,
                        readAccess,
                        writeAccess,
                        readAccess,
                        15,
                        false,
                        null
                );

        card.createFile(NDEF_CC_FILE_ID,ccSettings);

        byte[] cc = new byte[]{
                0x00,0x0F,
                0x20,
                0x00,(byte)(NDEF_FILE_SIZE>>8),(byte)NDEF_FILE_SIZE,
                0x00,(byte)0xFF,
                0x04,
                0x06,
                0x00,NDEF_DATA_FILE_ID,
                0x00,(byte)(NDEF_FILE_SIZE>>8),(byte)NDEF_FILE_SIZE,
                0x00,
                (byte)0x80
        };

        card.writeData(
                NDEF_CC_FILE_ID,
                0,
                cc.length,
                cc,
                IDESFireEV1.CommunicationType.Plain
        );

        Log.d(TAG,"CC File creado");
    }

    //────────────────────────────────────────
    // CREAR NDEF FILE
    //────────────────────────────────────────

    private void createNdefDataFile() throws Exception {

        byte readAccess = (byte)0xEE;
        byte writeAccess = (byte)0x00;

        DESFireEV3File.StdEV3DataFileSettings ndefSettings =
                new DESFireEV3File.StdEV3DataFileSettings(
                        IDESFireEV1.CommunicationType.Plain,
                        readAccess,
                        readAccess,
                        writeAccess,
                        readAccess,
                        NDEF_FILE_SIZE,
                        false,
                        null
                );

        card.createFile(NDEF_DATA_FILE_ID,ndefSettings);

        Log.d(TAG,"NDEF file creado");
    }

    //────────────────────────────────────────
    // ESCRIBIR URL
    //────────────────────────────────────────

    public void writeNdefUrl(String url) throws Exception {

        byte[] ndefMessage = buildNdefUriMessage(url);

        card.selectApplication(NDEF_AID);

        authenticateApp(null,0);

        card.writeData(
                NDEF_DATA_FILE_ID,
                0,
                ndefMessage.length,
                ndefMessage,
                IDESFireEV1.CommunicationType.Plain
        );

        Log.d(TAG,"NDEF escrito: "+url);
    }

    //────────────────────────────────────────
    // CONSTRUIR NDEF URI
    //────────────────────────────────────────

    private byte[] buildNdefUriMessage(String url){

        byte uriIdentifier;
        String payload;

        if(url.startsWith("https://")){
            uriIdentifier = 0x04;
            payload = url.substring(8);
        }
        else if(url.startsWith("http://")){
            uriIdentifier = 0x03;
            payload = url.substring(7);
        }
        else{
            uriIdentifier = 0x00;
            payload = url;
        }

        byte[] urlBytes = payload.getBytes(StandardCharsets.UTF_8);

        int payloadLen = 1 + urlBytes.length;

        byte[] record = new byte[5 + urlBytes.length];

        record[0]=(byte)0xD1;
        record[1]=0x01;
        record[2]=(byte)payloadLen;
        record[3]=0x55;
        record[4]=uriIdentifier;

        System.arraycopy(urlBytes,0,record,5,urlBytes.length);

        byte[] message = new byte[2 + record.length];

        message[0]=(byte)((record.length>>8)&0xFF);
        message[1]=(byte)(record.length&0xFF);

        System.arraycopy(record,0,message,2,record.length);

        return message;
    }

}
