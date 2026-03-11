package com.example.desfiresdm;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.util.Log;

import com.nxp.nfclib.CardType;
import com.nxp.nfclib.NxpNfcLib;
import com.nxp.nfclib.desfire.DESFireFactory;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;

/**
 * Gestor NFC centralizado usando el SDK TapLinx de NXP.
 * Usa IDESFireEV3 (interfaz pública) en lugar de DESFireEV3 (clase interna).
 */
public class NfcManager {

    private static final String TAG = "NfcManager";

    // Reemplaza con tu API key de TapLinx: https://inspire.nxp.com/mifare/index.html
    public static final String TAPLINX_API_KEY = "PUT_YOUR_TAPLINX_API_KEY_HERE";

    private static NfcManager instance;
    private NxpNfcLib nxpLib;
    private NfcAdapter nfcAdapter;
    private IDESFireEV1 currentCard;  // IDESFireEV3 extiende IDESFireEV1
    private CardType currentCardType;
    private boolean sdkInitialized = false;

    public interface NfcCallback {
        void onCardDetected(CardType cardType);
        void onError(String message);
    }

    private NfcCallback callback;

    private NfcManager() {}

    public static NfcManager getInstance() {
        if (instance == null) instance = new NfcManager();
        return instance;
    }

    public boolean initSdk(Activity activity) {
        try {
            nxpLib = NxpNfcLib.getInstance();
            nxpLib.registerActivity(activity, TAPLINX_API_KEY);
            nfcAdapter = NfcAdapter.getDefaultAdapter(activity);
            sdkInitialized = true;
            Log.d(TAG, "TapLinx SDK inicializado");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error SDK: " + e.getMessage());
            sdkInitialized = false;
            return false;
        }
    }

    public void setCallback(NfcCallback cb) { this.callback = cb; }
    public boolean isSdkInitialized() { return sdkInitialized; }
    public NfcAdapter getNfcAdapter() { return nfcAdapter; }

    public void enableForegroundDispatch(Activity activity) {
        if (nxpLib != null) {
            try {
                nxpLib.startForeGroundDispatch();
            } catch (Exception e) {
                Log.w(TAG, "startForeGroundDispatch: " + e.getMessage());
            }
        }
    }

    public void disableForegroundDispatch(Activity activity) {
        if (nxpLib != null) {
            try {
                nxpLib.stopForeGroundDispatch();
            } catch (Exception e) {
                Log.w(TAG, "stopForeGroundDispatch: " + e.getMessage());
            }
        }
    }

    /**
     * Procesa un Tag NFC. Devuelve true si es DESFire EV3.
     */
    public boolean processTag(Tag tag) {
        if (tag == null) return false;
        currentCard = null;
        currentCardType = null;

        try {
            CardType cardType = nxpLib.getCardType(tag);
            currentCardType = cardType;
            Log.d(TAG, "Tarjeta detectada: " + cardType);

            if (callback != null) callback.onCardDetected(cardType);

            if (cardType == CardType.DESFireEV3) {
                // getDESFireEV3 devuelve IDESFireEV3 que implementa IDESFireEV1
                currentCard = DESFireFactory.getInstance().getDESFireEV3(nxpLib.getCustomModules());
                Log.d(TAG, "DESFire EV3 instanciado como IDESFireEV3");
                return true;
            } else {
                String msg = "Tarjeta no compatible: " + cardType + ". Se requiere DESFire EV3.";
                if (callback != null) callback.onError(msg);
                return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error procesando tag: " + e.getMessage(), e);
            if (callback != null) callback.onError("Error: " + e.getMessage());
            return false;
        }
    }

    /** Devuelve la tarjeta actual como IDESFireEV3 (o null si no hay tarjeta EV3) */
    public IDESFireEV3 getCurrentCardEV3() {
        if (currentCard instanceof IDESFireEV3) return (IDESFireEV3) currentCard;
        return null;
    }

    /** Devuelve la tarjeta actual como IDESFireEV1 (base) */
    public IDESFireEV1 getCurrentCard() { return currentCard; }

    public boolean hasCard() { return currentCard != null; }
    public CardType getCurrentCardType() { return currentCardType; }
}
