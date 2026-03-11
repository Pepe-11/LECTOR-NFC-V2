package com.example.desfiresdm;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

import com.nxp.nfclib.CardType;
import com.nxp.nfclib.NxpNfcLib;
import com.nxp.nfclib.desfire.DESFireEV3;
import com.nxp.nfclib.desfire.DESFireFactory;
import com.nxp.nfclib.desfire.IDESFireEV1;

/**
 * Gestor NFC centralizado.
 * Envuelve el SDK TapLinx de NXP y expone operaciones de alto nivel
 * para trabajar con tarjetas MIFARE DESFire EV3.
 *
 * IMPORTANTE: Para usar el SDK en producción necesitas una licencia de NXP.
 * Regístrate en: https://www.nxp.com/taplinx
 * y sustituye TAPLINX_API_KEY por tu clave real.
 */
public class NfcManager {

    private static final String TAG = "NfcManager";

    // ── Reemplaza con tu API key de TapLinx ──────────────────────────────────
    // Obtén una clave gratuita de desarrollador en https://www.nxp.com/taplinx
    public static final String TAPLINX_API_KEY = "PUT_YOUR_TAPLINX_API_KEY_HERE";
    // ─────────────────────────────────────────────────────────────────────────

    private static NfcManager instance;
    private NxpNfcLib nxpLib;
    private NfcAdapter nfcAdapter;
    private DESFireEV3 currentCard;
    private boolean sdkInitialized = false;

    // Callback para notificar eventos a la UI
    public interface NfcCallback {
        void onCardDetected(CardType cardType);
        void onError(String message);
    }

    private NfcCallback callback;

    private NfcManager() {}

    public static NfcManager getInstance() {
        if (instance == null) {
            instance = new NfcManager();
        }
        return instance;
    }

    /**
     * Inicializa el SDK TapLinx. Llama esto en Application.onCreate() o en tu
     * primera Activity antes de usar cualquier funcionalidad NFC.
     */
    public boolean initSdk(Activity activity) {
        try {
            nxpLib = NxpNfcLib.getInstance();
            nxpLib.registerActivity(activity, TAPLINX_API_KEY);
            nfcAdapter = NfcAdapter.getDefaultAdapter(activity);
            sdkInitialized = true;
            Log.d(TAG, "TapLinx SDK inicializado correctamente");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error inicializando TapLinx SDK: " + e.getMessage());
            sdkInitialized = false;
            return false;
        }
    }

    public void setCallback(NfcCallback cb) {
        this.callback = cb;
    }

    public boolean isSdkInitialized() {
        return sdkInitialized;
    }

    public NfcAdapter getNfcAdapter() {
        return nfcAdapter;
    }

    /**
     * Activa el foreground dispatch para que la Activity reciba los intents NFC.
     * Llama esto en onResume().
     */
    public void enableForegroundDispatch(Activity activity) {
        if (nxpLib != null) {
            try {
                nxpLib.startForeGroundDispatch(activity);
            } catch (Exception e) {
                Log.w(TAG, "startForeGroundDispatch no disponible, usando adapter directo");
                // Fallback: el manifest ya configura el filtro tech
            }
        }
    }

    /**
     * Desactiva el foreground dispatch. Llama esto en onPause().
     */
    public void disableForegroundDispatch(Activity activity) {
        if (nxpLib != null) {
            try {
                nxpLib.stopForeGroundDispatch(activity);
            } catch (Exception e) {
                Log.w(TAG, "stopForeGroundDispatch no disponible");
            }
        }
    }

    /**
     * Procesa un Tag NFC recibido en onNewIntent().
     * Detecta el tipo de tarjeta y crea la instancia adecuada.
     *
     * @return true si es una DESFire EV3 compatible
     */
    public boolean processTag(Tag tag) {
        if (tag == null) return false;
        currentCard = null;

        try {
            CardType cardType = nxpLib.getCardType(tag);
            Log.d(TAG, "Tipo de tarjeta detectado: " + cardType);

            if (callback != null) {
                callback.onCardDetected(cardType);
            }

            if (cardType == CardType.DESFireEV3) {
                currentCard = (DESFireEV3) DESFireFactory.getInstance().getDESFire(nxpLib.getCustomModules());
                Log.d(TAG, "DESFire EV3 instanciado correctamente");
                return true;
            } else {
                Log.w(TAG, "Tarjeta no compatible: " + cardType);
                if (callback != null) {
                    callback.onError("Tarjeta no compatible. Se requiere DESFire EV3. Detectada: " + cardType);
                }
                return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error procesando tag: " + e.getMessage(), e);
            if (callback != null) {
                callback.onError("Error leyendo tarjeta: " + e.getMessage());
            }
            return false;
        }
    }

    public DESFireEV3 getCurrentCard() {
        return currentCard;
    }

    public boolean hasCard() {
        return currentCard != null;
    }
}
