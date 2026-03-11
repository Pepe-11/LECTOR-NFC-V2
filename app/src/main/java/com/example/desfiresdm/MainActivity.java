package com.example.desfiresdm;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.nxp.nfclib.CardType;

/**
 * Pantalla principal de la app.
 *
 * Muestra el estado del NFC y ofrece las opciones principales:
 *  - Leer tarjeta (ver UID, versión, NDEF)
 *  - Escribir URL NDEF
 *  - Configurar SDM
 */
public class MainActivity extends AppCompatActivity implements NfcManager.NfcCallback {

    private static final String TAG = "MainActivity";

    private TextView tvStatus;
    private TextView tvCardInfo;
    private Button btnRead;
    private Button btnWrite;
    private Button btnSdm;
    private Button btnInfo;

    private NfcManager nfcManager;
    private boolean sdkOk = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        initSdk();
        setupButtonListeners();

        // Procesar si la app se abrió desde un tag NFC
        if (getIntent() != null) {
            processNfcIntent(getIntent());
        }
    }

    private void initViews() {
        tvStatus   = findViewById(R.id.tv_status);
        tvCardInfo = findViewById(R.id.tv_card_info);
        btnRead    = findViewById(R.id.btn_read);
        btnWrite   = findViewById(R.id.btn_write);
        btnSdm     = findViewById(R.id.btn_sdm);
        btnInfo    = findViewById(R.id.btn_info);
    }

    private void initSdk() {
        nfcManager = NfcManager.getInstance();
        nfcManager.setCallback(this);
        sdkOk = nfcManager.initSdk(this);

        NfcAdapter nfcAdapter = nfcManager.getNfcAdapter();

        if (nfcAdapter == null) {
            showStatus("❌ Este dispositivo no tiene NFC", false);
            disableAllButtons();
            return;
        }

        if (!nfcAdapter.isEnabled()) {
            showStatus("⚠️ NFC está desactivado. Actívalo en Ajustes.", false);
            disableAllButtons();
            return;
        }

        if (!sdkOk) {
            showStatus("⚠️ SDK TapLinx no inicializado.\nVerifica tu API key en NfcManager.java", false);
        } else {
            showStatus("✅ NFC activo. Acerca una tarjeta DESFire EV3.", true);
        }
    }

    private void setupButtonListeners() {
        btnRead.setOnClickListener(v -> {
            if (nfcManager.hasCard()) {
                startActivity(new Intent(this, ReadCardActivity.class));
            } else {
                showToast("Primero acerca una tarjeta DESFire EV3");
            }
        });

        btnWrite.setOnClickListener(v -> {
            if (nfcManager.hasCard()) {
                startActivity(new Intent(this, WriteUrlActivity.class));
            } else {
                showToast("Primero acerca una tarjeta DESFire EV3");
            }
        });

        btnSdm.setOnClickListener(v -> {
            if (nfcManager.hasCard()) {
                startActivity(new Intent(this, SdmConfigActivity.class));
            } else {
                showToast("Primero acerca una tarjeta DESFire EV3");
            }
        });

        btnInfo.setOnClickListener(v -> showAppInfo());
    }

    @Override
    protected void onResume() {
        super.onResume();
        nfcManager.enableForegroundDispatch(this);
    }

    @Override
    protected void onPause() {
        super.onPause();
        nfcManager.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        processNfcIntent(intent);
    }

    private void processNfcIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action) ||
            NfcAdapter.ACTION_TAG_DISCOVERED.equals(action) ||
            NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {

            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if (tag != null) {
                showStatus("🔍 Procesando tarjeta...", true);
                boolean isEv3 = nfcManager.processTag(tag);
                if (isEv3) {
                    tvCardInfo.setText("✅ DESFire EV3 detectada\nPuedes leer, escribir o configurar SDM");
                    enableAllButtons();
                }
            }
        }
    }

    // ── NfcManager.NfcCallback ────────────────────────────────────────────────

    @Override
    public void onCardDetected(CardType cardType) {
        runOnUiThread(() -> {
            tvCardInfo.setText("Tipo: " + cardType.toString());
        });
    }

    @Override
    public void onError(String message) {
        runOnUiThread(() -> {
            showStatus("❌ " + message, false);
            tvCardInfo.setText("Sin tarjeta");
        });
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void showStatus(String msg, boolean ok) {
        runOnUiThread(() -> {
            tvStatus.setText(msg);
            tvStatus.setBackgroundColor(ok ?
                getColor(R.color.status_ok) :
                getColor(R.color.status_error));
        });
    }

    private void showToast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    private void disableAllButtons() {
        btnRead.setEnabled(false);
        btnWrite.setEnabled(false);
        btnSdm.setEnabled(false);
    }

    private void enableAllButtons() {
        btnRead.setEnabled(true);
        btnWrite.setEnabled(true);
        btnSdm.setEnabled(true);
    }

    private void showAppInfo() {
        new AlertDialog.Builder(this)
            .setTitle("DESFire EV3 SDM Tool")
            .setMessage(
                "Esta app permite:\n\n" +
                "📖 LEER: Ver UID, versión y contenido NDEF\n\n" +
                "✏️ ESCRIBIR: Guardar una URL en el fichero NDEF\n\n" +
                "🔐 SDM: Activar Secure Dynamic Messaging para\n" +
                "    generar URLs dinámicas con UID cifrado y MAC\n\n" +
                "Requisitos:\n" +
                "• Tarjeta MIFARE DESFire EV3\n" +
                "• API Key TapLinx de NXP\n" +
                "• Android 8.0+ con NFC\n\n" +
                "SDK: TapLinx v5.0.0 (NXP)"
            )
            .setPositiveButton("OK", null)
            .show();
    }
}
