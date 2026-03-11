package com.example.desfiresdm;

import android.os.AsyncTask;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.nxp.nfclib.desfire.DESFireEV3;

/**
 * Activity para configurar SDM (Secure Dynamic Messaging) en la tarjeta.
 *
 * SDM hace que la tarjeta genere automáticamente una URL dinámica
 * con campos criptográficos en cada lectura NFC.
 *
 * Parámetros configurables:
 *  - URL base con placeholders
 *  - Habilitar UID mirroring (UID cifrado en la URL)
 *  - Habilitar contador de lecturas
 *  - Habilitar cifrado de parte de los datos
 *  - Límite de lecturas
 *
 * El cálculo de offsets se hace automáticamente a partir de los placeholders
 * en la URL.
 */
public class SdmConfigActivity extends AppCompatActivity {

    private EditText etUrl;
    private CheckBox cbUidMirroring;
    private CheckBox cbReadCounter;
    private CheckBox cbEncryption;
    private CheckBox cbCounterLimit;
    private EditText etCounterLimit;
    private EditText etEncLength;
    private Button btnCalculateOffsets;
    private Button btnApplySdm;
    private Button btnDisableSdm;
    private ProgressBar progressBar;
    private TextView tvOffsets;
    private TextView tvResult;

    private NfcManager nfcManager;
    private SdmConfig currentConfig;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sdm_config);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Configurar SDM");
        }

        etUrl             = findViewById(R.id.et_sdm_url);
        cbUidMirroring    = findViewById(R.id.cb_uid_mirroring);
        cbReadCounter     = findViewById(R.id.cb_read_counter);
        cbEncryption      = findViewById(R.id.cb_encryption);
        cbCounterLimit    = findViewById(R.id.cb_counter_limit);
        etCounterLimit    = findViewById(R.id.et_counter_limit);
        etEncLength       = findViewById(R.id.et_enc_length);
        btnCalculateOffsets = findViewById(R.id.btn_calculate_offsets);
        btnApplySdm       = findViewById(R.id.btn_apply_sdm);
        btnDisableSdm     = findViewById(R.id.btn_disable_sdm);
        progressBar       = findViewById(R.id.progress_bar);
        tvOffsets         = findViewById(R.id.tv_offsets);
        tvResult          = findViewById(R.id.tv_result);

        nfcManager = NfcManager.getInstance();
        currentConfig = new SdmConfig();

        // Valores por defecto
        etUrl.setText("https://sdm.nfctron.com/st?p=00000000000000000000000000000000&m=0000000000000000");
        cbUidMirroring.setChecked(true);
        cbReadCounter.setChecked(true);

        btnCalculateOffsets.setOnClickListener(v -> calculateAndShowOffsets());
        btnApplySdm.setOnClickListener(v -> confirmAndApplySdm());
        btnDisableSdm.setOnClickListener(v -> confirmDisableSdm());

        cbCounterLimit.setOnCheckedChangeListener((cb, checked) ->
            etCounterLimit.setEnabled(checked));
        cbEncryption.setOnCheckedChangeListener((cb, checked) ->
            etEncLength.setEnabled(checked));
    }

    private void calculateAndShowOffsets() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) {
            Toast.makeText(this, "Introduce una URL", Toast.LENGTH_SHORT).show();
            return;
        }

        // Crear config temporal para calcular
        SdmConfig config = buildConfigFromUi();

        DesfireOperations ops = new DesfireOperations(null); // no necesita tarjeta para calcular
        ops.calculateSdmOffsets(url, config);

        // Mostrar resultado
        StringBuilder sb = new StringBuilder();
        sb.append("── OFFSETS CALCULADOS ───────\n");
        sb.append(String.format("PICC Data offset: %d (0x%02X)\n", config.getPiccDataOffset(), config.getPiccDataOffset()));
        sb.append(String.format("MAC offset:       %d (0x%02X)\n", config.getSdmMacOffset(), config.getSdmMacOffset()));
        if (cbReadCounter.isChecked()) {
            sb.append(String.format("Counter offset:   %d (0x%02X)\n", config.getSdmReadCounterOffset(), config.getSdmReadCounterOffset()));
        }
        if (cbEncryption.isChecked()) {
            sb.append(String.format("Enc offset:       %d (0x%02X)\n", config.getSdmEncOffset(), config.getSdmEncOffset()));
            sb.append(String.format("Enc length:       %d bytes\n", config.getSdmEncLength()));
        }
        sb.append("\n── URL con placeholders ─────\n");
        sb.append(url);

        tvOffsets.setText(sb.toString());
        currentConfig = config;
    }

    private void confirmAndApplySdm() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) {
            Toast.makeText(this, "Introduce una URL", Toast.LENGTH_SHORT).show();
            return;
        }

        // Primero calcular offsets
        currentConfig = buildConfigFromUi();
        DesfireOperations ops = new DesfireOperations(null);
        ops.calculateSdmOffsets(url, currentConfig);

        new AlertDialog.Builder(this)
            .setTitle("Aplicar SDM")
            .setMessage("Se configurará SDM en la tarjeta con:\n\n" +
                "URL: " + url + "\n" +
                "UID mirroring: " + cbUidMirroring.isChecked() + "\n" +
                "Counter: " + cbReadCounter.isChecked() + "\n" +
                "Encryption: " + cbEncryption.isChecked() + "\n\n" +
                "⚠️ Esta operación requiere autenticación con la clave maestra de la aplicación.\n" +
                "Si la tarjeta usa la clave por defecto (0x00*16) se procederá automáticamente.\n\n" +
                "¿Continuar?")
            .setPositiveButton("Aplicar", (d, w) -> new SdmTask(false).execute())
            .setNegativeButton("Cancelar", null)
            .show();
    }

    private void confirmDisableSdm() {
        new AlertDialog.Builder(this)
            .setTitle("Deshabilitar SDM")
            .setMessage("Se desactivará SDM en la tarjeta.\n\nLa URL seguirá siendo estática.\n\n¿Continuar?")
            .setPositiveButton("Deshabilitar", (d, w) -> new SdmTask(true).execute())
            .setNegativeButton("Cancelar", null)
            .show();
    }

    private SdmConfig buildConfigFromUi() {
        SdmConfig config = new SdmConfig();
        config.setBaseUrl(etUrl.getText().toString().trim());
        config.setUidMirroringEnabled(cbUidMirroring.isChecked());
        config.setSdmReadCounterEnabled(cbReadCounter.isChecked());
        config.setSdmEncryptionEnabled(cbEncryption.isChecked());
        config.setSdmReadCounterLimitEnabled(cbCounterLimit.isChecked());

        try {
            if (cbCounterLimit.isChecked() && !etCounterLimit.getText().toString().isEmpty()) {
                config.setSdmReadCounterLimit(Integer.parseInt(etCounterLimit.getText().toString()));
            }
        } catch (NumberFormatException ignored) {}

        try {
            if (cbEncryption.isChecked() && !etEncLength.getText().toString().isEmpty()) {
                config.setSdmEncLength(Integer.parseInt(etEncLength.getText().toString()));
            }
        } catch (NumberFormatException ignored) {}

        return config;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    // ── AsyncTask ─────────────────────────────────────────────────────────────

    private class SdmTask extends AsyncTask<Void, Void, String> {

        private final boolean disable;
        private String errorMsg;

        SdmTask(boolean disable) {
            this.disable = disable;
        }

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            btnApplySdm.setEnabled(false);
            btnDisableSdm.setEnabled(false);
            tvResult.setText(disable ? "Deshabilitando SDM..." : "Aplicando SDM...");
        }

        @Override
        protected String doInBackground(Void... voids) {
            DESFireEV3 card = nfcManager.getCurrentCard();
            if (card == null) { errorMsg = "No hay tarjeta activa"; return null; }

            DesfireOperations ops = new DesfireOperations(card);
            try {
                if (disable) {
                    // Deshabilitar SDM creando una config sin SDM
                    SdmConfig disableConfig = new SdmConfig();
                    disableConfig.setUidMirroringEnabled(false);
                    disableConfig.setSdmReadCounterEnabled(false);
                    disableConfig.setSdmEncryptionEnabled(false);
                    // El setSDMEnabled(false) se manejará en configureSdm cuando todos estén false
                    ops.configureSdm(disableConfig);
                    return "✅ SDM deshabilitado correctamente";
                } else {
                    // Primero escribir la URL si hay una nueva
                    String url = currentConfig.getBaseUrl();
                    if (!url.isEmpty()) {
                        ops.writeNdefUrl(url);
                    }
                    // Luego configurar SDM
                    ops.configureSdm(currentConfig);
                    return "✅ SDM configurado correctamente\n\nURL: " + currentConfig.getBaseUrl();
                }
            } catch (Exception e) {
                errorMsg = e.getMessage();
                return null;
            }
        }

        @Override
        protected void onPostExecute(String result) {
            progressBar.setVisibility(View.GONE);
            btnApplySdm.setEnabled(true);
            btnDisableSdm.setEnabled(true);
            if (result != null) {
                tvResult.setText(result);
                Toast.makeText(SdmConfigActivity.this,
                    disable ? "SDM deshabilitado" : "SDM configurado", Toast.LENGTH_SHORT).show();
            } else {
                tvResult.setText("❌ Error: " + errorMsg);
                Toast.makeText(SdmConfigActivity.this, "Error: " + errorMsg, Toast.LENGTH_LONG).show();
            }
        }
    }
}
