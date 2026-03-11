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

import com.nxp.nfclib.desfire.IDESFireEV3;

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

        etUrl               = findViewById(R.id.et_sdm_url);
        cbUidMirroring      = findViewById(R.id.cb_uid_mirroring);
        cbReadCounter       = findViewById(R.id.cb_read_counter);
        cbEncryption        = findViewById(R.id.cb_encryption);
        cbCounterLimit      = findViewById(R.id.cb_counter_limit);
        etCounterLimit      = findViewById(R.id.et_counter_limit);
        etEncLength         = findViewById(R.id.et_enc_length);
        btnCalculateOffsets = findViewById(R.id.btn_calculate_offsets);
        btnApplySdm         = findViewById(R.id.btn_apply_sdm);
        btnDisableSdm       = findViewById(R.id.btn_disable_sdm);
        progressBar         = findViewById(R.id.progress_bar);
        tvOffsets           = findViewById(R.id.tv_offsets);
        tvResult            = findViewById(R.id.tv_result);

        nfcManager = NfcManager.getInstance();
        currentConfig = new SdmConfig();

        etUrl.setText("https://sdm.nfctron.com/st?p=00000000000000000000000000000000&m=0000000000000000");
        cbUidMirroring.setChecked(true);
        cbReadCounter.setChecked(true);

        btnCalculateOffsets.setOnClickListener(v -> calculateAndShowOffsets());
        btnApplySdm.setOnClickListener(v -> confirmAndApplySdm());
        btnDisableSdm.setOnClickListener(v -> confirmDisableSdm());

        cbCounterLimit.setOnCheckedChangeListener((cb, checked) -> etCounterLimit.setEnabled(checked));
        cbEncryption.setOnCheckedChangeListener((cb, checked) -> etEncLength.setEnabled(checked));
    }

    private void calculateAndShowOffsets() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) { Toast.makeText(this, "Introduce una URL", Toast.LENGTH_SHORT).show(); return; }

        SdmConfig config = buildConfigFromUi();
        new DesfireOperations().calculateSdmOffsets(url, config);

        tvOffsets.setText(
            "── OFFSETS CALCULADOS ───────\n" +
            String.format("PICC offset: %d (0x%02X)\n", config.getPiccDataOffset(), config.getPiccDataOffset()) +
            String.format("MAC offset:  %d (0x%02X)\n", config.getSdmMacOffset(), config.getSdmMacOffset()) +
            (cbReadCounter.isChecked() ? String.format("Ctr offset:  %d (0x%02X)\n", config.getSdmReadCounterOffset(), config.getSdmReadCounterOffset()) : "") +
            "\n── URL ──────────────────────\n" + url
        );
        currentConfig = config;
    }

    private void confirmAndApplySdm() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) { Toast.makeText(this, "Introduce una URL", Toast.LENGTH_SHORT).show(); return; }

        currentConfig = buildConfigFromUi();
        new DesfireOperations().calculateSdmOffsets(url, currentConfig);

        new AlertDialog.Builder(this)
            .setTitle("Aplicar SDM")
            .setMessage("URL: " + url + "\nUID: " + cbUidMirroring.isChecked() + " | Counter: " + cbReadCounter.isChecked() + "\n\n⚠️ Modifica la tarjeta. ¿Continuar?")
            .setPositiveButton("Aplicar", (d, w) -> new SdmTask(false).execute())
            .setNegativeButton("Cancelar", null).show();
    }

    private void confirmDisableSdm() {
        new AlertDialog.Builder(this)
            .setTitle("Deshabilitar SDM")
            .setMessage("¿Desactivar SDM en la tarjeta?")
            .setPositiveButton("Deshabilitar", (d, w) -> new SdmTask(true).execute())
            .setNegativeButton("Cancelar", null).show();
    }

    private SdmConfig buildConfigFromUi() {
        SdmConfig config = new SdmConfig();
        config.setBaseUrl(etUrl.getText().toString().trim());
        config.setUidMirroringEnabled(cbUidMirroring.isChecked());
        config.setSdmReadCounterEnabled(cbReadCounter.isChecked());
        config.setSdmEncryptionEnabled(cbEncryption.isChecked());
        config.setSdmReadCounterLimitEnabled(cbCounterLimit.isChecked());
        try {
            if (cbCounterLimit.isChecked() && !etCounterLimit.getText().toString().isEmpty())
                config.setSdmReadCounterLimit(Integer.parseInt(etCounterLimit.getText().toString()));
        } catch (NumberFormatException ignored) {}
        try {
            if (cbEncryption.isChecked() && !etEncLength.getText().toString().isEmpty())
                config.setSdmEncLength(Integer.parseInt(etEncLength.getText().toString()));
        } catch (NumberFormatException ignored) {}
        return config;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    private class SdmTask extends AsyncTask<Void, Void, String> {
        private final boolean disable;
        private String errorMsg;

        SdmTask(boolean disable) { this.disable = disable; }

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            btnApplySdm.setEnabled(false);
            btnDisableSdm.setEnabled(false);
            tvResult.setText(disable ? "Deshabilitando SDM..." : "Aplicando SDM...");
        }

        @Override
        protected String doInBackground(Void... voids) {
            IDESFireEV3 card = nfcManager.getCurrentCardEV3();
            if (card == null) { errorMsg = "No hay tarjeta activa"; return null; }
            DesfireOperations ops = new DesfireOperations(card);
            try {
                if (disable) {
                    SdmConfig off = new SdmConfig();
                    off.setUidMirroringEnabled(false);
                    off.setSdmReadCounterEnabled(false);
                    off.setSdmEncryptionEnabled(false);
                    ops.configureSdm(off);
                    return "✅ SDM deshabilitado";
                } else {
                    ops.writeNdefUrl(currentConfig.getBaseUrl());
                    ops.configureSdm(currentConfig);
                    return "✅ SDM configurado\n\n" + currentConfig.getBaseUrl();
                }
            } catch (Exception e) { errorMsg = e.getMessage(); return null; }
        }

        @Override
        protected void onPostExecute(String result) {
            progressBar.setVisibility(View.GONE);
            btnApplySdm.setEnabled(true);
            btnDisableSdm.setEnabled(true);
            if (result != null) {
                tvResult.setText(result);
            } else {
                tvResult.setText("❌ " + errorMsg);
                Toast.makeText(SdmConfigActivity.this, "Error: " + errorMsg, Toast.LENGTH_LONG).show();
            }
        }
    }
}
