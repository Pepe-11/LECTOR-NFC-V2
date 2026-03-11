package com.example.desfiresdm;

import android.os.AsyncTask;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.nxp.nfclib.desfire.DESFireEV3;
import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;

/**
 * Activity para leer información de la tarjeta DESFire EV3:
 *  - UID
 *  - Versión hardware/software
 *  - Lista de aplicaciones
 *  - Contenido NDEF
 *  - Configuración SDM actual
 */
public class ReadCardActivity extends AppCompatActivity {

    private TextView tvResult;
    private ProgressBar progressBar;
    private Button btnReadBasic;
    private Button btnReadNdef;
    private Button btnReadSdm;

    private NfcManager nfcManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_read_card);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Leer Tarjeta");
        }

        tvResult    = findViewById(R.id.tv_result);
        progressBar = findViewById(R.id.progress_bar);
        btnReadBasic = findViewById(R.id.btn_read_basic);
        btnReadNdef  = findViewById(R.id.btn_read_ndef);
        btnReadSdm   = findViewById(R.id.btn_read_sdm);

        nfcManager = NfcManager.getInstance();

        btnReadBasic.setOnClickListener(v -> readBasicInfo());
        btnReadNdef.setOnClickListener(v -> readNdef());
        btnReadSdm.setOnClickListener(v -> readSdmConfig());
    }

    private void readBasicInfo() {
        new CardReadTask(CardReadTask.MODE_BASIC).execute();
    }

    private void readNdef() {
        new CardReadTask(CardReadTask.MODE_NDEF).execute();
    }

    private void readSdmConfig() {
        new CardReadTask(CardReadTask.MODE_SDM).execute();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    // ── AsyncTask para no bloquear el hilo de UI ──────────────────────────────

    private class CardReadTask extends AsyncTask<Void, Void, String> {
        static final int MODE_BASIC = 1;
        static final int MODE_NDEF  = 2;
        static final int MODE_SDM   = 3;

        private final int mode;
        private String error;

        CardReadTask(int mode) {
            this.mode = mode;
        }

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            tvResult.setText("Leyendo...");
            setButtonsEnabled(false);
        }

        @Override
        protected String doInBackground(Void... voids) {
            DESFireEV3 card = nfcManager.getCurrentCard();
            if (card == null) {
                error = "No hay tarjeta activa";
                return null;
            }
            DesfireOperations ops = new DesfireOperations(card);
            try {
                switch (mode) {
                    case MODE_BASIC: return readBasic(ops);
                    case MODE_NDEF:  return readNdefContent(ops);
                    case MODE_SDM:   return readSdm(ops);
                }
            } catch (Exception e) {
                error = e.getMessage();
            }
            return null;
        }

        @Override
        protected void onPostExecute(String result) {
            progressBar.setVisibility(View.GONE);
            setButtonsEnabled(true);
            if (result != null) {
                tvResult.setText(result);
            } else {
                tvResult.setText("❌ Error: " + error);
                Toast.makeText(ReadCardActivity.this, "Error: " + error, Toast.LENGTH_LONG).show();
            }
        }

        private String readBasic(DesfireOperations ops) throws Exception {
            StringBuilder sb = new StringBuilder();

            // UID
            byte[] uid = ops.readUid();
            sb.append("── UID ──────────────────────\n");
            sb.append(DesfireOperations.bytesToHex(uid)).append("\n\n");

            // Versión
            IDESFireEV1.VersionInfo version = ops.readVersion();
            if (version != null) {
                sb.append("── VERSIÓN ──────────────────\n");
                sb.append("HW: v").append(version.getHWMajorVersion())
                  .append(".").append(version.getHWMinorVersion()).append("\n");
                sb.append("SW: v").append(version.getSWMajorVersion())
                  .append(".").append(version.getSWMinorVersion()).append("\n\n");
            }

            // Aplicaciones
            byte[][] apps = ops.readApplicationIds();
            sb.append("── APLICACIONES (").append(apps != null ? apps.length : 0).append(") ───────\n");
            if (apps != null) {
                for (byte[] aid : apps) {
                    sb.append("  AID: ").append(DesfireOperations.bytesToHex(aid)).append("\n");
                }
            }

            return sb.toString();
        }

        private String readNdefContent(DesfireOperations ops) throws Exception {
            StringBuilder sb = new StringBuilder();
            sb.append("── CONTENIDO NDEF ───────────\n");
            String url = ops.readNdefAsString();
            sb.append(url).append("\n\n");

            sb.append("── RAW (hex, primeros 64 bytes) ─\n");
            byte[] raw = ops.readNdefFile();
            if (raw != null) {
                byte[] preview = new byte[Math.min(64, raw.length)];
                System.arraycopy(raw, 0, preview, 0, preview.length);
                sb.append(DesfireOperations.bytesToHex(preview));
                if (raw.length > 64) sb.append("...");
            }
            return sb.toString();
        }

        private String readSdm(DesfireOperations ops) throws Exception {
            DESFireEV3File.StdEV3DataFileSettings settings = ops.readSdmSettings();
            if (settings == null) {
                return "No se pudo leer la configuración SDM.\n" +
                       "(El fichero puede no existir o no estar autenticado)";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("── CONFIGURACIÓN SDM ────────\n");
            sb.append("SDM habilitado:      ").append(settings.isSDMEnabled()).append("\n");
            sb.append("UID mirroring:       ").append(settings.isUIDMirroringEnabled()).append("\n");
            sb.append("Counter SDM:         ").append(settings.isSDMReadCounterEnabled()).append("\n");
            sb.append("Counter limit:       ").append(settings.isSDMReadCounterLimitEnabled()).append("\n");
            sb.append("Cifrado SDM:         ").append(settings.isSDMEncryptFileDataEnabled()).append("\n\n");

            if (settings.isSDMEnabled()) {
                sb.append("── OFFSETS ──────────────────\n");
                sb.append("PICC Data offset:    ").append(settings.getPiccDataOffset()).append("\n");
                sb.append("MAC offset:          ").append(settings.getSdmMacOffset()).append("\n");
                sb.append("MAC input offset:    ").append(settings.getSdmMacInputOffset()).append("\n");
                if (settings.isSDMReadCounterEnabled()) {
                    sb.append("Counter offset:      ").append(settings.getSdmReadCounterOffset()).append("\n");
                }
                if (settings.isSDMEncryptFileDataEnabled()) {
                    sb.append("Enc offset:          ").append(settings.getSdmEncryptionOffset()).append("\n");
                    sb.append("Enc length:          ").append(settings.getSdmEncryptionLength()).append("\n");
                }
                if (settings.isSDMReadCounterLimitEnabled()) {
                    sb.append("Counter limit:       ").append(settings.getSdmReadCounterLimit()).append("\n");
                }
            }
            return sb.toString();
        }

        private void setButtonsEnabled(boolean enabled) {
            btnReadBasic.setEnabled(enabled);
            btnReadNdef.setEnabled(enabled);
            btnReadSdm.setEnabled(enabled);
        }
    }
}
