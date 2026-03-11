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

import com.nxp.nfclib.desfire.DESFireEV3File;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV3;

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

        tvResult     = findViewById(R.id.tv_result);
        progressBar  = findViewById(R.id.progress_bar);
        btnReadBasic = findViewById(R.id.btn_read_basic);
        btnReadNdef  = findViewById(R.id.btn_read_ndef);
        btnReadSdm   = findViewById(R.id.btn_read_sdm);

        nfcManager = NfcManager.getInstance();

        btnReadBasic.setOnClickListener(v -> new CardReadTask(1).execute());
        btnReadNdef.setOnClickListener(v -> new CardReadTask(2).execute());
        btnReadSdm.setOnClickListener(v -> new CardReadTask(3).execute());
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    private class CardReadTask extends AsyncTask<Void, Void, String> {
        private final int mode;
        private String error;

        CardReadTask(int mode) { this.mode = mode; }

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            tvResult.setText("Leyendo...");
            setButtonsEnabled(false);
        }

        @Override
        protected String doInBackground(Void... voids) {
            IDESFireEV3 card = nfcManager.getCurrentCardEV3();
            if (card == null) { error = "No hay tarjeta activa"; return null; }
            DesfireOperations ops = new DesfireOperations(card);
            try {
                switch (mode) {
                    case 1: return readBasic(ops);
                    case 2: return readNdef(ops);
                    case 3: return readSdm(ops);
                }
            } catch (Exception e) { error = e.getMessage(); }
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

            IDESFireEV1.CardDetails details = ops.readCardDetails();
            sb.append("── INFO TARJETA ─────────────\n");
            if (details != null) {
                sb.append("Nombre:      ").append(details.cardName).append("\n");
                sb.append("Versión HW:  ").append(details.majorVersion).append(".").append(details.minorVersion).append("\n");
                sb.append("Memoria:     ").append(details.freeMemory).append(" / ").append(details.totalMemory).append(" bytes\n");
                sb.append("Vendor ID:   ").append(DesfireOperations.bytesToHex(new byte[]{details.vendorID})).append("\n");
            }

            byte[][] apps = ops.readApplicationIds();
            sb.append("\n── APLICACIONES (").append(apps != null ? apps.length : 0).append(") ───────\n");
            if (apps != null) {
                for (byte[] aid : apps) {
                    sb.append("  AID: ").append(DesfireOperations.bytesToHex(aid)).append("\n");
                }
            }
            return sb.toString();
        }

        private String readNdef(DesfireOperations ops) throws Exception {
            StringBuilder sb = new StringBuilder();
            sb.append("── CONTENIDO NDEF ───────────\n");
            sb.append(ops.readNdefAsString()).append("\n\n");

            byte[] raw = ops.readNdefFile();
            sb.append("── RAW (primeros 64 bytes) ──\n");
            if (raw != null) {
                byte[] preview = new byte[Math.min(64, raw.length)];
                System.arraycopy(raw, 0, preview, 0, preview.length);
                sb.append(DesfireOperations.bytesToHex(preview));
                if (raw.length > 64) sb.append("...");
            }
            return sb.toString();
        }

        private String readSdm(DesfireOperations ops) throws Exception {
            DESFireEV3File.StdEV3DataFileSettings s = ops.readSdmSettings();
            if (s == null) return "No se pudo leer configuración SDM";

            StringBuilder sb = new StringBuilder();
            sb.append("── CONFIGURACIÓN SDM ────────\n");
            sb.append("SDM habilitado:  ").append(s.isSDMEnabled()).append("\n");
            sb.append("UID mirroring:   ").append(s.isUIDMirroringEnabled()).append("\n");
            sb.append("Counter SDM:     ").append(s.isSDMReadCounterEnabled()).append("\n");
            sb.append("Counter limit:   ").append(s.isSDMReadCounterLimitEnabled()).append("\n");
            sb.append("Cifrado SDM:     ").append(s.isSDMEncryptFileDataEnabled()).append("\n\n");

            if (s.isSDMEnabled()) {
                sb.append("── OFFSETS ──────────────────\n");
                sb.append("PICC offset:     ").append(DesfireOperations.bytesToHex(s.getPiccDataOffset())).append("\n");
                sb.append("MAC offset:      ").append(DesfireOperations.bytesToHex(s.getSdmMacOffset())).append("\n");
                if (s.isSDMReadCounterEnabled())
                    sb.append("Counter offset:  ").append(DesfireOperations.bytesToHex(s.getSdmReadCounterOffset())).append("\n");
                if (s.isSDMEncryptFileDataEnabled()) {
                    sb.append("Enc offset:      ").append(DesfireOperations.bytesToHex(s.getSdmEncryptionOffset())).append("\n");
                    sb.append("Enc length:      ").append(DesfireOperations.bytesToHex(s.getSdmEncryptionLength())).append("\n");
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
