package com.example.desfiresdm;

import android.os.AsyncTask;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.nxp.nfclib.desfire.IDESFireEV3;

public class WriteUrlActivity extends AppCompatActivity {

    private EditText etUrl;
    private EditText etAppKey;
    private Button btnWrite;
    private Button btnPreview;
    private Button btnInsertPlaceholders;
    private ProgressBar progressBar;
    private TextView tvResult;

    private NfcManager nfcManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_write_url);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Escribir URL NDEF");
        }

        etUrl                 = findViewById(R.id.et_url);
        etAppKey              = findViewById(R.id.et_app_key);
        btnWrite              = findViewById(R.id.btn_write);
        btnPreview            = findViewById(R.id.btn_preview);
        btnInsertPlaceholders = findViewById(R.id.btn_insert_placeholders);
        progressBar           = findViewById(R.id.progress_bar);
        tvResult              = findViewById(R.id.tv_result);

        nfcManager = NfcManager.getInstance();
        etUrl.setText("https://soporte.gcalidad.com/st?p=00000000000000000000000000000000&m=0000000000000000");

        btnWrite.setOnClickListener(v -> confirmAndWrite());
        btnPreview.setOnClickListener(v -> previewNdef());
        btnInsertPlaceholders.setOnClickListener(v -> showPlaceholderMenu());
    }

    private void confirmAndWrite() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) { Toast.makeText(this, "Introduce una URL", Toast.LENGTH_SHORT).show(); return; }

        int size = estimateNdefSize(url);
        if (size > DesfireOperations.NDEF_FILE_SIZE) {
            Toast.makeText(this, "URL demasiado larga (" + size + " bytes)", Toast.LENGTH_LONG).show();
            return;
        }

        new AlertDialog.Builder(this)
            .setTitle("Confirmar escritura")
            .setMessage("URL:\n" + url + "\n\nTamaño: " + size + " bytes\n\n⚠️ Modifica la tarjeta. ¿Continuar?")
            .setPositiveButton("Escribir", (d, w) -> new WriteTask().execute(url))
            .setNegativeButton("Cancelar", null).show();
    }

    private void previewNdef() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) { tvResult.setText("Introduce una URL"); return; }

        SdmConfig config = new SdmConfig();
        config.setBaseUrl(url);
        new DesfireOperations().calculateSdmOffsets(url, config);

        tvResult.setText("── PREVIEW ──────────────────\n" +
            "URL: " + url + "\n" +
            "Tamaño: " + estimateNdefSize(url) + " / " + DesfireOperations.NDEF_FILE_SIZE + " bytes\n\n" +
            "── OFFSETS SDM ──────────────\n" +
            "PICC offset: " + config.getPiccDataOffset() + "\n" +
            "MAC offset:  " + config.getSdmMacOffset() + "\n" +
            "Ctr offset:  " + config.getSdmReadCounterOffset());
    }

    private void showPlaceholderMenu() {
        String[] options = {
            "URL completa (PICC + MAC)",
            "URL solo MAC",
            "PICC placeholder (32 ceros)",
            "MAC placeholder (16 ceros)",
            "Counter placeholder (6 ceros)"
        };
        new AlertDialog.Builder(this)
            .setTitle("Insertar placeholder SDM")
            .setItems(options, (d, which) -> {
                switch (which) {
                    case 0: etUrl.setText("https://soporte.gcalidad.com/st?p=00000000000000000000000000000000&m=0000000000000000"); break;
                    case 1: etUrl.setText("https://soporte.gcalidad.com/st?m=0000000000000000"); break;
                    case 2: insertAtCursor("00000000000000000000000000000000"); break;
                    case 3: insertAtCursor("0000000000000000"); break;
                    case 4: insertAtCursor("000000"); break;
                }
            }).show();
    }

    private void insertAtCursor(String text) {
        int start = Math.max(etUrl.getSelectionStart(), 0);
        int end   = Math.max(etUrl.getSelectionEnd(), 0);
        etUrl.getText().replace(Math.min(start, end), Math.max(start, end), text);
    }

    private int estimateNdefSize(String url) {
        String stripped = url.startsWith("https://") ? url.substring(8)
            : (url.startsWith("http://") ? url.substring(7) : url);
        return 2 + 4 + 1 + stripped.getBytes().length;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    private class WriteTask extends AsyncTask<String, Void, String> {
        private String errorMsg;

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            btnWrite.setEnabled(false);
            tvResult.setText("Escribiendo...");
        }

        @Override
        protected String doInBackground(String... urls) {
            String url = urls[0];
            IDESFireEV3 card = nfcManager.getCurrentCardEV3();
            if (card == null) { errorMsg = "No hay tarjeta activa"; return null; }
            DesfireOperations ops = new DesfireOperations(card);
            try {
                // writeNdefUrl detecta automáticamente si necesita crear/recrear la app
                ops.writeNdefUrl(url);
                return "✅ URL escrita\n\n" + url;
            } catch (Exception e) { errorMsg = e.getMessage(); return null; }
        }

        @Override
        protected void onPostExecute(String result) {
            progressBar.setVisibility(View.GONE);
            btnWrite.setEnabled(true);
            if (result != null) {
                tvResult.setText(result);
            } else {
                tvResult.setText("❌ " + errorMsg);
                Toast.makeText(WriteUrlActivity.this, "Error: " + errorMsg, Toast.LENGTH_LONG).show();
            }
        }
    }
}
