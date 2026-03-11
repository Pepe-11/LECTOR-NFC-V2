package com.example.desfiresdm;

import android.os.AsyncTask;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.nxp.nfclib.desfire.DESFireEV3;

/**
 * Activity para escribir una URL en el fichero NDEF de la tarjeta.
 *
 * Flujo:
 *  1. Opcionalmente crear la app NDEF si no existe
 *  2. Escribir la URL en el fichero
 *
 * La URL puede contener placeholders de ceros para los campos SDM:
 *   - 32 ceros = campo PICC Data (UID cifrado, 16 bytes)
 *   - 16 ceros = campo MAC (8 bytes)
 *   - 6 ceros  = campo contador (3 bytes)
 */
public class WriteUrlActivity extends AppCompatActivity {

    private EditText etUrl;
    private EditText etAppKey;
    private Switch switchCreateApp;
    private Button btnWrite;
    private Button btnPreview;
    private Button btnInsertPlaceholders;
    private ProgressBar progressBar;
    private TextView tvResult;

    private NfcManager nfcManager;

    // URL de ejemplo con todos los placeholders SDM
    private static final String EXAMPLE_URL_FULL_SDM =
        "https://sdm.nfctron.com/st?p=00000000000000000000000000000000&m=0000000000000000";

    // URL de ejemplo solo con MAC (más sencillo)
    private static final String EXAMPLE_URL_MAC_ONLY =
        "https://sdm.nfctron.com/st?m=0000000000000000";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_write_url);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Escribir URL NDEF");
        }

        etUrl            = findViewById(R.id.et_url);
        etAppKey         = findViewById(R.id.et_app_key);
        switchCreateApp  = findViewById(R.id.switch_create_app);
        btnWrite         = findViewById(R.id.btn_write);
        btnPreview       = findViewById(R.id.btn_preview);
        btnInsertPlaceholders = findViewById(R.id.btn_insert_placeholders);
        progressBar      = findViewById(R.id.progress_bar);
        tvResult         = findViewById(R.id.tv_result);

        nfcManager = NfcManager.getInstance();

        // URL de ejemplo por defecto
        etUrl.setText(EXAMPLE_URL_FULL_SDM);

        btnWrite.setOnClickListener(v -> confirmAndWrite());
        btnPreview.setOnClickListener(v -> previewNdef());
        btnInsertPlaceholders.setOnClickListener(v -> showPlaceholderMenu());
    }

    private void confirmAndWrite() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) {
            Toast.makeText(this, "Introduce una URL", Toast.LENGTH_SHORT).show();
            return;
        }

        // Calcular el tamaño que ocupará
        int ndefSize = estimateNdefSize(url);
        if (ndefSize > DesfireOperations.NDEF_FILE_SIZE) {
            Toast.makeText(this,
                "URL demasiado larga (" + ndefSize + " bytes). Máximo " + DesfireOperations.NDEF_FILE_SIZE,
                Toast.LENGTH_LONG).show();
            return;
        }

        new AlertDialog.Builder(this)
            .setTitle("Confirmar escritura")
            .setMessage("URL a escribir:\n\n" + url + "\n\nTamaño estimado: " + ndefSize + " bytes\n\n" +
                        "¿Continuar?\n\n⚠️ ADVERTENCIA: Esta operación modifica la tarjeta.")
            .setPositiveButton("Escribir", (d, w) -> new WriteTask().execute(url))
            .setNegativeButton("Cancelar", null)
            .show();
    }

    private void previewNdef() {
        String url = etUrl.getText().toString().trim();
        if (url.isEmpty()) {
            tvResult.setText("Introduce una URL primero");
            return;
        }

        SdmConfig config = new SdmConfig();
        config.setBaseUrl(url);
        DesfireOperations ops = new DesfireOperations(null);
        ops.calculateSdmOffsets(url, config);

        int ndefSize = estimateNdefSize(url);

        StringBuilder sb = new StringBuilder();
        sb.append("── PREVIEW ──────────────────\n");
        sb.append("URL: ").append(url).append("\n");
        sb.append("Tamaño NDEF: ").append(ndefSize).append(" / ").append(DesfireOperations.NDEF_FILE_SIZE).append(" bytes\n\n");
        sb.append("── OFFSETS SDM CALCULADOS ───\n");
        sb.append("PICC Data offset: ").append(config.getPiccDataOffset()).append("\n");
        sb.append("MAC offset:       ").append(config.getSdmMacOffset()).append("\n");
        sb.append("Counter offset:   ").append(config.getSdmReadCounterOffset()).append("\n");

        tvResult.setText(sb.toString());
    }

    private void showPlaceholderMenu() {
        String[] options = {
            "URL completa con PICC + MAC",
            "URL solo con MAC",
            "Agregar PICC placeholder",
            "Agregar MAC placeholder",
            "Agregar Counter placeholder"
        };
        new AlertDialog.Builder(this)
            .setTitle("Insertar placeholder SDM")
            .setItems(options, (d, which) -> {
                switch (which) {
                    case 0: etUrl.setText(EXAMPLE_URL_FULL_SDM); break;
                    case 1: etUrl.setText(EXAMPLE_URL_MAC_ONLY); break;
                    case 2: insertAtCursor("00000000000000000000000000000000"); break;
                    case 3: insertAtCursor("0000000000000000"); break;
                    case 4: insertAtCursor("000000"); break;
                }
            })
            .show();
    }

    private void insertAtCursor(String text) {
        int start = Math.max(etUrl.getSelectionStart(), 0);
        int end   = Math.max(etUrl.getSelectionEnd(), 0);
        etUrl.getText().replace(Math.min(start, end), Math.max(start, end), text);
    }

    private int estimateNdefSize(String url) {
        // 2 (NLEN) + 4 (record header) + 1 (URI identifier) + url_minus_prefix
        String stripped = url;
        if (url.startsWith("https://")) stripped = url.substring(8);
        else if (url.startsWith("http://")) stripped = url.substring(7);
        return 2 + 4 + 1 + stripped.getBytes().length;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    // ── AsyncTask ─────────────────────────────────────────────────────────────

    private class WriteTask extends AsyncTask<String, Void, String> {

        private String errorMsg;

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            btnWrite.setEnabled(false);
            tvResult.setText("Escribiendo en la tarjeta...");
        }

        @Override
        protected String doInBackground(String... urls) {
            String url = urls[0];
            DESFireEV3 card = nfcManager.getCurrentCard();
            if (card == null) { errorMsg = "No hay tarjeta activa"; return null; }

            DesfireOperations ops = new DesfireOperations(card);
            try {
                // Crear aplicación NDEF si se solicitó
                if (switchCreateApp.isChecked()) {
                    ops.createNdefApp(null); // usa clave por defecto
                }

                // Escribir URL
                ops.writeNdefUrl(url);
                return "✅ URL escrita correctamente\n\n" + url;

            } catch (Exception e) {
                errorMsg = e.getMessage();
                return null;
            }
        }

        @Override
        protected void onPostExecute(String result) {
            progressBar.setVisibility(View.GONE);
            btnWrite.setEnabled(true);
            if (result != null) {
                tvResult.setText(result);
                Toast.makeText(WriteUrlActivity.this, "Escritura exitosa", Toast.LENGTH_SHORT).show();
            } else {
                tvResult.setText("❌ Error: " + errorMsg);
                Toast.makeText(WriteUrlActivity.this, "Error: " + errorMsg, Toast.LENGTH_LONG).show();
            }
        }
    }
}
