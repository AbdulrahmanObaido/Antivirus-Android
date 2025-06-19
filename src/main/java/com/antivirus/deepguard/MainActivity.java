package com.antivirus.deepguard;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.activity.ComponentActivity;
import androidx.annotation.Nullable;
import androidx.documentfile.provider.DocumentFile;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends ComponentActivity {

    private static final int REQUEST_CODE_PICK_FOLDER = 42;
    private Button scanFilesButton, scanAppsButton, updateDbButton, liveScanButton, permissionsButton;
    private ProgressBar progressBar;
    private ListView scanResultsList;
    private ArrayAdapter<String> scanResultsAdapter;
    private ScannerEngine scanner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        scanner = new ScannerEngine(this);

        scanFilesButton = findViewById(R.id.scan_files_button);
        scanAppsButton = findViewById(R.id.scan_apps_button);
        updateDbButton = findViewById(R.id.update_db_button);
        liveScanButton = findViewById(R.id.live_scan_button);
        permissionsButton = findViewById(R.id.permissions_button);

        progressBar = findViewById(R.id.scan_progress_bar);
        scanResultsList = findViewById(R.id.scan_results_list);
        scanResultsAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, new ArrayList<>());
        scanResultsList.setAdapter(scanResultsAdapter);

        scanFilesButton.setOnClickListener(v -> openFolderPicker());
        scanAppsButton.setOnClickListener(v -> scanAllInstalledApps());
        updateDbButton.setOnClickListener(v -> updateMalwareDatabase());
        liveScanButton.setOnClickListener(v -> startLiveScan());
        permissionsButton.setOnClickListener(v -> showAppPermissions());
    }

    private void openFolderPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, REQUEST_CODE_PICK_FOLDER);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE_PICK_FOLDER && resultCode == RESULT_OK && data != null) {
            Uri treeUri = data.getData();
            if (treeUri != null) {
                getContentResolver().takePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                scanSelectedFolder(treeUri);
            } else {
                Toast.makeText(this, "No folder selected.", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void scanSelectedFolder(Uri treeUri) {
        scanResultsAdapter.clear();
        progressBar.setVisibility(ProgressBar.VISIBLE);
        progressBar.setProgress(0);

        new Thread(() -> {
            DocumentFile pickedDir = DocumentFile.fromTreeUri(this, treeUri);
            if (pickedDir == null || !pickedDir.isDirectory()) {
                runOnUiThread(() -> {
                    progressBar.setVisibility(ProgressBar.GONE);
                    Toast.makeText(this, "Invalid folder.", Toast.LENGTH_SHORT).show();
                });
                return;
            }
            DocumentFile[] files = pickedDir.listFiles();
            int scanned = 0, infected = 0, total = files.length;

            for (DocumentFile file : files) {
                if (file.isFile()) {
                    scanned++;
                    boolean threat = scanner.isFileInfected(file);
                    String result = file.getName() + (threat ? " — THREAT FOUND" : " — Clean");
                    runOnUiThread(() -> scanResultsAdapter.add(result));
                    if (threat) infected++;
                    int progress = scanned * 100 / total;
                    runOnUiThread(() -> progressBar.setProgress(progress));
                }
            }
            int finalInfected = infected;
            runOnUiThread(() -> {
                progressBar.setVisibility(ProgressBar.GONE);
                Toast.makeText(this, "Scan complete. Threats found: " + finalInfected, Toast.LENGTH_LONG).show();
            });
        }).start();
    }

    private void scanAllInstalledApps() {
        scanResultsAdapter.clear();
        progressBar.setVisibility(ProgressBar.VISIBLE);
        progressBar.setProgress(0);

        new Thread(() -> {
            PackageManager pm = getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_META_DATA);
            int scanned = 0, infected = 0, total = packages.size();

            for (PackageInfo pkg : packages) {
                ApplicationInfo appInfo = pkg.applicationInfo;
                String apkPath = appInfo.publicSourceDir;
                String label = pm.getApplicationLabel(appInfo).toString();
                if (apkPath != null) {
                    scanned++;
                    boolean threat = scanner.isApkInfected(apkPath);
                    String result = label + (threat ? " — THREAT FOUND" : " — Clean");
                    runOnUiThread(() -> scanResultsAdapter.add(result));
                    if (threat) infected++;
                    int progress = scanned * 100 / total;
                    runOnUiThread(() -> progressBar.setProgress(progress));
                }
            }
            int finalInfected = infected;
            runOnUiThread(() -> {
                progressBar.setVisibility(ProgressBar.GONE);
                Toast.makeText(this, "App scan complete. Threats found: " + finalInfected, Toast.LENGTH_LONG).show();
            });
        }).start();
    }

    private void updateMalwareDatabase() {
        ProgressDialog dialog = ProgressDialog.show(this, "", "Updating malware DB...", true);
        new Thread(() -> {
            scanner.refreshVirusSignaturesFromInternet();
            runOnUiThread(() -> {
                dialog.dismiss();
                Toast.makeText(this, "Malware DB updated!", Toast.LENGTH_SHORT).show();
            });
        }).start();
    }

    private void startLiveScan() {
        scanResultsAdapter.clear();
        progressBar.setVisibility(ProgressBar.VISIBLE);
        progressBar.setProgress(0);

        new Thread(() -> {
            scanner.refreshVirusSignaturesFromInternet();

            PackageManager pm = getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_META_DATA);
            int scanned = 0, infected = 0, total = packages.size();
            for (PackageInfo pkg : packages) {
                ApplicationInfo appInfo = pkg.applicationInfo;
                String apkPath = appInfo.publicSourceDir;
                String label = pm.getApplicationLabel(appInfo).toString();
                if (apkPath != null) {
                    scanned++;
                    boolean threat = scanner.isApkInfected(apkPath);
                    String result = "[App] " + label + (threat ? " — THREAT FOUND" : " — Clean");
                    runOnUiThread(() -> scanResultsAdapter.add(result));
                    if (threat) infected++;
                    int progress = scanned * 100 / total;
                    runOnUiThread(() -> progressBar.setProgress(progress));
                }
            }
            int finalInfected = infected;
            runOnUiThread(() -> {
                progressBar.setVisibility(ProgressBar.GONE);
                Toast.makeText(this, "Live scan complete. Threats found: " + finalInfected, Toast.LENGTH_LONG).show();
            });
        }).start();
    }

    private void showAppPermissions() {
        String permissions = "- Internet\n- Query All Packages\n- SAF Storage Access\n";
        new AlertDialog.Builder(this)
                .setTitle("App Permissions")
                .setMessage(permissions)
                .setPositiveButton("OK", null)
                .show();
    }
}
