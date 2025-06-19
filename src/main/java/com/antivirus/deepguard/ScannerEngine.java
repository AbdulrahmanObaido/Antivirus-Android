package com.antivirus.deepguard;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import androidx.documentfile.provider.DocumentFile;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

public class ScannerEngine {
    private final Context context;
    private final Set<String> virusHashes = new HashSet<>();

    public ScannerEngine(Context context) {
        this.context = context;
        // Optionally, auto-fetch on init:
        new Thread(this::refreshVirusSignaturesFromInternet).start();
    }

    /**
     * Fetch the latest ClamAV SHA256 hashes from the community-maintained repository.
     */
    public Set<String> fetchVirusHashesFromInternet() {
        Set<String> result = new HashSet<>();
        try {
            URL url = new URL("https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/hash/SHA256");
            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.length() == 64) { // Only add valid SHA256 hashes
                    result.add(line.trim().toLowerCase());
                }
            }
            reader.close();
        } catch (Exception e) {
            Log.e("ScannerEngine", "Failed to update virus hashes", e);
        }
        return result;
    }

    /**
     * Replace the in-memory hash set with the latest from ClamAV.
     */
    public void refreshVirusSignaturesFromInternet() {
        Set<String> newHashes = fetchVirusHashesFromInternet();
        if (!newHashes.isEmpty()) {
            synchronized (virusHashes) {
                virusHashes.clear();
                virusHashes.addAll(newHashes);
            }
            Log.i("ScannerEngine", "Virus DB updated! Loaded: " + virusHashes.size() + " SHA256 signatures.");
        } else {
            Log.w("ScannerEngine", "No new hashes loaded!");
        }
    }

    /**
     * Scan a SAF DocumentFile for malware (by hash).
     */
    public boolean isFileInfected(DocumentFile file) {
        try {
            String hash = calculateSHA256(file.getUri());
            return virusHashes.contains(hash);
        } catch (Exception e) {
            Log.e("ScannerEngine", "File Scan error", e);
            return false;
        }
    }

    /**
     * Scan an APK file by absolute path for malware (by hash).
     */
    public boolean isApkInfected(String apkPath) {
        try (InputStream is = new FileInputStream(apkPath)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[4096];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            String hash = sb.toString();
            return virusHashes.contains(hash);
        } catch (Exception e) {
            Log.e("ScannerEngine", "APK Scan error", e);
            return false;
        }
    }

    /**
     * Calculate SHA256 hash for a file by Uri.
     */
    private String calculateSHA256(Uri fileUri) {
        try (InputStream is = context.getContentResolver().openInputStream(fileUri)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[4096];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            Log.e("ScannerEngine", "Hashing error", e);
            return "";
        }
    }
}
