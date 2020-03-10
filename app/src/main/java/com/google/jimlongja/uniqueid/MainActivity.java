package com.google.jimlongja.uniqueid;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
//import android.security.keymaster.KeymasterDefs;
//import android.security.keystore.DeviceIdAttestationException;
import android.util.Log;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

public class MainActivity extends Activity {

    public static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    private static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final String TAG = "UniqueID";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        displayFeaturesAndProperties();

        UniqueIDAsyncTask asyncTask = new UniqueIDAsyncTask();
        asyncTask.execute(getApplicationContext());

    }

    private void displayFeaturesAndProperties() {
        Log.i(TAG, String.format("Software ID Attestation Supported: %b", hasSystemFeature(SOFTWARE_DEVICE_ID_ATTESTATION)));
        Log.i(TAG, String.format("Hardware ID Attestation Supported: %b", hasSystemFeature(HARDWARE_DEVICE_UNIQUE_ATTESTATION)));
        Log.i(TAG, String.format("Verified Boot Supported: %b", hasSystemFeature(PackageManager.FEATURE_VERIFIED_BOOT)));
        Log.i(TAG, String.format("Device Admin Supported: %b", hasSystemFeature(PackageManager.FEATURE_DEVICE_ADMIN)));
        Log.i(TAG, "ro.product.brand:[" + BRAND + "]");
        Log.i(TAG, "ro.product.device:[" + DEVICE + "]");
        Log.i(TAG, "ro.build.product:[" + PRODUCT + "]");
        Log.i(TAG, "ro.product.manufacturer:[" + MANUFACTURER + "]");
        Log.i(TAG, "ro.product.model:[" + MODEL + "]");
    }

    private boolean hasSystemFeature(String feature) {
        PackageManager pm = getApplication().getPackageManager();
        return pm.hasSystemFeature(feature);
    }

}
