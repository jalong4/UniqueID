package com.google.jimlongja.uniqueid;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

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
    private static final long ONE_MINUTE_IN_MILLIS=60000;//millisecs
    private Challenge mChallenge;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        displayFeaturesAndProperties();

        // In order to use the devicepolicymanager issue the following adb command on the device:
        // adb shell dpm set-device-owner com.google.jimlongja.uniqueid/.UniqueIDAdminReceiver

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        long expiryEpoc = new Date().toInstant().toEpochMilli() + ONE_MINUTE_IN_MILLIS * 15;
        mChallenge = new Challenge(
                new Nonce("MDEyMzQ1Njc4OUFCQ0RFRg==", expiryEpoc),
                "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=");

        Log.i(TAG,"Challenge: \n" + gson.toJson(mChallenge));

        new UniqueIDAsyncTask().execute(new UniqueIDAsyncTaskParams(
                getApplicationContext(),
               false,false,
                gson.toJson(mChallenge),
                this::updateUIandLogOutput
        ));
    }

    private void displayFeaturesAndProperties() {
        Log.i(TAG, String.format("Software ID Attestation Supported: %b", hasSystemFeature(SOFTWARE_DEVICE_ID_ATTESTATION)));
        Log.i(TAG, String.format("Hardware ID Attestation Supported: %b", hasSystemFeature(HARDWARE_DEVICE_UNIQUE_ATTESTATION)));
        Log.i(TAG, String.format("Verified Boot Supported: %b", hasSystemFeature(PackageManager.FEATURE_VERIFIED_BOOT)));
        Log.i(TAG, String.format("Device Admin Supported: %b", hasSystemFeature(PackageManager.FEATURE_DEVICE_ADMIN)));
        Log.i(TAG, String.format("Device Id Attestation Supported: %b", isDeviceIdAttestationSupported()));
        Log.i(TAG," ");
        Log.i(TAG, "ro.product.brand:[" + BRAND + "]");
        Log.i(TAG, "ro.product.device:[" + DEVICE + "]");
        Log.i(TAG, "ro.build.product:[" + PRODUCT + "]");
        Log.i(TAG, "ro.product.manufacturer:[" + MANUFACTURER + "]");
        Log.i(TAG, "ro.product.model:[" + MODEL + "]");
    }

    private void updateUIandLogOutput(X509Certificate x509cert) {
        if (x509cert == null) {
            Log.e(TAG, "Failed to get x509 cert");
            return;
        }

        try {
            Attestation attestation = new Attestation(x509cert);
//            Log.i(TAG, attestation.toString());
            AuthorizationList teeEnforced = attestation.getTeeEnforced();
            Log.i(TAG, " ");
            Log.i(TAG, "TEE enforced attested brand:[" + teeEnforced.getBrand() + "]");
            Log.i(TAG, "TEE enforced attested device:[" + teeEnforced.getDevice() + "]");
            Log.i(TAG, "TEE enforced attested product:[" + teeEnforced.getProduct() + "]");
            Log.i(TAG, "TEE enforced attested manufacturer:[" + teeEnforced.getManufacturer() + "]");
            Log.i(TAG, "TEE enforced attested model:[" + teeEnforced.getModel() + "]");
            Log.i(TAG, " ");

            if (teeEnforced.getRootOfTrust() != null) {
                Log.i(TAG, "Root of Trust: ");
                Log.i(TAG, "Verified boot Key: " + BaseEncoding.base64().encode(teeEnforced.getRootOfTrust().getVerifiedBootKey()));
                Log.i(TAG, String.format("Device locked: %b", teeEnforced.getRootOfTrust().isDeviceLocked()));
                String verifiedBootState = RootOfTrust.verifiedBootStateToString(teeEnforced.getRootOfTrust().getVerifiedBootState());
                Log.i(TAG, "Verified boot state: " + verifiedBootState);
            }

            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            Challenge challenge = new Gson().fromJson(new String(attestation.getAttestationChallenge()), Challenge.class);

            Log.i(TAG, String.format("Challenge: %s", gson.toJson(challenge)));
            Log.i(TAG, String.format("Challenge is valid: %b", isValidChallenge(challenge)));

            Log.i(TAG, String.format("Challenge Length: %d", attestation.getAttestationChallenge().length));

        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
    }

    Boolean isValidChallenge(Challenge challenge) {

        boolean result = true;
        if (challenge.nonce.expirationEpoc < new Date().toInstant().toEpochMilli()) {
            Log.e(TAG, "Challenge was expired");
            result = false;
        }

        if (!mChallenge.nonce.value.equals(challenge.nonce.value)) {
            Log.e(TAG, "Invalid Nonce value returned in certificate");
            result = false;
        }

        if (!mChallenge.signiture.equals(challenge.signiture)) {
            Log.e(TAG, "Invalid Challenge signiture returned in certificate");
            result = false;
        }

        return result;
    }

    private boolean hasSystemFeature(String feature) {
        PackageManager pm = getApplication().getPackageManager();
        return pm.hasSystemFeature(feature);
    }

    private boolean isDeviceIdAttestationSupported() {
        DevicePolicyManager dpm =
                (DevicePolicyManager) getApplication().getSystemService(Context.DEVICE_POLICY_SERVICE);
        assert dpm != null;
        return dpm.isDeviceIdAttestationSupported();
    }

}
