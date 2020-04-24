package com.google.jimlongja.uniqueid;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;

import com.google.common.io.BaseEncoding;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

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

        // In order to use the devicepolicymanager issue the following adb command on the device:
        // adb shell dpm set-device-owner com.google.jimlongja.uniqueid/.UniqueIDAdminReceiver

        String challenge = "1JgY5jUTKIfCpK2IEdPVuBDE0ziqjQ8NPu3VLxscxCAhcjbCdcWn5H4VNi31po8U1JgY5jUTKIfCpK2IEdPVuBDE0ziqjQ8NPu3VLxscxCAhcjbCdcWn5H4VNi31po8U";

        new UniqueIDAsyncTask().execute(new UniqueIDAsyncTaskParams(
                getApplicationContext(),
               false,
                challenge,
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

            Log.i(TAG, String.format("Challenge: %s", new String(attestation.getAttestationChallenge())));
            Log.i(TAG, String.format("Challenge Length: %d", attestation.getAttestationChallenge().length));

        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
    }

    private boolean hasSystemFeature(String feature) {
        PackageManager pm = getApplication().getPackageManager();
        return pm.hasSystemFeature(feature);
    }

    private boolean isDeviceIdAttestationSupported() {
        DevicePolicyManager dpm =
                (DevicePolicyManager) getApplication().getSystemService(Context.DEVICE_POLICY_SERVICE);
        return dpm.isDeviceIdAttestationSupported();
    }

}
