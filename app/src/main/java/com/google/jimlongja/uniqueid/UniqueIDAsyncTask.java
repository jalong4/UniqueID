package com.google.jimlongja.uniqueid;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.security.AttestedKeyPair;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

public class UniqueIDAsyncTask extends AsyncTask<Context, Integer, Certificate> {

    public static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    private static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final int ID_TYPE_BASE_INFO = 1;
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";
    private static final String TAG = "UniqueIDAsyncTask";
    private PackageManager mPackageManager;

    @Override
    protected Certificate doInBackground(Context... contexts) {
        if (contexts.length != 1) {
            return null;
        }
        Context ctx = contexts[0];
        mPackageManager = ctx.getPackageManager();
        DevicePolicyManager devicePolicyManager =
                (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName componentName = ComponentName.createRelative(ctx, ".UniqueIDAdminReceiver");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = buildKeyGenParameterSpec();


            AttestedKeyPair keyPair = devicePolicyManager.generateKeyPair(componentName,
                    keyPairGenerator.getAlgorithm(),
                    keyGenParameterSpec,
                    DevicePolicyManager.ID_TYPE_BASE_INFO);

            List<Certificate> certificates = keyPair.getAttestationRecord();
            return certificates.get(0);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    protected void onPostExecute(Certificate certificate) {
        displayFeaturesAndProperties();


        if (certificate == null ) {
            Log.i(TAG, "Failed to get Attestation Certificate");
            return;
        }

        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) certificate;
            try {
                x509cert.checkValidity();
                Attestation assestation = new Attestation(x509cert);
                Log.i(TAG, assestation.toString());

            } catch (CertificateParsingException e) {
                e.printStackTrace();
            } catch (CertificateExpiredException e) {
                e.printStackTrace();
            } catch (CertificateNotYetValidException e) {
                e.printStackTrace();
            }
        }

    }

    private KeyGenParameterSpec buildKeyGenParameterSpec() {

        String challenge = "test";
        Date KeyValidityStart = new Date();
        Date KeyValidyForOriginationEnd =
                new Date(KeyValidityStart.getTime() + ORIGINATION_TIME_OFFSET);
        Date KeyValidyForComsumptionnEnd =
                new Date(KeyValidityStart.getTime() + CONSUMPTION_TIME_OFFSET);

        return new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)

                // Only permit the private key to be used if the user
                // authenticated within the last five minutes.
                .setUserAuthenticationRequired(false)
                // .setUserAuthenticationValidityDurationSeconds(5 * 60)

                // Request an attestation with challenge
                .setAttestationChallenge(challenge.getBytes())

                .setKeyValidityStart(KeyValidityStart)
                .setKeyValidityForOriginationEnd(KeyValidyForOriginationEnd)
                .setKeyValidityForConsumptionEnd(KeyValidyForComsumptionnEnd)

                .build();
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


    public boolean hasSystemFeature(String feature) {
        return mPackageManager.hasSystemFeature(feature);
    }
}