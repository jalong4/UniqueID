package com.google.jimlongja.uniqueid;

import android.app.Activity;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.security.AttestedKeyPair;
//import android.security.keymaster.KeymasterDefs;
//import android.security.keystore.DeviceIdAttestationException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

public class MainActivity extends Activity {

    public static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";
    private static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final int ID_TYPE_BASE_INFO = 1;

    private static final String TAG = "UniqueID";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        displayFeaturesAndProperties();
        Certificate certificate = getAttestationCertificate();

        if (certificate == null ) {
            Log.i(TAG, "Failed to get Attestation Certificate, exitting...");
            return;
        }

        Log.i(TAG, certificate != null ? "\n" + certificate.toString() : "Cert is null");

        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) certificate;
            Log.i(TAG, "Certificate principal " + x509cert.getSubjectX500Principal().getName());
            Log.i(TAG, "Certificate is valid not before " + x509cert.getNotBefore());
            Log.i(TAG, "Certificate is valid not after " + x509cert.getNotAfter());
            try {
                x509cert.checkValidity();
                Log.i(TAG, "Certificate is valid");
            } catch (Exception e) {
                Log.i(TAG, "Certificate is not valid: " + e);
            }

            try {
                Attestation attestation = new Attestation(x509cert);
                Log.i(TAG, attestation.toString());
            } catch (CertificateParsingException e) {
                Log.e(TAG, "CertificateParsingException");
                e.printStackTrace();
            }
        }

        Log.i(TAG, "done");
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

    private Certificate getAttestationCertificate() {

        // Create KeyPairGenerator and set generation parameters for an ECDSA key pair
        // using the NIST P-256 curve.


        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = buildKeyGenParameterSpec();
            keyPairGenerator.initialize(keyGenParameterSpec);

            // Generate the key pair. This will result in calls to both generate_key() and
            // attest_key() at the keymaster2 HAL.
            keyPairGenerator.generateKeyPair();

//            AttestedKeyPair keyPair1 = generateAttestedKeyPair(keyPairGenerator.getAlgorithm(),
//                    keyGenParameterSpec);

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);


            Certificate[] certificates = keyStore.getCertificateChain(KEYSTORE_ALIAS);
            return certificates[0];

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;

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

    private AttestedKeyPair generateAttestedKeyPair(@NonNull String keyAlgorithm,
                                                    @NonNull KeyGenParameterSpec keySpec) {

        DevicePolicyManager devicePolicyManager =
                (DevicePolicyManager) this.getSystemService(Context.DEVICE_POLICY_SERVICE);

        ComponentName componentName =
                ComponentName.createRelative(this, ".UniqueIDAdminReceiver");

        return devicePolicyManager.generateKeyPair(componentName, keyAlgorithm, keySpec,
                DevicePolicyManager.ID_TYPE_BASE_INFO);
    }

//    private void attestIds() {
//        try {
//            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_BRAND, BRAND);
//            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_DEVICE, DEVICE);
//            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_PRODUCT, PRODUCT);
//            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_MANUFACTURER, MANUFACTURER);
//            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_MODEL, MODEL);
//        } catch (DeviceIdAttestationException e) {
//            e.printStackTrace();
//        }
//    }

//    private void attestId(int idType, String expectedValue) throws DeviceIdAttestationException {
//        AttestationUtils.attestDeviceIds(getApplicationContext(), new int[]{idType}, expectedValue.getBytes());
//    }

    public boolean hasSystemFeature(String feature) {
        PackageManager pm = getApplicationContext().getPackageManager();
        return pm.hasSystemFeature(feature);
    }

}
