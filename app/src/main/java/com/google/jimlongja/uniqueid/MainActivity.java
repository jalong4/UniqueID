package com.google.jimlongja.uniqueid;

import android.app.Activity;

import android.app.admin.DevicePolicyManager;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.security.AttestedKeyPair;
import android.security.keymaster.KeymasterDefs;
import android.security.keystore.DeviceIdAttestationException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
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

        Certificate certificate = null;
        try {
            Log.i(TAG, "calling getAttestationCertificate");
            certificate = getAttestationCertificate();
        } catch (NoSuchProviderException e) {
            Log.e(TAG, "NoSuchProviderException");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "NoSuchAlgorithmException");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, "InvalidAlgorithmParameterException");
            e.printStackTrace();
        } catch (KeyStoreException e) {
            Log.e(TAG, "KeyStoreException");
            e.printStackTrace();
        } catch (CertificateException e) {
            Log.e(TAG, "CertificateException");
            e.printStackTrace();
        } catch (IOException e) {
            Log.e(TAG, "IOException");
            e.printStackTrace();
        }

        Log.i(TAG, String.format("Software ID Attestation Supported: %b", isDeviceIdAttestationSupported(SOFTWARE_DEVICE_ID_ATTESTATION)));
        Log.i(TAG, String.format("Hardware ID Attestation Supported: %b", isDeviceIdAttestationSupported(HARDWARE_DEVICE_UNIQUE_ATTESTATION)));
        Log.i(TAG, "ro.product.brand:[" + BRAND + "]");
        Log.i(TAG, "ro.product.device:[" + DEVICE + "]");
        Log.i(TAG, "ro.build.product:[" + PRODUCT + "]");
        Log.i(TAG, "ro.product.manufacturer:[" + MANUFACTURER + "]");
        Log.i(TAG, "ro.product.model:[" + MODEL + "]");

        attestIds();

        Log.i(TAG, certificate != null ? certificate.toString() : "Cert is null");


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

    private Certificate getAttestationCertificate() throws
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            KeyStoreException, CertificateException, IOException {

        String challenge = "test";
        Date KeyValidityStart = new Date();
        Date KeyValidyForOriginationEnd =
                new Date(KeyValidityStart.getTime() + ORIGINATION_TIME_OFFSET);
        Date KeyValidyForComsumptionnEnd =
                new Date(KeyValidityStart.getTime() + CONSUMPTION_TIME_OFFSET);

        // Create KeyPairGenerator and set generation parameters for an ECDSA key pair
        // using the NIST P-256 curve.

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN)
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

        keyPairGenerator.initialize(keyGenParameterSpec);

        // Generate the key pair. This will result in calls to both generate_key() and
        // attest_key() at the keymaster2 HAL.
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        DevicePolicyManager devicePolicyManager = (DevicePolicyManager) this.getSystemService(Context.DEVICE_POLICY_SERVICE);
        String keyAlgorithm = keyPairGenerator.getAlgorithm();
        ComponentName componentName = this.getComponentName();
        int idAttestationFlags = DevicePolicyManager.ID_TYPE_BASE_INFO;
        AttestedKeyPair keyPair =
                devicePolicyManager.generateKeyPair(
                        componentName, keyAlgorithm, keyGenParameterSpec, idAttestationFlags);

        if (keyPair == null) {
            return null;
        }

        // Get the certificate chain
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Certificate[] certificates = keyStore.getCertificateChain(KEYSTORE_ALIAS);

        // certs[0] is the attestation certificate. certs[1] signs certs[0], etc.,
        // up to certs[certs.length - 1].
        return certificates[0];

    }

    private void attestIds() {
        try {
            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_BRAND, BRAND);
            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_DEVICE, DEVICE);
            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_PRODUCT, PRODUCT);
            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_MANUFACTURER, MANUFACTURER);
            attestId(KeymasterDefs.KM_TAG_ATTESTATION_ID_MODEL, MODEL);
        } catch (DeviceIdAttestationException e) {
            e.printStackTrace();
        }
    }

//    private void testAttestedProps(KeyGenParameterSpec keySpec,
//                                   KeyPairGenerator keyPairGenerator) {
//        String algorithm = keyPairGenerator.getAlgorithm();
//        ComponentName componentName = this.getComponentName();
//        int idAttestationFlags = ID_TYPE_BASE_INFO;
//
//
//        DevicePolicyManager devicePolicyManager =
//                (DevicePolicyManager) getApplicationContext().getSystemService(
//                Context.DEVICE_POLICY_SERVICE);
//
//
//        AttestedKeyPair keyPair = devicePolicyManager.generateKeyPair(componentName, algorithm, keySpec, idAttestationFlags);
//
//    }


    private void attestId(int idType, String expectedValue) throws DeviceIdAttestationException {
        AttestationUtils.attestDeviceIds(getApplicationContext(), new int[]{idType}, expectedValue.getBytes());
    }


    public boolean isDeviceIdAttestationSupported(String feature) {
        PackageManager pm = getApplicationContext().getPackageManager();
        return pm.hasSystemFeature(feature);
    }


}
