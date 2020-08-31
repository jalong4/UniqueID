package com.google.jimlongja.uniqueid;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.AsyncTask;
import android.security.AttestedKeyPair;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class UniqueIDAsyncTask extends AsyncTask<UniqueIDAsyncTaskParams, Integer, X509Certificate> {

    private static final int ID_TYPE_BASE_INFO = 1;
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";
    private static final String TAG = "UniqueIDAsyncTask";
    private UniqueIDAsyncTaskInterface mCallback;

    @Override
    protected X509Certificate doInBackground(UniqueIDAsyncTaskParams... params) {
        if (params.length != 1) {
            return null;
        }
        Context context = params[0].context;
        Boolean fromDevicePolicyManager = false;
        mCallback = params[0].callback;
        String challenge = params[0].challenge;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = buildKeyGenParameterSpec(challenge);

            Log.i(TAG, "Generating keypair using: " +
                    (fromDevicePolicyManager ? "Device Policy Manager" : "KeyStore"));

            List<Certificate> certificates = getCertificateChainFromKeyStore(keyPairGenerator, keyGenParameterSpec);


            if (certificates == null || certificates.get(0) == null) {
                return null;
            }
            Certificate certificate = certificates.get(0);
            if (!(certificate instanceof X509Certificate)) {
                return null;
            }

            X509Certificate x509cert = (X509Certificate) certificate;
            x509cert.checkValidity();
            return x509cert;

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyStoreException |
                IOException | NoSuchProviderException | CertificateException  |
                InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

//    private List<Certificate> getCertificateChainFromDevicePolicyManager(
//            Context context,
//            KeyPairGenerator keyPairGenerator,
//            KeyGenParameterSpec keyGenParameterSpec) {
//
//        DevicePolicyManager devicePolicyManager =
//                (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
//        ComponentName componentName = ComponentName.createRelative(context, ".UniqueIDAdminReceiver");
//
//        AttestedKeyPair keyPair = devicePolicyManager.generateKeyPair(componentName,
//                keyPairGenerator.getAlgorithm(),
//                keyGenParameterSpec,
//                DevicePolicyManager.ID_TYPE_BASE_INFO);
//
//        return keyPair == null ? null : keyPair.getAttestationRecord();
//    }

    private List<Certificate> getCertificateChainFromKeyStore(
            KeyPairGenerator keyPairGenerator,
            KeyGenParameterSpec keyGenParameterSpec) throws InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException {

        keyPairGenerator.initialize(keyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.initSign(keyPair.getPrivate());

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return Arrays.asList(keyStore.getCertificateChain(KEYSTORE_ALIAS));
    }

    protected void onPostExecute(X509Certificate x509cert) {
        mCallback.onComplete(x509cert);
    }

    private KeyGenParameterSpec buildKeyGenParameterSpec(String challenge) {

        Date KeyValidityStart = new Date();
        Date KeyValidyForOriginationEnd =
                new Date(KeyValidityStart.getTime() + ORIGINATION_TIME_OFFSET);
        Date KeyValidyForComsumptionnEnd =
                new Date(KeyValidityStart.getTime() + CONSUMPTION_TIME_OFFSET);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN)
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

//                .setDevicePropertiesAttestationIncluded(true)

                .setKeyValidityStart(KeyValidityStart)
                .setKeyValidityForOriginationEnd(KeyValidyForOriginationEnd)
                .setKeyValidityForConsumptionEnd(KeyValidyForComsumptionnEnd);

        // Use reflection until new API signitures get update in the Android SDK
        // Print exception and continue if method is not present
        // setDevicePropertiesAttestationIncluded to true if it is supported
        try {
            ReflectionUtil.invoke(builder, "setDevicePropertiesAttestationIncluded", new Class<?>[]{boolean.class}, true);
            Log.i(TAG, "setDevicePropertiesAttestationIncluded:  true");
        } catch (ReflectionUtil.ReflectionIsTemporaryException e) {
            Log.i(TAG, "setDevicePropertiesAttestationIncluded:  Not supported");
        }

        return builder.build();


    }
}
