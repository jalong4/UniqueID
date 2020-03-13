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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
import java.util.Objects;
import java.util.concurrent.ExecutionException;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

public class UniqueIDAsyncTask extends AsyncTask<UniqueIDAsyncTaskParams, Integer, X509Certificate> {

    private static final int ID_TYPE_BASE_INFO = 1;
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";
    private static final String TAG = "UniqueIDAsyncTask";

    @Override
    protected X509Certificate doInBackground(UniqueIDAsyncTaskParams... params) {
        if (params.length != 1) {
            return null;
        }
        Context context = params[0].context;
        Boolean fromDevicePolicyManager = params[0].fromDevicePolicyManager;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = buildKeyGenParameterSpec();

            String from = fromDevicePolicyManager ? "Device Policy Manager" : "KeyStore";
            Log.i(TAG, "Generating keypair using: " + from);

            List<Certificate> certificates = fromDevicePolicyManager ?
                    getCertificateChainFromDevicePolicyManager(context, keyPairGenerator, keyGenParameterSpec) :
                    getCertificateChainFromKeyStore(keyPairGenerator, keyGenParameterSpec);


            if (certificates.get(0) == null) {
                return null;
            }
            Certificate certificate = certificates.get(0);
            if (!(certificate instanceof X509Certificate)) {
                return null;
            }

            X509Certificate x509cert = (X509Certificate) certificate;
            x509cert.checkValidity();
            return x509cert;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }

    private List<Certificate> getCertificateChainFromDevicePolicyManager(
            Context context,
            KeyPairGenerator keyPairGenerator,
            KeyGenParameterSpec keyGenParameterSpec) {

        DevicePolicyManager devicePolicyManager =
                (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName componentName = ComponentName.createRelative(context, ".UniqueIDAdminReceiver");

        AttestedKeyPair keyPair = devicePolicyManager.generateKeyPair(componentName,
                keyPairGenerator.getAlgorithm(),
                keyGenParameterSpec,
                DevicePolicyManager.ID_TYPE_BASE_INFO);

        return keyPair.getAttestationRecord();
    }

    private List<Certificate> getCertificateChainFromKeyStore(
            KeyPairGenerator keyPairGenerator,
            KeyGenParameterSpec keyGenParameterSpec) throws InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        keyPairGenerator.initialize(keyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        List<Certificate> certificates = Arrays.asList(keyStore.getCertificateChain(KEYSTORE_ALIAS));
        return certificates;
    }

    protected void onPostExecute(X509Certificate x509cert) {

        if (x509cert == null) {
            Log.e(TAG, "Failed to get x509 cert");
            return;
        }

        try {
            Attestation attestation = new Attestation(x509cert);
//            Log.i(TAG, attestation.toString());
            AuthorizationList teeEnforced = attestation.getTeeEnforced();
            Log.i(TAG," ");
            Log.i(TAG, "TEE enforced attested brand:[" + teeEnforced.getBrand() + "]");
            Log.i(TAG, "TEE enforced attested device:[" + teeEnforced.getDevice() + "]");
            Log.i(TAG, "TEE enforced attested product:[" + teeEnforced.getProduct() + "]");
            Log.i(TAG, "TEE enforced attested manufacturer:[" + teeEnforced.getManufacturer() + "]");
            Log.i(TAG, "TEE enforced attested model:[" + teeEnforced.getModel() + "]");
            Log.i(TAG," ");
            Log.i(TAG,"Root of Trust: ");
            Log.i(TAG,"Verified boot Key: " + BaseEncoding.base64().encode(teeEnforced.getRootOfTrust().getVerifiedBootKey()));
            Log.i(TAG,String.format("Device locked: %b", teeEnforced.getRootOfTrust().isDeviceLocked()));
            String verifiedBootState = teeEnforced.getRootOfTrust().verifiedBootStateToString(teeEnforced.getRootOfTrust().getVerifiedBootState());
            Log.i(TAG,"Verified boot state: " + verifiedBootState);
            Log.i(TAG,String.format("Challenge: %s", new String(attestation.getAttestationChallenge())));
            Log.i(TAG,String.format("Challenge Length: %d", attestation.getAttestationChallenge().length));

        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
    }

    private KeyGenParameterSpec buildKeyGenParameterSpec() {

        String challenge = "1JgY5jUTKIfCpK2IEdPVuBDE0ziqjQ8NPu3VLxscxCAhcjbCdcWn5H4VNi31po8U1JgY5jUTKIfCpK2IEdPVuBDE0ziqjQ8NPu3VLxscxCAhcjbCdcWn5H4VNi31po8U";
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
}