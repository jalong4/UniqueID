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

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

public class MainActivity extends Activity {


    private static final String TAG = "UniqueID";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new UniqueIDAsyncTask().execute(getApplicationContext());
    }

}
