package com.google.jimlongja.uniqueid;

import android.content.Context;

class UniqueIDAsyncTaskParams {
    UniqueIDAsyncTaskParams(Context context, Boolean fromDevicePolicyManager,
                            String challenge,
                            UniqueIDAsyncTaskInterface callback) {
        this.context = context;
        this.fromDevicePolicyManager = fromDevicePolicyManager;
        this.challenge = challenge;
        this.callback = callback;
    }
    Context context;
    Boolean fromDevicePolicyManager;
    String challenge;
    UniqueIDAsyncTaskInterface callback;
}
