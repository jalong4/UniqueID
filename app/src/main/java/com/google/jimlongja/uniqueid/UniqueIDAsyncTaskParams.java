package com.google.jimlongja.uniqueid;

import android.content.Context;

public class UniqueIDAsyncTaskParams {
    public UniqueIDAsyncTaskParams(Context context, Boolean fromDevicePolicyManager) {
        this.context = context;
        this.fromDevicePolicyManager = fromDevicePolicyManager;
    }
    Context context;
    Boolean fromDevicePolicyManager;
}
