package com.google.jimlongja.uniqueid;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;

public class UniqueIDAdminReceiver extends DeviceAdminReceiver {
    private static final String TAG = "UniqueIDAdminReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        switch (intent.getAction()) {
            default:
                super.onReceive(context, intent);
                break;
        }
    }
}
