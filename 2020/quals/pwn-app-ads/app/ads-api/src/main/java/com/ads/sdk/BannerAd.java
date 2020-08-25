// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.ads.sdk;

import android.content.Context;
import android.os.RemoteException;
import android.webkit.WebView;
import android.widget.FrameLayout;

import androidx.annotation.NonNull;

import com.ads.sdk.common.IAdControl;
import com.ads.sdk.common.Logger;

public class BannerAd extends FrameLayout {
    private final IAdControl control = new IAdControl.Stub() {
        @Override
        public void refresh(String url) throws RemoteException {
            loadAd(url);
        }
    };

    private WebView webView;

    public BannerAd(@NonNull Context context, android.util.AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public void loadAd(String url) {
        WebView newWebView = AdFactory.loadAd(control, getContext(), url);
        if (newWebView == null) {
            Logger.w("No new add to show.");
            return;
        }
        if (webView != null) {
            webView.destroy();
        }
        webView = newWebView;
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
        removeAllViews();
        addView(webView, params);
    }
}
