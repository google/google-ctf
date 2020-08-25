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

package com.ads.sdk.impl.webview;

import android.content.Context;
import android.webkit.WebView;

import com.ads.sdk.common.IAdControl;

public class AdWebView extends WebView {
    private final IAdControl control;

    public AdWebView(Context context, IAdControl control) {
        super(context);
        this.control = control;
        setWebViewClient(new AdWebViewClient());
        getSettings().setAllowContentAccess(false);
        getSettings().setAllowFileAccess(false);
        getSettings().setJavaScriptEnabled(true);
    }

    public IAdControl getControl() {
        return control;
    }
}
