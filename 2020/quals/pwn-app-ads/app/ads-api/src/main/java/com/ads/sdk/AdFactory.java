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

import com.ads.sdk.common.IAdControl;
import com.ads.sdk.common.IAdFactory;
import com.ads.sdk.common.dynamic.AidlUtils;
import com.ads.sdk.common.dynamic.ObjectWrapper;
import com.ads.sdk.dynamic.Loader;

import static com.ads.sdk.common.dynamic.AidlUtils.runRemote;

public class AdFactory {

    public static WebView loadAd(final IAdControl control, final Context context, final String url) {
        final IAdFactory factory = Loader.create(context).newAdFactory();
        return runRemote(new AidlUtils.RemoteThrowingFunction<WebView>() {
            @Override
            public WebView run() throws RemoteException {
                return ObjectWrapper.unwrap(factory.loadAd(control, ObjectWrapper.wrap(context), url));
            }
        });
    }
}
