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
import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.CalendarContract;
import android.util.Log;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.ads.sdk.common.Logger;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static com.ads.sdk.common.dynamic.AidlUtils.runRemote;

public class AdWebViewClient extends WebViewClient {
    private static final Map<String, JsMessageHandler> HANDLERS = new HashMap<>();

    static {
        HANDLERS.put("log", (view, request) -> {
            Logger.i("JS: " + request.getUrl().getQueryParameter("msg"));
            return true;
        });
        HANDLERS.put("refresh", (view, request) ->
                runRemote(() -> {
                    view.getControl().refresh(request.getUrl().getQueryParameter("url"));
                    return true;
                })
        );
        HANDLERS.put("init.mraid", (view, request) ->
                runRemote(() -> {
                    evalJs(view, "MRAID_CALLBACK('init', '2.0')");
                    return true;
                })
        );
        HANDLERS.put("resize.mraid", (view, request) ->
                runRemote(() -> {
                    Logger.i("MRAID: RESIZE is not supported");
                    return true;
                })
        );
        HANDLERS.put("create-calendar-event.mraid", (view, request) ->
                runRemote(() -> {
                    String title = request.getUrl().getQueryParameter("title");
                    String description = request.getUrl().getQueryParameter("desc");
                    String location = request.getUrl().getQueryParameter("loc");
                    long startMillis = Long.parseLong(request.getUrl().getQueryParameter("start"));
                    long endMillis = Long.parseLong(request.getUrl().getQueryParameter("end"));
                    Intent intent = new Intent(Intent.ACTION_INSERT)
                            .setData(CalendarContract.Events.CONTENT_URI)
                            .putExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, startMillis)
                            .putExtra(CalendarContract.EXTRA_EVENT_END_TIME, endMillis)
                            .putExtra(CalendarContract.Events.TITLE, title)
                            .putExtra(CalendarContract.Events.DESCRIPTION, description)
                            .putExtra(CalendarContract.Events.EVENT_LOCATION, location);
                    view.getContext().startActivity(intent);
                    evalJs(view, "MRAID_CALLBACK('create-calendar-event', true)");
                    return true;
                })
        );
        HANDLERS.put("play-video.mraid", (view, request) ->
                runRemote(() -> {
                    Intent intent = new Intent(Intent.ACTION_VIEW);
                    String videoUri = request.getUrl().getQueryParameter("uri");
                    intent.setDataAndType(Uri.parse(videoUri), "video/mp4");
                    view.getContext().startActivity(intent);
                    evalJs(view, "MRAID_CALLBACK('play-video', true)");
                    return true;
                })
        );
        HANDLERS.put("store-picture.mraid", (view, request) -> {
            new Thread(() -> {
                Context context = view.getContext();
                Uri pictureUri = Uri.parse(request.getUrl().getQueryParameter("url"));
                File mraidPath = new File(view.getContext().getExternalMediaDirs()[0], "mraid");
                String fileName = request.getUrl().getQueryParameter("name");
                mraidPath.mkdirs();
                File picturePath = new File(mraidPath, fileName);
                Logger.e("MRAID: storing picture");
                try {
                    FileUtils.copyURLToFile(new URL(pictureUri.toString()), picturePath);
                    evalJs(view, "MRAID_CALLBACK('store-picture', true)");
                } catch (IOException e) {
                    Logger.e("MRAID: unable to store picture", e);
                    evalJs(view, "MRAID_CALLBACK('store-picture', false)");
                }
            }).start();
            return true;
        });
        HANDLERS.put("supports.mraid", (view, request) -> {
            evalJs(view, "MRAID_CALLBACK('supports', {tel: true, sms: true, calendar: true, storePicture: true, inlineVideo: false}))");
            return true;
        });
    }

    private static Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());

    private static void evalJs(AdWebView adWebView, String js) {
        MAIN_HANDLER.post(() -> adWebView.evaluateJavascript(js, null));
    }

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        if (request.getUrl().getScheme().equals("ads")) {
            JsMessageHandler handler = HANDLERS.get(request.getUrl().getHost());
            if (handler != null) {
                return handler.handleMessage((AdWebView) view, request);
            }
        }
        return super.shouldOverrideUrlLoading(view, request);
    }
}
