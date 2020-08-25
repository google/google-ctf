package com.ads.sdk.common;

import com.ads.sdk.common.IAdControl;
import com.ads.sdk.common.dynamic.IObjectWrapper;

interface IAdFactory {
    IObjectWrapper loadAd(IAdControl control, IObjectWrapper context, String url) = 0;
}
