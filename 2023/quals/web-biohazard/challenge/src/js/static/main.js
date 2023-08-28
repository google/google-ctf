(()=>{var e="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof self?self:"undefined"!=typeof window?window:"undefined"!=typeof global?global:{},t={},r={},o=e.parcelRequire8812;null==o&&((o=function(e){if(e in t)return t[e].exports;if(e in r){var o=r[e];delete r[e];var n={id:e,exports:{}};return t[e]=n,o.call(n.exports,n,n.exports),n.exports}var i=new Error("Cannot find module '"+e+"'");throw i.code="MODULE_NOT_FOUND",i}).register=function(e,t){r[e]=t},e.parcelRequire8812=o),o.register("jUBUQ",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setHref=void 0;var r=o("2ENVC");e.exports.setHref=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&(e.href=o)}})),o.register("2ENVC",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */function r(e){var t;try{t=new URL(e)}catch(e){return"https:"}return t.protocol}Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.restrictivelySanitizeUrl=e.exports.unwrapUrlOrSanitize=e.exports.sanitizeJavascriptUrl=e.exports.extractScheme=void 0,e.exports.extractScheme=r;var o=["data:","http:","https:","mailto:","ftp:"];function n(e){if("javascript:"!==r(e))return e}e.exports.sanitizeJavascriptUrl=n,e.exports.unwrapUrlOrSanitize=function(e){return n(e)},e.exports.restrictivelySanitizeUrl=function(e){var t=r(e);return void 0!==t&&-1!==o.indexOf(t.toLowerCase())?e:"about:invalid#zClosurez"}})),o.register("efUhS",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setHref=void 0;var r=o("2ENVC");e.exports.setHref=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&(e.href=o)}})),o.register("14NpD",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setHref=void 0;var r=o("jiQFf");e.exports.setHref=function(e,t){e.href=(0,r.unwrapResourceUrl)(t)}})),o.register("jiQFf",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.unwrapResourceUrl=e.exports.isResourceUrl=e.exports.createResourceUrl=e.exports.TrustedResourceUrl=void 0;var r=o("6cacD"),n=o("klfJc"),i=function(){function e(e,t){(0,r.ensureTokenIsValid)(t),this.privateDoNotAccessOrElseWrappedResourceUrl=e}return e.prototype.toString=function(){return this.privateDoNotAccessOrElseWrappedResourceUrl.toString()},e}(),s=(window,window.TrustedScriptURL);e.exports.TrustedResourceUrl=null!=s?s:i,e.exports.createResourceUrl=function(e){var t,o=e,s=null===(t=(0,n.getTrustedTypesPolicy)())||void 0===t?void 0:t.createScriptURL(o);return null!=s?s:new i(o,r.secretToken)},e.exports.isResourceUrl=function(e){var t;return(null===(t=(0,n.getTrustedTypes)())||void 0===t?void 0:t.isScriptURL(e))||e instanceof i},e.exports.unwrapResourceUrl=function(e){var t;if(null===(t=(0,n.getTrustedTypes)())||void 0===t?void 0:t.isScriptURL(e))return e;if(e instanceof i)return e.privateDoNotAccessOrElseWrappedResourceUrl;throw new Error("")}})),o.register("6cacD",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.ensureTokenIsValid=e.exports.secretToken=void 0,e.exports.secretToken={},e.exports.ensureTokenIsValid=function(e){}})),o.register("klfJc",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.TEST_ONLY=e.exports.getTrustedTypesPolicy=e.exports.getTrustedTypes=void 0;var r,o="google#safe";function n(){var e;return""!==o&&null!==(e=function(){if("undefined"!=typeof window)return window.trustedTypes}())&&void 0!==e?e:null}e.exports.getTrustedTypes=n,e.exports.getTrustedTypesPolicy=function(){var e,t;if(void 0===r)try{r=null!==(t=null===(e=n())||void 0===e?void 0:e.createPolicy(o,{createHTML:function(e){return e},createScript:function(e){return e},createScriptURL:function(e){return e}}))&&void 0!==t?t:null}catch(e){r=null}return r},e.exports.TEST_ONLY={resetDefaults:function(){r=void 0,o="google#safe"},setTrustedTypesPolicyName:function(e){o=e}}})),o.register("3E1T5",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setFormaction=void 0;var r=o("2ENVC");e.exports.setFormaction=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&(e.formAction=o)}})),o.register("5U7de",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */var r=e.exports&&e.exports.__read||function(e,t){var r="function"==typeof Symbol&&e[Symbol.iterator];if(!r)return e;var o,n,i=r.call(e),s=[];try{for(;(void 0===t||t-- >0)&&!(o=i.next()).done;)s.push(o.value)}catch(e){n={error:e}}finally{try{o&&!o.done&&(r=i.return)&&r.call(i)}finally{if(n)throw n.error}}return s},n=e.exports&&e.exports.__spreadArray||function(e,t,r){if(r||2===arguments.length)for(var o,n=0,i=t.length;n<i;n++)!o&&n in t||(o||(o=Array.prototype.slice.call(t,0,n)),o[n]=t[n]);return e.concat(o||Array.prototype.slice.call(t))};Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setPrefixedAttribute=e.exports.buildPrefixedAttributeSetter=e.exports.insertAdjacentHtml=e.exports.setCssText=e.exports.setOuterHtml=e.exports.setInnerHtml=void 0;var i=o("brAVA"),s=o("jgpFH"),c=o("eMnpN");function a(e,t,r,o){if(0===e.length){throw new Error("")}var n=e.map((function(e){return(0,i.unwrapAttributePrefix)(e)})),s=r.toLowerCase();if(n.every((function(e){return 0!==s.indexOf(e)})))throw new Error('Attribute "'.concat(r,'" does not match any of the allowed prefixes.'));t.setAttribute(r,o)}function u(e){if("script"===e.tagName.toLowerCase())throw new Error("");if("style"===e.tagName.toLowerCase())throw new Error("")}e.exports.setInnerHtml=function(e,t){(function(e){return void 0!==e.tagName})(e)&&u(e),e.innerHTML=(0,s.unwrapHtml)(t)},e.exports.setOuterHtml=function(e,t){var r=e.parentElement;null!==r&&u(r),e.outerHTML=(0,s.unwrapHtml)(t)},e.exports.setCssText=function(e,t){e.style.cssText=(0,c.unwrapStyle)(t)},e.exports.insertAdjacentHtml=function(e,t,r){var o="beforebegin"===t||"afterend"===t?e.parentElement:e;null!==o&&u(o),e.insertAdjacentHTML(t,(0,s.unwrapHtml)(r))},e.exports.buildPrefixedAttributeSetter=function(e){for(var t=[],o=1;o<arguments.length;o++)t[o-1]=arguments[o];var i=n([e],r(t),!1);return function(e,t,r){a(i,e,t,r)}},e.exports.setPrefixedAttribute=a})),o.register("brAVA",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */var r,n=e.exports&&e.exports.__extends||(r=function(e,t){return r=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var r in t)Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r])},r(e,t)},function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Class extends value "+String(t)+" is not a constructor or null");function o(){this.constructor=e}r(e,t),e.prototype=null===t?Object.create(t):(o.prototype=t.prototype,new o)});Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.unwrapAttributePrefix=e.exports.createAttributePrefix=e.exports.SafeAttributePrefix=void 0;var i=o("6cacD"),s=function(){};e.exports.SafeAttributePrefix=s;var c=function(e){function t(t,r){var o=e.call(this)||this;return(0,i.ensureTokenIsValid)(r),o.privateDoNotAccessOrElseWrappedAttrPrefix=t,o}return n(t,e),t.prototype.toString=function(){return this.privateDoNotAccessOrElseWrappedAttrPrefix},t}(s);e.exports.createAttributePrefix=function(e){return new c(e,i.secretToken)},e.exports.unwrapAttributePrefix=function(e){if(e instanceof c)return e.privateDoNotAccessOrElseWrappedAttrPrefix;throw new Error("")}})),o.register("jgpFH",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.unwrapHtml=e.exports.isHtml=e.exports.EMPTY_HTML=e.exports.createHtml=e.exports.SafeHtml=void 0;var r=o("6cacD"),n=o("klfJc"),i=function(){function e(e,t){(0,r.ensureTokenIsValid)(t),this.privateDoNotAccessOrElseWrappedHtml=e}return e.prototype.toString=function(){return this.privateDoNotAccessOrElseWrappedHtml.toString()},e}();function s(e,t){return null!=t?t:new i(e,r.secretToken)}var c=(window,window.TrustedHTML);e.exports.SafeHtml=null!=c?c:i,e.exports.createHtml=function(e){var t,r=e;return s(r,null===(t=(0,n.getTrustedTypesPolicy)())||void 0===t?void 0:t.createHTML(r))},e.exports.EMPTY_HTML=function(){var e;return s("",null===(e=(0,n.getTrustedTypes)())||void 0===e?void 0:e.emptyHTML)}(),e.exports.isHtml=function(e){var t;return(null===(t=(0,n.getTrustedTypes)())||void 0===t?void 0:t.isHTML(e))||e instanceof i},e.exports.unwrapHtml=function(e){var t;if(null===(t=(0,n.getTrustedTypes)())||void 0===t?void 0:t.isHTML(e))return e;if(e instanceof i)return e.privateDoNotAccessOrElseWrappedHtml;throw new Error("")}})),o.register("eMnpN",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */var r,n=e.exports&&e.exports.__extends||(r=function(e,t){return r=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var r in t)Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r])},r(e,t)},function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Class extends value "+String(t)+" is not a constructor or null");function o(){this.constructor=e}r(e,t),e.prototype=null===t?Object.create(t):(o.prototype=t.prototype,new o)});Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.unwrapStyle=e.exports.isStyle=e.exports.createStyle=e.exports.SafeStyle=void 0;var i=o("6cacD"),s=function(){};e.exports.SafeStyle=s;var c=function(e){function t(t,r){var o=e.call(this)||this;return(0,i.ensureTokenIsValid)(r),o.privateDoNotAccessOrElseWrappedStyle=t,o}return n(t,e),t.prototype.toString=function(){return this.privateDoNotAccessOrElseWrappedStyle},t}(s);e.exports.createStyle=function(e){return new c(e,i.secretToken)},e.exports.isStyle=function(e){return e instanceof c},e.exports.unwrapStyle=function(e){if(e instanceof c)return e.privateDoNotAccessOrElseWrappedStyle;throw new Error("")}})),o.register("lol00",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setSrc=void 0;var r=o("jiQFf");e.exports.setSrc=function(e,t){e.src=(0,r.unwrapResourceUrl)(t)}})),o.register("6ldeR",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setAction=void 0;var r=o("2ENVC");e.exports.setAction=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&(e.action=o)}})),o.register("kd9iV",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setSrcdoc=e.exports.setSrc=void 0;var r=o("jgpFH"),n=o("jiQFf");e.exports.setSrc=function(e,t){e.src=(0,n.unwrapResourceUrl)(t).toString()},e.exports.setSrcdoc=function(e,t){e.srcdoc=(0,r.unwrapHtml)(t)}})),o.register("fnqWD",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setFormaction=void 0;var r=o("2ENVC");e.exports.setFormaction=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&(e.formAction=o)}})),o.register("kh4Pu",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setHrefAndRel=void 0;var r=o("2ENVC"),n=o("jiQFf"),i=["alternate","author","bookmark","canonical","cite","help","icon","license","next","prefetch","dns-prefetch","prerender","preconnect","preload","prev","search","subresource"];e.exports.setHrefAndRel=function(e,t,o){if((0,n.isResourceUrl)(t))e.href=(0,n.unwrapResourceUrl)(t).toString();else{if(-1===i.indexOf(o))throw new Error('TrustedResourceUrl href attribute required with rel="'.concat(o,'"'));var s=(0,r.unwrapUrlOrSanitize)(t);if(void 0===s)return;e.href=s}e.rel=o}})),o.register("7vb5v",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setData=void 0;var r=o("jiQFf");e.exports.setData=function(e,t){e.data=(0,r.unwrapResourceUrl)(t)}})),o.register("4oQMh",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setSrc=e.exports.setTextContent=void 0;var r=o("jiQFf"),n=o("5GK9D");function i(e){var t=function(e){var t,r=e.document,o=null===(t=r.querySelector)||void 0===t?void 0:t.call(r,"script[nonce]");return o&&(o.nonce||o.getAttribute("nonce"))||""}(e.ownerDocument&&e.ownerDocument.defaultView||window);t&&e.setAttribute("nonce",t)}e.exports.setTextContent=function(e,t){e.textContent=(0,n.unwrapScript)(t),i(e)},e.exports.setSrc=function(e,t){e.src=(0,r.unwrapResourceUrl)(t),i(e)}})),o.register("5GK9D",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.unwrapScript=e.exports.isScript=e.exports.EMPTY_SCRIPT=e.exports.createScript=e.exports.SafeScript=void 0;var r=o("6cacD"),n=o("klfJc"),i=function(){function e(e,t){(0,r.ensureTokenIsValid)(t),this.privateDoNotAccessOrElseWrappedScript=e}return e.prototype.toString=function(){return this.privateDoNotAccessOrElseWrappedScript.toString()},e}();function s(e,t){return null!=t?t:new i(e,r.secretToken)}var c=(window,window.TrustedScript);e.exports.SafeScript=null!=c?c:i,e.exports.createScript=function(e){var t,r=e;return s(r,null===(t=(0,n.getTrustedTypesPolicy)())||void 0===t?void 0:t.createScript(r))},e.exports.EMPTY_SCRIPT=function(){var e;return s("",null===(e=(0,n.getTrustedTypes)())||void 0===e?void 0:e.emptyScript)}(),e.exports.isScript=function(e){var t;return(null===(t=(0,n.getTrustedTypes)())||void 0===t?void 0:t.isScript(e))||e instanceof i},e.exports.unwrapScript=function(e){var t;if(null===(t=(0,n.getTrustedTypes)())||void 0===t?void 0:t.isScript(e))return e;if(e instanceof i)return e.privateDoNotAccessOrElseWrappedScript;throw new Error("")}})),o.register("egpjA",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setTextContent=void 0;var r=o("4fOM5");e.exports.setTextContent=function(e,t){e.textContent=(0,r.unwrapStyleSheet)(t)}})),o.register("4fOM5",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */var r,n=e.exports&&e.exports.__extends||(r=function(e,t){return r=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var r in t)Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r])},r(e,t)},function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Class extends value "+String(t)+" is not a constructor or null");function o(){this.constructor=e}r(e,t),e.prototype=null===t?Object.create(t):(o.prototype=t.prototype,new o)});Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.unwrapStyleSheet=e.exports.isStyleSheet=e.exports.createStyleSheet=e.exports.SafeStyleSheet=void 0;var i=o("6cacD"),s=function(){};e.exports.SafeStyleSheet=s;var c=function(e){function t(t,r){var o=e.call(this)||this;return(0,i.ensureTokenIsValid)(r),o.privateDoNotAccessOrElseWrappedStyleSheet=t,o}return n(t,e),t.prototype.toString=function(){return this.privateDoNotAccessOrElseWrappedStyleSheet},t}(s);e.exports.createStyleSheet=function(e){return new c(e,i.secretToken)},e.exports.isStyleSheet=function(e){return e instanceof c},e.exports.unwrapStyleSheet=function(e){if(e instanceof c)return e.privateDoNotAccessOrElseWrappedStyleSheet;throw new Error("")}})),o.register("fOBBN",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.setHref=void 0;var r=o("2ENVC");e.exports.setHref=function(e,t){var o=(0,r.extractScheme)(t);if("javascript:"!==o&&"data:"!==o)e.setAttribute("href",t);else;}})),o.register("6Pmxq",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.execCommandInsertHtml=e.exports.execCommand=e.exports.write=void 0;var r=o("jgpFH");e.exports.write=function(e,t){e.write((0,r.unwrapHtml)(t))},e.exports.execCommand=function(e,t,o){var n=String(t),i=o;return"inserthtml"===n.toLowerCase()&&(i=(0,r.unwrapHtml)(o)),e.execCommand(n,!1,i)},e.exports.execCommandInsertHtml=function(e,t){return e.execCommand("insertHTML",!1,(0,r.unwrapHtml)(t))}})),o.register("kAuWV",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.parseFromString=e.exports.parseXml=e.exports.parseHtml=void 0;var r=o("jgpFH");function n(e,t,o){return e.parseFromString((0,r.unwrapHtml)(t),o)}e.exports.parseHtml=function(e,t){return n(e,t,"text/html")},e.exports.parseXml=function(e,t){for(var o,i=n(e,(0,r.createHtml)(t),"text/xml"),s=document.createNodeIterator(i,NodeFilter.SHOW_ALL,null,!1);o=s.nextNode();)if(o instanceof HTMLElement||o instanceof SVGElement){throw new Error("unsafe XML")}return i},e.exports.parseFromString=n})),o.register("aiHiK",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.globalEval=void 0;var r=o("5GK9D");e.exports.globalEval=function(e,t){var o=(0,r.unwrapScript)(t),n=e.eval(o);return n===o&&(n=e.eval(o.toString())),n}})),o.register("2C28f",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.assign=e.exports.replace=e.exports.setHref=void 0;var r=o("2ENVC");e.exports.setHref=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&(e.href=o)},e.exports.replace=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&e.replace(o)},e.exports.assign=function(e,t){var o=(0,r.unwrapUrlOrSanitize)(t);void 0!==o&&e.assign(o)}})),o.register("3KPL1",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.createContextualFragment=void 0;var r=o("jgpFH");e.exports.createContextualFragment=function(e,t){return e.createContextualFragment((0,r.unwrapHtml)(t))}})),o.register("8Lcrp",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.register=void 0;var r=o("jiQFf");e.exports.register=function(e,t,o){return e.register((0,r.unwrapResourceUrl)(t),o)}})),o.register("gvU3b",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.objectUrlFromSafeSource=void 0,e.exports.objectUrlFromSafeSource=function(e){if("undefined"!=typeof MediaSource&&e instanceof MediaSource)return URL.createObjectURL(e);var t,r,o=e;if(t=o.type,2!==(null==(r=t.match(/^([^;]+)(?:;\w+=(?:\w+|"[\w;,= ]+"))*$/i))?void 0:r.length)||!(function(e){return/^image\/(?:bmp|gif|jpeg|jpg|png|tiff|webp|x-icon|heic|heif)$/i.test(e)}(r[1])||function(e){return/^video\/(?:mpeg|mp4|ogg|webm|x-matroska|quicktime|x-ms-wmv)$/i.test(e)}(r[1])||function(e){return/^audio\/(?:3gpp2|3gpp|aac|L16|midi|mp3|mp4|mpeg|oga|ogg|opus|x-m4a|x-matroska|x-wav|wav|webm)$/i.test(e)}(r[1]))){throw new Error("")}return URL.createObjectURL(o)}})),o.register("jAUBe",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.open=void 0;var r=o("2ENVC");e.exports.open=function(e,t,o,n){var i=(0,r.unwrapUrlOrSanitize)(t);return void 0!==i?e.open(i,o,n):null}})),o.register("ctk9y",(function(e,t){"use strict";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */var r=e.exports&&e.exports.__read||function(e,t){var r="function"==typeof Symbol&&e[Symbol.iterator];if(!r)return e;var o,n,i=r.call(e),s=[];try{for(;(void 0===t||t-- >0)&&!(o=i.next()).done;)s.push(o.value)}catch(e){n={error:e}}finally{try{o&&!o.done&&(r=i.return)&&r.call(i)}finally{if(n)throw n.error}}return s},n=e.exports&&e.exports.__spreadArray||function(e,t,r){if(r||2===arguments.length)for(var o,n=0,i=t.length;n<i;n++)!o&&n in t||(o||(o=Array.prototype.slice.call(t,0,n)),o[n]=t[n]);return e.concat(o||Array.prototype.slice.call(t))};Object.defineProperty(e.exports,"__esModule",{value:!0}),e.exports.importScripts=e.exports.createShared=e.exports.create=void 0;var i=o("jiQFf");e.exports.create=function(e,t){return new Worker((0,i.unwrapResourceUrl)(e),t)},e.exports.createShared=function(e,t){return new SharedWorker((0,i.unwrapResourceUrl)(e),t)},e.exports.importScripts=function(e){for(var t=[],o=1;o<arguments.length;o++)t[o-1]=arguments[o];e.importScripts.apply(e,n([],r(t.map((function(e){return(0,i.unwrapResourceUrl)(e)}))),!1))}}));
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
const n={};
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
let i,s="google#safe";function c(){return""!==s?function(){if("undefined"!=typeof window)return window.trustedTypes}()??null:null}function a(){if(void 0===i)try{i=c()?.createPolicy(s,{createHTML:e=>e,createScript:e=>e,createScriptURL:e=>e})??null}catch{i=null}return i}class u{privateDoNotAccessOrElseWrappedResourceUrl;constructor(e,t){this.privateDoNotAccessOrElseWrappedResourceUrl=e}toString(){return this.privateDoNotAccessOrElseWrappedResourceUrl.toString()}}window,window.TrustedScriptURL;function p(e){const t=e,r=a()?.createScriptURL(t);return r??new u(t,n)}
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
class l{privateDoNotAccessOrElseWrappedScript;constructor(e,t){this.privateDoNotAccessOrElseWrappedScript=e}toString(){return this.privateDoNotAccessOrElseWrappedScript.toString()}}window,window.TrustedScript;function f(e,...t){if(0===t.length)return p(e[0]);e[0].toLowerCase();const r=[e[0]];for(let o=0;o<t.length;o++)r.push(encodeURIComponent(t[o])),r.push(e[o+1]);return p(r.join(""))}var d={},v=d&&d.__createBinding||(Object.create?function(e,t,r,o){void 0===o&&(o=r);var n=Object.getOwnPropertyDescriptor(t,r);n&&!("get"in n?!t.__esModule:n.writable||n.configurable)||(n={enumerable:!0,get:function(){return t[r]}}),Object.defineProperty(e,o,n)}:function(e,t,r,o){void 0===o&&(o=r),e[o]=t[r]}),x=d&&d.__setModuleDefault||(Object.create?function(e,t){Object.defineProperty(e,"default",{enumerable:!0,value:t})}:function(e,t){e.default=t}),y=d&&d.__importStar||function(e){if(e&&e.__esModule)return e;var t={};if(null!=e)for(var r in e)"default"!==r&&Object.prototype.hasOwnProperty.call(e,r)&&v(t,e,r);return x(t,e),t};if(Object.defineProperty(d,"__esModule",{value:!0}),d.safeWorker=d.safeWindow=d.safeUrl=d.safeServiceWorkerContainer=d.safeRange=d.safeLocation=d.safeGlobal=d.safeDomParser=d.safeDocument=d.safeSvgUseEl=d.safeStyleEl=d.safeScriptEl=d.safeObjectEl=d.safeLinkEl=d.safeInputEl=d.safeIframeEl=d.safeFormEl=d.safeEmbedEl=d.safeElement=d.safeButtonEl=d.safeBaseEl=d.safeAreaEl=d.safeAnchorEl=void 0,d.safeAnchorEl=y(o("jUBUQ")),d.safeAreaEl=y(o("efUhS")),d.safeBaseEl=y(o("14NpD")),d.safeButtonEl=y(o("3E1T5")),d.safeElement=y(o("5U7de")),d.safeEmbedEl=y(o("lol00")),d.safeFormEl=y(o("6ldeR")),d.safeIframeEl=y(o("kd9iV")),d.safeInputEl=y(o("fnqWD")),d.safeLinkEl=y(o("kh4Pu")),d.safeObjectEl=y(o("7vb5v")),d.safeScriptEl=y(o("4oQMh")),d.safeStyleEl=y(o("egpjA")),d.safeSvgUseEl=y(o("fOBBN")),d.safeDocument=y(o("6Pmxq")),d.safeDomParser=y(o("kAuWV")),d.safeGlobal=y(o("aiHiK")),d.safeLocation=y(o("2C28f")),d.safeRange=y(o("3KPL1")),d.safeServiceWorkerContainer=y(o("8Lcrp")),d.safeUrl=y(o("gvU3b")),d.safeWindow=y(o("jAUBe")),d.safeWorker=y(o("ctk9y")),"/"!==location.pathname){const e=location.pathname.split("/view/"),t=new RegExp("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");2===e.length&&t.test(e[1])||(location.href="/"),interestObj={favorites:{}};const r=e[1],o=new XMLHttpRequest;o.addEventListener("load",(()=>{if(200===o.status){const e=JSON.parse(o.response);for(const t of Object.keys(e))void 0===interestObj[t]?interestObj[t]=e[t]:Object.assign(interestObj[t],e[t])}else alert(o.response),location.href="/"})),o.open("GET",`/bio/${r}`,!1),o.send()}function S(e,t){document.querySelector(`#bio-${e}`).textContent=`${e}: ${t}`}function w(){const e=document.querySelector("#editor-style").content;document.head.appendChild(e);const t=document.createElement("script");d.safeScriptEl.setSrc(t,f(editor)),document.body.appendChild(t)}window.addEventListener("DOMContentLoaded",(()=>{!function(){if("/"===location.pathname){const e=document.querySelector("#bio-edit").content;document.querySelector("#edit-div").appendChild(e);const t=document.querySelector("#form"),r=document.querySelector("#save");t.addEventListener("submit",(async e=>{e.preventDefault(),r.disabled=!0;const o=new FormData(t),n={},i={};o.forEach(((e,t)=>{"food"===t?i[t]=o.getAll(t):"sports"===t||"hobbies"===t?i[t]=e:n[t]=e})),n.favorites=i;const s=await fetch("/create",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(n)});if(200!==s.status){r.disabled=!1;const e=await s.text();throw alert(e),e}{const e=await s.json();location.href=`/view/${e.id}`}}))}else{const e=document.querySelector("#bio-view").content;document.querySelector("#view-div").appendChild(e),S("name",interestObj.name);const t=interestObj.favorites;if(t)for(let e of Object.keys(t))S(e,"food"===e?t[e].join(", "):t[e]);setInnerHTML(document.querySelector("#bio-html"),sanitizer.sanitize(interestObj.introduction));const r=document.querySelector("#report");r.addEventListener("click",(function(){r.disabled=!0,fetch("/report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:location.href})}).then((e=>{r.disabled=!1,200===e.status?alert("Report sent!"):alert("An error occured, try again later!")}))}))}}(),location.pathname.startsWith("/view/")||w()}))})();
//# sourceMappingURL=main.js.map
