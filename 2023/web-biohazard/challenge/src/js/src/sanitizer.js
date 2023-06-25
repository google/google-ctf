/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

goog.require('goog.dom');
goog.require('goog.dom.safe');
goog.require('goog.html.sanitizer.unsafe');
goog.require('goog.html.sanitizer.HtmlSanitizer.Builder');
goog.require('goog.string.Const');

window.addEventListener('DOMContentLoaded', () => {
  var Const = goog.string.Const;
  var unsafe = goog.html.sanitizer.unsafe;
  var builder = new goog.html.sanitizer.HtmlSanitizer.Builder();
  builder = unsafe.alsoAllowTags(
      Const.from('IFRAME is required for Youtube embed'), builder, ['IFRAME']);
  sanitizer = unsafe.alsoAllowAttributes(
      Const.from('iframe#src is required for Youtube embed'), builder,
      [
        {
        tagName: 'iframe',
        attributeName: 'src',
        policy: (s) => s.startsWith('https://') ? s : '',
        }
      ]).build();
});

setInnerHTML = function(elem, html) {
  goog.dom.safe.setInnerHtml(elem, html);
}



