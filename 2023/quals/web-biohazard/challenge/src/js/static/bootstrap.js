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
if (!location.pathname.startsWith('/view/')) {
  goog.require('goog.editor.Command');
  goog.require('goog.editor.Field');
  goog.require('goog.editor.plugins.BasicTextFormatter');
  goog.require('goog.editor.plugins.EnterHandler');
  goog.require('goog.editor.plugins.HeaderFormatter');
  goog.require('goog.editor.plugins.LinkBubble');
  goog.require('goog.editor.plugins.LinkDialogPlugin');
  goog.require('goog.editor.plugins.ListTabHandler');
  goog.require('goog.editor.plugins.LoremIpsum');
  goog.require('goog.editor.plugins.RemoveFormatting');
  goog.require('goog.editor.plugins.SpacesTabHandler');
  goog.require('goog.editor.plugins.UndoRedo');
  goog.require('goog.ui.editor.DefaultToolbar');
  goog.require('goog.ui.editor.ToolbarController');
  editor = (x=>x)`/static/editor.js`;
}
