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

var editor = new goog.editor.Field('editMe');

function getInterestsPreview() {
  let name = goog.dom.getElement('name').value;
  let favoriteFood = goog.dom.getElement('food').value;
  let hobbies = goog.dom.getElement('hobbies').value;
  let sport = goog.dom.getElement('sports').value;
}

function updateFieldContents() {
  let content = editor.getCleanContents();
  let youtubeLink = goog.dom.getElement('youtube').value;
  if (youtubeLink.startsWith('https://www.youtube.com/watch')) {
    let url = new URL(youtubeLink);
    let params = new URLSearchParams(url.search);
    let iframe = document.createElement('iframe');
    iframe.src = `https://www.youtube.com/embed/${params.get('v')}`;
    iframe.width = '560';
    iframe.height = '315';
    content += '<br>' + iframe.outerHTML;
  }
  let sanitizedContent = sanitizer.sanitize(content);
  setInnerHTML(goog.dom.getElement('preview'), sanitizedContent);
  goog.dom.getElement('introduction').value = sanitizedContent;
}

editor.registerPlugin(new goog.editor.plugins.BasicTextFormatter());
editor.registerPlugin(new goog.editor.plugins.RemoveFormatting());
editor.registerPlugin(new goog.editor.plugins.UndoRedo());
editor.registerPlugin(new goog.editor.plugins.ListTabHandler());
editor.registerPlugin(new goog.editor.plugins.SpacesTabHandler());
editor.registerPlugin(new goog.editor.plugins.EnterHandler());
editor.registerPlugin(new goog.editor.plugins.HeaderFormatter());
editor.registerPlugin(
new goog.editor.plugins.LoremIpsum('Click here to edit'));
editor.registerPlugin(
new goog.editor.plugins.LinkDialogPlugin());
editor.registerPlugin(new goog.editor.plugins.LinkBubble());

const buttons = [
    goog.editor.Command.LINK, goog.editor.Command.BOLD,
    goog.editor.Command.ITALIC, goog.editor.Command.UNORDERED_LIST,
    goog.editor.Command.FONT_COLOR, goog.editor.Command.FONT_FACE,
    goog.editor.Command.FONT_SIZE, goog.editor.Command.JUSTIFY_LEFT,
    goog.editor.Command.JUSTIFY_CENTER, goog.editor.Command.JUSTIFY_RIGHT];
var toolbar = goog.ui.editor.DefaultToolbar.makeToolbar(buttons,
    goog.dom.getElement('toolbar'));

new goog.ui.editor.ToolbarController(editor, toolbar);

editor.makeEditable();

goog.events.listen(editor, goog.editor.Field.EventType.DELAYEDCHANGE,
    updateFieldContents);

