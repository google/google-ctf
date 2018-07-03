/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


class I18n {

  constructor(fs, ds) {
    this.fs = fs;
    this.ds = ds;
    this.translations = {};
  }

  translationsForLang_(lang) {
    let translations = {};
    if (!lang.match(/^\w+$/)) {
      throw new Error('Badness detected in the language field');
    }

    return this.ds(lang).then((translations) => {
      this.translations = translations;
      return translations;
    }).catch((e) => {
      console.log(e);
      throw new Error(`Canmot open dictionnary: ${e}`);
    });
  }

  forSingleWord(word) {
    return this.translations[word];
  }

  translate_(translations, template) {
    var templateValue;
    try {
      templateValue = this.fs.load(template);
    } catch (e) {
      return `Couldn't load template: ${e}`;
    }
    for (const k of Object.keys(translations)) {
      templateValue = templateValue.replace(
          new RegExp(`\\[\\[${k}\\]\\]`, 'g'), translations[k]);
    }
    return templateValue;
  }

  async forTemplateWithLang(lang, template) {
    let translations = await this.translationsForLang_(lang);
    return this.translate_(translations, template);
  }

  forTemplate(template) {
    return this.translate_(this.translations, template);
  }

  async setupAngularService(app, lang) {
    const myI18n = this;

    await this.translationsForLang_(lang);

    app.service('i18n', function() {
      return {
        template: (t) => myI18n.forTemplate(t),
        word: (w) => myI18n.forSingleWord(w),
      }
    });
  }

}

module.exports = {
  build: (fs, ds) => new I18n(fs, ds)
};
